/*
 * Sessions, passwords, OAuth and outbound mail.
 *
 * Everything here runs on what the Workers runtime already ships - WebCrypto for
 * signing and hashing, fetch for the providers. No dependency, so nothing to keep
 * patched on a service that has to stay up for a moderator mid-screenshare.
 */

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(p + '='.repeat((4 - p.length % 4) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function randomId(bytes = 16) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

// Two strings of the same length compared with === leak where they first differ.
// It does not matter much for a session cookie behind TLS, and it costs four lines.
function sameSecret(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function sign(secret, msg) {
  return b64url(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(msg)));
}

// ---- sessions -------------------------------------------------------------
// A signed cookie rather than a sessions table: one less round trip on every
// request, and one less thing to expire by hand. The cost is that signing out
// everywhere means rotating SESSION_SECRET, which is the right trade for a tool
// where the sensitive action (uploading a scan) is gated by a server key anyway.

const COOKIE = 'aa_session';
const MAX_AGE = 60 * 60 * 24 * 30;

export async function makeSession(env, userId) {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const body = `${userId}.${exp}`;
  return `${body}.${await sign(env.SESSION_SECRET, body)}`;
}

export async function readSession(env, req) {
  const raw = (req.headers.get('cookie') || '')
    .split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  if (!raw) return null;
  const token = decodeURIComponent(raw.slice(COOKIE.length + 1));
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const body = token.slice(0, i), mac = token.slice(i + 1);
  if (!sameSecret(mac, await sign(env.SESSION_SECRET, body))) return null;
  const [userId, exp] = body.split('.');
  if (!userId || !exp || Number(exp) * 1000 < Date.now()) return null;
  return userId;
}

export function sessionCookie(value, secure) {
  const flags = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${value ? MAX_AGE : 0}` + (secure ? '; Secure' : '');
  return `${COOKIE}=${value ? encodeURIComponent(value) : ''}; ${flags}`;
}

// ---- passwords ------------------------------------------------------------

export async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromB64url(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  return b64url(bits);
}
export async function newPassword(password) {
  const salt = randomId(16);
  return { salt, hash: await hashPassword(password, salt) };
}
export async function checkPassword(password, salt, expected) {
  return sameSecret(await hashPassword(password, salt), expected);
}

// A password that is only ever checked against a hash still has a floor: eight
// characters is where "guessable in an afternoon" stops, and it is what every
// signup form the applicant has ever filled in already taught them to expect.
export function passwordProblem(p) {
  if (typeof p !== 'string' || p.length < 8) return 'Password must be at least 8 characters.';
  if (p.length > 200) return 'Password must be under 200 characters.';
  return null;
}
export function emailProblem(e) {
  if (typeof e !== 'string' || !/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(e) || e.length > 200) {
    return 'That does not look like an email address.';
  }
  return null;
}

// ---- OAuth ----------------------------------------------------------------
// Discord and Google differ in three URLs and the shape of one JSON response, so
// they are one flow with a table rather than two nearly identical flows that
// drift apart the first time one of them is fixed.

export const PROVIDERS = {
  discord: {
    scope: 'identify email',
    authorize: 'https://discord.com/oauth2/authorize',
    token: 'https://discord.com/api/oauth2/token',
    user: 'https://discord.com/api/users/@me',
    id: e => e.DISCORD_CLIENT_ID,
    secret: e => e.DISCORD_CLIENT_SECRET,
    profile: u => ({
      id: u.id,
      name: u.global_name || u.username,
      email: u.email || null,
      avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=128` : null,
    }),
  },
  google: {
    scope: 'openid email profile',
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    user: 'https://www.googleapis.com/oauth2/v3/userinfo',
    id: e => e.GOOGLE_CLIENT_ID,
    secret: e => e.GOOGLE_CLIENT_SECRET,
    profile: u => ({ id: u.sub, name: u.name || u.email, email: u.email || null, avatar: u.picture || null }),
  },
};

const STATE_COOKIE = 'aa_oauth';

// The state cookie carries where to go afterwards as well as the nonce, so a
// half-finished "apply for your server" click lands back on the form instead of
// dumping the applicant on the home page wondering whether it worked.
export async function startOAuth(env, url, name, next) {
  const p = PROVIDERS[name];
  const clientId = p.id(env);
  if (!clientId) return null;
  const nonce = randomId(16);
  const state = `${nonce}.${encodeURIComponent(next || '/app')}`;
  const signed = `${state}.${await sign(env.SESSION_SECRET, state)}`;
  const to = new URL(p.authorize);
  to.searchParams.set('client_id', clientId);
  to.searchParams.set('redirect_uri', `${url.origin}/auth/${name}/callback`);
  to.searchParams.set('response_type', 'code');
  to.searchParams.set('scope', p.scope);
  if (name === 'google') { to.searchParams.set('access_type', 'online'); to.searchParams.set('prompt', 'select_account'); }
  return {
    location: to.toString(),
    cookie: `${STATE_COOKIE}=${encodeURIComponent(signed)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600` +
      (url.protocol === 'https:' ? '; Secure' : ''),
  };
}

export async function finishOAuth(env, url, req, name) {
  const p = PROVIDERS[name];
  const code = url.searchParams.get('code');
  if (!code) return { error: 'No code came back from the provider.' };

  const raw = (req.headers.get('cookie') || '')
    .split(';').map(s => s.trim()).find(s => s.startsWith(STATE_COOKIE + '='));
  if (!raw) return { error: 'Your sign-in took too long. Try again.' };
  const signed = decodeURIComponent(raw.slice(STATE_COOKIE.length + 1));
  const i = signed.lastIndexOf('.');
  const state = signed.slice(0, i);
  if (!sameSecret(signed.slice(i + 1), await sign(env.SESSION_SECRET, state))) {
    return { error: 'That sign-in did not start here.' };
  }
  // The nonce is signed and short-lived, which is what makes the callback
  // unforgeable; comparing it to the query string too would need somewhere to
  // put it, and the cookie is that somewhere.
  if (url.searchParams.get('state') && url.searchParams.get('state') !== state) {
    return { error: 'That sign-in did not start here.' };
  }
  const next = decodeURIComponent(state.split('.').slice(1).join('.') || '/app');

  const body = new URLSearchParams({
    client_id: p.id(env), client_secret: p.secret(env), grant_type: 'authorization_code',
    code, redirect_uri: `${url.origin}/auth/${name}/callback`,
  });
  const tr = await fetch(p.token, {
    method: 'POST', body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
  });
  if (!tr.ok) return { error: `${name} refused the sign-in.` };
  const tok = await tr.json();
  if (!tok.access_token) return { error: `${name} refused the sign-in.` };

  const ur = await fetch(p.user, { headers: { Authorization: `Bearer ${tok.access_token}` } });
  if (!ur.ok) return { error: `${name} would not share your profile.` };
  return { profile: p.profile(await ur.json()), next };
}

export function clearStateCookie(secure) {
  return `${STATE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` + (secure ? '; Secure' : '');
}

// ---- mail -----------------------------------------------------------------
// Cloudflare cannot send mail, so verification and password resets go through
// Resend. With no key configured the caller is told the mail did not go out
// rather than being left to believe it did.

export async function sendMail(env, to, subject, text) {
  if (!env.RESEND_KEY) return { ok: false, reason: 'no mail service configured' };
  const from = env.MAIL_FROM || 'AsyncAnalyzer <onboarding@resend.dev>';
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [to], subject, text }),
  });
  if (!r.ok) return { ok: false, reason: await r.text() };
  return { ok: true };
}
