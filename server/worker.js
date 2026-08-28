/*
 * AsyncAnalyzer — the whole public product on one Cloudflare Worker.
 *
 * One Worker serves the site and the API from the same origin, which is why the
 * session cookie just works: no CORS dance, no second deploy, no third place for
 * a URL to be wrong.
 *
 * Secrets (wrangler secret put ...):
 *   SESSION_SECRET   signs session and OAuth-state cookies   (required)
 *   STAFF_KEY        uploads that are allowed to train the shared model
 *   DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET
 *   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
 *   RESEND_KEY, MAIL_FROM      verification and password-reset mail
 *   DISCORD_WEBHOOK            pinged when somebody applies
 *   VIEW_KEY                   legacy: read the raw history without an account
 */
import {
  makeSession, readSession, sessionCookie, startOAuth, finishOAuth, clearStateCookie,
  newPassword, checkPassword, passwordProblem, emailProblem, randomId, sendMail,
} from './auth.js';
import {
  context, can, isStaff, isOwner, upsertIdentity, claimOwnerIfFirst,
  createServer, serverBySlug, membersOf, notifyDiscord,
} from './tenancy.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type,x-key',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
};

const BASE_MODEL_URL = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml/model.json';
const BASE_SMODEL_URL = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml/session_model.json';
const TOOL_URL = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1';

function json(obj, code = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status: code, headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });
}
function redirect(to, cookies = []) {
  const h = new Headers({ Location: to });
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response('', { status: 302, headers: h });
}
function clip(s, n) { return String(s == null ? '' : s).slice(0, n); }
const now = () => new Date().toISOString();

// The scanned PC's own Windows account name travels inside modPath
// (C:\Users\<real name>\AppData\Roaming\.minecraft\mods). A moderator needs to
// know WHICH folder was scanned, not who the person is called on their own
// computer, and this row can end up in a screenshot.
function anonPath(p) {
  return String(p == null ? '' : p).replace(/(\\Users\\)[^\\]+/gi, '$1<user>');
}

// ponytail: per-isolate counters, so the real ceiling is (isolates x limit).
// That is enough to blunt a script and not enough to stop a distributed one;
// swap in a Durable Object if that day comes.
const RATE = new Map(), AUTH_RATE = new Map();
function limited(map, ip, perMinute) {
  const t = Date.now();
  const r = map.get(ip) || { n: 0, t };
  if (t - r.t > 60000) { r.n = 0; r.t = t; }
  r.n++; map.set(ip, r);
  return r.n > perMinute;
}

// A stored model from an OLDER version has a shorter feature_order, so the features
// added since would simply never be trained - silently, because a missing feature
// multiplies by 0 rather than failing. Refetch the new base instead; the team
// relearns from its next scans, which is cheap, and a half-trained model is not.
async function loadModel(env, key, baseUrl) {
  const row = await env.DB.prepare('SELECT v FROM meta WHERE k = ?').bind(key).first();
  const base = await (await fetch(baseUrl)).json();
  if (row) {
    const cur = JSON.parse(row.v);
    if ((cur.version || 0) >= (base.version || 0)) return cur;
  }
  const m = {
    version: base.version, feature_order: base.feature_order, intercept: base.intercept,
    weights: { ...base.weights }, base: { intercept: base.intercept, weights: { ...base.weights } },
    trainedCount: 0,
  };
  await env.DB.prepare('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)').bind(key, JSON.stringify(m)).run();
  return m;
}
const getModel = env => loadModel(env, 'model', BASE_MODEL_URL);
const getSModel = env => loadModel(env, 'smodel', BASE_SMODEL_URL);

function sgdStep(m, vec, label) {
  const O = m.feature_order, lr = 0.05, l2 = 0.02, clamp = 8;
  let z = m.intercept;
  for (let i = 0; i < O.length; i++) z += m.weights[O[i]] * (+vec[i] || 0);
  const p = z < -60 ? 0 : z > 60 ? 1 : 1 / (1 + Math.exp(-z));
  const err = p - label;
  for (let i = 0; i < O.length; i++) {
    const k = O[i];
    const w = m.weights[k] - lr * (err * (+vec[i] || 0) + l2 * (m.weights[k] - m.base.weights[k]));
    m.weights[k] = Math.max(-clamp, Math.min(clamp, w));
  }
  m.intercept = Math.max(-clamp, Math.min(clamp, m.intercept - lr * (err + l2 * (m.intercept - m.base.intercept))));
  m.trainedCount = (m.trainedCount || 0) + 1;
}

// D1 has no "ADD COLUMN IF NOT EXISTS", and schema.sql has to stay re-runnable,
// so the one column added after the first deploy is added here instead. Costs one
// failed statement per cold isolate and nothing after that.
let migrated = false;
async function migrate(env) {
  if (migrated) return;
  migrated = true;
  try { await env.DB.exec('ALTER TABLE scans ADD COLUMN server_id TEXT'); } catch { /* already there */ }
}

// A shared result must not carry the suspect's PC name, their Windows account or
// the unrelated software the system checks noticed. The verdict and what it rests
// on is the part anybody is entitled to argue with.
function publicScan(s) {
  return {
    scanId: s.scanId || s.id, serverTs: s.serverTs, verdict: s.verdict,
    targetUser: s.targetUser, scanner: s.scanner, toolVersion: s.toolVersion,
    totals: s.totals || {}, session: s.session || null,
    flagged: (s.flagged || []).map(m => ({ name: m.name, score: m.score, verdict: m.verdict, reasons: m.reasons })),
    review: (s.review || []).map(m => ({ name: m.name, score: m.score, verdict: m.verdict, reasons: m.reasons })),
  };
}

// Clean URLs the site owns but that no file matches one-to-one, because the last
// segment is data: /app/rayzesmp/scan/AB12 is one page, not one file per scan.
// These are extensionless on purpose. The asset server redirects a request for
// /share.html to /share, and a redirect would throw away the /s/<id> the page
// needs; asking it for the pretty name hands back the file itself.
function pageFor(path) {
  const app = path.match(/^\/app\/[^/]+(?:\/(team|setup))?$/);
  if (app) return app[1] ? `/app/${app[1]}` : '/app/server';
  if (/^\/app\/[^/]+\/scan\/[^/]+$/.test(path)) return '/app/scan';
  if (/^\/s\/[^/]+$/.test(path)) return '/share';
  if (/^\/join\/[^/]+$/.test(path)) return '/join';
  return null;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return new Response('', { status: 204, headers: CORS });

    const ip = (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
    const isApi = path.startsWith('/api/') || path.startsWith('/auth/');
    if (isApi && limited(RATE, ip, 120)) return json({ error: 'Too many requests. Wait a minute.' }, 429);

    // The one-liner a suspect runs points here rather than at GitHub, so the
    // download and the upload are the same host - one domain for a moderator to
    // read out loud, and one to allow if a network blocks the other.
    if (path === '/run.ps1') {
      const r = await fetch(TOOL_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
      if (!r.ok) return new Response('# AsyncAnalyzer is temporarily unavailable.\n', { status: 502, headers: { 'Content-Type': 'text/plain' } });
      return new Response(r.body, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=300' } });
    }

    if (!isApi) {
      const page = pageFor(path);
      if (page) {
        const to = new URL(req.url);
        to.pathname = page;
        return env.ASSETS.fetch(new Request(to, req));
      }
      return env.ASSETS.fetch(req);
    }

    await migrate(env);

    const secure = url.protocol === 'https:';
    const STAFF_KEY = env.STAFF_KEY || '';
    const VIEW_KEY = env.VIEW_KEY || '';
    const given = req.headers.get('x-key') || '';
    const staffKeyed = !!STAFF_KEY && given === STAFF_KEY;

    const userId = await readSession(env, req);
    const ctx = await context(env, userId);

    const need = (action, serverId) =>
      can(ctx, action, serverId) ? null : json({ error: ctx.user ? 'Not allowed.' : 'Sign in first.' }, ctx.user ? 403 : 401);
    const body = async () => { try { return await req.json(); } catch { return null; } };

    // ---------------------------------------------------------------- OAuth

    const oauthStart = path.match(/^\/auth\/(discord|google)$/);
    if (req.method === 'GET' && oauthStart) {
      const started = await startOAuth(env, url, oauthStart[1], url.searchParams.get('next'));
      if (!started) return redirect(`/login?error=${oauthStart[1]}+sign-in+is+not+configured+yet`);
      return redirect(started.location, [started.cookie]);
    }

    const oauthBack = path.match(/^\/auth\/(discord|google)\/callback$/);
    if (req.method === 'GET' && oauthBack) {
      const r = await finishOAuth(env, url, req, oauthBack[1]);
      if (r.error) return redirect(`/login?error=${encodeURIComponent(r.error)}`, [clearStateCookie(secure)]);
      const uid = await upsertIdentity(env, oauthBack[1], r.profile);
      await claimOwnerIfFirst(env, uid);
      return redirect(r.next || '/app', [sessionCookie(await makeSession(env, uid), secure), clearStateCookie(secure)]);
    }

    // ------------------------------------------------------ password accounts

    if (req.method === 'POST' && path.startsWith('/api/auth/')) {
      if (limited(AUTH_RATE, ip, 15)) return json({ error: 'Too many attempts. Wait a minute.' }, 429);
    }

    if (req.method === 'POST' && path === '/api/auth/logout') {
      return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', secure) });
    }

    if (req.method === 'POST' && path === '/api/auth/signup') {
      const b = await body();
      if (!b) return json({ error: 'Bad request.' }, 400);
      const email = String(b.email || '').trim().toLowerCase();
      const bad = emailProblem(email) || passwordProblem(b.password);
      if (bad) return json({ error: bad }, 400);
      const name = clip(String(b.name || '').trim() || email.split('@')[0], 60);

      const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      // An existing account is not news a stranger gets to fish for, so this
      // answers the same way either way and the mail does the telling.
      if (existing) {
        const hasPw = await env.DB.prepare('SELECT user_id FROM credentials WHERE user_id = ?').bind(existing.id).first();
        if (!hasPw) {
          const { salt, hash } = await newPassword(b.password);
          const token = randomId(24);
          await env.DB.prepare(
            `INSERT INTO credentials (user_id, hash, salt, verified, token, token_kind, token_exp) VALUES (?,?,?,0,?,'verify',?)`)
            .bind(existing.id, hash, salt, token, new Date(Date.now() + 864e5).toISOString()).run();
          await env.DB.prepare("INSERT OR IGNORE INTO identities (provider, provider_id, user_id) VALUES ('password',?,?)")
            .bind(email, existing.id).run();
          await sendMail(env, email, 'Confirm your AsyncAnalyzer account',
            `Confirm your address to finish setting up your password:\n\n${url.origin}/auth/verify?token=${token}\n\nThis link is good for 24 hours.`);
        }
        return json({ ok: true, check: 'mail' });
      }

      const uid = randomId(12);
      const { salt, hash } = await newPassword(b.password);
      const token = randomId(24);
      await env.DB.prepare('INSERT INTO users (id, email, name, avatar, global_role, created_ts) VALUES (?,?,?,NULL,NULL,?)')
        .bind(uid, email, name, now()).run();
      await env.DB.prepare("INSERT INTO identities (provider, provider_id, user_id) VALUES ('password',?,?)")
        .bind(email, uid).run();
      await env.DB.prepare(
        `INSERT INTO credentials (user_id, hash, salt, verified, token, token_kind, token_exp) VALUES (?,?,?,0,?,'verify',?)`)
        .bind(uid, hash, salt, token, new Date(Date.now() + 864e5).toISOString()).run();
      const mail = await sendMail(env, email, 'Confirm your AsyncAnalyzer account',
        `Welcome. Confirm your address to activate your account:\n\n${url.origin}/auth/verify?token=${token}\n\nThis link is good for 24 hours.`);
      // Saying "check your inbox" when no mail service is configured strands the
      // account with no way in, so say what actually happened instead.
      return json({ ok: true, check: 'mail', mailed: mail.ok, reason: mail.ok ? undefined : mail.reason });
    }

    if (req.method === 'GET' && path === '/auth/verify') {
      const token = url.searchParams.get('token') || '';
      const row = await env.DB.prepare("SELECT * FROM credentials WHERE token = ? AND token_kind = 'verify'").bind(token).first();
      if (!row || !row.token_exp || row.token_exp < now()) {
        return redirect('/login?error=' + encodeURIComponent('That confirmation link has expired. Sign up again.'));
      }
      await env.DB.prepare('UPDATE credentials SET verified = 1, token = NULL, token_kind = NULL, token_exp = NULL WHERE user_id = ?')
        .bind(row.user_id).run();
      await claimOwnerIfFirst(env, row.user_id);
      return redirect('/app', [sessionCookie(await makeSession(env, row.user_id), secure)]);
    }

    if (req.method === 'POST' && path === '/api/auth/login') {
      const b = await body();
      if (!b) return json({ error: 'Bad request.' }, 400);
      const email = String(b.email || '').trim().toLowerCase();
      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      const cred = user && await env.DB.prepare('SELECT * FROM credentials WHERE user_id = ?').bind(user.id).first();
      if (!cred || !await checkPassword(String(b.password || ''), cred.salt, cred.hash)) {
        return json({ error: 'Wrong email or password.' }, 401);
      }
      if (!cred.verified) return json({ error: 'Confirm your email address first — check your inbox.' }, 403);
      return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(await makeSession(env, user.id), secure) });
    }

    if (req.method === 'POST' && path === '/api/auth/forgot') {
      const b = await body();
      const email = String((b && b.email) || '').trim().toLowerCase();
      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (user) {
        const cred = await env.DB.prepare('SELECT user_id FROM credentials WHERE user_id = ?').bind(user.id).first();
        if (cred) {
          const token = randomId(24);
          await env.DB.prepare("UPDATE credentials SET token = ?, token_kind = 'reset', token_exp = ? WHERE user_id = ?")
            .bind(token, new Date(Date.now() + 36e5).toISOString(), user.id).run();
          await sendMail(env, email, 'Reset your AsyncAnalyzer password',
            `Set a new password here:\n\n${url.origin}/reset?token=${token}\n\nThis link is good for one hour. If you did not ask for it, ignore this mail.`);
        }
      }
      // Same answer whether or not the address exists. Otherwise this endpoint
      // becomes a way to ask "does this person have an account".
      return json({ ok: true });
    }

    if (req.method === 'POST' && path === '/api/auth/reset') {
      const b = await body();
      if (!b) return json({ error: 'Bad request.' }, 400);
      const bad = passwordProblem(b.password);
      if (bad) return json({ error: bad }, 400);
      const row = await env.DB.prepare("SELECT * FROM credentials WHERE token = ? AND token_kind = 'reset'")
        .bind(String(b.token || '')).first();
      if (!row || !row.token_exp || row.token_exp < now()) {
        return json({ error: 'That reset link has expired. Ask for a new one.' }, 400);
      }
      const { salt, hash } = await newPassword(b.password);
      // Resetting through a mailed link proves the address, so it verifies too.
      await env.DB.prepare('UPDATE credentials SET hash = ?, salt = ?, verified = 1, token = NULL, token_kind = NULL, token_exp = NULL WHERE user_id = ?')
        .bind(hash, salt, row.user_id).run();
      return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(await makeSession(env, row.user_id), secure) });
    }

    // ------------------------------------------------------------------- me

    if (req.method === 'GET' && path === '/api/me') {
      if (!ctx.user) return json({ user: null, providers: providerList(env) });
      const app = await env.DB.prepare(
        "SELECT id, name, status, created_ts FROM applications WHERE user_id = ? ORDER BY created_ts DESC LIMIT 1")
        .bind(ctx.user.id).first();
      return json({
        user: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email, avatar: ctx.user.avatar, role: ctx.user.global_role },
        servers: ctx.servers, application: app || null, staff: isStaff(ctx), owner: isOwner(ctx),
      });
    }

    // --------------------------------------------------------- applications

    if (req.method === 'POST' && path === '/api/applications') {
      if (!ctx.user) return json({ error: 'Sign in first.' }, 401);
      const b = await body();
      if (!b) return json({ error: 'Bad request.' }, 400);
      const name = clip(String(b.name || '').trim(), 60);
      const reason = clip(String(b.reason || '').trim(), 1000);
      if (name.length < 2) return json({ error: 'Give your server a name.' }, 400);
      if (reason.length < 20) return json({ error: 'Tell us in a sentence or two why you need it.' }, 400);

      const open = await env.DB.prepare("SELECT id FROM applications WHERE user_id = ? AND status = 'pending'")
        .bind(ctx.user.id).first();
      if (open) return json({ error: 'You already have an application waiting.' }, 409);

      const id = randomId(10);
      await env.DB.prepare(
        `INSERT INTO applications (id, user_id, name, discord_invite, players, age, reason, status, created_ts)
         VALUES (?,?,?,?,?,?,?, 'pending', ?)`)
        .bind(id, ctx.user.id, name, clip(b.discordInvite, 120), clip(b.players, 40), clip(b.age, 40), reason, now()).run();
      await notifyDiscord(env,
        `**New server application** — ${name}\nfrom **${ctx.user.name}** (${ctx.user.email || 'no email'})\n` +
        `players: ${clip(b.players, 40) || '?'} · running for: ${clip(b.age, 40) || '?'} · ${clip(b.discordInvite, 120) || 'no invite'}\n` +
        `> ${reason.replace(/\n/g, '\n> ')}\n${url.origin}/admin`);
      return json({ ok: true, id });
    }

    if (req.method === 'GET' && path === '/api/applications') {
      const g = need('admin'); if (g) return g;
      const rows = await env.DB.prepare(
        `SELECT a.*, u.name AS user_name, u.email AS user_email, u.avatar AS user_avatar
           FROM applications a JOIN users u ON u.id = a.user_id
          ORDER BY (a.status = 'pending') DESC, a.created_ts DESC LIMIT 300`).all();
      return json({ applications: rows.results || [] });
    }

    const decide = path.match(/^\/api\/applications\/([\w-]+)\/decide$/);
    if (req.method === 'POST' && decide) {
      const g = need('decide'); if (g) return g;
      const b = await body();
      const approve = b && b.decision === 'approve';
      const app = await env.DB.prepare("SELECT * FROM applications WHERE id = ? AND status = 'pending'").bind(decide[1]).first();
      if (!app) return json({ error: 'Already decided, or gone.' }, 404);

      let server = null;
      if (approve) server = await createServer(env, app);
      await env.DB.prepare('UPDATE applications SET status = ?, decided_ts = ?, decided_by = ?, server_id = ? WHERE id = ?')
        .bind(approve ? 'approved' : 'rejected', now(), ctx.user.id, server ? server.id : null, app.id).run();
      return json({ ok: true, server });
    }

    // -------------------------------------------------------------- servers

    if (req.method === 'GET' && path === '/api/servers') {
      if (!ctx.user) return json({ error: 'Sign in first.' }, 401);
      if (isStaff(ctx)) {
        const rows = await env.DB.prepare(
          `SELECT s.id, s.slug, s.name, s.status, s.created_ts, u.name AS owner_name,
                  (SELECT COUNT(*) FROM memberships m WHERE m.server_id = s.id) AS members,
                  (SELECT COUNT(*) FROM scans c WHERE c.server_id = s.id) AS scans
             FROM servers s JOIN users u ON u.id = s.owner_user_id ORDER BY s.created_ts DESC`).all();
        return json({ servers: rows.results || [], all: true });
      }
      return json({ servers: ctx.servers, all: false });
    }

    const sm = path.match(/^\/api\/servers\/([\w-]+)(?:\/(.*))?$/);
    if (sm) {
      const server = await serverBySlug(env, sm[1]);
      if (!server) return json({ error: 'No such server.' }, 404);
      const rest = sm[2] || '';
      const role = ctx.roles.get(server.id) || (isStaff(ctx) ? 'staff' : null);
      const readable = need('server:read', server.id); if (readable) return readable;
      const manage = () => need('server:manage', server.id);

      if (req.method === 'GET' && rest === '') {
        const mine = can(ctx, 'server:manage', server.id);
        return json({
          server: {
            slug: server.slug, name: server.name, status: server.status, createdTs: server.created_ts,
            discordInvite: server.discord_invite, players: server.players, age: server.age,
            // Every moderator needs the write key: it is inside the one-liner they
            // hand the suspect, so it was never a secret from them. Rotating it and
            // inviting new staff are the owner's alone.
            writeKey: server.write_key,
            inviteUrl: mine ? `${url.origin}/join/${server.invite_code}` : null,
          },
          role,
        });
      }

      if (req.method === 'GET' && rest === 'members') {
        return json({ members: await membersOf(env, server.id), canManage: can(ctx, 'server:manage', server.id) });
      }

      if (req.method === 'POST' && (rest === 'rotate-key' || rest === 'rotate-invite')) {
        const g = manage(); if (g) return g;
        const col = rest === 'rotate-key' ? 'write_key' : 'invite_code';
        const val = randomId(rest === 'rotate-key' ? 24 : 12);
        await env.DB.prepare(`UPDATE servers SET ${col} = ? WHERE id = ?`).bind(val, server.id).run();
        return json({ ok: true, writeKey: rest === 'rotate-key' ? val : undefined, inviteUrl: rest === 'rotate-invite' ? `${url.origin}/join/${val}` : undefined });
      }

      const member = rest.match(/^members\/([\w-]+)$/);
      if (member) {
        const g = manage(); if (g) return g;
        if (member[1] === server.owner_user_id) return json({ error: 'The server owner cannot be removed here.' }, 400);
        if (req.method === 'DELETE') {
          await env.DB.prepare('DELETE FROM memberships WHERE server_id = ? AND user_id = ?').bind(server.id, member[1]).run();
          return json({ ok: true });
        }
        if (req.method === 'POST') {
          const b = await body();
          const nr = b && b.role === 'owner' ? 'owner' : 'mod';
          await env.DB.prepare('UPDATE memberships SET role = ? WHERE server_id = ? AND user_id = ?')
            .bind(nr, server.id, member[1]).run();
          return json({ ok: true, role: nr });
        }
      }

      if (req.method === 'GET' && rest === 'history') {
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200') || 200, 1000);
        const rows = await env.DB.prepare('SELECT data FROM scans WHERE server_id = ? ORDER BY ts DESC LIMIT ?')
          .bind(server.id, limit).all();
        return json({ scans: (rows.results || []).map(r => summarise(JSON.parse(r.data))) });
      }

      const scan = rest.match(/^scan\/([\w-]+)$/);
      if (req.method === 'GET' && scan) {
        const row = await findScan(env, scan[1], server.id);
        return row ? json(row) : json({ error: 'No such scan on this server.' }, 404);
      }
    }

    // ------------------------------------------------------------- joining

    const join = path.match(/^\/api\/join\/([\w-]+)$/);
    if (req.method === 'POST' && join) {
      if (!ctx.user) return json({ error: 'Sign in first.' }, 401);
      const server = await env.DB.prepare('SELECT * FROM servers WHERE invite_code = ?').bind(join[1]).first();
      if (!server) return json({ error: 'That invite is no longer valid.' }, 404);
      await env.DB.prepare("INSERT OR IGNORE INTO memberships (server_id, user_id, role, added_ts) VALUES (?,?, 'mod', ?)")
        .bind(server.id, ctx.user.id, now()).run();
      return json({ ok: true, slug: server.slug, name: server.name });
    }

    // --------------------------------------------------------------- admin

    if (req.method === 'GET' && path === '/api/admin/users') {
      const g = need('admin'); if (g) return g;
      const rows = await env.DB.prepare(
        `SELECT u.id, u.name, u.email, u.avatar, u.global_role, u.created_ts,
                (SELECT COUNT(*) FROM memberships m WHERE m.user_id = u.id) AS servers
           FROM users u ORDER BY u.created_ts DESC LIMIT 500`).all();
      return json({ users: rows.results || [] });
    }

    const roleSet = path.match(/^\/api\/admin\/users\/([\w-]+)\/role$/);
    if (req.method === 'POST' && roleSet) {
      // Handing out AsyncAnalyzer staff is the one thing staff cannot do to
      // themselves: only the owner promotes.
      if (!isOwner(ctx)) return json({ error: 'Owner only.' }, 403);
      const b = await body();
      const r = b && ['staff', 'owner'].includes(b.role) ? b.role : null;
      if (roleSet[1] === ctx.user.id) return json({ error: 'You cannot change your own rank.' }, 400);
      await env.DB.prepare('UPDATE users SET global_role = ? WHERE id = ?').bind(r, roleSet[1]).run();
      return json({ ok: true, role: r });
    }

    // ---------------------------------------------------------- the tool

    // What the scanner calls before it does anything. A key that is not a live
    // server's key means the copy is not licensed to any server, and the tool
    // says so instead of scanning somebody's PC for nobody.
    if (req.method === 'GET' && path === '/api/verify') {
      const key = url.searchParams.get('key') || given;
      if (staffKeyed || (STAFF_KEY && key === STAFF_KEY)) return json({ ok: true, server: { name: 'AsyncAnalyzer staff', slug: null } });
      // Always 200. This answers a question - "is this key live?" - and a client
      // that gets a 4xx cannot tell "wrong key" from "cannot reach the server",
      // which is exactly the message the scanner then shows the wrong person.
      const s = key && await env.DB.prepare("SELECT slug, name, status FROM servers WHERE write_key = ?").bind(key).first();
      if (!s) return json({ ok: false, error: 'This copy is not linked to a server.' });
      if (s.status !== 'active') return json({ ok: false, error: 'That server is suspended.' });
      return json({ ok: true, server: { name: s.name, slug: s.slug } });
    }

    if (req.method === 'POST' && path === '/api/scan') {
      let serverId = null;
      if (!staffKeyed) {
        const s = given && await env.DB.prepare("SELECT id, status FROM servers WHERE write_key = ?").bind(given).first();
        if (!s) return json({ error: 'This copy is not linked to a server.' }, 401);
        if (s.status !== 'active') return json({ error: 'That server is suspended.' }, 403);
        serverId = s.id;
      }
      const b = await body();
      if (!b) return json({ error: 'bad json' }, 400);
      const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const rec = {
        id, serverTs: now(),
        scanner: clip(b.scanner || 'unknown', 80), targetUser: clip(b.targetUser, 80),
        pcName: clip(b.pcName, 80), modPath: anonPath(clip(b.modPath, 300)), verdict: clip(b.verdict || 'clean', 20),
        trusted: staffKeyed ? 1 : 0, serverId,
        totals: b.totals || {}, flagged: (b.flagged || []).slice(0, 200), review: (b.review || []).slice(0, 200),
        systemIssues: (b.systemIssues || []).slice(0, 200), toolVersion: clip(b.toolVersion, 20),
        modelVersion: b.modelVersion || 0, session: b.session || null,
        // The ID the tool printed on the scanned PC, and the code the moderator said
        // out loud before it started. This copy was written here, by the tool, not by
        // the person being checked - so if the report they show and this row disagree,
        // this row is the one to believe.
        scanId: clip(b.scanId, 32).toUpperCase(), scanCode: clip(b.scanCode, 40),
      };
      await env.DB.prepare('INSERT INTO scans (id, ts, scanner, target, pc, verdict, trusted, server_id, data) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(id, rec.serverTs, rec.scanner, rec.targetUser, rec.pcName, rec.verdict, rec.trusted, serverId, JSON.stringify(rec)).run();

      // A hash from an untrusted upload waits for a human. Approved hashes reach
      // every client on their next run, and a wrong cheat hash is therefore a
      // permanent team-wide false positive on a legitimate mod - somebody could
      // submit the SHA1 of sodium.jar and every scan on the team would confirm
      // it as a cheat.
      const state = staffKeyed ? 'approved' : 'pending';
      const addSig = async (h, kind) => {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind, scanner, target, scan_id, ts, state) VALUES (?,?,?,?,?,?,?)')
            .bind(String(h), kind, rec.scanner, rec.targetUser, id, rec.serverTs, state).run();
        } catch {
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind) VALUES (?,?)').bind(String(h), kind).run();
        }
      };
      for (const h of (b.newCheat || [])) if (h) await addSig(h, 'cheat');
      for (const h of (b.newGood || [])) if (h) await addSig(h, 'good');

      // Training too: 500 SGD steps per request, from a key handed to the person
      // being scanned, would let anyone walk the shared model wherever they liked.
      if (staffKeyed && Array.isArray(b.samples) && b.samples.length) {
        const m = await getModel(env);
        let n = 0;
        for (const s of b.samples.slice(0, 500)) if (Array.isArray(s.vec) && (s.label === 0 || s.label === 1)) { sgdStep(m, s.vec, s.label); n++; }
        if (n) await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('model', ?)").bind(JSON.stringify(m)).run();
      }
      const ss = b.sessionSample;
      if (staffKeyed && ss && Array.isArray(ss.vec) && (ss.label === 0 || ss.label === 1)) {
        const smod = await getSModel(env);
        sgdStep(smod, ss.vec, ss.label);
        await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('smodel', ?)").bind(JSON.stringify(smod)).run();
      }
      return json({ ok: true, id, trusted: rec.trusted === 1, signatureState: state, shareUrl: `${url.origin}/s/${id}` });
    }

    // A capability link: 16 hex characters nobody can guess, redacted content, no
    // account needed. That is what makes it postable in a Discord thread as proof.
    const share = path.match(/^\/api\/public\/scan\/([\w-]+)$/);
    if (req.method === 'GET' && share) {
      const row = await findScan(env, share[1], null);
      return row ? json(publicScan(row)) : json({ error: 'No such scan.' }, 404);
    }

    // ------------------------------------------------- shared intelligence

    if (req.method === 'GET' && path === '/api/signatures') {
      const rows = await env.DB.prepare("SELECT hash, kind FROM sigs WHERE state = 'approved'").all();
      const list = rows.results || [];
      return json({
        version: 100,
        knownCheatHashes: list.filter(r => r.kind === 'cheat').map(r => r.hash),
        knownGoodHashes: list.filter(r => r.kind === 'good').map(r => r.hash),
      });
    }

    if (req.method === 'GET' && path === '/api/signatures/pending') {
      const g = need('signatures'); if (g) return g;
      const rows = await env.DB.prepare("SELECT * FROM sigs WHERE state = 'pending' ORDER BY ts DESC LIMIT 500").all();
      return json({ count: (rows.results || []).length, hashes: rows.results || [] });
    }

    if (req.method === 'POST' && path === '/api/signatures/approve') {
      const g = need('signatures'); if (g) return g;
      const b = await body();
      let n = 0;
      for (const h of (Array.isArray(b && b.hashes) ? b.hashes.slice(0, 500) : [])) {
        // A rejected hash stays rejected. Approving it back has to be a delete
        // and a fresh contribution, not a retry that quietly wins.
        const r = await env.DB.prepare("UPDATE sigs SET state = 'approved' WHERE hash = ? AND state = 'pending'").bind(String(h)).run();
        n += (r.meta ? r.meta.changes : 0) || 0;
      }
      return json({ ok: true, approved: n });
    }

    // Revoking matters more than adding: without it a single wrong confirmation is
    // permanent for the whole team.
    if (req.method === 'DELETE' && path.startsWith('/api/signatures/')) {
      const g = need('signatures'); if (g) return g;
      const h = decodeURIComponent(path.split('/').pop());
      // Marked, not deleted: a row that is gone can be contributed again by the
      // next upload and nobody would notice it came back.
      const r = await env.DB.prepare("UPDATE sigs SET state = 'rejected' WHERE hash = ?").bind(h).run();
      return json({ ok: true, removed: r.meta ? r.meta.changes : 0 });
    }

    if (req.method === 'GET' && path === '/api/signatures/audit') {
      const g = need('signatures'); if (g) return g;
      const rows = await env.DB.prepare('SELECT * FROM sigs').all();
      return json({ count: (rows.results || []).length, hashes: rows.results || [] });
    }

    if (req.method === 'GET' && (path === '/api/model' || path === '/api/smodel')) {
      const m = path === '/api/model' ? await getModel(env) : await getSModel(env);
      return json({ version: m.version, trainedCount: m.trainedCount || 0, feature_order: m.feature_order, intercept: m.intercept, weights: m.weights });
    }

    // Every server's scans at once, including the rows from before servers
    // existed. Staff, or the legacy view key for anything still using it.
    const viewOK = isStaff(ctx) || staffKeyed || (VIEW_KEY && (url.searchParams.get('key') === VIEW_KEY || given === VIEW_KEY));

    if (req.method === 'GET' && path === '/api/history') {
      if (!viewOK) return json({ error: 'Not allowed.' }, 401);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '200') || 200, 1000);
      const rows = await env.DB.prepare('SELECT data FROM scans ORDER BY ts DESC LIMIT ?').bind(limit).all();
      return json({ scans: (rows.results || []).map(r => summarise(JSON.parse(r.data))) });
    }

    if (req.method === 'GET' && path.startsWith('/api/scan/')) {
      if (!viewOK) return json({ error: 'Not allowed.' }, 401);
      const row = await findScan(env, path.split('/').pop(), null);
      return row ? json(row) : json({ error: 'not found' }, 404);
    }

    return json({ error: 'not found' }, 404);
  },
};

function providerList(env) {
  return { discord: !!env.DISCORD_CLIENT_ID, google: !!env.GOOGLE_CLIENT_ID, password: !!env.RESEND_KEY };
}

// scanId and scanCode belong here. The report tells a moderator to look the Scan
// ID up in the dashboard, and leaving them out of the projection made the Scan ID
// column show a dash on every row and its search never match.
function summarise(s) {
  return {
    id: s.id, serverTs: s.serverTs, scanner: s.scanner, targetUser: s.targetUser, pcName: s.pcName,
    verdict: s.verdict, totals: s.totals, toolVersion: s.toolVersion,
    flaggedCount: (s.flagged || []).length, reviewCount: (s.review || []).length,
    session: s.session || null, scanId: s.scanId || '', scanCode: s.scanCode || '', trusted: s.trusted === 1,
  };
}

// Either id works. The moderator is reading the Scan ID off a screen - that is the
// one printed in the report - so looking it up must not require knowing the row id.
// scanId lives inside the JSON blob, hence the LIKE.
async function findScan(env, id, serverId) {
  const scope = serverId ? ' AND server_id = ?' : '';
  const bindings = serverId ? [id, serverId] : [id];
  let row = await env.DB.prepare(`SELECT data FROM scans WHERE id = ?${scope}`).bind(...bindings).first();
  if (!row) {
    const like = '%"scanId":"' + String(id || '').toUpperCase() + '"%';
    row = await env.DB.prepare(`SELECT data FROM scans WHERE data LIKE ?${scope} ORDER BY ts DESC LIMIT 1`)
      .bind(...(serverId ? [like, serverId] : [like])).first();
  }
  return row ? JSON.parse(row.data) : null;
}
