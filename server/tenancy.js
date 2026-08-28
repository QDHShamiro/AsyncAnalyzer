/*
 * Who exists, which server they belong to, and what they are allowed to do.
 *
 * Every permission decision in the worker goes through can() below. Scattering
 * "if (role === 'owner')" across thirty routes is how the thirty-first route
 * ends up without one, and this product's whole job is to be trusted with a
 * verdict about a real person.
 */
import { randomId } from './auth.js';

const now = () => new Date().toISOString();

export async function loadUser(env, userId) {
  if (!userId) return null;
  return await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
}

export async function membershipsOf(env, userId) {
  if (!userId) return [];
  const rows = await env.DB.prepare(
    `SELECT m.role, s.id, s.slug, s.name, s.status
       FROM memberships m JOIN servers s ON s.id = m.server_id
      WHERE m.user_id = ? ORDER BY s.name`).bind(userId).all();
  return rows.results || [];
}

// The request context every route works from: the user, and what they are on
// each server. Built once per request.
export async function context(env, userId) {
  const user = await loadUser(env, userId);
  if (!user) return { user: null, servers: [], roles: new Map() };
  const servers = await membershipsOf(env, user.id);
  return { user, servers, roles: new Map(servers.map(s => [s.id, s.role])) };
}

export const isStaff = ctx => !!ctx.user && (ctx.user.global_role === 'staff' || ctx.user.global_role === 'owner');
export const isOwner = ctx => !!ctx.user && ctx.user.global_role === 'owner';

/*
 * owner   - AsyncAnalyzer itself. Everything, everywhere.
 * staff   - AsyncAnalyzer staff. Reads every server, decides applications,
 *           works the signature queue. Does not touch anyone's team.
 * server owner - everything on their own server: team, key, history.
 * server mod   - their server's history, and running scans. Nothing else.
 */
export function can(ctx, action, serverId) {
  if (!ctx.user) return false;
  if (isOwner(ctx)) return true;
  const role = serverId ? ctx.roles.get(serverId) : null;

  switch (action) {
    case 'admin':          return isStaff(ctx);
    case 'decide':         return isStaff(ctx);
    case 'signatures':     return isStaff(ctx);
    case 'server:read':    return isStaff(ctx) || role === 'owner' || role === 'mod';
    // Staff deliberately cannot rename a team or rotate somebody's key. Reading
    // a verdict is support; editing another server's staff list is not.
    case 'server:manage':  return role === 'owner';
    default:               return false;
  }
}

// ---- identities -----------------------------------------------------------

// One person, several ways in. A Google sign-in that carries an email we already
// know joins that account rather than creating a second one - otherwise the
// server owner who first used Discord loses their server by signing in the
// "wrong" way one afternoon.
export async function upsertIdentity(env, provider, profile) {
  const existing = await env.DB.prepare(
    'SELECT user_id FROM identities WHERE provider = ? AND provider_id = ?')
    .bind(provider, String(profile.id)).first();
  if (existing) {
    await env.DB.prepare('UPDATE users SET name = ?, avatar = COALESCE(?, avatar) WHERE id = ?')
      .bind(profile.name, profile.avatar, existing.user_id).run();
    return existing.user_id;
  }

  let userId = null;
  if (profile.email) {
    const byMail = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(profile.email).first();
    if (byMail) userId = byMail.id;
  }
  if (!userId) {
    userId = randomId(12);
    await env.DB.prepare('INSERT INTO users (id, email, name, avatar, global_role, created_ts) VALUES (?,?,?,?,?,?)')
      .bind(userId, profile.email, profile.name, profile.avatar, null, now()).run();
  }
  await env.DB.prepare('INSERT OR IGNORE INTO identities (provider, provider_id, user_id) VALUES (?,?,?)')
    .bind(provider, String(profile.id), userId).run();
  return userId;
}

// The very first account to exist becomes the owner. Otherwise the first deploy
// has a working site nobody can administer, and the fix is hand-editing D1.
export async function claimOwnerIfFirst(env, userId) {
  const n = await env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE global_role IS NOT NULL').first();
  if ((n && n.c) > 0) return;
  await env.DB.prepare("UPDATE users SET global_role = 'owner' WHERE id = ?").bind(userId).run();
}

// ---- servers --------------------------------------------------------------

export function slugify(name) {
  const s = String(name || '').toLowerCase().normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return s || 'server';
}

async function freeSlug(env, name) {
  const base = slugify(name);
  for (let i = 0; i < 50; i++) {
    const slug = i ? `${base}-${i + 1}` : base;
    const hit = await env.DB.prepare('SELECT 1 FROM servers WHERE slug = ?').bind(slug).first();
    if (!hit) return slug;
  }
  return `${base}-${randomId(3)}`;
}

export async function createServer(env, app) {
  const id = randomId(10);
  const slug = await freeSlug(env, app.name);
  await env.DB.prepare(
    `INSERT INTO servers (id, slug, name, discord_invite, players, age, status, owner_user_id, write_key, invite_code, created_ts)
     VALUES (?,?,?,?,?,?, 'active', ?,?,?,?)`)
    .bind(id, slug, app.name, app.discord_invite, app.players, app.age, app.user_id, randomId(24), randomId(12), now()).run();
  await env.DB.prepare("INSERT OR REPLACE INTO memberships (server_id, user_id, role, added_ts) VALUES (?,?, 'owner', ?)")
    .bind(id, app.user_id, now()).run();
  return { id, slug };
}

export async function serverBySlug(env, slug) {
  return await env.DB.prepare('SELECT * FROM servers WHERE slug = ?').bind(String(slug || '')).first();
}

export async function membersOf(env, serverId) {
  const rows = await env.DB.prepare(
    `SELECT u.id, u.name, u.avatar, u.email, m.role, m.added_ts
       FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.server_id = ? ORDER BY m.role, u.name`).bind(serverId).all();
  return rows.results || [];
}

// ---- notifications --------------------------------------------------------

// Fire and forget: a Discord outage must not turn into "your application could
// not be submitted" for somebody who did nothing wrong.
export async function notifyDiscord(env, content) {
  if (!env.DISCORD_WEBHOOK) return;
  try {
    await fetch(env.DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: String(content).slice(0, 1900), allowed_mentions: { parse: [] } }),
    });
  } catch { /* the application is already stored; the ping is a convenience */ }
}
