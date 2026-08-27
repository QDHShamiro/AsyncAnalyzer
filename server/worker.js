/*
 * AsyncAnalyzer team backend — Cloudflare Worker (free, always-on) + D1.
 * Same API as server.js. Deploy with wrangler (see server/README.md).
 *
 * Secrets (wrangler secret put ...): WRITE_KEY, VIEW_KEY (optional).
 * D1 binding named DB (see wrangler.toml + schema.sql).
 */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type,x-key',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
};
const DASH = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/server/dashboard.html';

const BASE_MODEL_URL = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml/model.json';
const BASE_SMODEL_URL = 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml/session_model.json';

function json(obj, code = 200) {
  return new Response(JSON.stringify(obj), { status: code, headers: { 'Content-Type': 'application/json', ...CORS } });
}
function clip(s, n) { return String(s == null ? '' : s).slice(0, n); }

async function getModel(env) {
  const row = await env.DB.prepare("SELECT v FROM meta WHERE k='model'").first();
  if (row) return JSON.parse(row.v);
  const base = await (await fetch(BASE_MODEL_URL)).json();
  const m = { version: base.version, feature_order: base.feature_order, intercept: base.intercept, weights: { ...base.weights }, base: { intercept: base.intercept, weights: { ...base.weights } }, trainedCount: 0 };
  await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('model', ?)").bind(JSON.stringify(m)).run();
  return m;
}
async function getSModel(env) {
  const row = await env.DB.prepare("SELECT v FROM meta WHERE k='smodel'").first();
  if (row) return JSON.parse(row.v);
  const base = await (await fetch(BASE_SMODEL_URL)).json();
  const m = { version: base.version, feature_order: base.feature_order, intercept: base.intercept, weights: { ...base.weights }, base: { intercept: base.intercept, weights: { ...base.weights } }, trainedCount: 0 };
  await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('smodel', ?)").bind(JSON.stringify(m)).run();
  return m;
}
function sgdStep(m, vec, label) {
  const O = m.feature_order, lr = 0.05, l2 = 0.02, clamp = 8;
  let z = m.intercept;
  for (let i = 0; i < O.length; i++) z += m.weights[O[i]] * (+vec[i] || 0);
  const p = z < -60 ? 0 : z > 60 ? 1 : 1 / (1 + Math.exp(-z));
  const err = p - label;
  for (let i = 0; i < O.length; i++) {
    const k = O[i];
    let w = m.weights[k] - lr * (err * (+vec[i] || 0) + l2 * (m.weights[k] - m.base.weights[k]));
    m.weights[k] = Math.max(-clamp, Math.min(clamp, w));
  }
  m.intercept = Math.max(-clamp, Math.min(clamp, m.intercept - lr * (err + l2 * (m.intercept - m.base.intercept))));
  m.trainedCount = (m.trainedCount || 0) + 1;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response('', { status: 204, headers: CORS });
    const WRITE_KEY = env.WRITE_KEY || 'change-me';
    const VIEW_KEY = env.VIEW_KEY || '';
    const viewOK = () => !VIEW_KEY || (url.searchParams.get('key') || req.headers.get('x-key')) === VIEW_KEY;

    if (req.method === 'POST' && url.pathname === '/api/scan') {
      if ((req.headers.get('x-key') || '') !== WRITE_KEY) return json({ error: 'bad key' }, 401);
      let b; try { b = await req.json(); } catch { return json({ error: 'bad json' }, 400); }
      const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const rec = {
        id, serverTs: new Date().toISOString(),
        scanner: clip(b.scanner || 'unknown', 80), targetUser: clip(b.targetUser, 80),
        pcName: clip(b.pcName, 80), modPath: clip(b.modPath, 300), verdict: clip(b.verdict || 'clean', 20),
        totals: b.totals || {}, flagged: (b.flagged || []).slice(0, 200), review: (b.review || []).slice(0, 200),
        systemIssues: (b.systemIssues || []).slice(0, 200), toolVersion: clip(b.toolVersion, 20), modelVersion: b.modelVersion || 0, session: b.session || null,
      };
      await env.DB.prepare('INSERT INTO scans (id, ts, scanner, target, pc, verdict, data) VALUES (?,?,?,?,?,?,?)')
        .bind(id, rec.serverTs, rec.scanner, rec.targetUser, rec.pcName, rec.verdict, JSON.stringify(rec)).run();
      // Pooled hashes reach every client on their next run, so a wrong one becomes a
      // team-wide false positive nobody can trace. Record the source with each hash.
      const addSig = async (h, kind) => {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind, scanner, target, scan_id, ts) VALUES (?,?,?,?,?,?)')
            .bind(String(h), kind, rec.scanner, rec.targetUser, id, rec.serverTs).run();
        } catch {
          // a database created before attribution existed still has the 2-column table
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind) VALUES (?,?)')
            .bind(String(h), kind).run();
        }
      };
      for (const h of (b.newCheat || [])) if (h) await addSig(h, 'cheat');
      for (const h of (b.newGood || [])) if (h) await addSig(h, 'good');
      if (Array.isArray(b.samples) && b.samples.length) {
        const m = await getModel(env);
        let n = 0;
        for (const s of b.samples.slice(0, 500)) if (Array.isArray(s.vec) && (s.label === 0 || s.label === 1)) { sgdStep(m, s.vec, s.label); n++; }
        if (n) await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('model', ?)").bind(JSON.stringify(m)).run();
      }
      const ss = b.sessionSample;
      if (ss && Array.isArray(ss.vec) && (ss.label === 0 || ss.label === 1)) {
        const sm = await getSModel(env);
        sgdStep(sm, ss.vec, ss.label);
        await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('smodel', ?)").bind(JSON.stringify(sm)).run();
      }
      return json({ ok: true, id });
    }

    if (req.method === 'GET' && url.pathname === '/api/signatures') {
      const rows = (await env.DB.prepare('SELECT hash, kind FROM sigs').all()).results || [];
      return json({ version: 100, knownCheatHashes: rows.filter(r => r.kind === 'cheat').map(r => r.hash), knownGoodHashes: rows.filter(r => r.kind === 'good').map(r => r.hash) });
    }

    if (req.method === 'GET' && url.pathname === '/api/model') {
      const m = await getModel(env);
      return json({ version: m.version, trainedCount: m.trainedCount || 0, feature_order: m.feature_order, intercept: m.intercept, weights: m.weights });
    }

    // auditable view: which hash came from whose scan (view-gated, not public)
    if (req.method === 'GET' && url.pathname === '/api/signatures/audit') {
      if (!viewOK()) return json({ error: 'bad view key' }, 401);
      const rows = (await env.DB.prepare('SELECT * FROM sigs').all()).results || [];
      return json({ count: rows.length, hashes: rows });
    }

    // Revoking matters more than adding: without it a single wrong confirmation is
    // permanent for the whole team.
    if (req.method === 'DELETE' && url.pathname.startsWith('/api/signatures/')) {
      if ((req.headers.get('x-key') || '') !== WRITE_KEY) return json({ error: 'bad key' }, 401);
      const h = decodeURIComponent(url.pathname.split('/').pop());
      const r = await env.DB.prepare('DELETE FROM sigs WHERE hash = ?').bind(h).run();
      return json({ ok: true, removed: r.meta ? r.meta.changes : 0 });
    }

    if (req.method === 'GET' && url.pathname === '/api/smodel') {
      const m = await getSModel(env);
      return json({ version: m.version, trainedCount: m.trainedCount || 0, feature_order: m.feature_order, intercept: m.intercept, weights: m.weights });
    }

    if (req.method === 'GET' && url.pathname === '/api/history') {
      if (!viewOK()) return json({ error: 'bad view key' }, 401);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '200') || 200, 1000);
      const rows = (await env.DB.prepare('SELECT data FROM scans ORDER BY ts DESC LIMIT ?').bind(limit).all()).results || [];
      const scans = rows.map(r => { const s = JSON.parse(r.data); return { id: s.id, serverTs: s.serverTs, scanner: s.scanner, targetUser: s.targetUser, pcName: s.pcName, verdict: s.verdict, totals: s.totals, toolVersion: s.toolVersion, flaggedCount: (s.flagged || []).length, reviewCount: (s.review || []).length, session: s.session || null }; });
      return json({ scans, viewProtected: !!VIEW_KEY });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/scan/')) {
      if (!viewOK()) return json({ error: 'bad view key' }, 401);
      const id = url.pathname.split('/').pop();
      const row = await env.DB.prepare('SELECT data FROM scans WHERE id = ?').bind(id).first();
      return row ? json(JSON.parse(row.data)) : json({ error: 'not found' }, 404);
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      try { const r = await fetch(DASH); const html = await r.text(); return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } }); }
      catch { return new Response('<h1>AsyncAnalyzer backend</h1>', { headers: { 'Content-Type': 'text/html' } }); }
    }

    return json({ error: 'not found' }, 404);
  },
};
