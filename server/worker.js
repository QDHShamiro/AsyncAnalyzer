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

// The scanned PC's own Windows account name travels inside modPath
// (C:\Users\<real name>\AppData\Roaming\.minecraft\mods). A moderator needs to
// know WHICH folder was scanned, not who the person is called on their own
// computer, and this row can end up in a screenshot.
function anonPath(p) {
  return String(p == null ? '' : p).replace(/(\\Users\\)[^\\]+/gi, '$1<user>');
}

// Cloudflare has no per-IP limiter of its own here and server.js has had one all
// along - the README even names rate limiting as "the only guard" against the
// published write key, which was not true of the deployed half.
const RATE = new Map();
function limited(ip) {
  const now = Date.now();
  const r = RATE.get(ip) || { n: 0, t: now };
  if (now - r.t > 60000) { r.n = 0; r.t = now; }
  r.n++; RATE.set(ip, r);
  return r.n > 120;
}

// A stored model from an OLDER version has a shorter feature_order, so the features
// added since would simply never be trained - silently, because a missing feature
// multiplies by 0 rather than failing. Refetch the new base instead; the team
// relearns from its next scans, which is cheap, and a half-trained model is not.
async function getModel(env) {
  const row = await env.DB.prepare("SELECT v FROM meta WHERE k='model'").first();
  const base = await (await fetch(BASE_MODEL_URL)).json();
  if (row) {
    const cur = JSON.parse(row.v);
    if ((cur.version || 0) >= (base.version || 0)) return cur;
  }
  const m = { version: base.version, feature_order: base.feature_order, intercept: base.intercept, weights: { ...base.weights }, base: { intercept: base.intercept, weights: { ...base.weights } }, trainedCount: 0 };
  await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('model', ?)").bind(JSON.stringify(m)).run();
  return m;
}
async function getSModel(env) {
  const row = await env.DB.prepare("SELECT v FROM meta WHERE k='smodel'").first();
  const base = await (await fetch(BASE_SMODEL_URL)).json();
  if (row) {
    const cur = JSON.parse(row.v);
    if ((cur.version || 0) >= (base.version || 0)) return cur;
  }
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
    // The write key is PUBLISHED - that is what lets a scanned PC upload its own
    // result. So it cannot also be the authority to change what every client
    // believes. The staff key is not in the repo, and it is what separates
    // "somebody ran the tool" from "a moderator vouches for this".
    const STAFF_KEY = env.STAFF_KEY || '';
    const given = () => (req.headers.get('x-key') || '');
    const isStaff = () => !!STAFF_KEY && given() === STAFF_KEY;
    // A history row carries a Minecraft name, a PC name and a scan verdict about
    // a real person. Without a view key set, this used to hand all of it to
    // anybody who asked - so an unset key now means no history, not a public one.
    const viewOK = () => {
      const k = url.searchParams.get('key') || given();
      if (isStaff()) return true;
      if (!VIEW_KEY) return false;
      return k === VIEW_KEY;
    };
    const ip = (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
    if (limited(ip)) return json({ error: 'rate limited' }, 429);

    if (req.method === 'POST' && url.pathname === '/api/scan') {
      const trusted = isStaff();
      if (!trusted && given() !== WRITE_KEY) return json({ error: 'bad key' }, 401);
      let b; try { b = await req.json(); } catch { return json({ error: 'bad json' }, 400); }
      const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const rec = {
        id, serverTs: new Date().toISOString(),
        scanner: clip(b.scanner || 'unknown', 80), targetUser: clip(b.targetUser, 80),
        pcName: clip(b.pcName, 80), modPath: anonPath(clip(b.modPath, 300)), verdict: clip(b.verdict || 'clean', 20),
        trusted: trusted ? 1 : 0,
        totals: b.totals || {}, flagged: (b.flagged || []).slice(0, 200), review: (b.review || []).slice(0, 200),
        systemIssues: (b.systemIssues || []).slice(0, 200), toolVersion: clip(b.toolVersion, 20), modelVersion: b.modelVersion || 0, session: b.session || null,
        // The ID the tool printed on the scanned PC, and the code the moderator said
        // out loud before it started. This copy was written here, by the tool, not by
        // the person being checked - so if the report they show and this row disagree,
        // this row is the one to believe.
        scanId: clip(b.scanId, 32).toUpperCase(), scanCode: clip(b.scanCode, 40),
      };
      await env.DB.prepare('INSERT INTO scans (id, ts, scanner, target, pc, verdict, trusted, data) VALUES (?,?,?,?,?,?,?,?)')
        .bind(id, rec.serverTs, rec.scanner, rec.targetUser, rec.pcName, rec.verdict, rec.trusted, JSON.stringify(rec)).run();
      // Pooled hashes reach every client on their next run, so a wrong one becomes a
      // team-wide false positive nobody can trace. Record the source with each hash.
      // A hash from an untrusted upload waits for a human. Approved hashes reach
      // every client on their next run, and a wrong cheat hash is therefore a
      // permanent team-wide false positive on a legitimate mod - somebody could
      // submit the SHA1 of sodium.jar and every scan on the team would confirm
      // it as a cheat.
      const state = trusted ? 'approved' : 'pending';
      const addSig = async (h, kind) => {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind, scanner, target, scan_id, ts, state) VALUES (?,?,?,?,?,?,?)')
            .bind(String(h), kind, rec.scanner, rec.targetUser, id, rec.serverTs, state).run();
        } catch {
          // a database created before attribution existed still has the 2-column table
          await env.DB.prepare('INSERT OR IGNORE INTO sigs (hash, kind) VALUES (?,?)')
            .bind(String(h), kind).run();
        }
      };
      for (const h of (b.newCheat || [])) if (h) await addSig(h, 'cheat');
      for (const h of (b.newGood || [])) if (h) await addSig(h, 'good');
      // Training too: 500 SGD steps per request, from a key printed in the repo,
      // would let anyone walk the shared model wherever they liked.
      if (trusted && Array.isArray(b.samples) && b.samples.length) {
        const m = await getModel(env);
        let n = 0;
        for (const s of b.samples.slice(0, 500)) if (Array.isArray(s.vec) && (s.label === 0 || s.label === 1)) { sgdStep(m, s.vec, s.label); n++; }
        if (n) await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('model', ?)").bind(JSON.stringify(m)).run();
      }
      const ss = b.sessionSample;
      if (trusted && ss && Array.isArray(ss.vec) && (ss.label === 0 || ss.label === 1)) {
        const sm = await getSModel(env);
        sgdStep(sm, ss.vec, ss.label);
        await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('smodel', ?)").bind(JSON.stringify(sm)).run();
      }
      return json({ ok: true, id, trusted: rec.trusted === 1, signatureState: state });
    }

    // Only APPROVED hashes are handed out. This is the endpoint every client
    // pulls on every run, so anything here is believed by the whole team.
    if (req.method === 'GET' && url.pathname === '/api/signatures') {
      const rows = (await env.DB.prepare("SELECT hash, kind FROM sigs WHERE state = 'approved'").all()).results || [];
      return json({ version: 100, knownCheatHashes: rows.filter(r => r.kind === 'cheat').map(r => r.hash), knownGoodHashes: rows.filter(r => r.kind === 'good').map(r => r.hash) });
    }

    // The queue a moderator works through. Staff key only: it names who
    // contributed what, and it is the list that decides what the team believes.
    if (req.method === 'GET' && url.pathname === '/api/signatures/pending') {
      if (!isStaff()) return json({ error: 'staff key required' }, 401);
      const rows = (await env.DB.prepare("SELECT * FROM sigs WHERE state = 'pending' ORDER BY ts DESC LIMIT 500").all()).results || [];
      return json({ count: rows.length, hashes: rows });
    }

    if (req.method === 'POST' && url.pathname === '/api/signatures/approve') {
      if (!isStaff()) return json({ error: 'staff key required' }, 401);
      let b; try { b = await req.json(); } catch { return json({ error: 'bad json' }, 400); }
      const list = Array.isArray(b.hashes) ? b.hashes.slice(0, 500) : [];
      let n = 0;
      for (const h of list) {
        // A rejected hash stays rejected. Approving it back has to be a delete
        // and a fresh contribution, not a retry that quietly wins.
        const r = await env.DB.prepare("UPDATE sigs SET state = 'approved' WHERE hash = ? AND state = 'pending'").bind(String(h)).run();
        n += (r.meta ? r.meta.changes : 0) || 0;
      }
      return json({ ok: true, approved: n });
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
      if (!isStaff()) return json({ error: 'staff key required' }, 401);
      const h = decodeURIComponent(url.pathname.split('/').pop());
      // Marked, not deleted: a row that is gone can be contributed again by the
      // next upload and nobody would notice it came back.
      const r = await env.DB.prepare("UPDATE sigs SET state = 'rejected' WHERE hash = ?").bind(h).run();
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
      // scanId and scanCode belong here. The report tells a moderator to look the
      // Scan ID up in this dashboard, and leaving them out of the projection made
      // the dashboard's Scan ID column show a dash on every row and its search
      // never match - while server.js had them all along. That is what two
      // hand-maintained copies of one API do, and why they now have a parity test.
      const scans = rows.map(r => { const s = JSON.parse(r.data); return { id: s.id, serverTs: s.serverTs, scanner: s.scanner, targetUser: s.targetUser, pcName: s.pcName, verdict: s.verdict, totals: s.totals, toolVersion: s.toolVersion, flaggedCount: (s.flagged || []).length, reviewCount: (s.review || []).length, session: s.session || null, scanId: s.scanId || '', scanCode: s.scanCode || '', trusted: s.trusted === 1 }; });
      return json({ scans, viewProtected: !!VIEW_KEY });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/scan/')) {
      if (!viewOK()) return json({ error: 'bad view key' }, 401);
      const id = url.pathname.split('/').pop();
      // Either key works. The moderator is reading the Scan ID off a screen - that
      // is the one printed in the report - so looking it up must not require knowing
      // the server's own row id. scanId lives inside the JSON blob, hence the LIKE.
      let row = await env.DB.prepare('SELECT data FROM scans WHERE id = ?').bind(id).first();
      if (!row) {
        row = await env.DB.prepare(
          "SELECT data FROM scans WHERE data LIKE ? ORDER BY ts DESC LIMIT 1")
          .bind('%"scanId":"' + String(id || '').toUpperCase() + '"%').first();
      }
      return row ? json(JSON.parse(row.data)) : json({ error: 'not found' }, 404);
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      try { const r = await fetch(DASH); const html = await r.text(); return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } }); }
      catch { return new Response('<h1>AsyncAnalyzer backend</h1>', { headers: { 'Content-Type': 'text/html' } }); }
    }

    return json({ error: 'not found' }, 404);
  },
};
