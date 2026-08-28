#!/usr/bin/env node
/*
 * AsyncAnalyzer team backend — zero-dependency Node server.
 *
 * Stores scan history from every AsyncAnalyzer run (you, Luis, anyone on your
 * team) in one place, aggregates confirmed cheat/known-good hashes so the whole
 * team's detection improves together, and serves a web dashboard to browse it.
 *
 * Run:
 *   ASYNC_KEY=your-write-secret ASYNC_VIEWKEY=your-view-secret node server.js
 *
 * Then point the tool at it by editing ml/signatures.json in your GitHub repo:
 *   "telemetry": { "endpoint": "https://your-host:8787", "key": "your-write-secret" }
 *
 * Data is stored in ./data/scans.json and ./data/sigs.json (JSON files, no DB
 * to install). Fine for a screenshare team. For always-on free hosting use the
 * Cloudflare Worker version (worker.js) instead.
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8787;
const WRITE_KEY = process.env.ASYNC_KEY || 'change-me-write-key';
const VIEW_KEY = process.env.ASYNC_VIEWKEY || ''; // empty = no history at all (see viewOK)
// The write key is PUBLISHED - that is what lets a scanned PC upload its own
// result. So it cannot also be the authority to change what every client
// believes. The staff key is not in the repo, and it is what separates
// "somebody ran the tool" from "a moderator vouches for this".
const STAFF_KEY = process.env.ASYNC_STAFFKEY || '';
// Overridable so the parity tests can run against a throwaway directory
// instead of writing into the repo's own data folder.
const DATA_DIR = process.env.ASYNC_DATA || path.join(__dirname, 'data');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');
const SIGS_FILE = path.join(DATA_DIR, 'sigs.json');
const MAX_SCANS = 5000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
function load(file, def) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; } }
function save(file, obj) { fs.writeFileSync(file, JSON.stringify(obj)); }

let scans = load(SCANS_FILE, []);
let sigs = load(SIGS_FILE, { knownCheatHashes: [], knownGoodHashes: [], meta: {} });
if (!sigs.meta) sigs.meta = {};   // older stores predate attribution
if (!sigs.rejected) sigs.rejected = [];   // and predate the approval queue

// ---- shared (federated) model: trained by every team member's scans ----
const MODEL_FILE = path.join(DATA_DIR, 'model.json');
const BASE = load(path.join(__dirname, '..', 'ml', 'model.json'), null);
let model = load(MODEL_FILE, null);
// A stored model from an OLDER version has a shorter feature_order, so the features
// added since would simply never be trained - silently, because a missing feature
// multiplies by 0 rather than failing. Reset to the new base instead; the team
// relearns from its next scans, which is cheap, and a half-trained model is not.
if (model && BASE && (model.version || 0) < (BASE.version || 0)) model = null;
if (!model && BASE) {
  model = { version: BASE.version, feature_order: BASE.feature_order, intercept: BASE.intercept, weights: { ...BASE.weights }, trainedCount: 0 };
  save(MODEL_FILE, model);
}
// ---- shared (federated) SESSION model: learns from WHOLE scans, not single jars ----
const SMODEL_FILE = path.join(DATA_DIR, 'smodel.json');
const SBASE = load(path.join(__dirname, '..', 'ml', 'session_model.json'), null);
let smodel = load(SMODEL_FILE, null);
if (smodel && SBASE && (smodel.version || 0) < (SBASE.version || 0)) smodel = null;
if (!smodel && SBASE) {
  smodel = { version: SBASE.version, feature_order: SBASE.feature_order, intercept: SBASE.intercept, weights: { ...SBASE.weights }, trainedCount: 0 };
  save(SMODEL_FILE, smodel);
}
function sSgdStep(vec, label) {
  if (!smodel || !SBASE) return;
  const O = smodel.feature_order, lr = 0.05, l2 = 0.02, clamp = 8;
  let z = smodel.intercept;
  for (let i = 0; i < O.length; i++) z += smodel.weights[O[i]] * (+vec[i] || 0);
  const p = z < -60 ? 0 : z > 60 ? 1 : 1 / (1 + Math.exp(-z));
  const err = p - label;
  for (let i = 0; i < O.length; i++) {
    const k = O[i];
    let w = smodel.weights[k] - lr * (err * (+vec[i] || 0) + l2 * (smodel.weights[k] - SBASE.weights[k]));
    smodel.weights[k] = Math.max(-clamp, Math.min(clamp, w));
  }
  smodel.intercept = Math.max(-clamp, Math.min(clamp, smodel.intercept - lr * (err + l2 * (smodel.intercept - SBASE.intercept))));
  smodel.trainedCount = (smodel.trainedCount || 0) + 1;
}

function sgdStep(vec, label) {
  if (!model || !BASE) return;
  const O = model.feature_order, lr = 0.05, l2 = 0.02, clamp = 8;
  let z = model.intercept;
  for (let i = 0; i < O.length; i++) z += model.weights[O[i]] * (+vec[i] || 0);
  const p = z < -60 ? 0 : z > 60 ? 1 : 1 / (1 + Math.exp(-z));
  const err = p - label;
  for (let i = 0; i < O.length; i++) {
    const k = O[i];
    let w = model.weights[k] - lr * (err * (+vec[i] || 0) + l2 * (model.weights[k] - BASE.weights[k]));
    model.weights[k] = Math.max(-clamp, Math.min(clamp, w));
  }
  model.intercept = Math.max(-clamp, Math.min(clamp, model.intercept - lr * (err + l2 * (model.intercept - BASE.intercept))));
  model.trainedCount = (model.trainedCount || 0) + 1;
}

const rate = new Map(); // ip -> {n, t}
function limited(ip) {
  const now = Date.now();
  const r = rate.get(ip) || { n: 0, t: now };
  if (now - r.t > 60000) { r.n = 0; r.t = now; }
  r.n++; rate.set(ip, r);
  return r.n > 120;
}

function send(res, code, body, type) {
  res.writeHead(code, {
    'Content-Type': type || 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'content-type,x-key',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = ''; req.on('data', (c) => { d += c; if (d.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve(null); } });
  });
}

// The scanned PC's own Windows account name travels inside modPath
// (C:\Users\<real name>\AppData\Roaming\.minecraft\mods). A moderator needs to
// know WHICH folder was scanned, not who the person is called on their own
// computer, and this row can end up in a screenshot.
function anonPath(p) {
  return String(p == null ? '' : p).replace(/(\\Users\\)[^\\]+/gi, '$1<user>');
}

function summary(s) {
  return {
    id: s.id, serverTs: s.serverTs, scanner: s.scanner, targetUser: s.targetUser,
    pcName: s.pcName, verdict: s.verdict, totals: s.totals, toolVersion: s.toolVersion,
    flaggedCount: (s.flagged || []).length, reviewCount: (s.review || []).length,
    session: s.session || null,
    scanId: s.scanId || '', scanCode: s.scanCode || '', trusted: s.trusted === 1,
  };
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (limited(ip)) return send(res, 429, { error: 'rate limited' });

  // POST a scan
  const given = () => (req.headers['x-key'] || '');
  const isStaff = () => !!STAFF_KEY && given() === STAFF_KEY;
  // A history row carries a Minecraft name, a PC name and a scan verdict about a
  // real person. Without a view key set, this used to hand all of it to anybody
  // who asked - so an unset key now means no history, not a public one.
  const viewOK = () => {
    if (isStaff()) return true;
    if (!VIEW_KEY) return false;
    return (url.searchParams.get('key') || given()) === VIEW_KEY;
  };

  if (req.method === 'POST' && url.pathname === '/api/scan') {
    const trusted = isStaff();
    if (!trusted && given() !== WRITE_KEY) return send(res, 401, { error: 'bad key' });
    const body = await readBody(req);
    if (!body) return send(res, 400, { error: 'bad json' });
    const rec = {
      id: crypto.randomBytes(8).toString('hex'),
      serverTs: new Date().toISOString(),
      ip,
      scanner: String(body.scanner || 'unknown').slice(0, 80),
      targetUser: String(body.targetUser || '').slice(0, 80),
      pcName: String(body.pcName || '').slice(0, 80),
      modPath: anonPath(String(body.modPath || '').slice(0, 300)),
      trusted: trusted ? 1 : 0,
      verdict: String(body.verdict || 'clean').slice(0, 20),
      session: body.session || null,
      totals: body.totals || {},
      flagged: (body.flagged || []).slice(0, 200),
      review: (body.review || []).slice(0, 200),
      systemIssues: (body.systemIssues || []).slice(0, 200),
      toolVersion: String(body.toolVersion || '').slice(0, 20),
      modelVersion: body.modelVersion || 0,
      // The ID the tool printed on the scanned PC, and the code the moderator said
      // out loud before it started. This copy was written here, by the tool, not by
      // the person being checked - so if the report they show and this row disagree,
      // this row is the one to believe. That is the whole reason it is stored.
      scanId: String(body.scanId || '').slice(0, 32).toUpperCase(),
      scanCode: String(body.scanCode || '').slice(0, 40),
    };
    scans.push(rec);
    if (scans.length > MAX_SCANS) scans = scans.slice(-MAX_SCANS);
    save(SCANS_FILE, scans);

    // aggregate shared learning
    let changed = false;
    // Pooled hashes reach every client on their next run, so a wrong one becomes a
    // team-wide false positive that nobody can trace. Record who contributed each
    // hash and from which scan, so a bad entry can be found and removed.
    const gc = new Set(sigs.knownCheatHashes), gg = new Set(sigs.knownGoodHashes);
    const note = (h, kind) => {
      sigs.meta[h] = { kind, scanner: rec.scanner, target: rec.targetUser,
                       scanId: rec.id, ts: rec.serverTs,
                       state: trusted ? 'approved' : 'pending' };
    };
    // A hash from an untrusted upload waits for a human. Approved hashes reach
    // every client on their next run, so a wrong cheat hash is a permanent
    // team-wide false positive on a legitimate mod - somebody could submit the
    // SHA1 of sodium.jar and every scan on the team would confirm it as a cheat.
    const add = (h, kind, set) => {
      if (!h) return;
      if (sigs.rejected.includes(h)) return;   // stays rejected until re-contributed by staff
      if (sigs.meta[h] && sigs.meta[h].state === 'approved') return;
      note(h, kind);
      if (trusted) { set.add(h); }
      changed = true;
    };
    for (const h of (body.newCheat || [])) add(h, 'cheat', gc);
    for (const h of (body.newGood || [])) add(h, 'good', gg);
    if (changed) { sigs.knownCheatHashes = [...gc]; sigs.knownGoodHashes = [...gg]; save(SIGS_FILE, sigs); }

    // Training too: 500 SGD steps per request, from a key printed in the repo,
    // would let anyone walk the shared model wherever they liked.
    if (trusted && Array.isArray(body.samples) && model) {
      let n = 0;
      for (const s of body.samples.slice(0, 500)) {
        if (Array.isArray(s.vec) && (s.label === 0 || s.label === 1)) { sgdStep(s.vec, s.label); n++; }
      }
      if (n) save(MODEL_FILE, model);
    }

    // federated OVERALL-SCAN training: one labelled sample per finished scan
    const ss = body.sessionSample;
    if (trusted && ss && Array.isArray(ss.vec) && (ss.label === 0 || ss.label === 1) && smodel) {
      sSgdStep(ss.vec, ss.label);
      save(SMODEL_FILE, smodel);
    }
    return send(res, 200, { ok: true, id: rec.id, trusted: rec.trusted === 1,
                            signatureState: trusted ? 'approved' : 'pending',
                            modelTrained: model ? model.trainedCount : 0 });
  }

  // Only APPROVED hashes are handed out. This is the endpoint every client pulls
  // on every run, so anything here is believed by the whole team.
  if (req.method === 'GET' && url.pathname === '/api/signatures') {
    return send(res, 200, { version: 100, knownCheatHashes: sigs.knownCheatHashes, knownGoodHashes: sigs.knownGoodHashes });
  }

  // The queue a moderator works through. Staff key only: it names who
  // contributed what, and it is the list that decides what the team believes.
  if (req.method === 'GET' && url.pathname === '/api/signatures/pending') {
    if (!isStaff()) return send(res, 401, { error: 'staff key required' });
    const rows = Object.keys(sigs.meta)
      .filter(h => (sigs.meta[h].state || 'pending') === 'pending')
      .map(h => ({ hash: h, ...sigs.meta[h] }));
    return send(res, 200, { count: rows.length, hashes: rows });
  }

  if (req.method === 'POST' && url.pathname === '/api/signatures/approve') {
    if (!isStaff()) return send(res, 401, { error: 'staff key required' });
    const body = await readBody(req);
    if (!body) return send(res, 400, { error: 'bad json' });
    const list = Array.isArray(body.hashes) ? body.hashes.slice(0, 500) : [];
    let n = 0;
    for (const h of list) {
      const m = sigs.meta[h];
      // A rejected hash stays rejected. Approving it back has to be a delete and
      // a fresh contribution, not a retry that quietly wins.
      if (!m || (m.state || 'pending') !== 'pending') continue;
      m.state = 'approved';
      if (m.kind === 'cheat') { if (!sigs.knownCheatHashes.includes(h)) sigs.knownCheatHashes.push(h); }
      else { if (!sigs.knownGoodHashes.includes(h)) sigs.knownGoodHashes.push(h); }
      n++;
    }
    if (n) save(SIGS_FILE, sigs);
    return send(res, 200, { ok: true, approved: n });
  }

  // auditable view: which hash came from whose scan (view-gated, not public)
  if (req.method === 'GET' && url.pathname === '/api/signatures/audit') {
    if (!viewOK()) return send(res, 401, { error: 'bad view key' });
    const rows = [...sigs.knownCheatHashes, ...sigs.knownGoodHashes]
      .map(h => ({ hash: h, ...(sigs.meta[h] || { kind: 'unknown' }) }));
    return send(res, 200, { count: rows.length, hashes: rows });
  }

  // Revoking matters more than adding: without this a single wrong confirmation
  // is permanent for the whole team.
  if (req.method === 'DELETE' && url.pathname.startsWith('/api/signatures/')) {
    if (!isStaff()) return send(res, 401, { error: 'staff key required' });
    const h = decodeURIComponent(url.pathname.split('/').pop());
    const had = sigs.knownCheatHashes.includes(h) || sigs.knownGoodHashes.includes(h) || !!sigs.meta[h];
    sigs.knownCheatHashes = sigs.knownCheatHashes.filter(x => x !== h);
    sigs.knownGoodHashes = sigs.knownGoodHashes.filter(x => x !== h);
    // Marked, not forgotten: a row that is gone can be contributed again by the
    // next upload and nobody would notice it came back.
    if (sigs.meta[h]) sigs.meta[h].state = 'rejected';
    if (!sigs.rejected.includes(h)) sigs.rejected.push(h);
    if (had) save(SIGS_FILE, sigs);
    return send(res, 200, { ok: true, removed: had ? 1 : 0 });
  }

  // the shared, team-trained model (every client pulls this)
  if (req.method === 'GET' && url.pathname === '/api/model') {
    if (!model) return send(res, 404, { error: 'no model' });
    return send(res, 200, { version: model.version, trainedCount: model.trainedCount || 0, feature_order: model.feature_order, intercept: model.intercept, weights: model.weights });
  }

  // the shared, team-trained OVERALL-SCAN model (every client pulls this too)
  if (req.method === 'GET' && url.pathname === '/api/smodel') {
    if (!smodel) return send(res, 404, { error: 'no session model' });
    return send(res, 200, { version: smodel.version, trainedCount: smodel.trainedCount || 0, feature_order: smodel.feature_order, intercept: smodel.intercept, weights: smodel.weights });
  }

  // history (view-gated if VIEW_KEY set)
  if (req.method === 'GET' && url.pathname === '/api/history') {
    if (!viewOK()) return send(res, 401, { error: 'bad view key' });
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 1000);
    return send(res, 200, { scans: scans.slice(-limit).reverse().map(summary), viewProtected: !!VIEW_KEY });
  }

  // full scan detail (view-gated)
  if (req.method === 'GET' && url.pathname.startsWith('/api/scan/')) {
    if (!viewOK()) return send(res, 401, { error: 'bad view key' });
    const id = url.pathname.split('/').pop();
    // Either key works. The moderator is reading the Scan ID off a screen - that is
    // the one printed in the report - so looking it up must not require knowing the
    // server's own row id.
    const up = String(id || '').toUpperCase();
    const s = scans.find((x) => x.id === id) || scans.find((x) => (x.scanId || '') === up);
    return s ? send(res, 200, s) : send(res, 404, { error: 'not found' });
  }

  // dashboard
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    try { return send(res, 200, fs.readFileSync(path.join(__dirname, 'dashboard.html'), 'utf8'), 'text/html; charset=utf-8'); }
    catch { return send(res, 200, '<h1>AsyncAnalyzer backend running</h1><p>dashboard.html not found next to server.js</p>', 'text/html'); }
  }

  send(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.log(`AsyncAnalyzer backend on :${PORT}`);
  console.log(`  write key : ${WRITE_KEY === 'change-me-write-key' ? '(DEFAULT — set ASYNC_KEY!)' : 'set'}`);
  console.log(`  view key  : ${VIEW_KEY ? 'set' : '(none — history is public)'}`);
  console.log(`  scans     : ${scans.length}`);
});
