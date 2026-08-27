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
const VIEW_KEY = process.env.ASYNC_VIEWKEY || ''; // empty = history is public
const DATA_DIR = path.join(__dirname, 'data');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');
const SIGS_FILE = path.join(DATA_DIR, 'sigs.json');
const MAX_SCANS = 5000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
function load(file, def) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; } }
function save(file, obj) { fs.writeFileSync(file, JSON.stringify(obj)); }

let scans = load(SCANS_FILE, []);
let sigs = load(SIGS_FILE, { knownCheatHashes: [], knownGoodHashes: [], meta: {} });
if (!sigs.meta) sigs.meta = {};   // older stores predate attribution

// ---- shared (federated) model: trained by every team member's scans ----
const MODEL_FILE = path.join(DATA_DIR, 'model.json');
const BASE = load(path.join(__dirname, '..', 'ml', 'model.json'), null);
let model = load(MODEL_FILE, null);
if (!model && BASE) {
  model = { version: BASE.version, feature_order: BASE.feature_order, intercept: BASE.intercept, weights: { ...BASE.weights }, trainedCount: 0 };
  save(MODEL_FILE, model);
}
// ---- shared (federated) SESSION model: learns from WHOLE scans, not single jars ----
const SMODEL_FILE = path.join(DATA_DIR, 'smodel.json');
const SBASE = load(path.join(__dirname, '..', 'ml', 'session_model.json'), null);
let smodel = load(SMODEL_FILE, null);
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

function summary(s) {
  return {
    id: s.id, serverTs: s.serverTs, scanner: s.scanner, targetUser: s.targetUser,
    pcName: s.pcName, verdict: s.verdict, totals: s.totals, toolVersion: s.toolVersion,
    flaggedCount: (s.flagged || []).length, reviewCount: (s.review || []).length,
    session: s.session || null,
  };
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (limited(ip)) return send(res, 429, { error: 'rate limited' });

  // POST a scan
  if (req.method === 'POST' && url.pathname === '/api/scan') {
    if ((req.headers['x-key'] || '') !== WRITE_KEY) return send(res, 401, { error: 'bad key' });
    const body = await readBody(req);
    if (!body) return send(res, 400, { error: 'bad json' });
    const rec = {
      id: crypto.randomBytes(8).toString('hex'),
      serverTs: new Date().toISOString(),
      ip,
      scanner: String(body.scanner || 'unknown').slice(0, 80),
      targetUser: String(body.targetUser || '').slice(0, 80),
      pcName: String(body.pcName || '').slice(0, 80),
      modPath: String(body.modPath || '').slice(0, 300),
      verdict: String(body.verdict || 'clean').slice(0, 20),
      session: body.session || null,
      totals: body.totals || {},
      flagged: (body.flagged || []).slice(0, 200),
      review: (body.review || []).slice(0, 200),
      systemIssues: (body.systemIssues || []).slice(0, 200),
      toolVersion: String(body.toolVersion || '').slice(0, 20),
      modelVersion: body.modelVersion || 0,
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
                       scanId: rec.id, ts: rec.serverTs };
    };
    for (const h of (body.newCheat || [])) { if (h && !gc.has(h)) { gc.add(h); note(h, 'cheat'); changed = true; } }
    for (const h of (body.newGood || [])) { if (h && !gg.has(h)) { gg.add(h); note(h, 'good'); changed = true; } }
    if (changed) { sigs.knownCheatHashes = [...gc]; sigs.knownGoodHashes = [...gg]; save(SIGS_FILE, sigs); }

    // federated model training: every team member's labelled samples train ONE shared model
    if (Array.isArray(body.samples) && model) {
      let n = 0;
      for (const s of body.samples.slice(0, 500)) {
        if (Array.isArray(s.vec) && (s.label === 0 || s.label === 1)) { sgdStep(s.vec, s.label); n++; }
      }
      if (n) save(MODEL_FILE, model);
    }

    // federated OVERALL-SCAN training: one labelled sample per finished scan
    const ss = body.sessionSample;
    if (ss && Array.isArray(ss.vec) && (ss.label === 0 || ss.label === 1) && smodel) {
      sSgdStep(ss.vec, ss.label);
      save(SMODEL_FILE, smodel);
    }
    return send(res, 200, { ok: true, id: rec.id, modelTrained: model ? model.trainedCount : 0 });
  }

  // shared signatures (public — just hashes)
  if (req.method === 'GET' && url.pathname === '/api/signatures') {
    return send(res, 200, { version: 100, knownCheatHashes: sigs.knownCheatHashes, knownGoodHashes: sigs.knownGoodHashes });
  }

  // auditable view: which hash came from whose scan (view-gated, not public)
  if (req.method === 'GET' && url.pathname === '/api/signatures/audit') {
    if (VIEW_KEY && (url.searchParams.get('key') || req.headers['x-key']) !== VIEW_KEY) {
      return send(res, 401, { error: 'bad view key' });
    }
    const rows = [...sigs.knownCheatHashes, ...sigs.knownGoodHashes]
      .map(h => ({ hash: h, ...(sigs.meta[h] || { kind: 'unknown' }) }));
    return send(res, 200, { count: rows.length, hashes: rows });
  }

  // Revoking matters more than adding: without this a single wrong confirmation
  // is permanent for the whole team.
  if (req.method === 'DELETE' && url.pathname.startsWith('/api/signatures/')) {
    if ((req.headers['x-key'] || '') !== WRITE_KEY) return send(res, 401, { error: 'bad key' });
    const h = decodeURIComponent(url.pathname.split('/').pop());
    const before = sigs.knownCheatHashes.length + sigs.knownGoodHashes.length;
    sigs.knownCheatHashes = sigs.knownCheatHashes.filter(x => x !== h);
    sigs.knownGoodHashes = sigs.knownGoodHashes.filter(x => x !== h);
    delete sigs.meta[h];
    const removed = before - (sigs.knownCheatHashes.length + sigs.knownGoodHashes.length);
    if (removed) save(SIGS_FILE, sigs);
    return send(res, 200, { ok: true, removed });
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
    if (VIEW_KEY && (url.searchParams.get('key') || req.headers['x-key']) !== VIEW_KEY) return send(res, 401, { error: 'bad view key' });
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 1000);
    return send(res, 200, { scans: scans.slice(-limit).reverse().map(summary), viewProtected: !!VIEW_KEY });
  }

  // full scan detail (view-gated)
  if (req.method === 'GET' && url.pathname.startsWith('/api/scan/')) {
    if (VIEW_KEY && (url.searchParams.get('key') || req.headers['x-key']) !== VIEW_KEY) return send(res, 401, { error: 'bad view key' });
    const id = url.pathname.split('/').pop();
    const s = scans.find((x) => x.id === id);
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
