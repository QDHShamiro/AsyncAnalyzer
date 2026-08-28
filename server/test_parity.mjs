/*
 * Parity + behaviour tests for the two backends.
 *
 * There are two hand-maintained implementations of one API - server.js (Node,
 * for running it yourself) and worker.js (Cloudflare, the one that gets
 * deployed) - and they had already drifted apart without anybody noticing:
 * worker.js left scanId and scanCode out of /api/history, so on the deployed
 * half the dashboard's Scan ID column showed a dash on every row and its search
 * never matched. That is the exact mechanism the report tells moderators to use
 * ("look that ID up in the team dashboard"). worker.js also had no rate limiter,
 * while the README named rate limiting as the only guard against the published
 * write key.
 *
 * So both are started for real and asked the same questions. worker.js runs
 * against a D1 shim backed by node:sqlite - a real database, not a mock, because
 * a mock would agree with whatever the code did.
 *
 * Run:  node --experimental-sqlite server/test_parity.mjs
 */
import { DatabaseSync } from 'node:sqlite';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WRITE_KEY = 'write-key-for-tests';
const STAFF_KEY = 'staff-key-for-tests';
const VIEW_KEY = 'view-key-for-tests';

let passed = 0, failed = 0;
function check(name, ok, detail = '') {
  if (ok) passed++; else failed++;
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${ok || !detail ? '' : `\n         ${detail}`}`);
}
function eq(name, a, b) {
  const ok = JSON.stringify(a) === JSON.stringify(b);
  check(name, ok, ok ? '' : `server=${JSON.stringify(a)}\n         worker=${JSON.stringify(b)}`);
}

// --------------------------------------------------------------- D1 shim -----
// The subset of the D1 API worker.js uses, over a real SQLite database.
function makeDB() {
  const db = new DatabaseSync(':memory:');
  const schema = readFileSync(join(HERE, 'schema.sql'), 'utf8');
  db.exec(schema);
  return {
    prepare(sql) {
      let args = [];
      const api = {
        bind(...a) { args = a; return api; },
        async run() {
          const r = db.prepare(sql).run(...args);
          return { meta: { changes: Number(r.changes || 0) } };
        },
        async first() { return db.prepare(sql).get(...args) ?? null; },
        async all() { return { results: db.prepare(sql).all(...args) }; },
      };
      return api;
    },
  };
}

// worker.js fetches the base models from GitHub, which this sandbox cannot
// reach. Serve them from the repo instead - the point of the test is the API,
// not the network.
const realFetch = globalThis.fetch;
globalThis.fetch = async (u, o) => {
  const s = String(u);
  if (s.includes('/ml/model.json')) return new Response(readFileSync(join(HERE, '..', 'ml', 'model.json')));
  if (s.includes('/ml/session_model.json')) return new Response(readFileSync(join(HERE, '..', 'ml', 'session_model.json')));
  if (s.includes('dashboard.html')) return new Response('<html></html>');
  return realFetch(s, o);
};

const worker = (await import('./worker.js')).default;
const WENV = { DB: makeDB(), WRITE_KEY, STAFF_KEY, VIEW_KEY };

async function W(method, path, { key, body } = {}) {
  const headers = {};
  if (key) headers['x-key'] = key;
  if (body) headers['content-type'] = 'application/json';
  const res = await worker.fetch(new Request('https://x' + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  }), WENV);
  let j = null; try { j = await res.json(); } catch {}
  return { status: res.status, body: j };
}

// ------------------------------------------------------------- server.js -----
const dataDir = mkdtempSync(join(tmpdir(), 'aa-srv-'));
const PORT = 18787 + Math.floor(Math.random() * 900);
const child = spawn(process.execPath, [join(HERE, 'server.js')], {
  env: {
    ...process.env, PORT: String(PORT), ASYNC_KEY: WRITE_KEY,
    ASYNC_STAFFKEY: STAFF_KEY, ASYNC_VIEWKEY: VIEW_KEY, ASYNC_DATA: dataDir,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
async function S(method, path, { key, body } = {}) {
  const headers = {};
  if (key) headers['x-key'] = key;
  if (body) headers['content-type'] = 'application/json';
  const res = await realFetch(`http://127.0.0.1:${PORT}${path}`, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  let j = null; try { j = await res.json(); } catch {}
  return { status: res.status, body: j };
}
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try { await realFetch(`http://127.0.0.1:${PORT}/api/signatures`); return true; } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  return false;
}

// ------------------------------------------------------------------ cases ----
const SCAN = {
  scanner: 'Shamiro', targetUser: 'SomePlayer', pcName: 'GAMING-PC',
  modPath: 'C:\\Users\\Shamiro\\AppData\\Roaming\\.minecraft\\mods',
  verdict: 'flagged', scanId: 'A1B2C3D4E5F6', scanCode: 'banana',
  totals: { total: 12, verified: 10, flagged: 1 },
  flagged: [{ name: 'x.jar', score: 90, band: 'Confirmed' }],
  toolVersion: '4.0.0',
};
const POISON = { ...SCAN, scanId: 'FFFFFFFFFFFF', newCheat: ['0123456789abcdef0123456789abcdef01234567'] };

async function main() {
  if (!await waitUp()) { console.log('server.js did not start'); return 1; }

  console.log('=== Both backends, the same request, the same answer ===');
  for (const [name, call] of [
    ['a scan with the public key is accepted', (F) => F('POST', '/api/scan', { key: WRITE_KEY, body: SCAN })],
    ['a scan with a wrong key is refused', (F) => F('POST', '/api/scan', { key: 'nope', body: SCAN })],
    ['history without a key is refused', (F) => F('GET', '/api/history')],
    ['history with the view key is served', (F) => F('GET', '/api/history', { key: VIEW_KEY })],
    ['the pending queue needs the staff key', (F) => F('GET', '/api/signatures/pending', { key: VIEW_KEY })],
    ['approving needs the staff key', (F) => F('POST', '/api/signatures/approve', { key: WRITE_KEY, body: { hashes: ['x'] } })],
    ['revoking needs the staff key', (F) => F('DELETE', '/api/signatures/deadbeef', { key: WRITE_KEY })],
  ]) {
    const a = await call(S), b = await call(W);
    check(name + ` (${a.status})`, a.status === b.status,
      `server=${a.status} ${JSON.stringify(a.body)}\n         worker=${b.status} ${JSON.stringify(b.body)}`);
  }

  console.log('\n=== The Scan ID a moderator types in has to come back ===');
  // This is the bug that started this file: worker.js left scanId and scanCode
  // out of the /api/history projection, so the dashboard column was always a
  // dash and the search never matched - on the deployed half only.
  const hs = await S('GET', '/api/history', { key: VIEW_KEY });
  const hw = await W('GET', '/api/history', { key: VIEW_KEY });
  const rowS = (hs.body.scans || [])[0] || {};
  const rowW = (hw.body.scans || [])[0] || {};
  check('server.js history carries the Scan ID', rowS.scanId === 'A1B2C3D4E5F6', JSON.stringify(rowS));
  check('worker.js history carries the Scan ID', rowW.scanId === 'A1B2C3D4E5F6', JSON.stringify(rowW));
  eq('both carry the same summary fields', Object.keys(rowS).sort(), Object.keys(rowW).sort());
  check('the staff code comes back too', rowS.scanCode === 'banana' && rowW.scanCode === 'banana');

  console.log('\n=== A scanned PC cannot decide what the team believes ===');
  await S('POST', '/api/scan', { key: WRITE_KEY, body: POISON });
  await W('POST', '/api/scan', { key: WRITE_KEY, body: POISON });
  const sigS = await S('GET', '/api/signatures');
  const sigW = await W('GET', '/api/signatures');
  const poisoned = POISON.newCheat[0];
  check('server.js does NOT hand out an unapproved cheat hash',
    !(sigS.body.knownCheatHashes || []).includes(poisoned), JSON.stringify(sigS.body));
  check('worker.js does NOT hand out an unapproved cheat hash',
    !(sigW.body.knownCheatHashes || []).includes(poisoned), JSON.stringify(sigW.body));
  const penS = await S('GET', '/api/signatures/pending', { key: STAFF_KEY });
  const penW = await W('GET', '/api/signatures/pending', { key: STAFF_KEY });
  check('it is waiting in the queue instead (server)', (penS.body.hashes || []).some(h => h.hash === poisoned));
  check('it is waiting in the queue instead (worker)', (penW.body.hashes || []).some(h => h.hash === poisoned));

  console.log('\n=== ...but a moderator can approve it, and it then ships ===');
  await S('POST', '/api/signatures/approve', { key: STAFF_KEY, body: { hashes: [poisoned] } });
  await W('POST', '/api/signatures/approve', { key: STAFF_KEY, body: { hashes: [poisoned] } });
  const sigS2 = await S('GET', '/api/signatures');
  const sigW2 = await W('GET', '/api/signatures');
  check('approved, server.js now hands it out', (sigS2.body.knownCheatHashes || []).includes(poisoned));
  check('approved, worker.js now hands it out', (sigW2.body.knownCheatHashes || []).includes(poisoned));

  console.log('\n=== A revoked hash stays revoked ===');
  await S('DELETE', `/api/signatures/${poisoned}`, { key: STAFF_KEY });
  await W('DELETE', `/api/signatures/${poisoned}`, { key: STAFF_KEY });
  // contributing it again must not bring it back
  await S('POST', '/api/scan', { key: WRITE_KEY, body: POISON });
  await W('POST', '/api/scan', { key: WRITE_KEY, body: POISON });
  await S('POST', '/api/signatures/approve', { key: STAFF_KEY, body: { hashes: [poisoned] } });
  await W('POST', '/api/signatures/approve', { key: STAFF_KEY, body: { hashes: [poisoned] } });
  const sigS3 = await S('GET', '/api/signatures');
  const sigW3 = await W('GET', '/api/signatures');
  check('server.js keeps it out after a revoke', !(sigS3.body.knownCheatHashes || []).includes(poisoned));
  check('worker.js keeps it out after a revoke', !(sigW3.body.knownCheatHashes || []).includes(poisoned));

  console.log('\n=== The scanned PC\'s Windows name does not get stored ===');
  const detS = await S('GET', '/api/scan/A1B2C3D4E5F6', { key: VIEW_KEY });
  const detW = await W('GET', '/api/scan/A1B2C3D4E5F6', { key: VIEW_KEY });
  check('server.js anonymised modPath', detS.body.modPath === 'C:\\Users\\<user>\\AppData\\Roaming\\.minecraft\\mods', detS.body.modPath);
  check('worker.js anonymised modPath', detW.body.modPath === 'C:\\Users\\<user>\\AppData\\Roaming\\.minecraft\\mods', detW.body.modPath);
  check('the Scan ID printed on the PC finds the row (server)', detS.body.scanId === 'A1B2C3D4E5F6');
  check('the Scan ID printed on the PC finds the row (worker)', detW.body.scanId === 'A1B2C3D4E5F6');

  console.log('\n=== Only a trusted upload may move the shared model ===');
  const before = (await W('GET', '/api/model')).body.trainedCount || 0;
  const sample = { vec: new Array(40).fill(0.5), label: 1 };
  await W('POST', '/api/scan', { key: WRITE_KEY, body: { ...SCAN, scanId: 'B0B0B0B0B0B0', samples: [sample, sample, sample] } });
  const afterPublic = (await W('GET', '/api/model')).body.trainedCount || 0;
  check('a public-key upload trains nothing', afterPublic === before, `${before} -> ${afterPublic}`);
  await W('POST', '/api/scan', { key: STAFF_KEY, body: { ...SCAN, scanId: 'C0C0C0C0C0C0', samples: [sample] } });
  const afterStaff = (await W('GET', '/api/model')).body.trainedCount || 0;
  check('a staff upload does', afterStaff > afterPublic, `${afterPublic} -> ${afterStaff}`);

  console.log(`\n=== RESULT: ${passed} passed, ${failed} failed ===`);
  return failed ? 1 : 0;
}

let code = 1;
try { code = await main(); } catch (e) { console.log('ERROR', e); code = 1; }
child.kill();
rmSync(dataDir, { recursive: true, force: true });
process.exit(code);
