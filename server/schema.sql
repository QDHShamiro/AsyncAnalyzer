CREATE TABLE IF NOT EXISTS scans (
  id      TEXT PRIMARY KEY,
  ts      TEXT NOT NULL,
  scanner TEXT,
  target  TEXT,
  pc      TEXT,
  verdict TEXT,
  -- 1 when the upload carried the STAFF key. Only a trusted scan may train the
  -- shared model: the write key is published so a scanned PC can upload, which
  -- means anyone who reads the repo can POST, which means anyone could otherwise
  -- steer the model every client pulls.
  trusted INTEGER NOT NULL DEFAULT 0,
  data    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans (ts);

CREATE TABLE IF NOT EXISTS sigs (
  hash    TEXT PRIMARY KEY,
  kind    TEXT NOT NULL,
  -- who contributed it. A pooled hash reaches every client, so a wrong one would
  -- become a permanent team-wide false positive; attribution makes it traceable
  -- and DELETE /api/signatures/:hash makes it revocable.
  scanner TEXT,
  target  TEXT,
  scan_id TEXT,
  ts      TEXT,
  -- 'approved' hashes reach every client on their next run; 'pending' ones do
  -- not. A hash from an untrusted upload lands as pending and waits for a human,
  -- because a wrong cheat hash is a permanent team-wide false positive on a
  -- legitimate mod - exactly what this whole project exists to avoid. 'rejected'
  -- is kept rather than deleted so the same hash cannot quietly come back.
  state   TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_sigs_state ON sigs (state);

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
