CREATE TABLE IF NOT EXISTS scans (
  id      TEXT PRIMARY KEY,
  ts      TEXT NOT NULL,
  scanner TEXT,
  target  TEXT,
  pc      TEXT,
  verdict TEXT,
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
  ts      TEXT
);

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
