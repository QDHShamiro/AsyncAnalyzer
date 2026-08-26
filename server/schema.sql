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
  hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
