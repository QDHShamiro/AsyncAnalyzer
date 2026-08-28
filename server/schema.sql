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
  -- which approved server this scan belongs to. NULL on rows from before the
  -- website existed; those are visible to AsyncAnalyzer staff only, because
  -- there is no server they could belong to.
  server_id TEXT,
  data    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans (ts);
CREATE INDEX IF NOT EXISTS idx_scans_server ON scans (server_id, ts);

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

-- ---------------------------------------------------------------------------
-- Accounts, servers and the queue between them.
-- ---------------------------------------------------------------------------

-- One row per human, no matter how many ways they sign in. global_role is NULL
-- for everyone who is just staff on somebody's server; 'staff' and 'owner' are
-- AsyncAnalyzer itself and are set by hand, never by a signup.
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  email       TEXT UNIQUE,
  name        TEXT NOT NULL,
  avatar      TEXT,
  global_role TEXT,
  created_ts  TEXT NOT NULL
);

-- Discord, Google and password all point at the same user row, so signing in a
-- second way joins the existing account instead of forking a duplicate one.
CREATE TABLE IF NOT EXISTS identities (
  provider    TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  PRIMARY KEY (provider, provider_id)
);
CREATE INDEX IF NOT EXISTS idx_identities_user ON identities (user_id);

-- Password logins only. One token slot: a pending verify link is invalidated by
-- starting a password reset and the other way round, which is the behaviour you
-- want - two live tokens on one account is one more way in than anybody needs.
CREATE TABLE IF NOT EXISTS credentials (
  user_id    TEXT PRIMARY KEY,
  hash       TEXT NOT NULL,
  salt       TEXT NOT NULL,
  verified   INTEGER NOT NULL DEFAULT 0,
  token      TEXT,
  token_kind TEXT,
  token_exp  TEXT
);
CREATE INDEX IF NOT EXISTS idx_credentials_token ON credentials (token);

-- An approved server. write_key is what the one-liner carries, so it decides
-- which server a scan lands in - it is rotatable for exactly that reason.
CREATE TABLE IF NOT EXISTS servers (
  id             TEXT PRIMARY KEY,
  slug           TEXT UNIQUE NOT NULL,
  name           TEXT NOT NULL,
  discord_invite TEXT,
  players        TEXT,
  age            TEXT,
  status         TEXT NOT NULL DEFAULT 'active',
  owner_user_id  TEXT NOT NULL,
  write_key      TEXT UNIQUE NOT NULL,
  -- How a server owner gets their own moderators in without us knowing who they
  -- are: one link they paste in their staff channel. Rotatable, because a link
  -- pasted in a staff channel eventually ends up outside it.
  invite_code    TEXT UNIQUE,
  created_ts     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_servers_key ON servers (write_key);
CREATE INDEX IF NOT EXISTS idx_servers_invite ON servers (invite_code);

CREATE TABLE IF NOT EXISTS memberships (
  server_id TEXT NOT NULL,
  user_id   TEXT NOT NULL,
  role      TEXT NOT NULL,
  added_ts  TEXT NOT NULL,
  PRIMARY KEY (server_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships (user_id);

CREATE TABLE IF NOT EXISTS applications (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL,
  name           TEXT NOT NULL,
  discord_invite TEXT,
  players        TEXT,
  age            TEXT,
  reason         TEXT,
  status         TEXT NOT NULL DEFAULT 'pending',
  created_ts     TEXT NOT NULL,
  decided_ts     TEXT,
  decided_by     TEXT,
  server_id      TEXT
);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications (status, created_ts);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications (user_id);
