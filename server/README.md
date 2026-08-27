# AsyncAnalyzer Team Backend

Shared scan history + shared cheat intelligence for your team. Every AsyncAnalyzer
run (you, Luis, any staff) uploads its result here, everyone browses the history in
one dashboard, and confirmed cheat/known-good hashes are pooled so the whole team's
detection improves together.

The tool only uploads when **you** turn it on (via `ml/signatures.json` in your repo),
and it shows the scanned person an upload notice. It uploads scan **results** (mod
names, hashes, verdicts, system-check findings, usernames) — never their actual files.

---

## Option A — Cloudflare Worker (recommended, free, always-on)

Needs a free Cloudflare account + Node.

```bash
npm i -g wrangler
cd server
wrangler login
wrangler d1 create asyncanalyzer          # copy the database_id it prints
#  -> paste that id into wrangler.toml (database_id = "...")
wrangler d1 execute asyncanalyzer --remote --file=schema.sql
wrangler secret put WRITE_KEY              # type a long random secret (the upload key)
wrangler secret put VIEW_KEY               # optional: a secret to view the dashboard
wrangler deploy
```

Wrangler prints your URL, e.g. `https://asyncanalyzer-backend.YOURNAME.workers.dev`.
Open it in a browser → the dashboard. That's your history.

## Option B — Node server (runs anywhere: your PC, a VPS, Railway, Replit)

Zero dependencies.

```bash
cd server
ASYNC_KEY=your-long-write-secret ASYNC_VIEWKEY=your-view-secret node server.js
# dashboard at http://localhost:8787
```

Put it behind a domain / tunnel (e.g. Cloudflare Tunnel, or host on Railway) so the
tool can reach it. Data is stored in `server/data/*.json`.

---

## Point the tool at your backend

Edit **`ml/signatures.json`** in your GitHub repo and add a `telemetry` block:

```json
{
  "telemetry": {
    "enabled": true,
    "endpoint": "https://asyncanalyzer-backend.YOURNAME.workers.dev",
    "key": "your-long-write-secret",
    "pullSignatures": true
  }
}
```

That's it. Because the tool downloads `signatures.json` on every run, you control
uploading (on/off, where, which key) from GitHub — no need to touch the PowerShell
script. Set `"enabled": false` to turn team uploads off for everyone instantly.

- `endpoint` — your backend URL
- `key` — the WRITE_KEY (lets the tool POST scans)
- `pullSignatures` — also merge the team's pooled cheat/good hashes into detection

---

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/scan` | `x-key: WRITE_KEY` | upload one scan result |
| GET | `/api/history?limit=` | `?key=VIEW_KEY` (if set) | scan summaries, newest first |
| GET | `/api/scan/:id` | `?key=VIEW_KEY` (if set) | one full scan |
| GET | `/api/signatures` | public | pooled cheat/good hashes |
| GET | `/api/model` | public | the shared, team-trained **mod** model (clients pull this) |
| GET | `/api/smodel` | public | the shared, team-trained **overall-scan** model (clients pull this too) |
| GET | `/` | — | the dashboard |

Every scan can include a `samples` array (labelled feature vectors) **and** a
`sessionSample` (one labelled vector for the scan as a whole). The backend runs one
bounded, base-anchored SGD step per sample, so **two shared models learn from every
team member's scans**: one that judges single mods, and one that judges a whole scan
(mods + system + processes + JVM + history). Clients fetch `/api/model` each run and use it. The base-anchoring
means the shared model adapts to new cheats but can't drift into false positives.

> The write key lives in the (public) tool config, so treat it as append-only: worst
> case someone posts junk scans, which you can clear. Rotate it anytime by changing the
> secret and `signatures.json`. Keep `VIEW_KEY` private — it protects who can read the
> history.
