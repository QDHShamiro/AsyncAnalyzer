# The backend

One Cloudflare Worker serves the whole product: the public site, the accounts, the
server applications, every server's scan history, and the shared cheat intelligence.
Free tier, always on, one deploy.

```
worker.js     the router and every endpoint
auth.js       sessions, passwords, Discord/Google OAuth, outbound mail
tenancy.js    users, servers, memberships, and the one permission function
schema.sql    the D1 tables
wrangler.toml the deploy config; ../site is served as static assets
```

The site and the API share an origin, which is what lets the session cookie work
with no CORS arrangement and no second deployment to keep in step.

---

## Deploy

```bash
npm i -g wrangler
cd server
wrangler login
wrangler d1 create asyncanalyzer          # copy the database_id it prints
#  -> paste that id into wrangler.toml
wrangler d1 execute asyncanalyzer --remote --file=schema.sql
wrangler deploy
```

Wrangler prints the URL. Put that URL in `$script:HomeEndpoint` in
`src/00-header.ps1` and run `python3 build.py`, so the shipped scanner checks its key
against your backend.

### Secrets

None of these live in the repo. Set each with `wrangler secret put <NAME>`.

| Secret | Needed for | Where it comes from |
|---|---|---|
| `SESSION_SECRET` | **required** — signs the session and OAuth-state cookies | any long random string. Rotating it signs everybody out |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Discord sign-in | Discord Developer Portal → OAuth2. Redirect: `https://<host>/auth/discord/callback` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google sign-in | Google Cloud Console → Credentials. Redirect: `https://<host>/auth/google/callback` |
| `RESEND_KEY`, `MAIL_FROM` | email sign-up, password reset | resend.com. Without it, email accounts cannot confirm and the sign-up form says so instead of pretending |
| `DISCORD_WEBHOOK` | a ping when somebody applies | a webhook URL from your own Discord channel |
| `STAFF_KEY` | uploads allowed to train the shared model | any long random string |

A provider with no credentials is simply not offered on the login page.

### The first account

Whoever signs in first becomes the **owner** — everything, everywhere. Do that
yourself, immediately after the deploy. Every account after that starts with no
rank, and only the owner hands ranks out.

---

## Local development

```bash
cd server
printf 'SESSION_SECRET=anything-long\nSTAFF_KEY=local\n' > .dev.vars    # gitignored
wrangler d1 execute asyncanalyzer --local --file=schema.sql
wrangler dev --local
```

`wrangler dev` runs the real Worker against a local D1, which is why there is no
second Node implementation of this API any more — there used to be one, and the two
copies drifted.

---

## Ranks

| | owner | AsyncAnalyzer staff | server owner | server moderator |
|---|---|---|---|---|
| decide applications | yes | yes | — | — |
| read any server's scans | yes | yes | own only | own only |
| manage a team, rotate keys | yes | — | own server | — |
| work the signature queue | yes | yes | — | — |
| hand out ranks | yes | — | — | — |

Staff deliberately cannot edit somebody else's team. Reading a verdict is support;
changing who can run scans on a server is not.

Every decision goes through `can()` in `tenancy.js`. Adding a route means calling it,
not writing another `if`.

---

## The key in the command

Each approved server gets a `write_key`. It travels inside the one-liner the suspect
runs, so it is **not a secret** — it decides which server a scan belongs to, nothing
more. Every member can see it, only the server owner can rotate it, and rotating it
breaks every command already pasted in a staff channel.

The scanner calls `GET /api/verify?key=…` before it does anything. Without a live
key it refuses to scan. The scanner is one readable file that anybody can edit, so
this is a gate rather than a lock: it stops the tool being pointed at people by
nobody in particular.

### The staff key is a different thing

A scan uploaded with a server key is stored and shown. A scan uploaded with
`STAFF_KEY` is additionally *trusted*: it trains the shared models and its
contributed hashes are approved on arrival. Server keys never do either, because
they are handed to the person being scanned.

---

## API

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | `/api/me` | anyone | the session, its servers and rank |
| GET | `/auth/{discord,google}` | anyone | start a sign-in |
| POST | `/api/auth/{signup,login,forgot,reset,logout}` | anyone | password accounts |
| POST | `/api/applications` | signed in | apply with a server |
| GET | `/api/applications` | staff | the queue |
| POST | `/api/applications/:id/decide` | staff | approve → creates the server |
| GET | `/api/servers` | signed in | your servers (staff: all of them) |
| GET | `/api/servers/:slug` | member | detail, write key, invite link |
| GET | `/api/servers/:slug/history` | member | that server's scans |
| GET | `/api/servers/:slug/scan/:id` | member | one scan in full |
| GET/POST/DELETE | `/api/servers/:slug/members…` | server owner | the team |
| POST | `/api/servers/:slug/rotate-{key,invite}` | server owner | new key / new invite |
| POST | `/api/join/:code` | signed in | accept an invite |
| GET | `/api/admin/users` · POST `…/role` | staff · owner | people and ranks |
| GET | `/api/verify?key=` | the tool | is this copy linked to a live server |
| POST | `/api/scan` | the tool | upload one result |
| GET | `/api/public/scan/:id` | anyone with the link | the redacted, shareable result |
| GET | `/api/signatures` · `/api/model` · `/api/smodel` | public | what every client pulls each run |
| GET | `/api/signatures/pending` · POST `…/approve` · DELETE `/api/signatures/:hash` | staff | the queue that decides what the team believes |
| GET | `/run.ps1` | anyone | the scanner itself, from this origin |

---

## Privacy, in the code

* The scanned PC's Windows account name is stripped out of `modPath` before the row
  is stored (`C:\Users\<user>\…`), because that row ends up in screenshots.
* A shared result (`/api/public/scan/:id`) drops the PC name, the folder path and the
  system notes. The verdict and its reasons stay, because that is the part the
  accused is entitled to argue with.
* A scan belongs to one server. Another server cannot read it.

## Pooled hashes are automatic — so they must be revocable

A confirmed cheat hash reaches every client on its next run. That is the point, and
it is the risk: a wrong one is a permanent, team-wide false positive on a legitimate
mod. So a hash from an untrusted upload waits in `/api/signatures/pending`, every
pooled hash records the scan it came from, and `DELETE /api/signatures/:hash` marks
it rejected rather than deleting it — so the next upload cannot quietly put it back.

If nobody ever works the queue, the team stops learning. That is the cost, and it is
deliberate.
