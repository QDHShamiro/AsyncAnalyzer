# AsyncAnalyzer — STATUS / Handoff

> Handoff doc so Claude Code on Shamiro's PC (or anyone) can continue seamlessly.
> Last updated by the cloud session. Read this first.

## What this is
A Minecraft mod cheat scanner (Windows PowerShell, one-liner distributed) with a **local, self-improving AI** (logistic-regression model that runs in pure PowerShell — no cloud, no deps), a **team mode** (shared scan-history dashboard + **federated model** that learns from everyone's scans), and a **web dashboard backend**.

## Repo & branch
- Repo: `QDHShamiro/AsyncAnalyzer`
- **Work branch: `claude/mod-analyzer-improvement-c88trb`** (NOT merged to main yet).
- To continue locally:
  ```bash
  git fetch origin
  git checkout claude/mod-analyzer-improvement-c88trb
  git pull
  ```
- The live one-liner still points at `main`, so end users run the OLD version until this branch is merged. **Merge this branch to `main` to ship all improvements.**

## Run / verify (Windows)
```powershell
# normal scan (auto-detects Minecraft by itself now)
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1')"

# verify the AI + verdict logic in 5 seconds (do this after any change)
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'))) -SelfTest"
```
Flags: `-Ask` (manual path), `-Path "C:\...\mods"`, `-DeepScan`, `-DeepMemory`, `-SelfTest`, `-NoUpdate`, `-NoLearn`, `-Reset`, `-Share`.

## File map
- `AsyncAnalyzer.ps1` (~4590 lines) — the whole tool. Key sections:
  - Data lists (cheat strings / weak strings / package paths / legit modids / client tokens) ~line 30–470.
  - Embedded AI model (`$script:mlWeights`, `$script:mlIntercept`, v2) + `Invoke-MlModel`, `Get-JarFeatures`, `Get-ModFeatureVector`, `Get-ModVerdict`, `Write-VerdictCard` ~line 480–850.
  - Self-improvement: `Load/Save-LearnState`, `Update-ModelOnline` (SGD), `Invoke-CloudUpdate`, `Get-MinecraftName`, `Send-ScanResult` ~line 850–1000.
  - `Find-MinecraftModFolders` + **`Get-ScanTargets`** (autonomous target choice: every OPEN instance + configured paths). `Get-BestModFolder`/`Ask-YesNo` are now unreachable leftovers.
  - Autonomy: `Invoke-SelfElevate`, `Set-AutoDepth`, `Request-DeepEscalation`, `Add-ScanGap`/`Write-ScanGaps`, `Save-ScanSummary`.
  - Main scan loop (verify → features → verdict → learn) inside `if (-not $SkipModCheck)`.
  - `New-HtmlReport` (dark-mode report), `Run-SystemChecks`, `Run-PCscan`, `Run-BamScan`, `Run-JVMScan`.
- `ml/` — the AI pipeline (Python, offline):
  - `features.py` (22-feature schema, MUST match the PS extractor), `build_dataset.py` (downloads 36 real libs + synthesises profiles), `train_model.py` (logreg → `model.json` + `model_ps_snippet.txt`), `online_learn.py` (SGD, matches PS), `verdict.py` (reference port), `signatures.json` (community/cheat DB, auto-downloaded by the tool), tests: `test_verdict.py` (42/42), `test_selflearn.py` (self-learning proof).
- `server/` — team backend: `server.js` (zero-dep Node), `worker.js` (Cloudflare + D1), `schema.sql`, `wrangler.toml`, `dashboard.html`, `README.md`.

## AI / verdict (how it decides)
- 22 numeric features per jar (package paths, class-name obfuscation %, entropy, reflection, http/runtime, sigs, verified/legit…).
- Score 0–100 → bands: `<30 Clean / 30–59 Review / 60–84 Likely / 85–100 Confirmed`.
- Hard rules override the model: known-cheat hash = 100; cheat package path = ≥80; cheat download site = ≥75; fake identity ≥70; filename = known client ≥60. **Verified / legit-modid = capped ≤20 (never flagged).**
- Model trained on REAL clean libs (ASM, ByteBuddy, Gson, Netty, Kotlin, log4j…) so reflection/obfuscation alone don't false-flag. precision/recall 1.00; worst real lib 0.13.

## Self-improvement (all local)
1. Hash memory (`%APPDATA%\AsyncAnalyzer\learned.json`): verified → good, hard-confirmed cheat → cheat.
2. Online SGD nudges the local weights per confirmed verdict (base-anchored → can't drift into FPs).
3. Cloud auto-update pulls newest `ml/model.json` + `ml/signatures.json` from GitHub.

## Team mode + federated AI (off by default)
- Turn on via `ml/signatures.json` → `telemetry` block (`enabled`, `endpoint`, `key`, `pullSignatures`). No script edit needed.
- Deploy backend from `server/README.md` (Cloudflare Worker or Node).
- Every scan uploads its result (mods/hashes/verdict/usernames — NEVER files) + labelled feature samples. Backend trains ONE shared model; clients pull it via `/api/model`. Dashboard = the scan history. Tested end-to-end: shared model learned a new family 17→38% across 6 scans.

## How to retrain the model
```bash
cd ml && python3 build_dataset.py && python3 train_model.py
# then paste ml/model_ps_snippet.txt into the $script:mlWeights block of AsyncAnalyzer.ps1
# bump $script:mlModelVersion to match model.json "version"
```

## Validation done in the cloud env (no Windows / no pwsh here)
- Brace / here-string balance kept identical to the working original after every edit (Python checker).
- PS embedded weights verified == `ml/model.json` (v2).
- `-SelfTest` cases proven to pass via the mirrored Python logic.
- `node -c` on server.js/worker.js; backend + federated learning tested live with curl/node.
- **Not done: a real Windows PowerShell run.** That's the main open verification — run `-SelfTest` and a real scan on Windows.

## Doomsday / ghost-client intel (gathered this session)
- Doomsday is a **ghost / injectable** client, explicitly **screenshare-proof ("SS Bypass")** — the whole reason it needs detecting. Supports MC 1.8–1.21+, loaders Vanilla/Forge/Fabric/Feather/Lunar/LabyMod. Features: Aura, AutoCrystal, AutoTotem, HoleFill, Replenish.
- **Injectable** = it can inject into the running JVM, so it is not always a `.jar` in the mods folder. Two detection vectors: (a) the distributed `.jar` (random hash-named, e.g. `hb4zz1xxrd4.jar` — now floored to Review), (b) the **injected** form → that is what `-DeepMemory` (live memory scan) + the process/JVM scan are for. For a screenshare check, run with `-DeepMemory` on the suspect's live Minecraft.
- `doomsdayclient.com` is **blocked by this cloud env's egress proxy**, so no jar/hash could be pulled here. Mirrors seen in search: 9minecraft.net, exloader.net, cyde.xyz — NOT added as cheat download-domains on purpose (they also host legit mods → would cause false Zone.Identifier flags). Only dedicated cheat-vendor domains belong in `downloadDomains`.
- Added `HoleFill` / `AutoHoleFill` to `suspiciousPatterns` (distinctive crystal-PvP term, no legit-mod collision).

## Overall-scan AI (the second model) — newest work
The mod model scores ONE jar. A **session model** now scores the WHOLE scan and learns from it.
- `ml/session_model.py` is the **source of truth** for its 12 weights → exports `ml/session_model.json` → embedded in the `.ps1` as `$script:smWeights` (parity is machine-checked) and auto-updated from GitHub like the mod model.
- Features: flagged/review/unverified/random-name ratios, cheat-site download, hard-confirmed cheat, system issues, JVM injection, BAM-deleted executables, cheat processes, stray jars, cheat folders.
- PS functions: `Get-SessionRaw`, `Get-SessionVector`, `Invoke-SessionModel`, `Get-SessionVerdict`, `Get-SessionVerdictCached`, `Get-SessionLabel`, `Update-SessionModelOnline`, `Write-SessionCard`.
- **Evidence collection** was wired into three places: the mod loop (random names, cheat-site downloads, hard-confirmed), the JVM scan (`$script:Evidence.JvmInject`), and `Run-PCscan` (cheat processes, cheat folders, stray jars). BAM comes from `$script:BamDeleted`.
- **Ordering fix:** `Send-ScanResult` used to run BEFORE the deep/PC/BAM scans, so the team dashboard never saw that evidence. It now runs at the very end, after every stage — together with the overall verdict card and the session learning step.
- **Auto-labelling:** only unambiguous scans teach it (hard-confirmed / JVM injection / cheat process → 1; all-verified, issue-free scan → 0; everything else → no learning). That is what keeps it from drifting.
- **Federated:** the scan payload carries `sessionSample` + `session`; `server.js` and `worker.js` both train a shared session model and serve it at **`/api/smodel`**, which clients pull each run.
- Persisted in `learned.json` as `sweights` / `sintercept` / `ssamples` / `sessionModelVersion`.

Proven: `ml/test_session.py` 20/20; live backend test learned a novel whole-scan pattern **13% → 39%** across 30 scans from 3 simulated team members while clean scans stayed Clean (3%) and hard-confirmed stayed Confirmed (86%). `-SelfTest` is now **13 cases** (8 mod + 5 whole-scan) and all 5 new ones were verified against the PS-embedded weights.

## Also changed
- **The tool no longer opens anything on your PC.** `New-HtmlReport` used to call `Invoke-Item` (opening the report in your default app) and `Start-Process explorer.exe /select` (popping a file-explorer window). Both removed — it just prints the path now. Better for trust and it stops the window spam at the end of a scan.

## Injected ghost clients + deletion evidence (session model v2)
- **Memory scan rewritten** (`Run-JVMScan`): findings are deduped and structured instead of one flat string per region. Each reports **which** hack (a named *client* from `$script:distinctiveClientTokens` - so `signatures.json` extends the memory scan too) vs a *module* (what it is doing: autocrystal, killaura, holefill...), **where** (process, PID, memory address) and **how many hits** (1 hit could be chat text, dozens means loaded code). One compiled regex alternation replaces ~70 IndexOf passes per region.
- `-DeepMemory` **turns itself on when Minecraft is running** (`$script:MemoryAuto`), announced openly in the transparency notice. That is the only way to see an injected client.
- **Session model -> v2 (15 features)**: added `deleted_jars`, `mc_running`, `mem_client`; `bam_deleted` lowered 1.5 -> 1.0 to avoid double counting. New hard rules: a named client in live memory -> **>=85 Confirmed**; `.jar`s deleted **while Minecraft still runs** -> **>=60 Likely** (the wipe-before-the-screenshare pattern). Same deletions with the game closed stay Clean - people update mods.
- `mc_running` deliberately has weight **0.0**: the game being open is not evidence of anything, it only gates the deletion rule.
- Auto-labelling: `mem_client` counts as a cheat label; deleted jars alone still teach nothing.

## v5 — the tool decides everything itself
- **No prompts left.** The deep-scan question and "Press Enter to exit" are gone, so the result is written to the HTML report AND `%APPDATA%\AsyncAnalyzer\last-scan.txt` - without that a double-click run would show nothing.
- **Targets = every OPEN instance**, plus `scanPaths` (signatures.json, team-wide) and `%APPDATA%\AsyncAnalyzer\paths.txt` (local). Jars from all targets go into the same `$jarFiles`, so the per-jar loop needed no change.
- **Depth is automatic**: game running -> full check; otherwise quick, and `Request-DeepEscalation` switches to deep the moment the mod pass finds anything. Escalation widens the SEARCH only - it never moves a scoring threshold, or false flags would follow.
- **Self-elevation** via UAC (`-NoElevate` opts out; the elevated run always gets `-NoElevate` so it cannot loop). The one-liner has no local file, so the elevated process re-fetches the script - that is stated in the notice, not done quietly.
- **`$script:ScanGaps`** records everything that could not be checked (no admin, game closed, idle installs skipped, memory budget hit, unreadable folder) and prints it with the verdict.
- Mirrored + pinned in `ml/test_autoscan.py` (16 cases), including that escalation changes only search breadth.

## Benchmarks & CI (public, continuous)
- `ml/benchmark.py` -> generates `BENCHMARKS.md`. **Never hand-edit that file**; regenerate it.
- `.github/workflows/benchmark.yml` runs on every push to main, every PR, and weekly. It runs all six suites, checks the weights embedded in the `.ps1` still equal `ml/model.json` + `ml/session_model.json`, runs the benchmark, publishes it to the run summary, and commits a refreshed `BENCHMARKS.md` on main (`[skip ci]` so it cannot loop).
- **Regression gates fail the build**: no real library flagged by a cheat rule; aim + dropper always detected; detection independent of hiding depth.
- Corpus: `ml/fetch_jars.py` pulls **122** real libraries from Maven Central (cached in CI). Chosen to be hard: LWJGL (Minecraft's own input/GL library), AspectJ + OpenTelemetry (real Java agents), JNA, Spring, BouncyCastle.
- Two results are reported honestly instead of tuned away: 11 libraries match the Java-agent rule (correct - they really are agents; the rule is scoped to a jar in a mods folder), and ESP is left undetected on purpose (identical behaviour to a mob-radar minimap).
- To add data: extend the `LIBS` list in `fetch_jars.py` (clean side) or `ml/corpus_src/` (behaviour side), then rerun the benchmark.

## Open items / TODO
- [ ] **Real cheat hashes** (the one thing the cloud can't do): `$script:knownCheatHashes` / `ml/signatures.json` `knownCheatHashes` are empty. On a PC that actually has Doomsday/Ghost/Vape, run the tool with **`-Share`** (exports confirmed cheat SHA1s locally) or paste the SHA1 into `signatures.json` → instant 100% detection for the whole team. The tool already detects Doomsday without a hash (random-name → Review, package path / cheat site → Confirmed); the hash just makes it instant + certain.
- [ ] **Live Windows test** - THE open item. Shamiro decided: run `-SelfTest` (expect **26/26**) and one real scan BEFORE merging PR #2. Nothing has ever run in real PowerShell.
- [ ] Merge branch → main to ship.
- [ ] Optional: Discord webhook on flagged scan; dashboard login; more 2025/2026 cheat families.

## Recent detection improvement (this session) — Doomsday / ghost / random-named jars
The trigger: a real scan showed `hb4zz1xxrd4.jar` (a Doomsday download) as `? Source: unknown` — it scored < 30 and fell into the silent "Unknown" pile. `random_name`'s model weight is 0.0, and there was no floor. Fixed with **zero new false-flag risk**:

1. **`Get-ModVerdict` random-name floor** (`AsyncAnalyzer.ps1`, just before the verified-cap block): an **unverified** jar with a random / hash-style filename is floored to **Review** (35; 55 if it also has obfuscation / capability corroboration). It is **never** floored into a flag (Likely/Confirmed) by the name alone — real Doomsday still reaches Confirmed only via the existing hard rules (package path ≥80, cheat site ≥75, known hash =100). Verified / legit-modid jars are exempt (they're capped ≤20), so a legitimately hash-renamed known mod is unaffected. `Test-RandomFilename` already classifies `hb4zz1xxrd4` as random (0 vowels in the alpha run).
2. **`ml/signatures.json` → a real community cheat DB (version 3):** more `packagePaths` (`net/wurstclient`, `com/gamesense`, `org/rusherhack`, …), more distinctive `clientTokens` (`ghostclient`, `moonlightclient`, `entropyclient`, … — all compound, never bare words), and a **new `downloadDomains`** array (`doomsdayclient`, `vape.gg`, `wurstclient.net`, …). `downloadDomains` is wired data-driven: the loader merges it into `$script:cheatDomainMap` + `$script:cheatDownloadSources`, and `Get-DownloadSource` consults it — so a team can add a new cheat site with **no script edit**, and it propagates via auto-update.
3. **2 new `-SelfTest` cases** (now 8 total): "random-named jar, unverified → Review" and "random-named jar but verified → Clean".

Verified here (no Windows): `ml/test_verdict.py` 44/44 (incl. the two random-name cases + all 37 real libs still Clean), `ml/test_selflearn.py` 4/4, brace/here-string balance identical to HEAD, and a Python mirror of `Test-RandomFilename` catches `hb4zz1xxrd4.jar` + 4 other hash-names while giving **0 false positives** on 20 real mod filenames. Still to do on Windows: run `-SelfTest` (expect 8/8) and a real scan.
