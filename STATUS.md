# AsyncAnalyzer — STATUS / Handoff

> Handoff doc so Claude Code on Shamiro's PC (or anyone) can continue seamlessly.
> Last updated by the cloud session. Read this first.

## What this is
A Minecraft mod cheat scanner (Windows PowerShell, one-liner distributed) with a **local, self-improving AI** (logistic-regression model that runs in pure PowerShell — no cloud, no deps), a **team mode** (shared scan-history dashboard + **federated model** that learns from everyone's scans), and a **web dashboard backend**.

## Repo & branch
- Repo: `QDHShamiro/AsyncAnalyzer`
- **Everything is on `main`.** The one-liner points at `main`, so every push ships
  immediately to everyone who runs it. There is no staging branch - that is why the
  checks below are not optional.
- To continue locally:
  ```bash
  git fetch origin main && git checkout main && git pull
  ```

## Run / verify (Windows)
```powershell
# normal scan (auto-detects Minecraft by itself now)
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1')"

# verify the AI + verdict logic in 5 seconds (do this after any change)
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'))) -SelfTest"
```
Flags: `-Ask` (manual path), `-Path "C:\...\mods"`, `-DeepScan`, `-DeepMemory`, `-Code <word>`, `-SelfTest`, `-NoUpdate`, `-NoLearn`, `-Reset`, `-Share`.

## Editing the script
`AsyncAnalyzer.ps1` is **assembled** from `src/*.ps1` by `python3 build.py`. Edit the section files, not the shipped one - a build overwrites it, and CI fails on `build.py --check` if the two drift. The build is a plain ordered concatenation (PowerShell runs top to bottom and the file is full of order-dependent top-level code), which is what let the split be proven: the first build was byte-for-byte identical to the file that had been shipping. See `src/README.md` for the section map.

## File map
- `AsyncAnalyzer.ps1` (~5847 lines, **generated** - edit `src/`) — the whole tool. Key sections:
  - Data lists (cheat strings / weak strings / package paths / legit modids / client tokens) ~line 30–470.
  - Embedded AI model (`$script:mlWeights`, `$script:mlIntercept`, v2) + `Invoke-MlModel`, `Get-JarFeatures`, `Get-ModFeatureVector`, `Get-ModVerdict`, `Write-VerdictCard` ~line 480–850.
  - Self-improvement: `Load/Save-LearnState`, `Update-ModelOnline` (SGD), `Invoke-CloudUpdate`, `Get-MinecraftName`, `Send-ScanResult` ~line 850–1000.
  - `Find-MinecraftModFolders` + **`Get-ScanTargets`** (autonomous target choice: every OPEN instance + configured paths). `Get-BestModFolder`/`Ask-YesNo` are now unreachable leftovers.
  - Autonomy: `Invoke-SelfElevate`, `Set-AutoDepth`, `Request-DeepEscalation`, `Add-ScanGap`/`Write-ScanGaps`, `Save-ScanSummary`.
  - Main scan loop (verify → features → verdict → learn) inside `if (-not $SkipModCheck)`.
  - `New-HtmlReport` (the screenshare evidence document), `Add-Finding` + the `Write-SystemFlag`/`Write-Detail` hook that feeds it, `Run-SystemChecks`, `Run-PCscan`, `Run-BamScan`, `Run-JVMScan`.
- `ml/` — the AI pipeline (Python, offline):
  - `features.py` (22-feature schema, MUST match the PS extractor), `build_dataset.py` (downloads 36 real libs + synthesises profiles), `train_model.py` (logreg → `model.json` + `model_ps_snippet.txt`), `online_learn.py` (SGD, matches PS), `verdict.py` (reference port), `signatures.json` (community/cheat DB, auto-downloaded by the tool), tests: `test_verdict.py` (194), `test_bytecode.py` (263), `test_session.py` (40), `test_memory.py` (9), `test_autoscan.py` (23), `test_report.py` (46), `test_macro.py` (42, autoclicker/macro classification + PS parity), `test_logscan.py` (29, log evidence + pre-filter + PS parity), `test_instscan.py` (31, launcher profiles / packs / config folders + PS parity), `test_selftest_cases.py` (38, runs the PS self-test cases through the Python port), `test_selflearn.py` (self-learning proof).
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

Proven: `ml/test_session.py` 27/27; live backend test learned a novel whole-scan pattern **13% → 39%** across 30 scans from 3 simulated team members while clean scans stayed Clean (3%) and hard-confirmed stayed Confirmed (86%). `-SelfTest` is now **42 cases** (23 mod + 8 whole-scan + 11 report) and every new one was verified against the PS-embedded weights.

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
- **Self-elevation** via UAC (`-NoElevate` opts out; the elevated run always gets `-NoElevate` so it cannot loop). The one-liner has no local file, so the running script writes its own text to a temp copy and elevates that: `Get-SelfSource` takes the text from the call stack (`GetFullScript`), the only place that still holds it under `iex` - `$MyInvocation` inside a function is the function, which is why the elevated window used to close at once. The copy runs in the same engine with `-NoExit` (a new window must keep its output) and `-EncodedCommand` (a `-Path` with a space survives), and deletes itself before the first check.
- **`$script:ScanGaps`** records everything that could not be checked (no admin, game closed, idle installs skipped, memory budget hit, unreadable folder) and prints it with the verdict.
- Mirrored + pinned in `ml/test_autoscan.py` (16 cases), including that escalation changes only search breadth.

## 1.8.9 / 1.12 names — the biggest gap there was
The behaviour tables only ever knew 1.13+ Mojang, Yarn and intermediary names.
**1.8.9 is where most Minecraft PvP cheating happens** (Lunar, Badlion), and a
1.8.9 killaura calls none of them: `C03PacketPlayer`, `rotationYaw`,
`PlayerControllerMP.attackEntity`. All twelve rules were blind to it.
- MCP names for 1.7.10-1.12.2 added to `BEHAVIOUR`, `_REFLECTIVE_API`, `_MIXIN_API`
  and `_PREFILTER`; the PowerShell tables are regenerated FROM `ml/bytecode.py` so
  they cannot drift, and parity is machine-checked.
- **Measured before shipping**: 0 of 179 real libraries gained even a single
  signal, let alone tripped a rule. These names are Minecraft-specific enough that
  no general Java library touches them.
- Corpus: `mc/MC18.java` stub plus a compiled 1.8.9 aura, flight, minimap and
  sprint mod, with their own benchmark section and gate.
- The new **pre-filter reachability check** in `test_bytecode.py` immediately found
  three patterns (`swingHand`, `method_6104`, `getLoadedEntityList`) named in a
  behaviour rule but missing from the pre-filter — so a class whose only Minecraft
  reference was one of them was never parsed and the rule silently did nothing.

## Bypassing the symbol table — the three holes, all closed
The behaviour rules read each class's **constant pool symbol table**: to call a
Minecraft method you must name it there. Twice now that turned out to be avoidable,
and both times the fix was the same shape — read the vocabulary out of the string
constants too, under a gate narrow enough that ordinary code cannot trip it.

1. **Reflection.** `Class.forName("net.minecraft…")` + `getDeclaredMethod("setYRot")`
   moves every API name into strings. Measured before the fix: an aim cheat rewritten
   that way scored **Clean 3/100** — one refactor, all twelve rules blind. Gate: the
   class must actually reflect. Reported as *hiding*, because no ordinary mod does it.
2. **Mixins** (`$script:bcMixinApi`, `$script:bcMixinPacketApi`, `$script:bcMixinArea`).
   A mixin does not call the game — the loader compiles it *into* a game class, and the
   target is an **annotation value**: a string. Silent rotations mix into
   `ServerboundMovePlayerPacket`, shadow `yRot` and overwrite it; through the symbol
   table that class calls nothing. Gate: the class must be a mixin. **Not** reported as
   hiding — every Fabric mod is mixins. The bare shadow-field names (`yRot`/`xRot`) are
   narrower still: they only count for a mixin that targets an outgoing **move packet**,
   because a camera or freelook mod shadows the same fields and mixes into the *player*.
   `ml/corpus_src/clean/MixinFreelook.java` exists purely to fail if that stops holding.
   `*.mixins.json` is read as well: a jar declaring mixins the reader could not parse is
   recorded as a **coverage gap**, not reported clean.

3. **Class transformers** (`bc_transformer` -> `bc_coretarget`). A Forge coremod or
   a LaunchWrapper tweaker is handed every class name the game loads and decides
   what to rewrite by COMPARING it against string constants. Calls nothing. Gate:
   the class must implement the transformer API. Never the finding — OptiFine is a
   tweaker — so it is scope, and what it rewrites is what is read. `MANIFEST.MF`
   (`FMLCorePlugin`, `TweakClass`), `META-INF/coremods.json` and
   `accesstransformer.cfg` are read as scope too.

Measured after all three: **0 false flags on 179 real libraries**, all mixin cheat variants
caught, all 11 legit mixin variants clean. Parity between `ml/bytecode.py` and the four
PowerShell tables is machine-checked in `test_bytecode.py` — a silent drift there
reopens the hole.

## Session model v3 - the behaviour rules finally reach the whole-scan verdict
**The bug this fixes was real and quiet.** The whole-scan model saw the behaviour
rules only through `flagged_ratio`, and a big modpack divides that away. Measured:
a 100-mod pack containing ONE behaviour-confirmed aimbot scored **3/100, Clean**;
the same jar recognised by hash scored 85. Backwards - the behaviour reading is the
stronger of the two, because a hash breaks when one byte changes.

- `Get-ModVerdict` now returns `BehaviourScore` (the highest score any behaviour
  rule set, tracked in `$bhv` alongside `$score`) and `HiddenApi`. The mod loop
  turns those into `$script:Evidence.BehaviourCheat` / `.BehaviourLikely` /
  `.HiddenApi`, counted only where the finding actually stands (a verified mod is
  capped safe, so its behaviour is part of the mod's own function).
- Session model **v2 -> v3, 15 -> 20 features**: `behaviour_cheat` (4.5, same as a
  hash match), `behaviour_likely` (2.0), `server_rule` (0.8), `hidden_api` (0.8),
  `macro_cheat` (4.5). Hard rules: behaviour-confirmed >=85, behaviour-likely >=60,
  server-rule floored to Review (30) - a rule question needs a person and nothing more.
- `$script:smModelVersion = 3` means a stored v2 `learned.json` is discarded on
  load (the check was already there), so existing users get the new prior rather
  than a 15-weight model against a 20-feature order.
- `server.js` and `worker.js` now **reset a stored model whose version is older
  than the shipped base**. Without it a deployed backend keeps training the old
  15-feature model forever and the new features are dead for the whole team.

**The invariant that came out of this, now enforced by `test_session.py`:** every
raw signal that can auto-label a scan as a CHEAT must also be a model FEATURE.
`label_for` decides what the model trains on; teaching it from evidence the vector
cannot see pushes the INTERCEPT instead of a weight, so every later scan starts
closer to "cheat". The macro signals did exactly that when they went in as hard
rules only. Three checks now guard it: the invariant, that the PS
`Get-SessionVector` covers every feature (a missing key multiplies by `$null` = 0,
silently), and that the PS feature ORDER equals the Python one.

## Alternative clients (Lunar / Badlion / Feather / LabyMod)
- The three clients' mods folders were already looked up by EXACT path, which works
  until one of them moves. LabyMod has no mods folder at all - its extensions are
  jars in `addons/` - so a cheat as a LabyMod addon was never opened.
- `Get-AltClientRoots` + `Find-AltClientModDirs` (`src/80-discovery.ps1`): each
  client root is walked to depth 4 and every directory literally named `mods` or
  `addons` is taken. Survives a version bump by construction.
- Those folders are **always** scan targets (`AltClient=$true`), open or not: a
  handful of jars, and exactly where one gets parked when `.minecraft` is watched.
  They are excluded from `$plain`, so they are neither the "most likely install"
  guess nor counted as a skipped one - reporting a folder as unchecked while
  checking it is the one thing the coverage box cannot survive.
- **Deliberately NOT collected: the jars a client ships itself.** Lunar's own client
  jars render entities and read the entity list (nametags, waypoints), so treating
  them as mods would put a SERVER-RULE finding on every Lunar user's report. The
  walker only takes mods/ and addons/, which those are not in. Pinned in
  `ml/test_autoscan.py`.
- Client installed but no mods/addons folder found -> `Add-ScanGap`. A format that
  cannot be read is not a clean result.

## The rest of the .minecraft folder (not mods/)
- `ml/instscan.py` is the source of truth; `$script:instKnownMain`, `instJavaAgent`,
  `instMainClass`, `instTweakClass`, `instPackExec` in `src/10-signatures.ps1` are
  generated from it, parity-checked by `ml/test_instscan.py` (31).
  `Test-CheatName` / `Test-CheatConfigDir` / `Run-InstanceScan` / `Show-InstanceScan`
  in `src/94-pcscan.ps1`, run on every scan.
- Four things, all structural: `versions/<v>/<v>.json` mainClass + `--tweakClass`
  (an injected client installs itself as a custom version profile), `-javaagent:`
  in a launcher profile, `.class`/`.jar` inside a resource or shader pack, and a
  `config/<name>` folder named after a known client.
- **Config folders match EXACTLY on the normalised name, not as a substring.** The
  test file carries `doomsday-realms-datapack-helper`, which a boundary match reads
  as the Doomsday client because doomsday is also an English word - it caught that
  on the first run. A config folder is named after the client and nothing else.
- Session model **v4 -> v5**: `instance_cheat` (5.0, hard rule >=85, auto-labels).
  `instance_agent` is raw-only at >=60 and does NOT auto-label - it is the one
  entry here with an innocent reading (a profiler, a dev setup), so it goes to a
  person with the path rather than being called proof. That split is exactly what
  the "every cheat-label signal must be a feature" invariant allows.
- The transparency notice now lists what is read inside Minecraft, because "only
  scans your mods folder" stopped being true.

## Game logs and crash reports (the evidence that outlives the jar)
- `ml/logscan.py` is the source of truth; `$script:logChatLine` / `logCodeContext`
  in `src/10-signatures.ps1` are generated from it and parity-checked by
  `ml/test_logscan.py`. `Test-LogLine` / `Read-LogText` / `Run-LogScan` /
  `Show-LogScan` live in `src/94-pcscan.ps1`; it runs on EVERY scan.
- Reads `logs/latest.log`, `logs/*.log.gz` (gzip, decompressed) and
  `crash-reports/*.txt` for every instance folder that was scanned, newest 25 files,
  4 MB each (tail only for a huge log).
- **The trap, and the reason this needed care: latest.log contains the chat.**
  Someone typing "killaura" at another player writes that word into the log. A
  scanner matching module names there accuses people for what they SAID, and it
  looks like hard evidence because it is timestamped. So module names are never
  matched, chat lines are dropped first, and only two things count: a cheat
  vendor's Java PACKAGE path, or a known client name inside a code context (stack
  frame / classloader / mixin config / jar name) with separator boundaries.
- `test_logscan.py` (21) is mostly negatives on purpose: chat about cheating, a
  staff ban broadcast, a `/report` command, an anticheat MOTD, a chat line that
  spells out a cheat package.
- Session model **v3 -> v4**: new feature `log_cheat` (5.0) + hard rule >=85 +
  auto-label. No logs folder -> `Add-ScanGap`.
- **`Build-LogPreFilter` is what makes this affordable at all.** `Test-LogLine`
  costs ~75 string operations per line (15 package paths in two spellings, ~60
  client tokens); 25 log files of up to 4 MB is on the order of a million lines,
  which in PowerShell is minutes - not a scan anyone can sit through at a
  screenshare. One compiled alternation runs over the whole file first, and a clean
  player's logs contain none of those names, so the per-line pass never runs. Same
  reasoning as `$script:bcPreFilter`. Rebuilt after a signature update (a new client
  name that never enters the pre-filter would be unsearchable, silently), and
  `test_logscan.py` asserts every real hit still survives it.

## Autoclickers / macro files (the half that is not a mod)
- `ml/macro.py` is the source of truth for the patterns; `$script:macroLangs`,
  `$script:macroCheatNames`, `$script:macroDriverPaths` in `src/10-signatures.ps1`
  are **generated from it**, and `ml/test_macro.py` machine-checks that they match.
- `Test-MacroFile` + `Run-MacroScan` (`src/94-pcscan.ps1`) read `.ahk .ahk2 .au3
  .lua .vbs` in Downloads / Desktop / Documents / Temp (+2 sub-levels) and in the
  script folders of G HUB, LGS, Synapse 2+3, iCUE, SteelSeries, Glorious, Bloody.
- Runs on **every** scan, not only the deep one (`Show-MacroScan`, called from
  `99-finish.ps1` before the deep gate). A macro does not need the game to be open,
  so closing Minecraft before the screenshare must not hide it.
- **Three levels, and the difference is evidence, not confidence.** Click loop +
  names Minecraft -> **cheat** (session verdict >=85). Click loop + the FILE named
  after the technique -> **named**, also **>=85**: butterfly-click, blockhit and
  autocrystal are Minecraft words, so the file says what it is. What it does not say
  is which game it was used in - a question for the person reading the report, not a
  reason to score it lower. Click loop, nothing tying it to the game -> **macro**,
  reported and never accused.
- Why `.lua` is safe to scan at all: the rules require the Logitech/Razer driver
  API (`PressMouseButton`, `OnEvent`, `IsMouseButtonPressed`...). Minecraft's own
  Lua (ComputerCraft), Garry's Mod and Roblox share none of that vocabulary.
- The negatives are the load-bearing half of `test_macro.py`: an AHK text expander,
  a window tiler, a single remap, an AutoIt installer script, a ComputerCraft
  turtle, a G HUB lighting profile, and **a recoil script for a shooter** - a real
  click loop in a real mouse driver that is not a Minecraft cheat. 42/42.
- Reaches the whole-scan verdict through **hard rules**, not model features: the 15
  session features are trained and versioned and one cannot be bolted on without
  retraining. `test_session.py` now machine-checks that the hard rules AND the
  auto-label inputs are identical in `src/30-runtime.ps1` and `ml/session_model.py`
  - a rule added on one side only used to be completely invisible.
- **The honest limit, printed on every scan:** a macro burned into a mouse's
  ONBOARD memory (Bloody, A4Tech, onboard Razer/Logitech profiles) runs on the
  device and leaves nothing on the PC. `Add-ScanGap` states it unconditionally.
  What IS visible is that a driver macro store exists and when it last changed.

## Report authenticity: staff code + scan ID
The gap: a report is a file on the PC of the person being checked, so they can edit
it, and no hash inside that same file helps - they control the hash too. Shamiro's
call was to do both of the narrowing options.
- **`-Code <word>`** - the moderator says a word before the scan; it appears in the
  console, the HTML report, the pasteable summary and `last-scan.txt`. A report made
  before that word was chosen cannot carry it, so it DATES the report. It does not
  prove the contents, and the report says that rather than implying otherwise. No
  code given -> the field says so instead of being blank.
- **`$script:ScanId`** - random per run, uploaded with the result. `GET /api/scan/<id>`
  now resolves EITHER the server's row id or the scan ID printed in the report
  (the moderator is reading it off a screen, so it must not need the server's id).
  The dashboard shows and searches both. Tested end to end against `server.js`:
  POST with a scanId, look it up by the printed ID, and an unknown ID 404s.
- Both are stored in `server.js` and `worker.js`; the worker matches the scan ID
  inside the JSON blob, so no schema migration is needed.
- `ml/test_report.py` (58) pins that both reach all four places, that the
  "no code was given" wording exists, that the panel is actually rendered and not
  just assigned, and that the text does not overclaim - the uploaded copy is named
  as the one to trust.

## Baritone, and two bugs it exposed
Shamiro's call was that Baritone counts as a cheat rather than a server-rule
question. It WAS coming out Likely already - but through the **freecam** rule,
because Baritone aims the player and draws its path, which is rotation plus
rendering without a forged packet. Right verdict, wrong reason, in a document a
moderator shows to somebody. `baritone` is now a `distinctiveClientToken` (so the
filename is an identity match) and `baritone/` is a `cheatPackagePath` (so a jar
that ships those classes is flagged for shipping them).

Two real bugs came out of writing the test cases for it:
1. **The behavioural clean cap overrode a filename identity match.** The cap
   exists so obfuscated names and alarming STRINGS cannot push an inventory sorter
   into Review - behaviour beating a text heuristic. A filename matching a known
   cheat client is not a text heuristic, it is identity, the same kind of thing as
   a hash or a package path. Without it in the exclusion list, a file called
   `wurstclient-7.36.jar` that only read the keyboard came out **Clean 20**.
   Fixed in `src/50-analysis.ps1` and `ml/verdict.py`; `test_verdict.py` 194 still
   green, so the guaranteed-clean cases (inventory sorter, reach/CPS display) are
   unaffected.
2. **`ml/test_selftest_cases.py` was silently not reading two field kinds.**
   `FilenameClient` was missing from its flag list and only NUMERIC fields were
   read out of `New-TestFeatures`, so any self-test case using `PackageHits` or
   `FilenameClient` was scored by the mirror as if the field were not there -
   passing or failing for the wrong reason. Both fixed.

## ml/audit.py - the dead-end detector
The failure mode this project keeps producing is a signal that is measured and
never reaches a decision. **Every instance of it looks like success**: nothing
errors, no test fails, the scan just quietly scores lower than every suite says it
should. Three real ones so far - the derived signals missing from `FEATURES`, the
three behaviour tokens missing from the pre-filter, and `macro_cheat` auto-labelling
while not being a model feature. None failed a test; each was found by looking.

So `ml/audit.py` looks, on every build, at the joins where a signal can go missing:
`Evidence field -> Get-SessionRaw -> vector or hard rule -> a band`, every behaviour
category to a rule or a reason, every function to a caller, every mod-model feature
to the extractor that produces it.

**It found two on its first run:**
1. `bc_transformer` was gated on in the bytecode reader and never read by any rule
   or reason. The coremod scope line depended entirely on `FMLCorePlugin` being in
   the manifest - a text field a cheat can simply leave out - so a class transformer
   visible only in the bytecode produced nothing. Now it has its own scope line.
2. **`selfwipe` was not reported, and a comment said it was.** Four behaviour
   categories are parsed on every class to derive it, and the code then printed
   nothing at all; the comment claimed "it is reported rather than tuned". It is a
   reason line now, unscored, which is what the comment promised - and a reason
   without a score cannot cause a false flag because it does not move the band.

One false positive of its own on the first run too (`random_named` reaches the model
through `Get-SessionVector` under another name), which is why it also follows the
one-link chain from a category into a derived signal.

## The token floor - how "vape" was invisible to three of four readers
Four readers use the client-name list: the filename match, the memory scan, the log
reader and the instance reader. The last two (and the log pre-filter) skipped any
name shorter than **5** characters. `vape` is four. So one of the most-used clients
there is was searched for by the filename and memory scans and by nothing else -
no error, no failing test, the name was simply never looked for.

- One named constant now, `$script:tokenFloor` / `logscan.TOKEN_FLOOR`, set to 4,
  and `ml/audit.py` fails the build if any name in the list falls below it.
- The audit also checks the two floors are the same number in both languages, and
  that no client name collides with a known-good mod id - which is the check that
  matters when the TEAM adds a name later, not when I do.
- `test_logscan.py` gained the four-letter case and two negatives for the price of
  a shorter floor: the name inside a longer word (`vaporizer`), and the name in
  chat. Both stay clean, because the boundary rule and the chat filter still run.

**Worth recording how this one was found and nearly missed:** the first patch that
was supposed to lower the floor did not match the indentation in `logscan.py` and
silently replaced nothing. The test then failed - which is the only reason it was
caught - and the fix was to assert on the replacement rather than trust it. That is
the same failure this whole audit exists for, in the tooling around it.

## Benchmarks & CI (public, continuous)
- `ml/benchmark.py` -> generates `BENCHMARKS.md` + appends to `ml/benchmark_history.csv`.
- CI runs eleven suites plus `audit.py` (the dead-end detector).
- **CI owns both generated files.** Run the benchmark locally as much as you like, but do NOT commit the regenerated files - the bot writes them on every push to main, and committing your own copy produces a merge conflict every time (it already did once). If you do hit that conflict: resolve it by regenerating rather than hand-editing, and for the history take the UNION of both sides keyed by commit.
- `.github/workflows/benchmark.yml` runs on every push to main, every PR, and weekly. It runs all seven suites, checks the weights embedded in the `.ps1` still equal `ml/model.json` + `ml/session_model.json`, runs the benchmark, publishes it to the run summary, and commits a refreshed `BENCHMARKS.md` on main (`[skip ci]` so it cannot loop).
- **Regression gates fail the build**: no real library flagged by a cheat rule; aim + dropper always detected; detection independent of hiding depth.
- Corpus: `ml/fetch_jars.py` pulls **177** real libraries from Maven Central (cached in CI). Chosen to be hard: LWJGL (Minecraft's own input/GL library), AspectJ + OpenTelemetry (real Java agents), JNA, Spring, BouncyCastle.
- Two results are reported honestly instead of tuned away: 11 libraries match the Java-agent rule (correct - they really are agents; the rule is scoped to a jar in a mods folder), and ESP is left undetected on purpose (identical behaviour to a mob-radar minimap).
- To add data: extend the `LIBS` list in `fetch_jars.py` (clean side) or `ml/corpus_src/` (behaviour side), then rerun the benchmark.

## Open items / TODO
- [ ] **Real cheat hashes** (the one thing the cloud can't do): `$script:knownCheatHashes` / `ml/signatures.json` `knownCheatHashes` are empty. On a PC that actually has Doomsday/Ghost/Vape, run the tool with **`-Share`** (exports confirmed cheat SHA1s locally) or paste the SHA1 into `signatures.json` → instant 100% detection for the whole team. The tool already detects Doomsday without a hash (random-name → Review, package path / cheat site → Confirmed); the hash just makes it instant + certain.
- [ ] **Live Windows test — THE open item.** Nothing has ever run in real PowerShell.
      Run `-SelfTest` (expect **84/84**), then one real scan with Minecraft running.
      Check specifically: (a) UAC appears and declining it still scans, (b) every open
      instance shows up, (c) "JVM / RUNTIME INJECTION" actually has content, (d)
      `last-scan.txt` is written, (e) the HTML report opens and its Coverage box is
      filled in. The bytecode parser and the repaired memory API have only ever been
      checked statically.
- [ ] **GitHub Pages** — Shamiro has to click it once: Settings → Pages → branch `main`,
      folder `/docs`. The page is already generated and committed.
- [ ] Optional: Discord webhook on flagged scan; dashboard login; more 2025/2026 cheat families.

## Recent detection improvement (this session) — Doomsday / ghost / random-named jars
The trigger: a real scan showed `hb4zz1xxrd4.jar` (a Doomsday download) as `? Source: unknown` — it scored < 30 and fell into the silent "Unknown" pile. `random_name`'s model weight is 0.0, and there was no floor. Fixed with **zero new false-flag risk**:

1. **`Get-ModVerdict` random-name floor** (`AsyncAnalyzer.ps1`, just before the verified-cap block): an **unverified** jar with a random / hash-style filename is floored to **Review** (35; 55 if it also has obfuscation / capability corroboration). It is **never** floored into a flag (Likely/Confirmed) by the name alone — real Doomsday still reaches Confirmed only via the existing hard rules (package path ≥80, cheat site ≥75, known hash =100). Verified / legit-modid jars are exempt (they're capped ≤20), so a legitimately hash-renamed known mod is unaffected. `Test-RandomFilename` already classifies `hb4zz1xxrd4` as random (0 vowels in the alpha run).
2. **`ml/signatures.json` → a real community cheat DB (version 3):** more `packagePaths` (`net/wurstclient`, `com/gamesense`, `org/rusherhack`, …), more distinctive `clientTokens` (`ghostclient`, `moonlightclient`, `entropyclient`, … — all compound, never bare words), and a **new `downloadDomains`** array (`doomsdayclient`, `vape.gg`, `wurstclient.net`, …). `downloadDomains` is wired data-driven: the loader merges it into `$script:cheatDomainMap` + `$script:cheatDownloadSources`, and `Get-DownloadSource` consults it — so a team can add a new cheat site with **no script edit**, and it propagates via auto-update.
3. **2 new `-SelfTest` cases**: "random-named jar, unverified → Review" and "random-named jar but verified → Clean".

Verified here (no Windows): `ml/test_verdict.py` green (incl. the two random-name cases + every real lib still Clean), `ml/test_selflearn.py` 4/4, brace/here-string balance identical to HEAD, and a Python mirror of `Test-RandomFilename` catches `hb4zz1xxrd4.jar` + 4 other hash-names while giving **0 false positives** on 20 real mod filenames.

## The screenshare report (newest work)
The report used to be a summary. It is now the **document a staff member acts on**,
because that is who actually reads it - during the screenshare, with the suspect
watching, after the console has already closed.

- **The overall-scan verdict is the headline.** Before, the banner showed a *mod-count*
  verdict ("Clean - no cheats detected") while the whole-scan AI further down could say
  "LIKELY CHEATING" off a live memory hit. Two different answers on one page; the wrong
  one was on top. Now there is one verdict and it is the session verdict.
- **Coverage is a section, not a footnote.** What was checked, and beside it *what could
  not be checked*, from `$script:ScanGaps`. If anything is missing and the verdict is
  Clean or Review, that is said directly under the headline. A clean result only covers
  what it lists, and the page has to say so where it cannot be skipped.
- **Every finding carries its reasoning.** `Add-Finding` collects level, area, the exact
  items (paths, PIDs, hashes, memory addresses) and the WHAT/WHY/HOW/FIX text.
  `Write-SystemFlag` and `Write-Detail` were hooked instead of editing ~12 call sites,
  so every system check records itself with no chance of one being forgotten. The PC
  scan, JVM scan, service check and BAM scan record theirs explicitly.
- **Checks that passed are kept**, collapsed - they are the proof of what was looked at.
- **The score scale draws the real band edges** (30/60/85). `ml/test_report.py` fails the
  build if those ever stop matching `Get-SessionVerdict`/`Get-ModVerdict` - a scale that
  misplaces its own thresholds is worse than no scale.
- **Prints to PDF** black-on-white, so it can be attached to a ban appeal, and *Copy
  summary* puts a plain-text version on the clipboard for a ticket.
- `New-HtmlReport` takes an optional output path so `-SelfTest` can render the whole
  thing to a temp file and check it - the report is no longer the untested part.

Two bugs found while doing this, both only visible on Windows:
- `@($undefined)` in PowerShell is a **one-element array containing `$null`**, not an
  empty one. Every list the report iterates is now filtered, or an unset list would have
  produced phantom rows in the file inventory.
- `Write-SystemFlag` printed its evidence items via loose `foreach` loops at each call
  site, so none of them reached the report. Items are now passed to the flag itself.
