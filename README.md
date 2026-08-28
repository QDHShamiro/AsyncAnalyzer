<div align="center">

# 🛡️ AsyncAnalyzer

### The screenshare tool that shows its working

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](#-requirements)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white)](#-requirements)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Benchmark](https://github.com/QDHShamiro/AsyncAnalyzer/actions/workflows/benchmark.yml/badge.svg)](https://github.com/QDHShamiro/AsyncAnalyzer/actions/workflows/benchmark.yml)
[![Real libraries](https://img.shields.io/badge/false%20flags-0%20of%20186%20real%20libraries-brightgreen)](BENCHMARKS.md)

**One command on the suspect's PC. You get a report that names what was found, why
it counts, and — just as importantly — what could not be checked.**

</div>

---

> **This README is written for the person running the screenshare.**
> If you are here to work on the code, jump to [For developers](#-for-developers).

## ⚡ Run it

Have them paste this into PowerShell. No download, no install, nothing to configure.

```powershell
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1')"
```

It finds the Minecraft installations itself, decides how deep to look, and asks
nothing. It will ask Windows for Administrator once — **let it**, because without
that it cannot read which programs ran and were then deleted, which is one of the
strongest things it can tell you. Declining still runs the scan; the report then
says that part is missing.

**Do this before they close the game.** A ghost client lives in the running
process. Once Minecraft is closed, that evidence is gone and no tool gets it back.

When it finishes:

| | |
|---|---|
| `%TEMP%\AsyncAnalyzer_Report.html` | the full report — open this |
| `%APPDATA%\AsyncAnalyzer\last-scan.txt` | plain-text summary, if the window closed |

---

## 📄 Reading the report

It is ordered the way the question actually gets answered.

**1 — The verdict, in words.** One answer for the whole scan: mods, system, running
processes, live game memory and execution history judged together. The score sits on
a scale that draws the real decision thresholds, so you can see how far into a band
it fell instead of trusting a number.

**2 — What it rests on.** Every reason, numbered. Read these before you say anything
to the player.

**3 — Coverage.** What was checked, and beside it **what could not be**. This is
part of the result, not a disclaimer. A clean verdict from a scan that ran without
Administrator and with the game closed covers far less than one that had both — and
when that happens it says so directly under the headline.

**4 — Scan record.** Time (local and UTC), PC name, Windows user, whether it ran as
admin, whether Minecraft was running, which folders were scanned, a report ID.

**5 — Every finding**, with the exact paths, hashes, process IDs and memory
addresses, plus what the check does and why it matters.

**6 — The full file list**, searchable.

*Copy summary* puts a plain-text version on your clipboard for a ticket. **Ctrl+P**
gives a clean black-on-white PDF you can attach to a ban appeal.

---

## 🎯 What each verdict means

| Band | Score | What you can say |
|:--|:--:|:--|
| ✅ **Verified** | — | Hash matches a real published release on Modrinth/CurseForge. **Never flagged**, by any rule. |
| 🟢 **Clean** | 0–29 | Nothing cheat-like in what was checked. |
| 🟡 **Review** | 30–59 | Something does not fit. **Not proof.** Look at it and decide. |
| 🟣 **Server rule** | 30–59 | Recognised for certain — but whether it is *allowed* is your rulebook, not a technical question. **Never proof of cheating.** |
| 🟠 **Likely** | 60–84 | Strong signs. Every point needs an answer before you close it. |
| 🔴 **Confirmed** | 85–100 | A hard rule matched: a known cheat hash, a cheat-client package path, a cheat download source, or a client found live in the game's memory. |

**Server rule** exists because two very different things used to both say "Review",
and you could not tell them apart: *we are not sure what this is* versus *we are sure
what this is, and your rules decide*. A schematic printer and a mob-radar minimap are
the second kind. It can never be raised into an accusation — but if the same jar
**also** forges movement packets, that finding stands and it is not a printer any more.

### What a finding is not

- **It is not a ban on its own.** It tells you what the code does. Whether that is
  against your rules is your call, and the report is written so you can make it.
- **A clean result is not innocence.** It covers what was checked. Read the coverage
  box — that is why it is there.
- **ESP is not detected.** An ESP and a mob-radar minimap perform the same operations,
  and the bytecode does not contain what separates them. It is surfaced as a server-rule
  finding rather than accused. That costs detection on purpose.
- **This is not an anticheat.** It looks at one PC at one moment. It cannot see what
  someone did on your server.

---

## 🔒 What it does to their PC

You are asking someone to run a script on their machine. They are entitled to a
straight answer, and so are you:

- **It only reads.** No file is modified, moved, renamed or deleted. Nothing is
  installed and nothing is left running.
- **Nothing leaves the machine.** The analysis is local. Team upload exists but is
  off unless your team turns it on, and it sends *results* — never their files.
- **It opens nothing.** No windows pop up, no file explorer, no browser. It prints
  where the report is and stops.
- **They can read it first.** The whole scanner is one PowerShell file. Open the raw
  URL in a browser and read it top to bottom before running it.
- **It says what it could not check**, instead of implying it checked everything.

---

## 🤝 Found a cheat? Add its hash

`ml/signatures.json` currently has **no real cheat hashes**, and that is the single
biggest gap in this tool. One hash turns a cheat into an instant, certain detection
for everyone on your team.

If you have the jar, this takes ten seconds:

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'))) -HashOnly 'C:\path\to\folder'"
```

It hashes the jars in that folder and writes a ready-to-paste block to
`%APPDATA%\AsyncAnalyzer\hashes.txt`. **It does not scan, upload, move or delete
anything, and it does not need the internet** — it only computes SHA1. Send the file
or open a [pull request](https://github.com/QDHShamiro/AsyncAnalyzer/pulls).

> Only add hashes of files you are **certain** are cheats. A pooled hash reaches
> every client on their next run, so a wrong one becomes a team-wide false
> accusation. It is revocable — see `server/README.md` — but it is easier to be
> sure now than to explain later.

The tool already catches Doomsday and friends without a hash, through behaviour and
package paths. The hash just makes it instant and beyond argument.

---
## 🧬 It reads what a mod *does*, not what it says

Scraping strings out of a jar loses to any cheat that encrypts them. So the analyser parses
the **constant pool** of each class — the symbol table. To call a Minecraft method you have
to name it there. You can obfuscate your own class names; you cannot obfuscate the API you
call.

**There was one way around that, and it is closed.** Reach the API *reflectively* —
`Class.forName("net.minecraft…")` plus `getDeclaredMethod("setYRot")` — and every name moves
out of the symbol table into a plain string. Measured before the fix: an aim cheat rewritten
that way scored **Clean, 3/100**. One refactor, all twelve rules blind. String constants are
now checked for the same API names — but only where the class actually reflects, and only for
the handful of APIs a cheat needs. A compatibility shim that reflects on
`Minecraft.getInstance()` to see whether another mod is installed stays clean; one that
reflectively assembles a movement packet does not. The report also says when an API was
hidden this way, because no ordinary mod has a reason to.

**1.8.9 was a hole of a different kind, and it was the biggest one.** The behaviour tables
were written against 1.13+ Mojang, Yarn and intermediary names. **1.8.9 is where most
Minecraft PvP cheating happens** — it's what Lunar and Badlion players run — and a 1.8.9
killaura calls *none* of those names. It sends a `C03PacketPlayer`, writes `rotationYaw`,
and asks `PlayerControllerMP` to attack. Against the tables as they were, that class matched
nothing at all: **every one of the twelve rules was blind to it.** The MCP names for 1.7.10
through 1.12.2 are in now, measured at **zero new signals across all 179 real libraries** —
they are Minecraft-specific enough that no general Java library touches them — and the
corpus carries a compiled 1.8.9 aura, a 1.8.9 flight, a 1.8.9 minimap and a 1.8.9 sprint mod
so the line is drawn in that dialect too.

**Mixins were the second way around it, and that is closed too.** A Mixin is not a mod
calling Minecraft — the loader compiles it *into* a Minecraft class, and it names its target
in an **annotation** (`@Mixin(targets = "net.minecraft…")`, `@Inject(method = "aiStep")`)
rather than calling it. Annotation values are string constants, and everything the mixin
touches inside the target it reaches through `@Shadow` members declared on *itself*. So the
target never enters the symbol table. Worked example, and the reason this exists: **silent
rotations** — mix into `ServerboundMovePlayerPacket`, shadow its `yRot` field, overwrite it
in the constructor. Your view never turns; the server is told it did. Read through the
symbol table, that class is two floats and no Minecraft at all.

So mixin annotations are read too, and the target is written into the report — *what* the mod
compiles itself into: player movement, the network handler, rendering, menus. The technique
itself is **never** the finding: Sodium, Lithium and the Fabric API are nothing but mixins.
The **target** is. That distinction is measured, not asserted — the corpus carries a freelook
mod that shadows exactly the same rotation fields the cheat does, and it stays Clean, because
a camera mixes into the *player* and a cheat into the *packet that reports your aim*. And
`*.mixins.json` is read as well: a jar that declares mixins whose classes could not be parsed
is listed as a **gap in coverage**, not reported as clean.

**And the third door: class transformers.** A Forge **coremod** or a LaunchWrapper
**tweaker** is handed every class name the game loads and decides what to rewrite by
*comparing that name against string constants*. It calls nothing, so the symbol table sees
an empty class — the same shape as reflection and Mixin, one more door. Those strings are
read now. Installing a transformer is never the finding (OptiFine is a tweaker, half of
Forge is coremods); it is recorded as **scope**, and what it rewrites is what's read.
`META-INF/coremods.json` and `accesstransformer.cfg` are read the same way — as scope,
listed, never scored.

That gives behaviour instead of text:

| behaviour | meaning | verdict |
|---|---|---|
| writes a rotation **and** forges its own movement packet | the aim/killaura fingerprint — no legit mod fakes its own movement | 🔴 **Confirmed** |
| decrypts data **then** defines a class from it | loader / dropper | 🔴 **Confirmed** |
| ships Java-agent hooks | can rewrite game code while it runs | 🟠 **Likely** |
| mixes into the outgoing move packet **and** names its rotation fields | silent rotations — rewriting what the server is told you are aiming at | 🔴 **Confirmed** |
| mixes into the player or the renderer | how every ordinary Fabric mod is built | ⚪ recorded as scope, **never** a finding |
| a class transformer that rewrites the player to spoof the rotation it reports | a coremod cheat — the target is a string it compares against, never a call | 🔴 **Confirmed** |
| a class transformer, an access transformer, a coremod script | how half of Forge works | ⚪ recorded as scope, **never** a finding |
| renders **and** sweeps every entity | ESP… **or** a mob-radar minimap | 🟡 **Review**, never an accusation |

That last row is the honest part. **ESP and a mob radar genuinely do the same thing** — the
information that separates them isn't in the bytecode, and no amount of AI recovers it. So
an unverified mod doing it gets surfaced for a human look; a *verified* minimap stays Clean.

**Speed.** Fully parsing every class is not affordable — a 200-mod pack is ~44 000 classes.
But *sampling* is worse than slow, it's wrong: a cheat whose aura module sits at class #150
is invisible to a 40-class sample, and real jars run to a **median of 218 classes**. So every
class gets a cheap native scan and only matches get parsed properly. Detection is
**depth-independent** (pinned by a regression test), and verified mods are skipped entirely
since they're capped safe anyway — so a normal scan only pays for the unverified remainder.

> Measured on 239 samples of real compiled bytecode (77 real Maven libraries as the clean
> side): **precision 1.000, 0 false flags**, recall 0.875 — where every miss is that
> ambiguous ESP/radar class. Full numbers and limits in [`ml/BAKEOFF.md`](ml/BAKEOFF.md).

**Does a bigger AI help?** I tested it properly: logistic regression vs. a neural network
vs. gradient-boosted trees, 5-fold cross-validation. **All three scored identically.** The
behavioural features do the work, not the model — so the simple one ships. Claiming a neural
net here would be marketing, not engineering.

### 👻 Injected ghost clients — what it actually tells you

Doomsday and friends inject themselves into the **running game**, so the jar may already
be deleted. When Minecraft is running the live-memory check turns on by itself and reports
three things, not just "something found":

```
◉ INJECTED CHEAT CLIENT: doomsday
    identified live in javaw.exe (PID 8124) at 0x1F4A0000, 37 hit(s). This IS a cheat
    and it is loaded in the running game right now — it is not in the mods folder at all.
◉ Cheat module active in memory: autocrystal
    found in javaw.exe (PID 8124) at 0x1F51C000, 12 hit(s). A cheat feature is live in the game.
```

- **Which hack** — a named client (from the same community list in `signatures.json`, so
  adding a client there teaches the memory scan too) vs. a **module** that tells you what
  it's doing (`autocrystal`, `killaura`, `holefill`…).
- **Where** — process, PID and memory address, plus how many hits (1 hit could be chat
  text; dozens means loaded code).
- **Whether it's a cheat** — a named client in the live heap sets the overall verdict to
  **Confirmed**, because the cheat is running *right now*.
- **Whether it was injected** — the tool also knows every Java package that exists in a jar
  on your disk. If a cheat is live in memory and **no file on disk contains it**, it was
  injected straight into the running game. That's the whole point of a ghost client, and it
  means *deleting files before the check cannot hide it*. That stronger claim is gated: it
  needs a distinctive name **and** repeated hits, so a stray chat message never triggers it.

The sweep walks the game's whole address space rather than a token sample, bounded by a
**time budget** (120 s, or 600 s with `-Deep`) so the cost stays predictable whether the
game took 2 GB or 12 GB.

**Deleted it right before the screenshare?** If `.jar` files ran on this PC and are now
gone **while Minecraft is still open**, the overall verdict goes to at least **Likely** —
the classic wipe-before-the-check pattern. If the game isn't running, the same deletions
stay **Clean**; people update mods all the time.

### 🌙 Lunar, Badlion, Feather, LabyMod — the other Minecraft on the PC

Their mods folders were already looked up by exact path, which works right up until one
of them moves. **LabyMod doesn't have a mods folder at all** — its extensions are jars in
`addons/`, so a cheat shipped as a LabyMod addon was simply never opened.

Now each client's *root* is walked to a bounded depth and every directory literally named
`mods` or `addons` is taken, which survives a version bump by construction. Those folders
are **always scanned**, open or not: they hold a handful of jars rather than a modpack, and
they are exactly where a jar gets parked when `.minecraft` is the folder being watched.

What is deliberately *not* taken is the jars a client ships itself. Lunar's own client jars
render entities and read the entity list — that's what nametags and waypoints are — so
treating them as mods would put a **SERVER-REGEL** finding on the report of every Lunar
user alive. The walker only collects `mods/` and `addons/`, which those are not in.

And if a client is installed but no mods/addons folder turns up under it, that goes in the
**coverage box** — it means a format this tool cannot read, which is not the same as clean.

### 🖱 Autoclicker — the half that is not a mod

An autoclicker is never in the mods folder. It is an AutoHotkey script on the desktop, an
AutoIt binary, or — the case people assume a screenshare cannot see — a **Lua script running
inside the mouse driver**, where the clicks are produced below the game entirely. So
**every** scan reads `.ahk`, `.ahk2`, `.au3`, `.lua` and `.vbs` files in Downloads, Desktop,
Documents, Temp *and* the script folders that G HUB, Synapse, iCUE, SteelSeries, Glorious
and Bloody run code out of. Not the deep scan — every scan: a macro doesn't need the game to
be open, so closing Minecraft before the screenshare must not hide it.

Clicking the mouse is not a cheat, so there are three levels and the difference between
them is **evidence, not confidence**:

| what was found | verdict |
|---|---|
| repeats mouse input in a loop **and** names Minecraft, the launcher or `javaw` | 🔴 **Confirmed** — an autoclicker aimed at this game |
| repeats mouse input in a loop and the **file** is named after the technique (`blockhit`, `butterflyclick`, `autocrystal`) | 🔴 **Confirmed** — those are Minecraft words; the file says what it is. What it doesn't say is *which game* it was used in — that question goes to the person reading the report, it isn't a reason to score it lower |
| repeats mouse input in a loop, nothing ties it to the game | ⚪ reported as *a click macro exists*, **never** an accusation |

That last row is the one that keeps this honest. A recoil script for a shooter is a real
click loop in a real mouse driver and it is **not** a Minecraft cheat — it is in the test
corpus for exactly that reason, next to an AutoHotkey text expander, a window-tiling
script, a G HUB lighting profile, and a ComputerCraft turtle program (Minecraft's own Lua,
which names the game constantly and is not a macro at all). None of them may ever come
back as a cheat, and `ml/test_macro.py` fails the build if one does.

**What it cannot see, stated on every scan.** A macro burned into a mouse's **onboard
memory** — Bloody and A4Tech devices, and the onboard profiles of Razer and Logitech
hardware — runs on the device itself and leaves *nothing* on the PC. No PC scan can detect
it, so it is listed in the report's coverage box every time rather than only when something
turns up. What the tool *can* show you is that a driver macro store exists and **when it
was last changed** — a profile edited ten minutes before the screenshare is worth a
question.

It weighs the evidence the way a screenshare admin would: a **confirmed cheat jar**,
an **injected JVM** or a **running cheat process** is proof (→ Likely/Confirmed);
**cheat jars stashed outside the mods folder** are worth a look (→ Review); and
"lots of unverified mods" is completely normal and stays **Clean**. Then it *learns
from that scan* — see below.

**One thing it used to get badly wrong, and now doesn't.** The whole-scan model saw the
behaviour rules only through the *ratio* of flagged mods — and a big modpack divides that
away to nothing. Measured: a 100-mod pack containing **one behaviour-confirmed aimbot**
scored **3/100, Clean**. The same jar recognised by *hash* scored 85. That was exactly
backwards, because the behaviour reading is the stronger of the two: a hash breaks the
moment one byte changes, and "forges its own movement packet while writing a computed
rotation" survives renaming, obfuscation and string encryption.

So the scan model is **v3** and what the code *does* now reaches it directly: a
behaviour-confirmed mod → **Confirmed**, a behaviour-*likely* one → **Likely**, a
**server-rule** finding → floored to **Review** (a person has to answer it; it is still
never an accusation), plus mods that hide the Minecraft API behind reflection, and click
macros. Same numbers on the other side of the line: a perfectly clean scan is 2/100, a
140-mod pack with nothing wrong is 2/100, and eight server-rule findings still cannot add
up to a flag.

There's a rule behind that which the tests now enforce: **every signal that can auto-label
a scan as a cheat must also be a model feature.** Auto-labelling decides what the model
*trains* on, so teaching it from evidence the feature vector cannot see pushes the
intercept instead of a weight — and every scan afterwards starts a little closer to
"cheat". That is precisely what the click-macro signals did when they went in as hard
rules only, it would have drifted silently, and `ml/test_session.py` fails the build for
it now.

---

## 🚩 Flags

| Flag | Does |
|---|---|
| *(none)* | **Auto-detects** your Minecraft and scans it. Recommended. |
| `-Ask` | Pick the install from a list / paste a path manually. |
| `-Path "C:\…\mods"` | Scan an exact folder. |
| `-SelfTest` | Verify the AI + verdict logic on your machine, then exit. |
| `-HashOnly "C:\…\folder"` | **Only** compute SHA1 for the jars in that folder and write a paste-ready block. No scan, no upload, no internet. |
| `-Deep` | Analyse **every** class in every jar instead of a sample. Slower, for when you're really investigating someone. |
| `-NoElevate` | Don't ask Windows for Administrator (some checks are then skipped). |
| `-DeepScan` | Also scan drives, recycle bin and processes for cheat traces. |
| `-DeepMemory` | Force the live-memory check on. It already turns on by itself whenever Minecraft is running. |
| `-Share` | Export confirmed cheat hashes locally to contribute them. |
| `-NoUpdate` | Skip the GitHub model/signature auto-update. |
| `-NoLearn` | Don't adapt the local model this run. |
| `-Reset` | Wipe the learned memory and start fresh. |
| `-Yes` | Kept for compatibility &mdash; the tool decides the depth itself now. |
| `-Dev` | Quick developer mode. |

Pass flags with the scriptblock form:
```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'))) -SelfTest"
```

---

## 👥 Team mode — shared scan history

Running a screenshare / anticheat team? Turn on **team mode** and every scan (yours, Luis's, any staff) lands in **one shared dashboard** — and **the AI itself learns from everyone's scans**, not just each PC. Confirmed detections from all team members train **two** shared models on the backend — one for single mods, one for whole scans — and every client pulls both on the next run. The more your team scans, the smarter it gets for everyone.

<div align="center">

`Staff runs scan` → `result + labelled samples upload` → `one shared model trains on all scans` → `every client pulls the smarter model`

</div>

- Deploy the tiny backend once (**Cloudflare Worker**, free & always-on, or a **zero-dep Node server**) — full steps in [`server/README.md`](server/README.md).
- Flip it on from **`ml/signatures.json`** in your repo (no need to touch the script):
  ```json
  "telemetry": { "enabled": true, "endpoint": "https://…workers.dev", "key": "your-write-secret", "pullSignatures": true }
  ```
- The tool shows the scanned person an **upload notice** (honest by design). Set `"enabled": false` to turn it off for everyone instantly.

The dashboard shows who scanned whom, when, the verdict, and every flagged mod with its reasons — a clean, shareable proof log.

---

## 🧠 Self-improvement

Detection gets better **every time you use it** — all on your machine, nothing uploaded:

1. **Hash memory** — every verified mod is remembered as *good* (instant + offline next time); every hard-confirmed cheat is remembered as *cheat*.
2. **Online learning** — each confirmed verdict does one bounded SGD step on the model weights (anchored to the base model, so it adapts but can never drift into false positives). Stored in `%APPDATA%\AsyncAnalyzer\learned.json`.
3. **Whole-scan learning** — every *finished scan* also teaches the overall-scan AI, so the tool gets better at reading a **situation**, not just a file. Only unambiguous scans teach it (a hard-confirmed cheat / injected JVM → *cheat*; an all-verified, issue-free scan → *clean*); anything in between teaches it nothing, which is what stops it drifting.
4. **Cloud auto-update** — on start it pulls the newest models + community signature list from this repo, so improvements reach **everyone** (turn off with `-NoUpdate`).

> Proven: after confirming a handful of a *new* cheat family, the model's score for it climbs from **20% → 66%** — while all 37 real clean libraries stay Clean. (`python3 ml/test_selflearn.py`)

**Hybrid sharing:** the community cheat list (`ml/signatures.json`) is downloaded by everyone. Run with `-Share` to export *only* confirmed cheat **hashes** (never files) locally so you can contribute them back.

---

## 🤖 The AI model

Trained here, shipped as plain numbers embedded in the script (so it runs with zero dependencies).

```
ml/
├── features.py        # the 22-feature schema (matches the PowerShell extractor)
├── build_dataset.py   # downloads REAL clean libraries + builds labelled data
├── train_model.py     # trains the model, exports weights + metrics
├── online_learn.py    # the self-improvement SGD step (matches the .ps1)
├── verdict.py         # reference port of the verdict logic
├── signatures.json    # community cheat list (auto-downloaded by the tool)
├── session_model.py   # the overall-scan model (source of truth for its weights)
├── session_model.json # overall-scan weights the .ps1 embeds + auto-updates from
├── test_session.py    # proves the overall-scan AI scores + learns correctly
├── model.json         # trained weights + version + metrics
├── test_verdict.py    # end-to-end tests (cheats, clean, anticheat, verified)
├── test_selflearn.py  # proves self-learning helps without false positives
└── test_report.py     # static checks on the screenshare report (thresholds, honesty, encoding)
```

Retrain anytime:
```bash
cd ml && python3 build_dataset.py && python3 train_model.py
```

The **negative class is trained on real libraries** — ASM, ByteBuddy, Javassist, Gson, Netty, Kotlin, log4j, Night-Config… exactly the "scary but legit" code naive scanners false-flag. That's *why* reflection and bytecode manipulation on their own no longer trigger a flag.

---

## 📊 Benchmarks — measured, public, and rerun on every push

Detection is **measured continuously**, not claimed once. [`BENCHMARKS.md`](BENCHMARKS.md)
and the [**benchmark page**](https://qdhshamiro.github.io/AsyncAnalyzer/benchmarks.html) are
generated by `python3 ml/benchmark.py` and refreshed by CI on every push, so the numbers in
this repo are never hand-typed.

> **One-time setup:** Pages has to be switched on once, by hand —
> *Settings → Pages → Build and deployment → Source → **GitHub Actions***.
> The workflow tries to do it itself, but creating a Pages site with the workflow
> token is not permitted by default (`Resource not accessible by integration`), so
> it says so in the run summary. The run stays **green** while it waits &mdash; a
> workflow that is permanently red for something waiting on a human teaches people
> to ignore red. Every push after that one click deploys on its own.

The whole site — [overview](https://qdhshamiro.github.io/AsyncAnalyzer/),
[benchmarks](https://qdhshamiro.github.io/AsyncAnalyzer/benchmarks.html) and
[how it works](https://qdhshamiro.github.io/AsyncAnalyzer/how-it-works.html) — is generated
by `python3 ml/site.py` and deployed straight from this repo by GitHub Actions. The rule
documentation is **read out of the shipped script when the page is built**, so it cannot
describe a rule the tool no longer runs.

| | |
|---|---|
| **False flags on real software** | **0** of **184** real libraries — through the *full* verdict chain, against **all 12** cheat rules, not just one |
| Aim / killaura / pathing / timer | detected, independent of where it hides (class 0 → 4995 of 5000) |
| Combat, movement, world, ghost utilities | **198 of 222** reconstructed cheat variants caught &mdash; scaffold, no-fall, blink, speed, nuker, inventory-move, velocity, triggerbot, autoclicker, freecam, Baritone-style pathing |
| Dropper (decrypt → defineClass) | detected |
| Legit auto-walk vs. pathing cheat | told apart — the cheat forges its own movement packet, the mod uses the game's input |
| Team learning | a new cheat pattern climbs 13% → 35% while clean scans stay at 9% |
| Cost | ~0.35 ms per class; verified mods are skipped entirely |

The build **fails** if a real library is ever flagged by a cheat rule. That gate exists
because this failure mode is silent — a detector that starts flagging legitimate mods looks
fine right up until someone gets accused.

Two results are reported honestly rather than tuned away:

- **11 libraries match the Java-agent rule** — AspectJ, ByteBuddy, OpenTelemetry, Spring
  Instrument, Mockito… Those matches are *correct*: they really do ship instrumentation.
  The rule is scoped to *a jar in a mods folder*, where an agent is abnormal.
- **ESP is not decidable from bytecode.** ESP and a mob-radar minimap do the same thing, so
  it is surfaced for review instead of accused. That costs recall on purpose.
- **A HTTP config pull with reflection is not detectable.** That rule would have matched 87
  of the real libraries, so it does not ship. A ghost client that keeps its modules on a
  server and pulls them at runtime is caught by what it then *does*, not by the download.
- **A jar that deletes itself is measured but not accused.** It is the wipe pattern and
  it would be valuable, but it could not be made safe. Per jar it matched sixteen
  legitimate bytecode libraries (ByteBuddy, Javassist, Groovy, log4j-core…). Measured per
  *class* and excluding native-library unpacking it was clean across 479 jars locally —
  and still flagged a real library in CI, twice, on the wider corpus this sandbox cannot
  reach. Two narrowings did not fix it, so the signal is reported and left out of the
  score. A rule that flags real code is worse than a gap.

Reproduce it yourself from a clean checkout:
```bash
python3 ml/fetch_jars.py && python3 ml/benchmark.py
```

`fetch_jars.py` pulls the negative class from Maven Central and, for the
Minecraft-ecosystem entries, from Mojang's, Sponge's and Fabric's own repositories.
CI currently gets **184** of 189 declared. Every download is verified to be a real
jar containing classes — an error page saved as a `.jar` and two empty aggregator
jars had been silently counted as libraries — and whatever it could **not** fetch is
listed by name at the end of the run, so the declared list cannot quietly drift away
from what is actually on disk again.

The benchmark always counts what is on disk, so the headline number stays honest
whatever the fetcher managed to get.

## ✅ Proof it works

| Test | Result |
|---|---|
| `ml/train_model.py` | precision **1.00**, recall **1.00**; worst real-library cheat score **0.13** |
| `ml/test_verdict.py` | **194/194** — cheats caught, real libs Clean, anticheats Clean, impersonation closed |
| `ml/test_selflearn.py` | learns a new family 20 → 66% while keeping every clean file safe |
| `ml/test_session.py` | **27/27** — overall-scan AI: clean scans stay Clean, learns a new *whole-scan* pattern 13 → 30% without drifting |
| federated (live backend) | overall-scan model learned 13 → 39% across 30 scans from 3 team members; clean + hard-confirmed unchanged |
| `-SelfTest` (in-tool) | 58 known cases — mod-level, impersonation, whole-scan **and the report itself** (it renders end to end and is checked, so the document staff read is never the untested part) |
| `ml/test_report.py` | **46/46** — the score scale draws the engine's real band edges, a clean verdict never claims proof, an incomplete scan says so, no template variable is silently undefined |

---

---

## 🛠 For developers

`AsyncAnalyzer.ps1` is **generated** — edit `src/*.ps1` and run `python3 build.py`.
CI fails on `build.py --check` if the shipped file drifts from its sources. See
[`src/README.md`](src/README.md) for the section map and [`STATUS.md`](STATUS.md) for
the current handover.

```bash
python3 build.py            # assemble the shipped script
python3 ml/ps_lint.py       # static checks (no PowerShell needed)
python3 ml/fetch_jars.py    # download the real-library corpus
python3 ml/benchmark.py     # measure everything, regenerate BENCHMARKS.md
python3 ml/site.py          # regenerate the public site into docs/
cd ml && for t in test_*.py; do python3 "$t"; done
```

The site is deployed by GitHub Actions from `docs/`. It needs Pages switched on once
by hand — *Settings → Pages → Build and deployment → Source → **GitHub Actions*** —
because creating a Pages site with the workflow token is not permitted by default.
The workflow says so in its run summary and stays green while it waits.

## 📋 Requirements

- Windows 10 / 11 · PowerShell 5.1+
- Administrator for the full scan (deleted-program history)
- Python 3 only for development

---

<div align="center">

Made by [**QDHShamiro**](https://github.com/QDHShamiro) · [discord.gg/asyncstudios](https://discord.gg/asyncstudios)

</div>
