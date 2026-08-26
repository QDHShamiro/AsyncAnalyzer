# AsyncAnalyzer

Minecraft Mod Forensics + Cheat Detection Suite — now with a **local AI model**.

Scans your mods folder for cheat clients (Doomsday, LiquidBounce, Meteor, Vape, and friends),
malware, and obfuscation. Every mod gets a **cheat probability and a confidence score** from a
trained model that runs entirely on your PC — no cloud, no API key, nothing uploaded.

---

## Run (no install required)

Open PowerShell and paste:

```powershell
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1')"
```

You will be prompted for your mods folder, or type `auto` to detect it, or press Enter for the
default `.minecraft\mods`.

Want to read the whole script before you run it? Open the raw URL above in your browser first.

### Options

| Flag | What it does |
|---|---|
| *(none)* | Fast, **mods-folder-only** scan. Recommended. |
| `-DeepScan` | Also scans your drives, recycle bin and processes for cheat traces. |
| `-DeepMemory` | Also reads live Minecraft memory for loaded cheats (slower, off by default). |
| `-Yes` | Answer "yes" to the deep-scan prompt automatically. |
| `-SelfTest` | Verify the AI model + verdict logic on your machine, then exit. |
| `-Dev` | Quick developer mode (10 items per category). |

Verify the detector works before trusting it:

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'))) -SelfTest"
```

It runs known cheat / clean / anticheat / verified cases through the real
scoring engine and prints PASS/FAIL for each. Use the same
`& ([scriptblock]::Create((irm '...'))) -Flag` form to pass any flag above
(the short `iex (irm '...')` form runs a plain scan with no flags).

---

## Is this tool safe? (yes — here's exactly what it does)

- **Read-only.** It never changes, deletes, or quarantines anything.
- **Runs on your PC.** It never uploads your files or your data.
- **Network use is limited to hash lookups** on Modrinth / CurseForge / Megabase — only the
  file's hash is sent, never the file itself.
- **The cheat verdict is a local AI model.** No cloud call, no API key.
- By default it only touches your **mods folder**. The whole-PC scan and live-memory scan are
  **opt-in**.

---

## How the verdict works

Instead of "one bad word = FLAGGED", every mod is scored **0–100**:

| Band | Score | Meaning |
|---|---|---|
| ✓ Verified | — | Hash matched on Modrinth / CurseForge. **Never flagged.** |
| Clean | 0–29 | Nothing cheat-like. |
| Review | 30–59 | Worth a manual look, not confirmed. |
| Likely | 60–84 | Probably a cheat. |
| Confirmed | 85–100 | Cheat. |

The score combines a **trained logistic-regression model** (22 features: package paths, class-name
obfuscation, entropy, reflection, network behaviour, signatures, …) with a few hard rules
(known-cheat hash, cheat-client package path, known cheat download site). Verified and
known-good mods are **capped as safe** — an anticheat mod full of `killaura`/`reach` detection
names is recognised for what it is, not flagged.

Every flag shows **why**: the AI probability plus the top contributing factors.

---

## The AI model (`ml/`)

The model is trained here and shipped as plain numbers embedded in the script (so it runs in
PowerShell with no dependencies).

```
ml/
  features.py         shared feature schema (must match the PowerShell extractor)
  build_dataset.py    downloads real, known-clean library jars + builds labelled data
  train_model.py      trains the model, prints metrics, exports weights
  dataset.csv         the training data
  model.json          the trained weights + held-out metrics
```

Retrain any time:

```bash
cd ml
python3 build_dataset.py   # gathers real jars + profiles -> dataset.csv
python3 train_model.py     # -> model.json + model_ps_snippet.txt
```

Then paste `model_ps_snippet.txt` into the `$script:mlWeights` block of `AsyncAnalyzer.ps1`.

The negative (clean) class is trained on **real** open-source libraries — ASM, ByteBuddy,
Javassist, Gson, Netty, Kotlin, log4j — exactly the "scary but legit" code that naive scanners
false-flag. That is why reflection and bytecode manipulation on their own no longer trigger a flag.
To make detection even stronger, add real sample hashes to `$script:knownCheatHashes` /
`$script:knownGoodHashes` in the script.

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1+
- Run as Administrator for the full deep scan (BAM history, some system checks)
- Python 3 only if you want to retrain the model

---

Made by [QDHShamiro](https://github.com/QDHShamiro) · discord.gg/asyncstudios
