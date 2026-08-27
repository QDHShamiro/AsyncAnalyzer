# Sections

`AsyncAnalyzer.ps1` is assembled from these files, in filename order, by
`python3 build.py`. **Edit here, not there** — the shipped script is overwritten
on every build, and CI fails if it does not match (`python3 build.py --check`).

The build is a plain ordered concatenation and nothing more. PowerShell executes
top to bottom and this script is full of top-level statements whose order
matters, so anything cleverer could change behaviour silently. Because it is only
concatenation, the split could be proven correct: the first build came out
byte-for-byte identical to the file that had been shipping.

| section | what lives here |
|---|---|
| `00-header` | param block, PowerShell version + encoding guard, counters and run state |
| `10-signatures` | cheat strings, filename tokens, patterns, package paths, legit mod ids |
| `20-models` | the embedded mod + session models and their inference |
| `30-runtime` | scan gaps, self-elevation, auto-depth, learning state, telemetry |
| `40-bytecode` | constant-pool parser and behavioural feature extraction |
| `50-analysis` | jar features, the verdict, self-test |
| `60-report` | the HTML report |
| `70-console` | console output helpers and cards |
| `80-discovery` | finding Minecraft installs and choosing scan targets |
| `90-jvm` | live JVM / memory inspection |
| `91-system` | system + service forensics |
| `95-main` | the run itself: self-test gate, targets, mod scan |
| `96-pcscan` | process whitelist, whole-PC scan, BAM history |
| `99-finish` | overall verdict, learning, upload, closing output |

Adding a section: name it so it sorts into the right position (the numeric
prefix is the execution order), then rebuild.
