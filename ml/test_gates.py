#!/usr/bin/env python3
"""The checks that guard this repo have to be able to SEE what they check.

Every other suite here asks whether the tool is right. This one asks whether the
gates would notice if it were not - because a gate that silently passes is worse
than no gate at all: it is believed.

It exists because of a real one. The workflow ran the self-test with

    $out = & ./AsyncAnalyzer.ps1 -SelfTest 2>&1 | Out-String

and then decided pass/fail by searching $out. Every line the tool prints goes
through W, which is Write-Host, which writes to the INFORMATION stream. 2>&1
merges only the ERROR stream, so $out came back with 324 characters of runner
noise, "All 91 self-tests passed" was not in it, and the step could only ever
fail. Measured, not guessed: the same command with *>&1 returns 9120 characters
and finds the line.

Run: python3 test_gates.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WF = (ROOT / ".github" / "workflows" / "benchmark.yml").read_text(encoding="utf-8")
SELFTEST = (ROOT / "scripts" / "selftest.ps1").read_text(encoding="utf-8")
CONSOLE = (ROOT / "src" / "70-console.ps1").read_text(encoding="utf-8")
ANALYSIS = (ROOT / "src" / "50-analysis.ps1").read_text(encoding="utf-8")
# The self-test capture lives in scripts/selftest.ps1 so the workflow and a run by
# hand cannot drift; the delivery-path capture is still inline in the workflow.
# Both are "somewhere a gate reads the tool's output", so both are checked.
GATES = WF + "\n" + SELFTEST

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))


# --- the premise: the tool prints through Write-Host --------------------------
_w = re.search(r"function W\(.*?\n\}", CONSOLE, re.S)
check("W is the one console writer", _w is not None)
check("...and it writes to the host, so its output is NOT the error stream",
      bool(_w) and "Write-Host" in _w.group(0))

# --- therefore every gate that reads the tool's output must merge all streams --
# A pipeline that captures the script's output and then greps it.
captures = re.findall(r"\$out\s*=\s*&[^\n]*?(\*>&1|\d>&1)[^\n]*\|\s*Out-String", GATES)
check("the gates capture the tool's output in at least two places", len(captures) >= 2,
      str(captures))
bad = [c for c in captures if c != "*>&1"]
check("every capture merges ALL streams, not just errors", not bad,
      f"{bad} cannot see Write-Host output")

# --- and it must run the way CI runs it, not more leniently -------------------
# GitHub Actions sets $ErrorActionPreference = 'stop' for every pwsh step. Under
# it a missing EXTERNAL command is fatal - `chcp`, eight lines in, killed the
# script before one check had run, while the same run without Stop passed. Testing
# it the lenient way here is exactly how that was missed.
check("the self-test harness runs under the same ErrorActionPreference as CI",
      "$ErrorActionPreference = 'stop'" in SELFTEST)
check("...and the workflow uses that harness rather than its own copy",
      "scripts/selftest.ps1" in WF)
check("a self-test that dies partway through is a failure, not a pass",
      "never reached its summary line" in SELFTEST)

# --- and the string it greps for has to be one the tool really prints ---------
sentinels = re.findall(r"\$out -(?:not)?match '([^']+)'", GATES)
check("the self-test gate greps for something", bool(sentinels))
# 'All \d+ self-tests passed' must correspond to a real Write in the source.
want = [s for s in sentinels if "self-test" in s]
check("the gate looks for the self-test verdict line", bool(want), str(sentinels))
for s in want:
    # turn the regex back into the literal the script would have to print
    literal = s.replace(r"\d+", "").replace(r"\(", "(").replace(r"\)", ")")
    frag = literal.replace("  ", " ").strip()
    head = frag.split(" ", 1)[0] if frag.startswith("All") else frag
    tail = "self-tests passed" if "passed" in frag else "self-test(s) FAILED"
    check(f"the tool actually prints {tail!r}", tail in ANALYSIS)

# --- the gates that must never quietly drop out of the run --------------------
for step, why in (
        ("scripts/check-order.ps1", "call order (this shipped twice)"),
        ("build.py --check", "the shipped file matches src/"),
        # There is one backend now, so there is nothing to check parity against.
        # What replaced it guards the same class of silent failure: the site has no
        # bundler, so a stray character in a page's inline module is only noticed by
        # the person who opens that page and finds it blank.
        ("scripts/check-site.py", "the site's pages actually parse"),
        ("[scriptblock]::Create", "the delivery path, which is iex and not -File"),
):
    check(f"the workflow still runs the check for {why}", step in WF)

# A test suite that exists but is not in the loop is not a test.
loop = re.search(r"for t in ([^;]+); do", WF)
listed = set(loop.group(1).split()) if loop else set()
on_disk = {p.stem for p in (ROOT / "ml").glob("test_*.py")}
missing = sorted(on_disk - listed)
check("every ml/test_*.py is in the CI loop", not missing, f"not run: {missing}")

# --- and a full artifact store must not be what turns the build red -----------
# It did: eight pushes in a row went red on "Artifact storage quota has been hit",
# with every real check green underneath. A build that is always red is not read.
_up = re.search(r"- uses: actions/upload-artifact@v4.*?(?=\n      - |\Z)", WF, re.S)
check("the artifact upload cannot fail the build",
      bool(_up) and "continue-on-error: true" in _up.group(0))
check("...and the numbers still reach the run summary regardless",
      "GITHUB_STEP_SUMMARY" in WF and "if: always()" in WF)


# --- a suite has to fail with a non-zero exit code, and only then -------------
# test_sysscan.py ended in `return 0 if failed else 1` - inverted. It printed
# "69 passed, 0 failed" and exited 1, which turned the whole job red for eight
# pushes and was misread as the artifact-quota failure sitting next to it. The
# other half is worse: the day one of those 69 checks actually failed, it would
# have exited 0 and CI would have gone green on a broken detector.
#
# The CI loop invokes each suite directly under `set -e`, so the exit code IS the
# result. Piping it to `tail -1` to read the last line - which is how this was
# missed by hand - throws that away.
_BAD_EXIT = re.compile(r"(?:return|sys\.exit\(|SystemExit\()\s*0\s+if\s+(failed|bad|problems)\b(?!\s*==)")
_HAS_EXIT = re.compile(r"return\s+[01]\s+if\b|sys\.exit\(|SystemExit\(")
suites = sorted((ROOT / "ml").glob("test_*.py")) + [ROOT / "ml" / "audit.py", ROOT / "ml" / "ps_lint.py"]
inverted, silent = [], []
for f in suites:
    # Comments and the two patterns above are themselves lines containing the shape
    # they look for, so without this the file reports itself.
    src = "\n".join(l for l in f.read_text(encoding="utf-8").splitlines()
                    if not l.lstrip().startswith(("#", "_BAD_EXIT", "_HAS_EXIT")))
    if _BAD_EXIT.search(src):
        inverted.append(f.name)
    if not _HAS_EXIT.search(src):
        silent.append(f.name)
check("no suite reports success as a failure (or the reverse)", not inverted, str(inverted))
check("every suite ends in an exit code at all", not silent, str(silent))
print("=== gate checks ===")
failed = 0
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not ok) else ""))
    failed += not ok
print(f"\n=== RESULT: {len(results) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
