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
CONSOLE = (ROOT / "src" / "70-console.ps1").read_text(encoding="utf-8")
ANALYSIS = (ROOT / "src" / "50-analysis.ps1").read_text(encoding="utf-8")

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
captures = re.findall(r"\$out\s*=\s*&[^\n]*?(\*>&1|\d>&1)[^\n]*\|\s*Out-String", WF)
check("the workflow captures the tool's output somewhere", len(captures) >= 2,
      str(captures))
bad = [c for c in captures if c != "*>&1"]
check("every capture merges ALL streams, not just errors", not bad,
      f"{bad} cannot see Write-Host output")

# --- and the string it greps for has to be one the tool really prints ---------
sentinels = re.findall(r"\$out -(?:not)?match '([^']+)'", WF)
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
        ("test_parity.mjs", "the two backends answer the same"),
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

print("=== gate checks ===")
failed = 0
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not ok) else ""))
    failed += not ok
print(f"\n=== RESULT: {len(results) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
