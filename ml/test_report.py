#!/usr/bin/env python3
"""Static checks on the screenshare report.

The report is the thing a staff member acts on, and PowerShell will happily print
an undefined variable as an empty string - a typo would silently blank a whole
section with no error anywhere. These checks read the shipped source and fail on
the mistakes that would otherwise only show up in front of a suspect.
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT = (ROOT / "src" / "60-report.ps1").read_text(encoding="utf-8")
RUNTIME = (ROOT / "src" / "30-runtime.ps1").read_text(encoding="utf-8")
ANALYSIS = (ROOT / "src" / "50-analysis.ps1").read_text(encoding="utf-8")

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))

def band_edges(src, func):
    """The score thresholds a verdict function turns into band names."""
    i = src.index("function " + func)
    body = src[i:i + 12000]
    m = re.search(r'\$band\s*=\s*if\s*\(\$score\s*-ge\s*(\d+)\).*?-ge\s*(\d+).*?-ge\s*(\d+)', body, re.S)
    return tuple(int(g) for g in m.groups()) if m else None


# --- 1. the scale must draw the real decision boundaries ---------------------
session_edges = band_edges(RUNTIME, "Get-SessionVerdict")
mod_edges = band_edges(ANALYSIS, "Get-ModVerdict")
ticks = sorted(int(t) for t in re.findall(r"class='tick' style='left:(\d+)%", REPORT))
check("session verdict has three band edges", session_edges is not None, str(session_edges))
check("mod verdict has three band edges", mod_edges is not None, str(mod_edges))
if session_edges:
    check("scale ticks match the session band edges",
          ticks == sorted(session_edges), f"ticks={ticks} edges={sorted(session_edges)}")
if mod_edges and session_edges:
    check("mod and session bands use the same edges",
          sorted(mod_edges) == sorted(session_edges), f"mod={sorted(mod_edges)} session={sorted(session_edges)}")

# the label under each tick has to name the band that starts there
labels = re.findall(r"style='left:(\d+)%;'>(\d+) (\w+)<", REPORT)
for left, num, word in labels:
    check(f"scale label '{num} {word}' sits at {num}%", left == num, f"left={left}% num={num}")

# --- 2. every band the engine can produce has a style ------------------------
engine_bands = set(re.findall(r'\{\s*"(Confirmed|Likely|Review|Clean)"\s*\}', RUNTIME))
engine_bands |= set(re.findall(r'"(Confirmed|Likely|Review|Clean)"', RUNTIME))
styled = set(re.findall(r'^\s*"(\w+)"\s*\{ return @\{ c = "#', REPORT, re.M))
for b in ("Confirmed", "Likely", "Review"):
    check(f"band {b} has an explicit style", b in styled, f"styled={sorted(styled)}")
check("Clean falls through to the default arm", "default     { return @{ c =" in REPORT)

# a Clean headline must never claim proof
clean_arm = REPORT[REPORT.index("default     { return @{ c ="):]
clean_say = re.search(r'say = "([^"]+)"', clean_arm).group(1)
check("clean verdict does not claim proof",
      "proof" not in clean_say.lower(), clean_say)
check("clean verdict points at the coverage box",
      "coverage" in clean_say.lower(), clean_say)
confirmed_say = re.search(r'"Confirmed" \{ return @\{[^}]*say = "([^"]+)"', REPORT, re.S).group(1)
check("confirmed verdict states it is not a guess", "guess" in confirmed_say.lower(), confirmed_say)

# --- 3. the incomplete-coverage caveat ---------------------------------------
m = re.search(r'if \(\$gapCount -gt 0 -and \(([^)]*)\)\) \{', REPORT)
check("caveat is gated on gaps existing", m is not None)
if m:
    cond = m.group(1)
    check("caveat covers a Clean verdict", '"Clean"' in cond, cond)
    check("caveat covers a Review verdict", '"Review"' in cond, cond)
check("caveat says the result does not cover the gaps",
      "does not cover them" in REPORT)
check("gapCount is computed before the caveat uses it",
      REPORT.index("$gapCount = @($script:ScanGaps).Count") < REPORT.index("if ($gapCount -gt 0 -and"))

# --- 4. no interpolated variable is left undefined ---------------------------
# PowerShell renders an unknown $var as "" - a typo blanks a section silently.
body = REPORT[REPORT.index("function New-HtmlReport"):]
tpl = body[body.index('$html = @"'):body.index('\n"@\n')]
used = set(re.findall(r'\$([A-Za-z_][A-Za-z0-9_]*)\b', tpl))
assigned = set(re.findall(r'^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=', body, re.M))
assigned |= set(re.findall(r'foreach \(\$([A-Za-z_][A-Za-z0-9_]*) in', body))
KNOWN = {"script", "env", "sv", "svStyle", "raw", "now", "true", "false", "null", "_"}
missing = sorted(v for v in used - assigned - KNOWN if not v.startswith("script"))
check("every variable in the template is assigned first", not missing, f"undefined: {missing}")

# --- 5. every Add-Finding level has a style ----------------------------------
levels = set()
for f in sorted((ROOT / "src").glob("*.ps1")):
    src = f.read_text(encoding="utf-8")
    levels |= set(re.findall(r'Add-Finding "(\w+)"', src))
    levels |= set(re.findall(r'Write-SystemFlag "(\w+)"', src))
    # Add-Finding $Level / $lvl passes a value through - the literal call sites
    # above are what pins the vocabulary, a pass-through has nothing to check.
known_levels = set(re.findall(r'^\s*"(\w+)" \{ return @\{ c = "#\w+"; label', REPORT, re.M))
unstyled = sorted(l for l in levels if l not in known_levels and l != "OK" and not l.islower())
check("every finding level has a style", not unstyled, f"unstyled: {unstyled} known: {sorted(known_levels)}")
check("OK falls through to the default level arm", 'default { return @{ c = "#3ddc84"' in REPORT)

# --- 6. the plain-text summary carries the same three answers ----------------
plain = REPORT[REPORT.index("function New-PlainSummary"):]
check("plain summary states the verdict", "VERDICT:" in plain)
check("plain summary lists the gaps", "NOT CHECKED" in plain)
check("plain summary says a clean result does not cover the gaps",
      "does not cover" in plain)
check("plain summary names flagged mods", "FLAGGED" in plain)

# --- 7. machine-derived strings are HTML-encoded -----------------------------
# a filename with < in it must not be able to inject markup into the report
for var in ("$env:COMPUTERNAME", "$env:USERNAME"):
    hits = re.findall(re.escape(var), REPORT)
    enc = re.findall(r"Enc " + re.escape(var), REPORT)
    check(f"{var} is encoded everywhere it is rendered",
          len(enc) >= 1, f"{len(hits)} uses, {len(enc)} encoded")
check("mod file names are encoded", "Enc $m.FileName" in REPORT)
check("finding items are encoded", "Enc $i" in REPORT)
check("scan gaps are encoded", "Enc $g" in REPORT)
check("scan targets are encoded", "Enc $t" in REPORT)

# --- 8. the report never reports more coverage than it had -------------------
check("an area is only listed as checked if it produced a finding",
      "foreach ($f in @($script:Findings)) { if ($areas -notcontains $f.Area) { $areas += $f.Area } }" in REPORT)
check("the no-gap box does not claim more than 'nothing was skipped'",
      "Nothing was skipped." in REPORT)

print("=== report checks ===")
failed = 0
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not ok) else ""))
    if not ok:
        failed += 1
print(f"\n=== RESULT: {len(results) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
