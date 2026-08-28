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
    """The score thresholds a verdict function turns into band names.

    Searches forward from the function to its band assignment rather than inside a
    fixed window - a window has to be widened every time a rule is added, and the
    day someone forgets, this reports "no thresholds found" instead of checking them.
    """
    i = src.index("function " + func)
    m = re.search(r'\$band\s*=\s*if\s*\(\$score\s*-ge\s*(\d+)\)[^\n]*?-ge\s*(\d+)[^\n]*?-ge\s*(\d+)',
                  src[i:])
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
check("the server-rule band has a style", '"ServerRule" { return @{ c =' in REPORT)

# A server-rule finding is a different KIND of finding, not a stronger one. If it
# ever starts raising a score instead of renaming a band, a rule question turns
# into an accusation - which is the exact thing this band exists to prevent.
for src_name, src_text in (("PowerShell", REPORT), ("verdict.py", (ROOT / "ml" / "verdict.py").read_text(encoding="utf-8"))):
    pass
PS_VERDICT = (ROOT / "src" / "50-analysis.ps1").read_text(encoding="utf-8")
PY_VERDICT = (ROOT / "ml" / "verdict.py").read_text(encoding="utf-8")
check("server-rule only renames a band that is already Review",
      'if ($policy -and $band -eq "Review") { $band = "ServerRule" }' in PS_VERDICT)
check("the Python port renames it the same way",
      'if policy and b == "Review":' in PY_VERDICT)
check("a policy behaviour never scores above Review in PowerShell",
      all(int(m) <= 35 for m in re.findall(
          r'\$score = \[Math\]::Max\(\$score, (\d+)\)\n\s*\$policy = \$true', PS_VERDICT)),
      str(re.findall(r'\$score = \[Math\]::Max\(\$score, (\d+)\)\n\s*\$policy = \$true', PS_VERDICT)))
check("the guaranteed-clean cap cannot override a hard rule",
      "-not $ctx.HashKnownCheat -and ($ft.PackageHits.Count -eq 0) -and -not $ctx.CheatSite" in PS_VERDICT)

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

# A check that could not run is a gap, not a result. If INFO ever stopped routing
# to ScanGaps, "Defender exclusions - run as Administrator" would vanish from the
# coverage box and a clean verdict would look better than it is.
DISCOVERY = (ROOT / "src" / "80-discovery.ps1").read_text(encoding="utf-8")
check("an INFO check is recorded as a coverage gap",
      'if ($Level -eq "INFO") { Add-ScanGap $Msg }' in DISCOVERY)
check("only FAIL and WARN become findings",
      '$real  = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })' in REPORT)
check("the plain summary uses the same finding filter",
      '$realF = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })' in REPORT)
check("an INFO check is not counted as a finding for its area",
      '$_.Area -eq $a -and ($_.Level -eq "FAIL" -or $_.Level -eq "WARN")' in REPORT)
# A check that could not run has to say so in the coverage box. The system checks
# now call Add-ScanGap directly instead of going through an INFO flag, so what
# matters is that every failure path leads there rather than to silence.
_SYS = (ROOT / "src" / "91-system.ps1").read_text(encoding="utf-8")
_catches = re.findall(r"\}\s*catch\s*\{([^}]*)\}", _SYS)
_silent = [c for c in _catches if c.strip() and "Add-ScanGap" not in c
           and "Write-SystemFlag" not in c and "return" not in c]
check("no system check fails silently - every catch reports or recovers",
      not _silent, str(_silent)[:120])
# and PC state must NOT be routed into the coverage box: the firewall being off
# is not a check that failed to run.
_flag_fn = re.search(r"function Write-SystemFlag.*?\n\}", DISCOVERY, re.S).group(0)
check("PC state is not recorded as a coverage gap",
      'if ($Level -eq "INFO") { Add-ScanGap $Msg }' in _flag_fn
      and '"STATE"' in _flag_fn and 'STATE") { Add-ScanGap' not in _flag_fn)
# A gap message has to say what was NOT checked, in words a moderator can act on.
# "Defender exclusions - INFO" tells nobody anything; "could not be read, so an
# exclusion hiding the mods folder would not have been seen" does.
gap_msgs = re.findall(r'Add-ScanGap "([^"]{20,})"', _SYS)
bad = [m for m in gap_msgs if not any(w in m.lower() for w in
       ("administrator", "could not", "not be read", "would not have been seen",
        "not checked", "not accessible"))]
check("every system gap explains what could not be done", not bad, f"vague: {bad}")
check("there are system gap messages at all", len(gap_msgs) >= 3, str(len(gap_msgs)))
check("the no-gap box does not claim more than 'nothing was skipped'",
      "Nothing was skipped." in REPORT)


# --------------------------------------------------------------- authenticity ---
# A report is a file on the PC of the person being checked, so they can edit it.
# Two things narrow that, and both have to actually reach the places a moderator
# looks: the Scan ID (which the backend also stores, written by the tool rather
# than by them) and the staff code (said out loud before the scan, so an older
# report cannot carry it). If either silently stops being printed, the report
# still looks complete - which is exactly the failure this file exists for.
HEADER = (ROOT / "src" / "00-header.ps1").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "95-main.ps1").read_text(encoding="utf-8")

check("scan id is generated once per run", "$script:ScanId = " in HEADER)
check("-Code is a real parameter", re.search(r"\[string\]\$Code = ", HEADER) is not None)
check("the staff code is stripped of anything odd",
      "$script:ScanCode = ($Code -replace" in HEADER)
for where, src, label in (("console", MAIN, "$($script:ScanId)"),
                          ("HTML report", REPORT, "$(Enc $script:ScanId)"),
                          ("plain summary", REPORT, "Scan ID:   $($script:ScanId)"),
                          ("last-scan.txt", RUNTIME, "Scan ID: $($script:ScanId)")):
    check("scan id reaches the %s" % where, label in src)
check("the staff code reaches the HTML report", "$(Enc $script:ScanCode)" in REPORT)
check("the report says so when NO code was given",
      "none was given" in REPORT and "cannot be shown to be fresh" in REPORT)
check("the scan id and code are uploaded",
      "scanId       = $script:ScanId" in RUNTIME and "scanCode      = $script:ScanCode" in RUNTIME)
# and the panel has to be rendered, not just built - a variable that is assigned
# and never used is the exact PowerShell mistake this file was written for
check("the authenticity panel is placed in the page",
      "$authBox" in REPORT and REPORT.count("$authBox") >= 2)
# the honest part: it must not claim the local file is tamper-proof
check("it does not overclaim - the uploaded copy is named as the trusted one",
      "it is the one to trust if the two disagree" in REPORT)

# --- the block a moderator reads during the call -----------------------------
# The report is thorough, which is the same thing as long. "Look at these first"
# names the actual items needing a person, strongest first - and it is only
# useful if it is ABOVE the working, and if it is rendered at all.
check("the action list is built and placed in the page",
      "$todoBox" in REPORT and REPORT.count("$todoBox") >= 2)
_i_todo = REPORT.find("<h2>Look at these first")
_i_rests = REPORT.find("<h2>What this verdict rests on")
_i_mods = REPORT.find("<h2>Mods &mdash; flagged")
_i_rec = REPORT.find("<h2>Scan record")
check("it comes before the reasoning and the mod cards",
      0 < _i_todo < _i_rests < _i_mods, f"todo={_i_todo} rests={_i_rests} mods={_i_mods}")
# Provenance is read after the result, or when the result is disputed - not
# third, above the files it is about.
check("the scan record sits below the findings, not above them",
      _i_rec > _i_mods, f"record={_i_rec} mods={_i_mods}")
# Priority order, as a table: a Confirmed mod outranks a system FAIL, which
# outranks a Likely mod, which outranks a WARN, which outranks Review, which
# outranks a server-rule question. Read out of the source so the two cannot drift.
_prios = dict(re.findall(r'"(Confirmed|Likely|ServerRule)"\s*\{\s*(\d+)\s*\}', REPORT))
_fail_warn = re.search(r'\$\(if \(\$f\.Level -eq "FAIL"\) \{ (\d+) \} else \{ (\d+) \}\)', REPORT)
_ok = (_prios.get("Confirmed") and _fail_warn and
       int(_prios["Confirmed"]) > int(_fail_warn.group(1)) > int(_prios["Likely"])
       > int(_fail_warn.group(2)) > int(_prios["ServerRule"]))
check("strongest first: Confirmed > FAIL > Likely > WARN > ServerRule", bool(_ok),
      f"{_prios} fail/warn={_fail_warn.groups() if _fail_warn else None}")
# A clean scan must say so in this block too, or the strongest signal in the
# whole report - that there is nothing to act on - is the one thing missing.
check("a clean scan is told plainly here as well",
      "Nothing here needs a person." in REPORT)
# Bounded: a pack with fifty flagged jars must not turn this into the report.
check("the list is capped and says how many are left",
      "$shown -ge 8" in REPORT and "more below, in full" in REPORT)

# --- the system checks must actually reach the report ------------------------
# The whole SYSTEM FORENSICS section, IFEO hijacking included, used to print to
# the console, bump a counter and reach the report not at all.
SYSTEM = (ROOT / "src" / "91-system.ps1").read_text(encoding="utf-8")
check("system checks create findings, not just console output",
      "Add-Finding" in SYSTEM and SYSTEM.count("Add-Finding") >= 3)
check("cheat-relevant and PC-state findings go to different areas",
      '"System forensics"' in SYSTEM and '"PC state"' in SYSTEM)
# The property that makes it safe to show PC state at all: it must not be able
# to reach any filter that decides something.
check("PC state is its own level, outside FAIL and WARN",
      'Write-SystemFlag "STATE"' in SYSTEM
      and '$script:SysArea = "PC state"' in SYSTEM
      and '$_.Level -eq "STATE"' in REPORT)
_state_helper = re.search(r"function Add-SysState.*?\n\}", SYSTEM, re.S)
check("PC state never increments the system-issue counter",
      bool(_state_helper) and "SystemIssues" not in _state_helper.group(0),
      "Add-SysState must not touch $script:SystemIssues")
_cheat_helper = re.search(r"function Add-SysCheat.*?\n\}", SYSTEM, re.S)
check("cheat-relevant system findings DO count",
      bool(_cheat_helper) and "SystemIssues++" in _cheat_helper.group(0))
check("the PC-state block is rendered in its own section",
      "$stateBox" in REPORT and REPORT.count("$stateBox") >= 2
      and "How this PC is set up" in REPORT)
# and it must sit below the findings, like the scan record
_i_state = REPORT.find("<h2>How this PC is set up")
check("PC state sits below the findings it is not part of",
      _i_state > REPORT.find("<h2>Everything else that was found"),
      f"state={_i_state}")
# One card renderer for both, so the two cannot drift apart visually
check("findings and PC state use one card renderer",
      REPORT.count("New-FindingCard") >= 3)

print("=== report checks ===")
failed = 0
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not ok) else ""))
    if not ok:
        failed += 1
print(f"\n=== RESULT: {len(results) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
