"""
Static sanity checks for AsyncAnalyzer.ps1.

There is no PowerShell in this environment, so the script cannot be parsed or run
here. Brace balance alone is a weak proof - it says nothing about calling a
function that does not exist, which is exactly the mistake a large refactor
produces and which only shows up at runtime on someone's machine.

Checks:
  1. every Verb-Noun command used is either defined in the file or a known cmdlet
  2. no function is defined twice (the later one silently wins in PowerShell)
  3. $script: variables that are read but never assigned
  4. functions that are defined but never called (dead code, reported not failed)

Run:  python3 ml/ps_lint.py
"""
import re
import sys
import os

PS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "AsyncAnalyzer.ps1")

# Built-in cmdlets and common .NET-ish calls this script legitimately uses.
BUILTIN = {
    "Write-Host", "Write-Output", "Write-Error", "Write-Warning", "Write-Verbose",
    "Get-Content", "Set-Content", "Out-File", "Out-Null", "Out-String",
    "Get-ChildItem", "Get-Item", "Test-Path", "New-Item", "Remove-Item", "Copy-Item",
    "Join-Path", "Split-Path", "Resolve-Path", "Get-Date", "Start-Sleep",
    "Get-Process", "Stop-Process", "Start-Process", "Get-Service",
    "Get-WmiObject", "Get-CimInstance", "Invoke-WebRequest", "Invoke-RestMethod",
    "ConvertTo-Json", "ConvertFrom-Json", "ConvertTo-Csv", "ConvertFrom-Csv",
    "Select-Object", "Where-Object", "ForEach-Object", "Sort-Object", "Group-Object",
    "Measure-Object", "Compare-Object", "New-Object", "Add-Type", "Add-Member",
    "Get-Random", "Get-Command", "Get-Member", "Get-Variable", "Set-Variable",
    "Read-Host", "Get-Host", "Select-String", "Get-FileHash", "Get-ItemProperty",
    "Get-WinEvent", "Get-ScheduledTask", "Get-MpPreference", "Get-NetTCPConnection",
    "Get-Culture", "Set-Location", "Push-Location", "Pop-Location", "Export-Csv",
    "Import-Csv", "Get-Location", "Invoke-Expression", "Invoke-Command",
    "Get-PSDrive", "Get-Volume", "Get-Disk", "Get-ComputerInfo", "Get-LocalUser",
    "Get-Acl", "Test-NetConnection", "Clear-Host", "Write-Progress",
    "Get-AuthenticodeSignature", "Get-PSCallStack", "Get-EventLog", "Test-Connection",
}

def strip_noncode(src):
    """Blank out strings, comments and here-strings, character by character.

    Regexes are not good enough for this: the first version of this linter used
    them and mis-paired a here-string terminator, which swallowed a large region
    of the file and produced four confident false alarms about functions that were
    defined and called perfectly well. A scanner that tracks state cannot do that.
    Everything removed is replaced by spaces so line and column numbers survive.
    """
    out = list(src)
    i, n = 0, len(src)
    sq = dq = herdq = hersq = lc = bc = False

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if herdq:
            if two == '"@' and (i == 0 or src[i - 1] == "\n"):
                blank(i, i + 2); herdq = False; i += 2; continue
            blank(i, i + 1); i += 1; continue
        if hersq:
            if two == "'@" and (i == 0 or src[i - 1] == "\n"):
                blank(i, i + 2); hersq = False; i += 2; continue
            blank(i, i + 1); i += 1; continue
        if bc:
            if two == "#>":
                blank(i, i + 2); bc = False; i += 2; continue
            blank(i, i + 1); i += 1; continue
        if lc:
            if c == "\n":
                lc = False
            else:
                blank(i, i + 1)
            i += 1; continue
        if sq:
            blank(i, i + 1)
            if c == "'":
                if src[i + 1:i + 2] == "'":
                    blank(i, i + 2); i += 2; continue
                sq = False
            i += 1; continue
        if dq:
            blank(i, i + 1)
            if c == "`":
                blank(i, i + 2); i += 2; continue
            if c == '"':
                dq = False
            i += 1; continue
        if two == '@"' and (i == 0 or src[i - 1] in "\n=(,+ \t"):
            blank(i, i + 2); herdq = True; i += 2; continue
        if two == "@'" and (i == 0 or src[i - 1] in "\n=(,+ \t"):
            blank(i, i + 2); hersq = True; i += 2; continue
        if two == "<#":
            blank(i, i + 2); bc = True; i += 2; continue
        if c == "#":
            blank(i, i + 1); lc = True; i += 1; continue
        if c == "'":
            blank(i, i + 1); sq = True; i += 1; continue
        if c == '"':
            blank(i, i + 1); dq = True; i += 1; continue
        if c == "`":
            i += 2; continue
        i += 1
    return "".join(out)


def main():
    src = open(PS, encoding="utf-8").read()

    lint = strip_noncode(src)

    defined = re.findall(r'(?m)^\s*function\s+([A-Za-z][\w-]*)', lint)
    defset = set(defined)

    problems, notes = [], []

    # 1. duplicate definitions - PowerShell silently keeps the last one
    dupes = {n for n in defined if defined.count(n) > 1}
    for d in sorted(dupes):
        problems.append("function defined %d times (the last one silently wins): %s"
                        % (defined.count(d), d))

    # 2. calls to things that are neither defined here nor known cmdlets
    called = set()
    for m in re.finditer(r'(?:^|[\n;{(|&]|\s-)\s*([A-Z][a-zA-Z]+-[A-Z][\w]*)', lint):
        called.add(m.group(1))
    unknown = sorted(c for c in called if c not in defset and c not in BUILTIN)
    for u in unknown:
        problems.append("calls something that is not defined and is not a known cmdlet: %s" % u)

    # 3. $script: variables read but never assigned
    assigned = set(re.findall(r'\$script:(\w+)\s*(?:=|\+=|\+\+|--)', lint))
    assigned |= set(re.findall(r'\$script:(\w+)\.\w+\s*=', lint))
    read = set(re.findall(r'\$script:(\w+)', lint))
    never = sorted(r for r in read - assigned)
    for n in never:
        problems.append("$script:%s is read but never assigned" % n)

    # 4. dead functions - reported, not a failure.
    # Counted against the RAW source on purpose: a call inside a here-string (the
    # HTML report builds itself that way) is still a call, and the stripped copy
    # cannot see it.
    for f in sorted(defset):
        uses = len(re.findall(r'(?<![\w-])%s(?![\w-])' % re.escape(f), src))
        if uses <= 1:
            notes.append("defined but never called: %s" % f)

    print("=== AsyncAnalyzer.ps1 static checks ===")
    print("  functions defined : %d" % len(defset))
    print("  commands used     : %d" % len(called))
    print()
    if problems:
        print("PROBLEMS")
        for p in problems:
            print("  ! " + p)
    else:
        print("  no problems found")
    if notes:
        print()
        print("Notes (not failures)")
        for n in notes:
            print("  - " + n)
    print()
    print("=== RESULT: %d problem(s) ===" % len(problems))
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(main())
