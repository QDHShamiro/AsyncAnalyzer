#!/usr/bin/env python3
"""The parallel read is allowed to be faster. It is not allowed to be different.

Reading jars on several cores is the one change in this tool that could make the
same PC come out with two different answers, depending on how many cores it has.
The runtime already proves equivalence on every start (three -SelfTest cases build
real jars, read them both ways and compare). This file guards the property those
cases rest on: that the worker only READS.

Run: python3 test_parallel.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAR = (ROOT / "src" / "84-parallel.ps1").read_text(encoding="utf-8")
JAR = (ROOT / "src" / "85-jarscan.ps1").read_text(encoding="utf-8")
BC = (ROOT / "src" / "40-bytecode.ps1").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "95-main.ps1").read_text(encoding="utf-8")
ANALYSIS = (ROOT / "src" / "50-analysis.ps1").read_text(encoding="utf-8")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))


# --- 1. the worker decides nothing -------------------------------------------
worker = re.search(r"\$script:parWorker = \{(.*?)\n\}", PAR, re.S)
check("the worker body was found", worker is not None)
body = worker.group(1) if worker else ""
for bad, why in (
        (r"\$script:\w+\s*=", "assigns to shared script state"),
        (r"Add-Finding", "creates a finding"),
        (r"Add-ScanGap", "records a coverage gap"),
        (r"Add-DiskPackages", "mutates the shared package set"),
        (r"Add-Evidence", "records evidence"),
        (r"\bW\s+\"", "writes to the console from a thread"),
        (r"Get-ModVerdict|Get-SessionVerdict|Invoke-MlModel", "reaches a verdict"),
):
    check(f"the worker never {why}", re.search(bad, body) is None)
called = set(re.findall(r"\b(Get-[A-Za-z0-9]+)\s+\$Path", body))
check("the worker calls only the three readers",
      called == {"Get-FileSHA1", "Get-JarFeatures", "Get-JarPackages"}, str(sorted(called)))

# --- 2. the shared set is returned, never written from a thread ---------------
_getpkg = BC.split("function Get-JarPackages")[1].split("function Add-DiskPackages")[0] if "function Get-JarPackages" in BC else ""
check("Get-JarPackages returns a list instead of adding to the set",
      bool(_getpkg) and "$script:DiskPackages.Add" not in _getpkg and "return $out" in _getpkg)
check("Add-DiskPackages is the wrapper that folds them in",
      re.search(r"function Add-DiskPackages.*?\$script:DiskPackages\.Add", BC, re.S) is not None)
check("DiskPackages is on the never-copy list",
      "$script:parNeverCopy = @('DiskPackages')" in PAR)
check("...and the fold adds them on the main thread",
      "foreach ($p in @($Pre.Packages)) { [void]$script:DiskPackages.Add($p) }" in JAR)

# --- 3. the verdict order is still the file order -----------------------------
check("the analysis loop is still sequential and in the original order",
      re.search(r"foreach \(\$jar in \$jarFiles\) \{", MAIN) is not None)
check("each jar is handed its own precomputed read, by path",
      "Invoke-JarAnalysis $jar $pre[$jar.FullName]" in MAIN)
check("the late-folder scan gets the same treatment",
      "Invoke-JarAnalysis $jar $prel[$jar.FullName]" in JAR)

# --- 4. no precomputed read means read it here, exactly as before -------------
check("SHA1 falls back to computing inline",
      "if ($Pre) { $Pre.Sha1 } else { Get-FileSHA1 $jar.FullName }" in JAR)
check("features and packages fall back too",
      re.search(r"\} else \{\s*\n\s*Add-DiskPackages \$jar\.FullName\s*\n\s*\$feat = Get-JarFeatures", JAR) is not None)
check("a jar the pool did not return is simply absent from the table",
      "if ($r -and $r.Path -and $r.Features) { $out[[string]$r.Path] = $r }" in PAR)
check("a failed pool yields nothing rather than a partial answer",
      re.search(r"\} catch \{[^}]*\$out = @\{\}", PAR, re.S) is not None)
check("a folder too small to be worth a pool is read inline",
      "$list.Count -lt 6" in PAR)

# --- 5. the closure is derived, not maintained --------------------------------
check("the worker's functions come from their own ASTs",
      "FunctionDefinitionAst" not in PAR and "CommandAst" in PAR
      and "$cmd.ScriptBlock.Ast" in PAR)
check("the roots are exactly what the worker calls",
      "$script:parRoots = @('Get-FileSHA1', 'Get-JarFeatures', 'Get-JarPackages')" in PAR)

# --- 6. the equivalence is checked at runtime, not only here ------------------
for label in ("Parallel read returns exactly what reading inline returns",
              "The worker is handed everything those functions need",
              "...and never the one set that is shared"):
    check(f"-SelfTest checks: {label}", f'Label = "{label}"' in ANALYSIS)

# --- 7. the fingerprint nobody can use is not computed ------------------------
# 583 ms a jar, measured, for a number CurseForge refuses to answer without a key.
check("Murmur2 is skipped when there is no CurseForge key",
      "if (-not $verifiedName -and -not [string]::IsNullOrWhiteSpace($script:CurseForgeApiKey))" in JAR)

print("=== parallel-read checks ===")
failed = 0
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not ok) else ""))
    failed += not ok
print(f"\n=== RESULT: {len(results) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
