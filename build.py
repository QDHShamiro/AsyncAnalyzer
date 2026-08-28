"""
Assemble AsyncAnalyzer.ps1 from the ordered sections in src/.

The one-liner downloads a single file, so the shipped script stays a single file.
Splitting is for the people editing it - 5400 lines in one buffer is how seven
dead functions survived unnoticed for weeks.

The build is a plain ordered concatenation with no rewriting, which is deliberate:
PowerShell executes top to bottom and the script is full of top-level statements
whose order matters, so anything cleverer than concatenation could change
behaviour silently. Because it is only concatenation, `--check` can prove the
shipped file still matches its sources exactly - byte for byte.

    python3 build.py            # rebuild AsyncAnalyzer.ps1 from src/
    python3 build.py --check    # fail if the shipped file is out of date
"""
import glob
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
OUT = os.path.join(ROOT, "AsyncAnalyzer.ps1")


def assemble():
    parts = sorted(glob.glob(os.path.join(SRC, "*.ps1")))
    if not parts:
        raise SystemExit("no sections in src/")
    return "\n".join(open(p, encoding="utf-8").read() for p in parts), parts


def parse_check(path):
    """Run the shipped file past a real PowerShell parser, if one is here.

    Everything else in this repo is a Python mirror of what the PowerShell is
    meant to DO. None of it can see a syntax error. The first real Windows run
    died on one - a $( ) holding a double quote inside a double-quoted string -
    that the mirrors, the tests and the brace counter had all passed, because a
    brace counter treats a string as opaque and that is exactly where the error
    was. If pwsh is installed, use it; if not, say so rather than implying the
    file was checked.
    """
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/pwsh/pwsh" if os.path.exists("/opt/pwsh/pwsh") else None)
    if not pwsh:
        return None
    script = (
        "$e=$null;"
        "$null=[System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$null,[ref]$e);"
        "if($e){$e|ForEach-Object{'{0}:{1}  {2}' -f $_.Extent.StartLineNumber,"
        "$_.Extent.StartColumnNumber,$_.Message};exit 1}" % path
    )
    r = subprocess.run([pwsh, "-NoProfile", "-Command", script],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return (False, (r.stdout + r.stderr).strip())
    # Parsing is not enough. PowerShell resolves a function call when it RUNS,
    # so a call that is reached before its "function Foo {}" line has executed
    # dies at runtime and nothing static about the syntax can see it. That
    # shipped twice.
    order = os.path.join(ROOT, "scripts", "check-order.ps1")
    if os.path.exists(order):
        r2 = subprocess.run([pwsh, "-NoProfile", "-File", order, path],
                            capture_output=True, text=True, timeout=300)
        if r2.returncode != 0:
            return (False, (r2.stdout + r2.stderr).strip())
    return (True, "")


def main():
    built, parts = assemble()
    check = "--check" in sys.argv
    current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else None

    if check:
        if current == built:
            print("AsyncAnalyzer.ps1 is up to date with src/ (%d sections)" % len(parts))
            return 0
        print("AsyncAnalyzer.ps1 does NOT match src/ - run: python3 build.py", file=sys.stderr)
        if current is not None:
            import difflib
            diff = list(difflib.unified_diff(current.split("\n"), built.split("\n"),
                                             "shipped", "built", lineterm="", n=1))
            print("\n".join(diff[:40]), file=sys.stderr)
        return 1

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(built)
    print("built AsyncAnalyzer.ps1 from %d sections (%d lines)"
          % (len(parts), built.count("\n") + 1))
    res = parse_check(OUT)
    if res is None:
        print("  (no pwsh here - the file was NOT parse-checked)")
    elif res[0]:
        print("  PowerShell: parses, and no function is called before it exists")
    else:
        print("  PowerShell PARSE ERRORS:\n" + res[1], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
