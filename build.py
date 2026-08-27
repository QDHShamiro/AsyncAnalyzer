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
    return 0


if __name__ == "__main__":
    sys.exit(main())
