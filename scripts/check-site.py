#!/usr/bin/env python3
"""Static checks for site/.

There is no build step and no bundler, so nothing else would notice a stray
character in a page's inline module until somebody opened that page and found it
blank. That happened once already, which is why this exists.

    python3 scripts/check-site.py
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
MODULE = re.compile(r'<script type="module">(.*?)</script>', re.S)

# Every page needs the one stylesheet and the shared runtime. A page that links
# neither still renders - as unstyled text with no navigation, which is worse
# than an error because it looks like a deployment that half worked.
NEEDS = ('href="/assets/app.css"',)


def node_check(source, label, problems):
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, encoding="utf-8") as f:
        f.write(source)
        tmp = f.name
    try:
        r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
        if r.returncode != 0:
            first = [l for l in r.stderr.splitlines() if "SyntaxError" in l or ".mjs:" in l]
            problems.append("%s: %s" % (label, " / ".join(first[:2]) or "syntax error"))
    finally:
        os.unlink(tmp)


def main():
    if not os.path.isdir(SITE):
        print("site/ does not exist - run python3 ml/site.py first", file=sys.stderr)
        return 1

    problems, pages, modules = [], 0, 0

    for name in sorted(os.listdir(os.path.join(SITE, "assets"))):
        if name.endswith(".js"):
            p = os.path.join(SITE, "assets", name)
            node_check(open(p, encoding="utf-8").read(), "assets/" + name, problems)
            modules += 1

    for dirpath, _, files in os.walk(SITE):
        for name in sorted(files):
            if not name.endswith(".html"):
                continue
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, SITE).replace(os.sep, "/")
            src = open(p, encoding="utf-8").read()
            pages += 1
            for needle in NEEDS:
                if needle not in src:
                    problems.append("%s: does not link %s" % (rel, needle))
            for i, code in enumerate(MODULE.findall(src)):
                node_check(code, "%s (module %d)" % (rel, i + 1), problems)
                modules += 1

    print("site: %d page(s), %d module(s) checked" % (pages, modules))
    for p in problems:
        print("  ! " + p)
    print("=== RESULT: %d problem(s) ===" % len(problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
