"""Run every -SelfTest bytecode case through ml/verdict.py.

The self-test cases are written in PowerShell and no PowerShell runs here, so
without this they would be unverified until someone runs the tool on Windows -
which is exactly the kind of thing that is discovered in front of a suspect.
"""
import os, re, sys, pathlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verdict as V

ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / 'src' / '50-analysis.ps1').read_text(encoding='utf-8')
body = src[src.index('function Invoke-SelfTest'):]
cases = re.findall(
    r'@\{ Label = "([^"]+)"; Bands = @\(([^)]*)\); Over = @\{(.*?)\} \}\n', body)

def to_raw(over):
    raw = {}
    bc = {"classes_parsed": 10}
    m = re.search(r'Bytecode = \(New-TestBytecode @\{([^}]*)\}\)', over)
    if m:
        for k, v in re.findall(r'(\w+)\s*=\s*([\d.]+)', m.group(1)):
            if k in ("ObfNameRatio", "StrReadableRatio", "StrEntropy"):
                continue
            bc["bc_" + k[:-5].lower() + "_ratio"] = float(v)
    raw["bytecode"] = bc
    # FilenameClient was missing here, which meant every self-test case that used it
    # was silently unverified on this side: the mirror scored it as if the filename
    # had never matched, and passed for the wrong reason or failed for one.
    for flag, key in (("Verified", "verified"), ("LegitModId", "legit_modid"),
                      ("HashKnownCheat", "hash_known_cheat"), ("RandomName", "random_name"),
                      ("CheatSite", "cheatsite"), ("FilenameClient", "filename_client")):
        if re.search(r'\b%s = \$true' % flag, over):
            raw[key] = True
    f = re.search(r'Features = \(New-TestFeatures @\{([^}]*)\}\)', over)
    if f:
        # Same gap on the other side: only NUMERIC fields were read out, so a case
        # setting PackageHits (a list) looked to the mirror like an empty jar.
        for lst, key in (("PackageHits", "pkgpath"), ("StrongStrings", "strong_sig"),
                         ("WeakStrings", "weak_sig")):
            m2 = re.search(r'%s\s*=\s*@\(([^)]*)\)' % lst, f.group(1))
            if m2 and re.search(r'["\']', m2.group(1)):
                raw[key] = len(re.findall(r'["\'][^"\']+["\']', m2.group(1)))
        for k, v in re.findall(r'(\w+)\s*=\s*([\d.]+)', f.group(1)):
            raw[{"SingleCharClsPct": "singlechar_cls_pct", "HighEntropyPct": "high_entropy_pct",
                 "AvgEntropy": "avg_entropy", "ReflectionCount": "reflection_count",
                 "PaddingEntry": "padding_entry", "HiddenPayload": "hidden_payload"}.get(k, k.lower())] = float(v)
    return raw

BYTECODE_ONLY = [c for c in cases if "New-TestBytecode" in c[2]]
print("checking %d self-test cases that carry bytecode\n" % len(BYTECODE_ONLY))
bad = 0
for label, bands, over in BYTECODE_ONLY:
    want = re.findall(r'"(\w+)"', bands)
    got = V.verdict(to_raw(over))
    ok = got["band"] in want
    if not ok:
        bad += 1
    print("  %s  %-40s -> %-10s score=%-3d (want %s)"
          % ("PASS" if ok else "FAIL", label, got["band"], got["score"], "/".join(want)))
print("\n=== RESULT: %d passed, %d failed ===" % (len(BYTECODE_ONLY) - bad, bad))
sys.exit(1 if bad else 0)
