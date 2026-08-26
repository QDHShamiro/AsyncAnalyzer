"""
Reference port of the AsyncAnalyzer.ps1 verdict logic (Get-ModFeatureVector +
Invoke-MlModel + Get-ModVerdict). Kept byte-for-byte equivalent to the
PowerShell so we can test the end-to-end behaviour here. If you change the
scoring in the .ps1, change it here too and re-run test_verdict.py.
"""

import json
import math
import os

import features
from features import FEATURE_NAMES, raw_to_vector

_MODEL = json.load(open(os.path.join(os.path.dirname(__file__), "model.json")))
_W = _MODEL["weights"]
_B = _MODEL["intercept"]
_ORDER = _MODEL["feature_order"]


def ml_probability(raw_vec):
    z = _B + sum(_W[_ORDER[i]] * raw_vec[i] for i in range(len(_ORDER)))
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def band(score):
    if score >= 85:
        return "Confirmed"
    if score >= 60:
        return "Likely"
    if score >= 30:
        return "Review"
    return "Clean"


def verdict(raw):
    """raw = the raw-signals dict (same one features.extract_from_jar returns,
    plus provenance flags). Returns {score, band, probability}."""
    vec = raw_to_vector(raw)
    p = ml_probability(vec)
    score = round(p * 100)

    if raw.get("hash_known_cheat"):
        score = 100
    if raw.get("pkgpath"):
        score = max(score, 80)
    if raw.get("cheatsite"):
        score = max(score, 75)
    if raw.get("fake_identity"):
        score = max(score, 70)
    if raw.get("filename_client"):
        score = max(score, 60)

    # Random / hash-style filename on an unverified mod: floor to Review (never a flag)
    # so it is surfaced instead of slipping through as "unknown". Verified / legit mods
    # are exempt (capped safe below). Mirrors Get-ModVerdict in AsyncAnalyzer.ps1.
    if raw.get("random_name") and not (raw.get("verified") or raw.get("legit_modid")):
        floor = 35
        if (
            raw.get("high_entropy_pct", 0.0) >= 0.25
            or raw.get("singlechar_cls_pct", 0.0) >= 0.25
            or raw.get("fullwidth_cls_pct", 0.0) > 0
            or raw.get("nested_hollow")
            or (
                raw.get("reflection_count", 0) >= 2
                and (raw.get("http_download") or raw.get("runtime_exec") or raw.get("http_exfil"))
            )
        ):
            floor = 55
        if score < floor:
            score = floor

    if raw.get("verified") or raw.get("legit_modid"):
        score = min(score, 20)

    return {"score": score, "band": band(score), "probability": round(p * 100)}


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        r = features.extract_from_jar(path)
        print(path, verdict(r))
