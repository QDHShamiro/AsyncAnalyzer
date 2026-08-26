"""
Prove the self-improvement loop:
  1. Take a "novel cheat family" the base model is unsure about (~borderline).
  2. Feed a handful of user-confirmed cheat examples of it (online SGD steps).
  3. Show the model now scores that family clearly higher — it LEARNED.
  4. Show the 22 real clean library jars STILL score Clean afterwards
     (self-improvement must never create false positives).

Run:  python3 test_selflearn.py
"""

import copy
import json
import os

import features
import online_learn
import verdict
from features import FEATURE_NAMES, raw_to_vector

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = json.load(open(os.path.join(HERE, "model.json")))
ORDER = MODEL["feature_order"]


def score_with(weights, intercept, vec):
    z = intercept + sum(weights[ORDER[i]] * vec[i] for i in range(len(ORDER)))
    return round(online_learn.sigmoid(z) * 100)


def main():
    # a novel cheat family the base model UNDER-detects (scores it low): two
    # cheat signatures + one weak indicator, no package path, no known hash.
    # It is separable from legit libs (which have no cheat signatures at all).
    novel = dict(strong_count=2, weak_count=1, avg_entropy=6.2)
    novel_vec = raw_to_vector(novel)

    # a legit control that looks a bit similar (runtime lib) — must stay low
    control = dict(runtime_exec=1, reflection_count=2, avg_entropy=6.6,
                   novowel_cls_pct=0.2)
    control_vec = raw_to_vector(control)

    weights = copy.deepcopy(MODEL["weights"])
    intercept = MODEL["intercept"]
    base_w = copy.deepcopy(MODEL["weights"])
    base_b = MODEL["intercept"]

    before_novel = score_with(weights, intercept, novel_vec)
    before_control = score_with(weights, intercept, control_vec)

    print("=== Before learning ===")
    print(f"  novel cheat family : {before_novel}%")
    print(f"  legit control      : {before_control}%")

    # negatives the tool learns from automatically (every verified mod is a
    # confirmed label-0 example) — load a few real clean jars as negatives
    jars = os.path.join(HERE, "jars_legit")
    neg_vecs = []
    if os.path.isdir(jars):
        for f in sorted(os.listdir(jars)):
            if f.endswith(".jar"):
                neg_vecs.append(raw_to_vector(features.extract_from_jar(os.path.join(jars, f))))

    # realistic mixed stream: each round = 1 confirmed cheat (label 1) +
    # 1 confirmed-clean verified mod (label 0). Keeps the boundary balanced.
    print("\n=== Learning from a mixed confirmed stream (cheats + verified) ===")
    for k in range(30):
        j = dict(novel)
        j["avg_entropy"] = 6.4 + (k % 3) * 0.1
        j["singlechar_cls_pct"] = 0.1 + (k % 3) * 0.02
        intercept, _ = online_learn.sgd_step(
            weights, intercept, raw_to_vector(j), ORDER, label=1, lr=0.12,
            base=base_w, base_intercept=base_b)
        if neg_vecs:
            intercept, _ = online_learn.sgd_step(
                weights, intercept, neg_vecs[k % len(neg_vecs)], ORDER, label=0,
                lr=0.12, base=base_w, base_intercept=base_b)
        if k in (0, 14, 29):
            print(f"  round {k+1:2d}: novel now {score_with(weights, intercept, novel_vec)}%")

    after_novel = score_with(weights, intercept, novel_vec)
    after_control = score_with(weights, intercept, control_vec)

    print("\n=== After learning ===")
    print(f"  novel cheat family : {before_novel}% -> {after_novel}%  "
          f"({'LEARNED' if after_novel > before_novel + 15 else 'no change'})")
    print(f"  legit control      : {before_control}% -> {after_control}%")

    # SAFETY 1: no clean jar is ever pushed into the Flagged band (>=60) by
    # learning. Worst it can do to an unknown legit file is nudge it to Review.
    # SAFETY 2: real mods are verified -> hard Clean cap, immune to model drift.
    worst_raw = 0
    worst_verdict_clean = True
    n = 0
    if os.path.isdir(jars):
        for f in sorted(os.listdir(jars)):
            if not f.endswith(".jar"):
                continue
            raw = features.extract_from_jar(os.path.join(jars, f))
            worst_raw = max(worst_raw, score_with(weights, intercept, raw_to_vector(raw)))
            raw["verified"] = 1  # real mods are verified on Modrinth/CurseForge
            if verdict.verdict(raw)["band"] != "Clean":
                worst_verdict_clean = False
            n += 1

    ok_learn = before_novel < 40 and after_novel >= 60
    ok_safe = worst_raw < 60            # learning never creates a Flagged false-positive
    ok_verified = worst_verdict_clean   # verified files stay Clean regardless
    ok_control = after_control < 60

    print("\n=== SAFETY after adaptation ===")
    print(f"  worst raw score on {n} real jars : {worst_raw}  "
          f"({'never Flagged' if ok_safe else 'FLAGGED A CLEAN FILE'})")
    print(f"  same jars as verified mods       : "
          f"{'all Clean (hard cap)' if ok_verified else 'REGRESSION'}")

    print("\n=== RESULT ===")
    print(f"  learned the new family    : {'PASS' if ok_learn else 'FAIL'}")
    print(f"  never flags a clean file  : {'PASS' if ok_safe else 'FAIL'}")
    print(f"  verified files stay Clean : {'PASS' if ok_verified else 'FAIL'}")
    print(f"  legit control safe        : {'PASS' if ok_control else 'FAIL'}")
    return 0 if (ok_learn and ok_safe and ok_verified and ok_control) else 1


if __name__ == "__main__":
    raise SystemExit(main())
