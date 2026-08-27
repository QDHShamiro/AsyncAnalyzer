"""
Proves the session ("overall scan") model:
  1. scores realistic scans correctly (clean stays Clean — no false alarms),
  2. auto-labels only unambiguous scans,
  3. genuinely LEARNS a new overall pattern from repeated scans,
  4. does NOT drift into false positives on clean scans while learning.

Run:  python3 test_session.py
"""

import copy
import session_model as S

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {label:46s} {detail}")
    else:
        failed += 1
        print(f"  [FAIL] {label:46s} {detail}")


# ---------------------------------------------------------------- scoring ---
SCANS = [
    # (label, raw, allowed bands)
    ("Perfectly clean (all verified)",
     dict(total_mods=25, verified=25), {"Clean"}),
    ("Normal player, nothing verified",
     dict(total_mods=20, verified=0, review=0), {"Clean"}),
    ("Modpack w/ a few unknown + random names",
     dict(total_mods=40, verified=22, random_named=3), {"Clean"}),
    ("One mod in Review, nothing else",
     dict(total_mods=15, verified=10, review=1), {"Clean"}),
    ("Confirmed cheat jar found",
     dict(total_mods=20, verified=12, flagged=1, hard_confirmed=1), {"Confirmed"}),
    ("Clean mods but JVM injection",
     dict(total_mods=18, verified=18, jvm_inject=2), {"Likely", "Confirmed"}),
    ("Clean mods but cheat process running",
     dict(total_mods=12, verified=9, cheat_procs=1), {"Likely", "Confirmed"}),
    ("Mods deleted right before the scan",
     dict(total_mods=6, verified=2, bam_deleted=6, sys_issues=2), {"Clean", "Review"}),
    ("Stray cheat jars + cheat folder on disk",
     dict(total_mods=10, verified=8, stray_jars=3, cheat_folders=1), {"Review", "Likely"}),
    ("Downloaded from a cheat site",
     dict(total_mods=10, verified=5, cheatsite_dl=1, flagged=1), {"Likely", "Confirmed"}),
    # v2: injected ghost clients + the "wiped it before the screenshare" pattern
    ("Cheat client identified in live memory",
     dict(total_mods=20, verified=20, mem_client=1, jvm_inject=1, mc_running=1), {"Confirmed"}),
    ("Jars deleted while Minecraft still runs",
     dict(total_mods=5, verified=3, deleted_jars=2, bam_deleted=2, mc_running=1), {"Likely", "Confirmed"}),
    ("Same deletions but Minecraft is closed",
     dict(total_mods=5, verified=3, deleted_jars=2, bam_deleted=2), {"Clean", "Review"}),
    ("Clean scan while Minecraft is running",
     dict(total_mods=25, verified=25, mc_running=1), {"Clean"}),
    ("Busy modpack, game open, nothing wrong",
     dict(total_mods=140, verified=90, random_named=4, mc_running=1), {"Clean"}),
]

print("=== Session scoring (whole scan, not one jar) ===")
for label, raw, allowed in SCANS:
    v = S.verdict(raw)
    check(label, v["band"] in allowed,
          f"score={v['score']:3d} band={v['band']:9s} want {sorted(allowed)}")

# --------------------------------------------------------------- labelling ---
print("\n=== Auto-labelling (only unambiguous scans teach) ===")
check("confirmed cheat -> label 1",
      S.label_for(dict(total_mods=10, verified=5, hard_confirmed=1)) == 1)
check("jvm injection -> label 1",
      S.label_for(dict(total_mods=10, verified=10, jvm_inject=1)) == 1)
check("all-verified clean scan -> label 0",
      S.label_for(dict(total_mods=10, verified=10)) == 0)
check("ambiguous (review only) -> no label",
      S.label_for(dict(total_mods=10, verified=8, review=1)) is None)
check("ambiguous (deleted execs) -> no label",
      S.label_for(dict(total_mods=10, verified=10, bam_deleted=4)) is None)
check("memory-identified client -> label 1",
      S.label_for(dict(total_mods=10, verified=10, mem_client=1)) == 1)
check("deleted jars alone -> no label",
      S.label_for(dict(total_mods=10, verified=10, deleted_jars=2, mc_running=1)) is None)
check("empty scan -> no label",
      S.label_for(dict(total_mods=0)) is None)

# ---------------------------------------------------------------- learning ---
print("\n=== Learning from whole scans (federated-style) ===")
# A NEW pattern the prior underrates: a mods folder full of random/hash-named
# jars and nothing verified — exactly how ghost clients (Doomsday) ship. Base
# score is low; after the team confirms it repeatedly, it should score far higher.
# The clean control includes a modpack with a FEW random names, so this also
# tests that the model learns the ratio, not just "random names exist".
NOVEL = dict(total_mods=12, verified=0, random_named=9, review=2)
CLEAN_CONTROL = [
    dict(total_mods=25, verified=25),
    dict(total_mods=20, verified=0),
    dict(total_mods=40, verified=22, random_named=3),
    dict(total_mods=15, verified=10, review=1),
    dict(total_mods=140, verified=90, random_named=4, mc_running=1),
]

w = copy.deepcopy(S.WEIGHTS)
b = S.INTERCEPT
before = S.verdict(NOVEL, w, b)["score"]

# 12 scans across the "team": the novel pattern confirmed, mixed with clean ones
for _ in range(12):
    vec = S.raw_to_vector(NOVEL)
    w, b = S.sgd_step(w, b, vec, 1)
    for c in CLEAN_CONTROL:
        w, b = S.sgd_step(w, b, S.raw_to_vector(c), 0)

after = S.verdict(NOVEL, w, b)["score"]
check("novel cheat pattern score climbs", after > before + 15,
      f"{before}% -> {after}%")

worst_clean = 0
for c in CLEAN_CONTROL:
    v = S.verdict(c, w, b)
    worst_clean = max(worst_clean, v["score"])
check("clean scans stay Clean after learning", worst_clean < 30,
      f"worst clean score {worst_clean}")

# a genuinely clean scan must never be pushed up by learning
v_clean = S.verdict(dict(total_mods=25, verified=25), w, b)
check("all-verified scan still Clean", v_clean["band"] == "Clean",
      f"score={v_clean['score']}")

# hard proof must still dominate no matter what the weights drifted to
v_hard = S.verdict(dict(total_mods=20, verified=12, flagged=1, hard_confirmed=1), w, b)
check("hard-confirmed still Confirmed", v_hard["band"] == "Confirmed",
      f"score={v_hard['score']}")

print(f"\n=== RESULT: {passed} passed, {failed} failed ===")
raise SystemExit(0 if failed == 0 else 1)
