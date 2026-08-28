"""
Session ("overall scan") model — the second AI in AsyncAnalyzer.

The mod model scores ONE jar. This one scores the WHOLE scan: mods plus the
system evidence (JVM injection, cheat processes, deleted executables, stray
jars, cheat folders, system issues). It is the thing that answers
"does this PC look like someone is cheating?" instead of only
"is this single file a cheat?".

It is a logistic regression like the mod model, so it:
  * runs in pure PowerShell (dot product + sigmoid, no deps),
  * learns online with the same bounded, base-anchored SGD (can't drift into
    false positives),
  * can be trained federated on the backend across every team member's scans.

This file is the SOURCE OF TRUTH for the weights. Run it to (re)generate
ml/session_model.json, which the .ps1 embeds and auto-updates from.
"""

import json
import math
import os

FEATURE_NAMES = [
    "flagged_ratio",     # flagged mods / total mods
    "review_ratio",      # review mods / total mods
    "unverified_ratio",  # (total - verified) / total
    "random_ratio",      # random/hash-named jars / total
    "cheatsite_dl",      # 0/1 any mod downloaded from a known cheat site
    "hard_confirmed",    # 0/1 any mod Confirmed by a hard rule (hash/pkg/site)
    "sys_issues",        # min(systemIssues,10)/10
    "jvm_inject",        # min(jvmFindings,5)/5
    "bam_deleted",       # min(deleted executables,10)/10
    "cheat_procs",       # min(flagged cheat processes,5)/5
    "stray_jars",        # min(stray cheat jars on disk,3)/3
    "cheat_folders",     # min(cheat client folders found,2)/2
    "deleted_jars",      # min(.jar files that ran and were deleted,3)/3
    "mc_running",        # 0/1 Minecraft is running right now
    "mem_client",        # 0/1 a named cheat CLIENT was identified in the live JVM
    # --- v3: what the BEHAVIOUR rules found -----------------------------------
    # These were the tool's strongest evidence and they reached this model through
    # nothing but flagged_ratio, which a big modpack divides away: measured, a
    # 100-mod pack containing ONE behaviour-confirmed aimbot scored 3/100 - Clean.
    # A hash match scored 85 for the same jar. That was backwards: the behaviour
    # rules survive renaming, obfuscation and string encryption, and a hash does not.
    "behaviour_cheat",   # 0/1 a mod was CONFIRMED by a behaviour rule (aim, scaffold, ...)
    "behaviour_likely",  # 0/1 a mod reached Likely by a behaviour rule
    "server_rule",       # server-rule findings (ESP, printer) - a rule question, low weight
    "hidden_api",        # mods reaching Minecraft through reflection so the names are hidden
    # A click macro is a cheat that is never in the mods folder. It has to be a
    # FEATURE and not only a hard rule: label_for() teaches on it, and teaching on
    # evidence the vector cannot see pushes the intercept instead of the weight.
    "macro_cheat",       # 0/1 a click macro that loops and names Minecraft
]

VERSION = 3

# Expert prior. Deliberately conservative: nothing except real proof
# (a hard-confirmed cheat, an injected JVM, a cheat process) can push a scan
# out of Clean on its own. "Lots of unverified mods" is normal and must stay
# Clean — that is the difference between this and a paranoid scanner.
INTERCEPT = -4.0
WEIGHTS = {
    "flagged_ratio":    4.0,
    "review_ratio":     1.2,
    "unverified_ratio": 0.8,
    "random_ratio":     1.5,
    "cheatsite_dl":     3.0,
    "hard_confirmed":   4.5,
    "sys_issues":       1.2,
    "jvm_inject":       3.0,
    "bam_deleted":      1.0,   # lowered: deleted_jars now carries the specific signal
    "cheat_procs":      3.5,
    "stray_jars":       2.0,
    "cheat_folders":    3.0,
    "deleted_jars":     2.5,
    "mc_running":       0.0,   # running Minecraft is not evidence of anything by itself
    "mem_client":       5.0,
    # A behaviour-confirmed cheat is proof of the same order as a hash match, so it
    # carries the same weight as hard_confirmed rather than less.
    "behaviour_cheat":  4.5,
    "behaviour_likely": 2.0,
    # Deliberately small. A server-rule finding is NOT an accusation - it exists to
    # put a rule question in front of a person, and the hard rule below floors the
    # scan at Review for exactly that. It must never add up to a flag on its own.
    "server_rule":      0.8,
    "hidden_api":       0.8,
    "macro_cheat":      4.5,
}


def _c01(x):
    x = float(x)
    return 0.0 if x < 0 else (1.0 if x > 1 else x)


def raw_to_vector(raw):
    """raw = plain counts dict -> the ordered, normalised feature vector."""
    total = max(int(raw.get("total_mods", 0)), 0)
    den = float(total) if total > 0 else 1.0
    return [
        _c01(raw.get("flagged", 0) / den),
        _c01(raw.get("review", 0) / den),
        _c01((total - raw.get("verified", 0)) / den) if total > 0 else 0.0,
        _c01(raw.get("random_named", 0) / den),
        1.0 if raw.get("cheatsite_dl") else 0.0,
        1.0 if raw.get("hard_confirmed") else 0.0,
        _c01(min(raw.get("sys_issues", 0), 10) / 10.0),
        _c01(min(raw.get("jvm_inject", 0), 5) / 5.0),
        _c01(min(raw.get("bam_deleted", 0), 10) / 10.0),
        _c01(min(raw.get("cheat_procs", 0), 5) / 5.0),
        _c01(min(raw.get("stray_jars", 0), 3) / 3.0),
        _c01(min(raw.get("cheat_folders", 0), 2) / 2.0),
        _c01(min(raw.get("deleted_jars", 0), 3) / 3.0),
        1.0 if raw.get("mc_running") else 0.0,
        1.0 if raw.get("mem_client", 0) else 0.0,
        1.0 if raw.get("behaviour_cheat", 0) else 0.0,
        1.0 if raw.get("behaviour_likely", 0) else 0.0,
        _c01(min(raw.get("server_rule", 0), 2) / 2.0),
        _c01(min(raw.get("hidden_api", 0), 2) / 2.0),
        1.0 if raw.get("macro_cheat", 0) else 0.0,
    ]


def probability(vec, weights=None, intercept=None):
    w = WEIGHTS if weights is None else weights
    b = INTERCEPT if intercept is None else intercept
    z = b + sum(w[FEATURE_NAMES[i]] * vec[i] for i in range(len(FEATURE_NAMES)))
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


def verdict(raw, weights=None, intercept=None):
    """Mirrors Get-SessionVerdict in AsyncAnalyzer.ps1."""
    vec = raw_to_vector(raw)
    p = probability(vec, weights, intercept)
    score = round(p * 100)

    # Hard rules — real proof always wins over the model.
    if raw.get("hard_confirmed"):
        score = max(score, 85)
    if raw.get("jvm_inject", 0) > 0:
        score = max(score, 60)
    if raw.get("cheat_procs", 0) > 0:
        score = max(score, 60)
    if raw.get("cheatsite_dl"):
        score = max(score, 60)
    if raw.get("stray_jars", 0) > 0 or raw.get("cheat_folders", 0) > 0:
        score = max(score, 30)
    # A named cheat client sitting in the live JVM heap is the strongest proof there is:
    # the cheat is loaded and running right now, whatever the mods folder looks like.
    if raw.get("mem_client", 0) > 0:
        score = max(score, 85)
    # Jars that ran on this PC and were deleted while the game is still open is the
    # classic "he wiped it right before the screenshare" pattern.
    if raw.get("deleted_jars", 0) > 0 and raw.get("mc_running"):
        score = max(score, 60)
    # A mod confirmed by its BEHAVIOUR is proof of the same order as a hash match -
    # and stronger in one way, because it survives renaming and string encryption
    # while a hash does not. Before this rule existed, one behaviour-confirmed
    # aimbot in a 100-mod pack left the whole scan reading Clean at 3/100.
    if raw.get("behaviour_cheat", 0) > 0:
        score = max(score, 85)
    if raw.get("behaviour_likely", 0) > 0:
        score = max(score, 60)
    # A server-rule finding is not an accusation, and this floor is not one either:
    # it puts the scan in front of a person, which is the entire purpose of the band.
    if raw.get("server_rule", 0) > 0:
        score = max(score, 30)
    # An autoclicker is not a mod and never appears in the mods folder. A script
    # that repeats mouse input IN A LOOP and names the Minecraft window, the
    # launcher or javaw has no second reading. These reach the verdict as hard
    # rules rather than as features: the 15 above are trained and versioned, and
    # one cannot be bolted on without retraining the model.
    if raw.get("macro_cheat", 0) > 0:
        score = max(score, 85)
    # Butterfly-click, blockhit, autocrystal and the rest are Minecraft terms. A file
    # with one of those names containing a click loop IS an autoclicker; what the file
    # alone does not prove is which game it was used in - a question for the person
    # reading the report rather than a reason to score it lower.
    if raw.get("macro_named", 0) > 0:
        score = max(score, 85)

    return {"score": score, "band": band(score), "probability": round(p * 100)}


def label_for(raw):
    """Auto-label a finished scan. Returns 1, 0 or None (ambiguous -> no learning).
    Only unambiguous scans teach the model — that is what keeps it from drifting."""
    if (raw.get("hard_confirmed") or raw.get("jvm_inject", 0) > 0
            or raw.get("cheat_procs", 0) > 0 or raw.get("mem_client", 0) > 0
            or raw.get("macro_cheat", 0) > 0 or raw.get("behaviour_cheat", 0) > 0):
        return 1
    if (
        raw.get("total_mods", 0) > 0
        and raw.get("flagged", 0) == 0
        and raw.get("review", 0) == 0
        and raw.get("sys_issues", 0) == 0
        and raw.get("bam_deleted", 0) == 0
        and raw.get("stray_jars", 0) == 0
        and raw.get("cheat_folders", 0) == 0
        and raw.get("deleted_jars", 0) == 0
        and raw.get("macro_cheat", 0) == 0
        and raw.get("macro_named", 0) == 0
        and raw.get("behaviour_cheat", 0) == 0
        and raw.get("behaviour_likely", 0) == 0
        and raw.get("server_rule", 0) == 0
        and raw.get("verified", 0) >= 0.6 * raw.get("total_mods", 0)
    ):
        return 0
    return None


def sgd_step(weights, intercept, vec, label, lr=0.05, l2=0.02, clamp=8.0,
             base_weights=None, base_intercept=None):
    """One bounded, base-anchored SGD step. Same maths as the mod model."""
    bw = WEIGHTS if base_weights is None else base_weights
    bi = INTERCEPT if base_intercept is None else base_intercept
    p = probability(vec, weights, intercept)
    err = p - label
    for i, k in enumerate(FEATURE_NAMES):
        w = weights[k] - lr * (err * vec[i] + l2 * (weights[k] - bw[k]))
        weights[k] = max(-clamp, min(clamp, w))
    intercept = intercept - lr * (err + l2 * (intercept - bi))
    intercept = max(-clamp, min(clamp, intercept))
    return weights, intercept


if __name__ == "__main__":
    out = {
        "version": VERSION,
        "feature_order": FEATURE_NAMES,
        "intercept": INTERCEPT,
        "weights": WEIGHTS,
        "note": "Session / overall-scan model. Source of truth: ml/session_model.py",
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "session_model.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print("wrote", path)
