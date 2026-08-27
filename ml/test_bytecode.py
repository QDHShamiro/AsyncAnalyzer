"""
Proves the behavioural (bytecode) analyser on REAL compiled bytecode.

The point it demonstrates: every individual behaviour appears in BOTH cheats and
legitimate mods. A minimap renders; so does ESP. A keybind mod polls input; so
does KillAura. A config library uses reflection; so does a dropper. Only the
COMBINATION separates them - which is exactly what a linear model cannot express
and why the detector needs an interaction-capable one.

The cheat sources under corpus_src/cheat are reconstructions of behaviour read
out of real cheat-client source (Meteor Client @8038a0a): rewriting your own
outgoing ServerboundMovePlayerPacket with forged yaw/pitch. They are compiled by
javac, so the constant pools are produced by a real compiler, not hand-written.

Run:  python3 test_bytecode.py     (needs javac; skips cleanly without it)
"""

import glob
import os
import shutil
import subprocess
import sys
import tempfile

import bytecode

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "corpus_src")


def build(tmp):
    out = os.path.join(tmp, "out")
    os.makedirs(out, exist_ok=True)
    srcs = glob.glob(os.path.join(SRC, "**", "*.java"), recursive=True)
    if not srcs:
        return None
    r = subprocess.run(["javac", "-nowarn", "-d", out] + srcs,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("javac failed:\n", r.stderr[-500:])
        return None
    jars = os.path.join(tmp, "jars")
    os.makedirs(jars, exist_ok=True)
    # the mc/ package is the game's own API - it lives in Minecraft, never inside
    # a mod jar. Bundling it would make every jar look like it touches packets.
    for kind, names in (("cheat", ["KillAura", "Esp", "Flight", "Loader"]),
                        ("clean", ["Minimap", "ConfigBinder", "Keybinds"])):
        for nm in names:
            jp = os.path.join(jars, "%s_%s.jar" % (kind, nm))
            subprocess.run(["jar", "cf", jp] + sorted(glob.glob(
                os.path.join(out, kind, nm + "*.class"))), cwd=out, check=False)
    return jars


def rules(r):
    """Combination rules. Ratios, not raw counts: netty-handler does crypto in 2 of
    120 classes because it speaks TLS, while a packed loader does it in nearly all
    of them. Counting absolutely made netty look like a dropper."""
    return {
        # forging your own outgoing movement packet with a computed rotation
        "aim": r["bc_movepacket_ratio"] > 0 and r["bc_rotation_ratio"] > 0,
        # drawing from a full entity sweep
        "esp": r["bc_render_ratio"] > 0 and r["bc_entityscan_ratio"] > 0,
        # decrypt-then-define-a-class, across most of the jar
        "dropper": (r["bc_crypto_ratio"] >= 0.5
                    and (r["bc_classload_ratio"] > 0 or r["bc_reflect_ratio"] >= 0.5)),
    }


def main():
    if not shutil.which("javac"):
        print("javac not available - skipping bytecode corpus test")
        return 0
    tmp = tempfile.mkdtemp(prefix="aa_bc_")
    try:
        jars = build(tmp)
        if not jars:
            print("could not build corpus")
            return 1
        passed = failed = 0
        print("=== Behaviour extraction on real compiled bytecode ===")
        for jp in sorted(glob.glob(os.path.join(jars, "*.jar"))):
            r = bytecode.extract_jar(jp)
            hit = any(rules(r).values())
            want = os.path.basename(jp).startswith("cheat_")
            ok = hit == want
            passed += ok
            failed += not ok
            got = sorted(k.replace("bc_", "") for k, v in r.items()
                         if k.startswith("bc_") and v and not k.endswith("_ratio"))
            print("  [%s] %-26s combo=%-5s %s" % (
                "PASS" if ok else "FAIL", os.path.basename(jp), hit, got))

        # real libraries must trip no combination rule at all
        print("\n=== Real library jars (must trip no rule) ===")
        worst = []
        for jp in sorted(glob.glob(os.path.join(HERE, "jars_legit", "*.jar"))):
            r = bytecode.extract_jar(jp, max_classes=120)
            if any(rules(r).values()):
                worst.append(os.path.basename(jp))
                failed += 1
            else:
                passed += 1
        n = len(glob.glob(os.path.join(HERE, "jars_legit", "*.jar")))
        print("  %d real jars, %d tripped a rule%s" % (
            n, len(worst), (": " + ", ".join(worst)) if worst else " -> none"))

        print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
        return 0 if failed == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
