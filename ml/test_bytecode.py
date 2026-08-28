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


def coverage_test():
    """A cheat's modules are not required to sit at the front of the archive.

    First-N sampling missed a cheat class at position 40 of 300 completely, and
    real jars run to a median of 218 classes - so the default scan would have been
    blind to any real cheat client. Behaviour detection must be depth-independent.
    """
    import io
    import zipfile
    src = dst = None
    for root, _, files in os.walk(tempfile.gettempdir()):
        pass
    # build the probe from the compiled corpus
    tmp = tempfile.mkdtemp(prefix="aa_cov_")
    try:
        jars = build(tmp)
        if not jars:
            return 0, 0
        out = os.path.join(tmp, "out")
        cheat = sorted(glob.glob(os.path.join(out, "cheat", "KillAura*.class")))[0]
        filler = sorted(glob.glob(os.path.join(out, "clean", "Keybinds*.class")))[0]
        cb = open(cheat, "rb").read()
        fb = open(filler, "rb").read()
        lb = open(sorted(glob.glob(os.path.join(out, "cheat", "Loader*.class")))[0], "rb").read()
        passed = failed = 0

        def build_probe(pos, total, payload):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for i in range(total):
                    z.writestr("p/C%05d.class" % i, payload if i == pos else fb)
            probe = os.path.join(tmp, "probe.jar")
            open(probe, "wb").write(buf.getvalue())
            return probe

        print("\n=== Depth independence (default fast mode) ===")
        for total in (300, 1000, 5000):
            for frac in (0.0, 0.13, 0.5, 0.999):
                pos = int(total * frac)
                r = bytecode.extract_jar(build_probe(pos, total, cb), max_classes=40)
                ok = r["bc_movepacket"] > 0 and r["bc_rotation"] > 0
                passed += ok
                failed += not ok
                print("  [%s] aim cheat at %5d of %5d -> detected=%s" % (
                    "PASS" if ok else "FAIL", pos, total, ok))

        # a dropper hidden in the very last class of a huge jar
        r = bytecode.extract_jar(build_probe(4999, 5000, lb), max_classes=40)
        ok = r["bc_crypto_ratio"] > 0 and (r["bc_classload_ratio"] > 0 or r["bc_reflect_ratio"] > 0)
        passed += ok
        failed += not ok
        print("  [%s] dropper at  4999 of  5000 -> detected=%s" % ("PASS" if ok else "FAIL", ok))

        # and the same jar with no cheat class in it must stay quiet
        r = bytecode.extract_jar(build_probe(-1, 5000, fb), max_classes=40)
        quiet = not (r["bc_movepacket"] > 0 and r["bc_rotation"] > 0) and r["bc_crypto"] == 0
        passed += quiet
        failed += not quiet
        print("  [%s] clean 5000-class jar stays quiet" % ("PASS" if quiet else "FAIL"))
        return passed, failed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)



def parity_test():
    """The behaviour table lives in two places - ml/bytecode.py and the shipped
    PowerShell. They have to name the same categories and the same patterns, or the
    tool detects something different from what the corpus measured and nothing here
    would notice."""
    import re
    root = os.path.dirname(HERE)
    ps = open(os.path.join(root, "src", "30-runtime.ps1"), encoding="utf-8").read()
    block = re.search(r"\$script:bcBehaviour = \[ordered\]@\{(.*?)\n\}", ps, re.S).group(1)
    ps_cats = {}
    for m in re.finditer(r"^\s*'(\w+)'\s*=\s*'(.*)'\s*$", block, re.M):
        ps_cats[m.group(1)] = m.group(2)
    py_cats = {k[3:]: "|".join(v) for k, v in bytecode.BEHAVIOUR.items()}

    passed = failed = 0
    print("\n=== PowerShell / Python behaviour parity ===")
    missing = sorted(set(py_cats) - set(ps_cats))
    extra = sorted(set(ps_cats) - set(py_cats))
    for label, bad in (("only in Python", missing), ("only in PowerShell", extra)):
        if bad:
            print("  FAIL  %s: %s" % (label, ", ".join(bad)))
            failed += 1
        else:
            passed += 1
    for k in sorted(set(ps_cats) & set(py_cats)):
        # compare the alternation sets, not the raw string - order is free
        a = set(x for x in py_cats[k].split("|") if x)
        b = set(x for x in ps_cats[k].split("|") if x)
        if a == b:
            passed += 1
        else:
            failed += 1
            print("  FAIL  %s differs: py-only=%s ps-only=%s"
                  % (k, sorted(a - b), sorted(b - a)))
    print("  %d categories compared, %d mismatch(es)" % (len(py_cats), failed))

    # The reflective table lives in two places as well, and it is the one that
    # closes the evasion - a drift there reopens it silently.
    ps_refl = re.search(r"\$script:bcReflectiveApi = \[ordered\]@\{(.*?)\n\}", ps, re.S)
    if ps_refl:
        ps_r = dict(re.findall(r"^\s*'(\w+)'\s*=\s*'(.*)'\s*$", ps_refl.group(1), re.M))
        py_r = {k[3:]: v.pattern for k, v in bytecode._REFLECTIVE_API.items()}
        same = {k: ps_r.get(k) == py_r[k] for k in py_r}
        bad = [k for k, ok in same.items() if not ok]
        passed += len(py_r) - len(bad)
        failed += len(bad)
        print("  reflective table: %d categories, %d mismatch(es)%s"
              % (len(py_r), len(bad), (" -> " + ", ".join(bad)) if bad else ""))
        if set(ps_r) != set(py_r):
            failed += 1
            print("  FAIL  reflective categories differ: ps=%s py=%s"
                  % (sorted(ps_r), sorted(py_r)))
    else:
        failed += 1
        print("  FAIL  no reflective table found in the PowerShell source")

    # An aim cheat that reaches Minecraft reflectively used to score Clean at
    # 3/100 - every behaviour rule was evadable with one refactor. Pin the close.
    for sym, want in (("net.minecraft.network.protocol.game.ServerboundMovePlayerPacket", True),
                      ("com.example.MovePlayerHelper", False),
                      ("setYRot", True),
                      ("resetYRotation", False)):
        got = any(rx.search(sym) for rx in bytecode._REFLECTIVE_API.values())
        ok = got == want
        passed += ok
        failed += (not ok)
        print("  %s  reflective token on %-58s -> %s"
              % ("PASS" if ok else "FAIL", sym, got))

    # A bare "\.swing" matched javax/swing and rhino's swingGui field. Pin the fix:
    # a Swing application dropped into a mods folder must not read as combat code.
    for sym, want in (("javax/swing/JButton.setText", False),
                      ("org/x/MoreWindows.swingGui", False),
                      ("net/minecraft/client/player/LocalPlayer.swing", True),
                      ("net/minecraft/class_746.method_6104", True)):
        got = bool(bytecode._COMPILED["bc_attack"].search(sym))
        ok = got == want
        passed += ok
        failed += (not ok)
        print("  %s  attack pattern on %-46s -> %s"
              % ("PASS" if ok else "FAIL", sym, got))
    return passed, failed


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

        cp, cf = coverage_test()
        passed += cp
        failed += cf

        pp, pf = parity_test()
        passed += pp
        failed += pf

        print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
        return 0 if failed == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
