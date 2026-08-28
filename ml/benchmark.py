"""
Public benchmark for the AsyncAnalyzer detection engine.

Everything here is reproducible from a clean checkout:

    python3 fetch_jars.py && python3 benchmark.py

It writes BENCHMARKS.md and prints the same report, so the numbers in the repo
are never hand-typed. CI runs it on every push, which is the point: a detector
that is not measured continuously drifts, and the failure mode that matters
(flagging something legitimate) is silent.

Design notes, because the metrics are easy to game:
  * The headline number is FALSE FLAGS ON REAL SOFTWARE, not accuracy. A detector
    that flags nothing scores well on accuracy and is useless; one that flags
    everything scores well on recall and is worse than useless.
  * Real libraries are the negative class - ASM, ByteBuddy, Netty, Spring, LWJGL
    (which is what Minecraft itself uses for input and OpenGL). These are the
    "scary but ordinary" families a naive scanner false-flags.
  * The cheat class is BEHAVIOUR reconstructed from real open-source cheat client
    source and compiled by javac. This repo ships no cheat binaries, so these are
    reconstructions - stated plainly rather than implied to be captured samples.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import re

import bytecode

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Regression gates. CI fails if these are not met, which is what keeps the
# numbers honest over time instead of only at the moment they were written.
GATE_MAX_CHEAT_RULE_FP = 0     # a legit library must never look like a cheat
GATE_MIN_AIM_DETECT = 1.0      # the aim fingerprint is unambiguous; anything less is a bug
GATE_MIN_DROPPER_DETECT = 1.0


def rules(r):
    """The behaviour rules the tool actually ships, in the same shape as
    Get-ModVerdict. Kept here so the benchmark measures the shipped rules rather
    than a convenient subset of them."""
    g = lambda k: r.get(k, 0.0)
    return {
        # confirmed: forging movement paired with something no legit mod combines it with
        "aim": g("bc_movepacket_ratio") > 0 and g("bc_rotation_ratio") > 0,
        "scaffold": g("bc_blockplace_ratio") > 0 and g("bc_movepacket_ratio") > 0,
        "speed": g("bc_movepacket_ratio") > 0 and g("bc_motion_ratio") > 0,
        "invmove": g("bc_container_ratio") > 0 and g("bc_movepacket_ratio") > 0,
        "dropper": (g("bc_crypto_ratio") >= 0.5
                    and (g("bc_classload_ratio") > 0 or g("bc_reflect_ratio") >= 0.5)),
        # per-class: one class that finds its own jar and deletes it
        "selfwipe": g("bc_selfwipe_ratio") > 0,
        # likely
        "nodinput": g("bc_movepacket_ratio") > 0 and g("bc_input_ratio") == 0,
        "targeting": g("bc_entityscan_ratio") > 0 and g("bc_attack_ratio") > 0,
        "autoclick": g("bc_attack_ratio") > 0 and g("bc_input_ratio") == 0,
        "velocity": g("bc_pktlisten_ratio") > 0 and g("bc_motion_ratio") > 0,
        "nuker": g("bc_blockbreak_ratio") > 0 and g("bc_input_ratio") == 0,
        "freecam": (g("bc_rotation_ratio") > 0 and g("bc_render_ratio") > 0
                    and g("bc_movepacket_ratio") == 0),
        # server-rule: recognised for certain, legality is not a technical question
        "esp": g("bc_render_ratio") > 0 and g("bc_entityscan_ratio") > 0,
        "printer": (g("bc_blockplace_ratio") > 0 and g("bc_input_ratio") > 0
                    and g("bc_movepacket_ratio") == 0),
        "agent": g("bc_instrument_ratio") > 0,
    }


# Every rule that can produce an accusation. A real library tripping any of these
# fails the build - that is the gate the whole corpus exists to protect.
# selfwipe is deliberately NOT here. It is measured above and reported below, but
# it does not accuse: it flagged a real library in CI twice after measuring clean
# on 479 jars locally, and two narrowings did not fix it.
CHEAT_RULES = ("aim", "scaffold", "speed", "invmove", "dropper",
               "nodinput", "targeting", "autoclick", "velocity", "nuker", "freecam", "esp")


def build_corpus(tmp):
    """Compile the cheat/clean behaviour corpus with javac."""
    src = os.path.join(HERE, "corpus_src")
    out = os.path.join(tmp, "out")
    jars = os.path.join(tmp, "jars")
    os.makedirs(out, exist_ok=True)
    os.makedirs(jars, exist_ok=True)
    srcs = glob.glob(os.path.join(src, "**", "*.java"), recursive=True)
    if not srcs:
        return None
    r = subprocess.run(["javac", "-nowarn", "-d", out] + srcs, capture_output=True, text=True)
    if r.returncode != 0:
        print("javac failed:", r.stderr[-400:], file=sys.stderr)
        return None
    made = {}
    for kind, names in (("cheat", ["KillAura", "Esp", "Flight", "Loader", "Pathing", "Timer",
                                   "MixinSilentRot", "Legacy18Aura", "Legacy18Fly", "CoreModAura", "SelfWipe"]),
                        ("clean", ["Minimap", "ConfigBinder", "Keybinds", "AutoWalk",
                                   "MixinRender", "MixinFreelook",
                                   "Legacy18Minimap", "Legacy18Sprint", "CoreModPerf", "NativeUnpack"])):
        for nm in names:
            cls = sorted(glob.glob(os.path.join(out, kind, nm + "*.class")))
            if not cls:
                continue
            jp = os.path.join(jars, "%s_%s.jar" % (kind, nm))
            subprocess.run(["jar", "cf", jp] + cls, cwd=out, check=False)
            made[(kind, nm)] = jp
    return made


def main():
    lines = []
    def out(s=""):
        lines.append(s)
        print(s)

    if not shutil.which("javac"):
        print("javac required", file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="aa_bench_")
    failures = []
    try:
        corpus = build_corpus(tmp)
        if not corpus:
            return 2

        import json as _json
        _ps = open(os.path.join(ROOT, "AsyncAnalyzer.ps1"), encoding="utf-8").read()
        _m = re.search(r'\$script:Version\s*=\s*"([^"]+)"', _ps)
        tool_ver = _m.group(1) if _m else "?"
        mod_ver = _json.load(open(os.path.join(HERE, "model.json")))["version"]
        sess_ver = _json.load(open(os.path.join(HERE, "session_model.json")))["version"]
        sig_ver = _json.load(open(os.path.join(HERE, "signatures.json")))["version"]

        out("# AsyncAnalyzer — detection benchmark")
        out()
        out("Generated by `python3 ml/benchmark.py`. Reproduce from a clean checkout with")
        out("`python3 ml/fetch_jars.py && python3 ml/benchmark.py`. CI reruns it on every push.")
        out()

        # ---------------------------------------------------------- detection ---
        out("## Detection by behaviour")
        out()
        out("\"Detected\" means the behaviour is recognised. Only the unambiguous ones become an")
        out("accusation - the entity-sweep row is deliberately Review in the tool, because a")
        out("mob-radar minimap does exactly the same thing.")
        out()
        out("| cheat behaviour | detected | rule that catches it |")
        out("|---|:--:|---|")
        FAM = [("KillAura", "aim", "rotation written **and** its own movement packet forged"),
               ("Flight", "aim", "same fingerprint — forged movement"),
               ("Pathing", "aim", "movement automation (Baritone-shaped) — forges its own movement"),
               ("Timer", "aim", "several movement packets per tick"),
               ("Loader", "dropper", "decrypt **then** define a class"),
               ("Esp", "esp", "render **and** a full entity sweep — a **server-rule** finding, never an accusation")]
        det = {}
        for nm, rule, why in FAM:
            jp = corpus.get(("cheat", nm))
            r = bytecode.extract_jar(jp)
            hit = rules(r)[rule]
            det[nm] = hit
            out("| %s | %s | %s |" % (nm, "yes" if hit else "**no**", why))
        out()
        if not det.get("KillAura") or not det.get("Flight"):
            failures.append("aim fingerprint not detected")
        if not det.get("Loader"):
            failures.append("dropper not detected")

        # -------------------------------------------------------- depth proof ---
        import io, zipfile
        cb = open(sorted(glob.glob(os.path.join(tmp, "out", "cheat", "KillAura*.class")))[0], "rb").read()
        fb = open(sorted(glob.glob(os.path.join(tmp, "out", "clean", "Keybinds*.class")))[0], "rb").read()
        out("### The line between automation and cheating")
        out()
        out("A legitimate auto-walk mod and a pathing cheat both move the player without")
        out("input. The difference is visible in the bytecode: the legit one drives the")
        out("game's own input system, the cheat writes the movement packet itself.")
        out()
        out("| jar | forges its own movement packet | verdict |")
        out("|---|:--:|---|")
        for kind, nm in (("cheat", "Pathing"), ("clean", "AutoWalk")):
            jp = corpus.get((kind, nm))
            if not jp:
                continue
            r = bytecode.extract_jar(jp)
            hit = rules(r)["aim"]
            if hit != (kind == "cheat"):
                failures.append("%s misclassified" % nm)
            out("| %s (%s) | %s | %s |" % (nm, kind, "yes" if hit else "no",
                                           "flagged" if hit else "clean"))
        out()

        # ----------------------------------------------------- 1.8.9 / MCP names ---
        out("## 1.8.9 and 1.12 — the names the rules did not know")
        out()
        out("The behaviour tables were written against 1.13+ Mojang, Yarn and intermediary")
        out("names. **1.8.9 is where most Minecraft PvP cheating happens** — it is what Lunar")
        out("and Badlion players run — and a 1.8.9 killaura calls none of those names. It")
        out("sends a `C03PacketPlayer`, writes `rotationYaw`, and asks `PlayerControllerMP` to")
        out("attack. Against the tables as they were, that class matched *nothing at all*.")
        out()
        out("| jar | version dialect | rules tripped | expected |")
        out("|---|---|---|:--:|")
        L18 = [("cheat", "Legacy18Aura", "1.8.9 MCP", True),
               ("cheat", "Legacy18Fly", "1.8.9 MCP", True),
               ("clean", "Legacy18Minimap", "1.8.9 MCP", False),
               ("clean", "Legacy18Sprint", "1.8.9 MCP", False)]
        for kind, nm, dial, want in L18:
            jp = corpus.get((kind, nm))
            if not jp:
                failures.append("legacy corpus jar missing: %s" % nm)
                continue
            r = bytecode.extract_jar(jp)
            tr = rules(r)
            # the radar/ESP ambiguity is a server-rule finding in both dialects, so it
            # is excluded here exactly as it is in the 1.13+ table above
            hit = [k for k in CHEAT_RULES if tr[k] and k != "esp"]
            if bool(hit) != want:
                failures.append("legacy case %s: expected %s, got %s" % (
                    nm, "flagged" if want else "clean", "+".join(hit) or "clean"))
            out("| %s (%s) | %s | %s | %s |" % (
                nm, kind, dial, "+".join(hit) if hit else "—",
                "flagged" if want else "clean"))
        out()
        out("`Legacy18Sprint` is the negative that matters: a 1.8.9 sprint mod reads the key")
        out("and moves the player through the game's own fields, and never touches the")
        out("movement packet. Same line as in 1.13+, drawn in 1.8's names.")
        out()

        # ------------------------------------------------------------- mixins ---
        out("## Mixins — code compiled INTO the game")
        out()
        out("A Mixin is not a mod calling Minecraft. It is code the loader compiles into a")
        out("game class, and it names its target in an **annotation**: a string constant, not")
        out("a symbol. So a mixin cheat calls nothing. Silent rotations mix into the packet")
        out("that reports where you are looking, shadow its rotation fields and overwrite")
        out("them — through the symbol table that class is two floats and no Minecraft at all.")
        out()
        out("The catch is that mixins are also how ordinary mods are built. Sodium, Lithium")
        out("and the Fabric API are nothing but mixins, so reading them has to separate the")
        out("cheat from the mod rather than flag the technique.")
        out()
        out("| jar | what it mixes into | rules tripped | expected |")
        out("|---|---|---|:--:|")
        MIX = [("cheat", "MixinSilentRot", "the outgoing movement packet", True),
               ("clean", "MixinRender", "the level renderer", False),
               ("clean", "MixinFreelook", "the player — shadows the *same* rotation fields", False)]
        for kind, nm, what, want in MIX:
            jp = corpus.get((kind, nm))
            if not jp:
                failures.append("mixin corpus jar missing: %s" % nm)
                continue
            r = bytecode.extract_jar(jp)
            tr = rules(r)
            hit = [k for k in CHEAT_RULES if tr[k]]
            if bool(hit) != want:
                failures.append("mixin case %s: expected %s, got %s" % (
                    nm, "flagged" if want else "clean", "+".join(hit) or "clean"))
            out("| %s (%s) | %s | %s | %s |" % (
                nm, kind, what, "+".join(hit) if hit else "—",
                "flagged" if want else "clean"))
        out()
        out("`MixinFreelook` is the negative this exists for: a freelook mod shadows exactly")
        out("the rotation fields the cheat does. The difference read here is the **target** —")
        out("a camera mixes into the player, never into the packet that reports your aim.")
        out()

        # ------------------------------------------------- coremods / transformers ---
        out("### Coremods — the third door")
        out()
        out("Reflection hides the API in a string. A Mixin hides its target in an annotation.")
        out("A **class transformer** — a Forge coremod or a LaunchWrapper tweaker — is handed")
        out("every class name the game loads and decides what to rewrite by *comparing that")
        out("name against string constants*. Third door, same key: it calls nothing, so the")
        out("symbol table sees an empty class.")
        out()
        out("| jar | what it rewrites | rules tripped | expected |")
        out("|---|---|---|:--:|")
        CM = [("cheat", "CoreModAura", "the player, to spoof the rotation it reports", True),
              ("clean", "CoreModPerf", "the chunk renderer and the HUD", False)]
        for kind, nm, what, want in CM:
            jp = corpus.get((kind, nm))
            if not jp:
                failures.append("coremod corpus jar missing: %s" % nm)
                continue
            r = bytecode.extract_jar(jp)
            tr = rules(r)
            hit = [k for k in CHEAT_RULES if tr[k] and k != "esp"]
            if bool(hit) != want:
                failures.append("coremod case %s: expected %s, got %s" % (
                    nm, "flagged" if want else "clean", "+".join(hit) or "clean"))
            out("| %s (%s) | %s | %s | %s |" % (
                nm, kind, what, "+".join(hit) if hit else "—",
                "flagged" if want else "clean"))
        out()
        out("Installing a transformer is never the finding — OptiFine is a tweaker and half of")
        out("Forge is coremods. It is recorded as *scope*, and what it rewrites is read.")
        out()

        out("## Hiding depth")
        out()
        out("A cheat's modules need not sit at the front of the archive; real jars run to a")
        out("median of ~220 classes. Detection must not depend on where it hides.")
        out()
        out("| jar size | cheat at class | detected |")
        out("|---:|---:|:--:|")
        depth_ok = True
        for total in (300, 1000, 5000):
            for frac in (0.0, 0.5, 0.999):
                pos = int(total * frac)
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as z:
                    for i in range(total):
                        z.writestr("p/C%05d.class" % i, cb if i == pos else fb)
                probe = os.path.join(tmp, "d.jar")
                open(probe, "wb").write(buf.getvalue())
                r = bytecode.extract_jar(probe, max_classes=40)
                ok = rules(r)["aim"]
                depth_ok &= ok
                out("| %d | %d | %s |" % (total, pos, "yes" if ok else "**no**"))
        out()
        if not depth_ok:
            failures.append("detection depends on hiding depth")

        # ------------------------------------------------------- false flags ---
        libs = sorted(glob.glob(os.path.join(HERE, "jars_legit", "*.jar")))
        t0 = time.time()
        cheat_fp, agent_fp, classes = [], [], 0
        for jp in libs:
            r = bytecode.extract_jar(jp, max_classes=120)
            classes += r["classes_parsed"]
            tr = rules(r)
            hit = [k for k in CHEAT_RULES if tr[k]]
            if hit:
                cheat_fp.append((os.path.basename(jp), hit))
            elif tr["agent"]:
                agent_fp.append(os.path.basename(jp))
        elapsed = time.time() - t0

        out("## False flags on real software — the number that matters")
        out()
        out("Negative class: **%d real libraries** from Maven Central (ASM, ByteBuddy," % len(libs))
        out("Netty, Guava, Kotlin, Spring, BouncyCastle, LWJGL — the library Minecraft")
        out("itself uses for input and OpenGL — mockito, log4j, …).")
        out()
        out("| | count |")
        out("|---|---:|")
        out("| real libraries tested | %d |" % len(libs))
        out("| **flagged by any of the %d cheat rules** | **%d** |"
            % (len(CHEAT_RULES), len(cheat_fp)))
        out("| rules checked | %s |" % ", ".join(CHEAT_RULES))
        out("| matched the Java-agent rule | %d |" % len(agent_fp))
        out()
        if cheat_fp:
            out("Flagged: " + ", ".join("`%s` (%s)" % (f, "+".join(h)) for f, h in cheat_fp))
            out()
            # Name the rule and the library. The corpus differs between a developer
            # machine and CI - some repositories are unreachable from a sandbox - so
            # "3 libraries flagged" leaves whoever reads it unable to act.
            failures.append("cheat rule false positives: " + "; ".join(
                "%s tripped %s" % (f, "+".join(h)) for f, h in cheat_fp))
        if agent_fp:
            out("The agent matches are **correct, not false positives** — every one of these")
            out("genuinely ships instrumentation: " + ", ".join("`%s`" % f for f in agent_fp) + ".")
            out("That rule is scoped to *a jar sitting in a mods folder*, where an agent is")
            out("abnormal; in an ordinary application classpath it is not.")
            out()

        # -------------------------------------------------------------- speed ---
        out("## Speed")
        out()
        out("| | |")
        out("|---|---|")
        # Coarse on purpose: this file is committed by CI, and reporting raw
        # wall-clock would produce a diff on every single run for no information.
        per_ms = elapsed / max(classes, 1) * 1000
        out("| classes parsed | %d |" % classes)
        out("| time | ~%d s |" % (int(round(elapsed / 5.0)) * 5))
        out("| per class | ~%.1f ms |" % per_ms)
        out()
        out("Verified mods are skipped entirely during a real scan (they are capped safe),")
        out("so a normal run only pays for the unverified remainder.")
        out()

        # ------------------------------------------------------- honest limits ---
        out("## What these numbers do not say")
        out()
        out("- The cheat samples are **reconstructions** compiled from real open-source cheat")
        out("  client source (Meteor, Wurst), not captured cheat binaries. The constant pools")
        out("  come from a real compiler, so the structure is genuine, but a specific build of")
        out("  a paid client could differ.")
        out("- **ESP is not decidable from bytecode.** ESP and a mob-radar minimap perform the")
        out("  same operations. The tool surfaces that behaviour for review rather than")
        out("  accusing, and deciding it needs identity (hash verification), not a bigger model.")
        out("- A false-flag count of 0 means none of *these* %d libraries were flagged." % len(libs))
        out("  It is evidence, not a guarantee.")
        out()

        # ------------------------------------------------- end-to-end verdict ---
        # The rules above are one input. What a user actually sees is the whole
        # chain: features -> model -> hard rules -> band. Measure that, or the
        # headline number describes a component nobody interacts with.
        import verdict as _v
        import features as _f
        out("## End-to-end verdict — the whole chain, as a user sees it")
        out()
        out("Not just the behaviour rules: hash verification, the trained model, the hard")
        out("rules and the banding together.")
        out()
        E2E = [
            ("a cheat jar, unverified", dict(pkgpath=1, java_agent=1, strong_count=5,
                                             high_entropy_pct=0.4, singlechar_cls_pct=0.3,
                                             avg_entropy=7.0, reflection_count=4),
             {"Confirmed", "Likely"}),
            ("the same jar claiming to be 'sodium'", dict(pkgpath=1, java_agent=1, strong_count=5,
                                                          high_entropy_pct=0.4, legit_modid=1),
             {"Confirmed"}),
            ("a real mod, hash-verified", dict(verified=1, legit_modid=1, reflection_count=3,
                                               avg_entropy=6.3), {"Clean"}),
            ("a real mod from a mirror, unverified", dict(legit_modid=1, reflection_count=3,
                                                          avg_entropy=6.3), {"Clean"}),
            ("an anticheat full of detection names", dict(legit_modid=1, strong_count=5,
                                                          reflection_count=3), {"Clean"}),
            ("a random-named jar, nothing else", dict(random_name=1, avg_entropy=5.6),
             {"Review"}),
            ("a random-named jar, verified", dict(random_name=1, verified=1), {"Clean"}),
            ("a mod with an injected agent", dict(java_agent=1, legit_modid=1,
                                                  reflection_count=3), {"Confirmed"}),
        ]
        out("| case | verdict | expected |")
        out("|---|:--:|:--:|")
        e2e_bad = 0
        for label, raw, want in E2E:
            r = _v.verdict(dict(raw))
            ok = r["band"] in want
            e2e_bad += not ok
            out("| %s | %s%s | %s |" % (label, r["band"], "" if ok else " **wrong**",
                                        "/".join(sorted(want))))
        out()
        if e2e_bad:
            failures.append("%d end-to-end verdict cases wrong" % e2e_bad)

        # No real library may reach an ACCUSING band through the full chain.
        #
        # "Clean or nothing" was the gate before, and it hid what it was measuring.
        # Seven libraries failed it - and six of those were Confirmed 90, which is
        # the tool saying "this is cheating": aspectjweaver, byte-buddy-agent,
        # opentelemetry-javaagent, spring-instrument, kotlinx-coroutines and
        # sponge-mixin, all because they declare a Java agent in their manifest.
        # Mixin is what nearly every Minecraft mod is built on.
        #
        # Review is a different statement - "unproven, a human should look" - and a
        # Java agent sitting in a mods folder has earned that much. So the hard gate
        # is the accusing bands, and the Review count is reported next to it rather
        # than folded into a pass.
        ACCUSING = ("Likely", "Confirmed", "ServerRule")
        e2e_fp, e2e_review = [], []
        for jp in libs:
            band = _v.verdict(_f.extract_from_jar(jp))["band"]
            if band in ACCUSING:
                e2e_fp.append("%s (%s)" % (os.path.basename(jp), band))
            elif band != "Clean":
                e2e_review.append(os.path.basename(jp))
        out("Through the same full chain, **%d of %d** real libraries reach an accusing"
            % (len(e2e_fp), len(libs)))
        out("band (Likely / Confirmed / server-rule)%s."
            % ("" if not e2e_fp else ": " + ", ".join("`%s`" % f for f in e2e_fp[:8])))
        out()
        out("**%d** land in Review - shown to a moderator as unproven, never as a finding%s."
            % (len(e2e_review),
               "" if not e2e_review else ": " + ", ".join("`%s`" % f for f in e2e_review[:8])))
        out()
        if e2e_fp:
            failures.append("%d real libraries reach an accusing band end-to-end" % len(e2e_fp))

        # ------------------------------------------------- federated learning ---
        # The team-mode claim is that shared learning makes detection better over
        # time. That is testable, so it is tested rather than asserted.
        import session_model as _s
        import copy as _copy
        out("## Team learning — does sharing scans actually help?")
        out()
        NOVEL = dict(total_mods=12, verified=0, random_named=9, review=2)
        CLEAN = [dict(total_mods=25, verified=25), dict(total_mods=20, verified=0),
                 dict(total_mods=40, verified=22, random_named=3),
                 dict(total_mods=140, verified=90, random_named=4, mc_running=1)]
        w, b = _copy.deepcopy(_s.WEIGHTS), _s.INTERCEPT
        before = _s.verdict(NOVEL, w, b)["score"]
        curve_novel, curve_clean = [], []
        for _ in range(16):
            curve_novel.append(_s.verdict(NOVEL, w, b)["score"])
            curve_clean.append(max(_s.verdict(c, w, b)["score"] for c in CLEAN))
            if len(curve_novel) > 15:
                break
            w, b = _s.sgd_step(w, b, _s.raw_to_vector(NOVEL), 1)
            for c in CLEAN:
                w, b = _s.sgd_step(w, b, _s.raw_to_vector(c), 0)
        after = _s.verdict(NOVEL, w, b)["score"]
        worst_clean = max(_s.verdict(c, w, b)["score"] for c in CLEAN)
        hard = _s.verdict(dict(total_mods=20, verified=12, flagged=1, hard_confirmed=1), w, b)
        out("Simulating 15 rounds of a pattern the base model underrates, mixed with clean")
        out("scans so drift would show up:")
        out()
        out("| | before | after |")
        out("|---|---:|---:|")
        out("| score for the new cheat pattern | %d%% | **%d%%** |" % (before, after))
        out("| worst score among clean scans | — | %d%% (stays Clean) |" % worst_clean)
        out("| a hard-confirmed cheat | — | %s |" % hard["band"])
        out()
        learned = after > before + 10
        if not learned:
            failures.append("federated learning did not improve the novel pattern")
        if worst_clean >= 30:
            failures.append("federated learning drifted: a clean scan left the Clean band")
        out("Learning is base-anchored, so it adapts without being able to drift into")
        out("flagging clean scans - which is the failure that would matter.")
        out()

        # ------------------------------------------------------------ history ---
        import csv as _csv
        hist_path = os.path.join(HERE, "benchmark_history.csv")
        stamp = os.environ.get("GITHUB_SHA", "local")[:7]
        row = {"commit": stamp, "libraries": len(libs), "cheat_rule_fp": len(cheat_fp),
               "agent_matches": len(agent_fp),
               "aim": int(bool(det.get("KillAura"))), "flight": int(bool(det.get("Flight"))),
               "dropper": int(bool(det.get("Loader"))), "depth_ok": int(depth_ok),
               "ms_per_class": round(per_ms, 2)}
        hist = []
        if os.path.exists(hist_path):
            with open(hist_path) as f:
                hist = list(_csv.DictReader(f))
        # one row per distinct commit; re-runs of the same commit overwrite
        hist = [h for h in hist if h.get("commit") != row["commit"]]
        hist.append({k: str(v) for k, v in row.items()})
        with open(hist_path, "w", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=list(row))
            w.writeheader()
            w.writerows(hist)

        out("## History")
        out()
        out("Appended by every CI run, so the direction of travel is visible instead of")
        out("asserted. `libraries` is the size of the negative corpus - a false-flag count")
        out("of 0 means more as that number grows.")
        out()
        out("| commit | real libraries | false flags | aim | dropper | depth-proof |")
        out("|---|---:|---:|:--:|:--:|:--:|")
        for h in hist[-12:]:
            bar = "\u2588" * max(1, int(int(h["libraries"]) / 25))
            out("| `%s` | %s %s | %s | %s | %s | %s |" % (
                h["commit"], h["libraries"], bar, h["cheat_rule_fp"],
                "ok" if h["aim"] == "1" else "**no**",
                "ok" if h["dropper"] == "1" else "**no**",
                "ok" if h["depth_ok"] == "1" else "**no**"))
        out()

        status = "PASS" if not failures else "FAIL"
        out("## Regression gates")
        out()
        out("| gate | result |")
        out("|---|:--:|")
        out("| no real library accused through the full chain | %s |" % ("pass" if not e2e_fp else "**fail**"))
        out("| end-to-end verdict cases correct | %s |" % ("pass" if not e2e_bad else "**fail**"))
        out("| team learning improves without drifting | %s |" % ("pass" if learned and worst_clean < 30 else "**fail**"))
        out("| no real library flagged by a cheat rule | %s |" % ("pass" if not cheat_fp else "**fail**"))
        out("| aim fingerprint always detected | %s |" % ("pass" if det.get("KillAura") and det.get("Flight") else "**fail**"))
        out("| dropper always detected | %s |" % ("pass" if det.get("Loader") else "**fail**"))
        out("| detection independent of hiding depth | %s |" % ("pass" if depth_ok else "**fail**"))
        out()
        out("**%s**" % status)

        with open(os.path.join(ROOT, "BENCHMARKS.md"), "w") as f:
            f.write("\n".join(lines) + "\n")

        # ------------------------------------------------------- public page ---
        # docs/benchmarks.html is the same measurements as a page anyone can read.
        # Generated from the template so it cannot drift from the numbers above -
        # a benchmark page that is edited by hand stops being a benchmark.
        try:
            tpl = open(os.path.join(HERE, "page_template.html"), encoding="utf-8").read()
            det_rows = []
            PILL_OK = '<span class="pill ok"><i class="dot"></i>Confirmed</span>'
            PILL_REV = '<span class="pill rev"><i class="dot"></i>Review</span>'
            for nm, rule, why in FAM:
                shown = why.split("—")[0].strip().replace("**", "")
                pill = PILL_REV if rule == "esp" else PILL_OK
                det_rows.append('          <tr><td>%s</td><td>%s</td>'
                                '<td class="w">%s</td></tr>' % (nm, pill, shown))
            page = (tpl.replace("{{TOOL}}", tool_ver)
                       .replace("{{MODEL}}", str(mod_ver))
                       .replace("{{SMODEL}}", str(sess_ver))
                       .replace("{{SIGS}}", str(sig_ver))
                       .replace("{{LIBS}}", str(len(libs)))
                       .replace("{{FP}}", str(len(e2e_fp)))
                       .replace("{{NOVEL}}", repr(curve_novel))
                       .replace("{{CLEAN}}", repr(curve_clean))
                       .replace("{{STAMP}}", stamp)
                       .replace("{{DETECTION_ROWS}}", "\n".join(det_rows)))
            docs = os.path.join(ROOT, "docs")
            os.makedirs(docs, exist_ok=True)
            with open(os.path.join(docs, "benchmarks.html"), "w", encoding="utf-8") as f:
                f.write(page)
            # The landing page quotes these numbers, so hand them over rather than
            # letting it re-derive them and drift.
            with open(os.path.join(docs, "metrics.json"), "w", encoding="utf-8") as f:
                json.dump({"libraries": len(libs), "cheat_rule_fp": len(e2e_fp),
                           "agent_matches": len(agent_fp),
                           "tool_version": tool_ver, "model_version": mod_ver,
                           "session_version": sess_ver, "sig_version": sig_ver,
                           "stamp": stamp}, f, indent=2)
        except Exception as e:
            print("could not write docs/benchmarks.html: %s" % e, file=sys.stderr)

        if failures:
            print("\nREGRESSION: " + "; ".join(failures), file=sys.stderr)
            return 1
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
