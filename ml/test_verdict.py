"""
End-to-end test of the detection pipeline: build real .jar files that mimic
cheats and legit mods, run them through the SAME feature extractor + verdict
logic the PowerShell script uses, and assert the band is correct.

Run:  python3 test_verdict.py
"""

import io
import os
import re
import struct
import tempfile
import zipfile

import features
import verdict

# mirror of $script:legitModIds (subset) and $script:distinctiveClientTokens
LEGIT_MODIDS = {
    "grimac", "grim", "vulcan", "nocheatplus", "sodium", "iris", "lithium",
    "fabric", "fabricapi", "create", "jei", "journeymap", "twilightforest",
}
CLIENT_TOKENS = {"doomsday", "liquidbounce", "vapeclient", "wurstclient", "meteorclient"}

HERE = os.path.dirname(os.path.abspath(__file__))


def _fake_class(seed, size=800):
    # produce bytecode-ish bytes; entropy varies with seed
    b = bytearray(b"\xca\xfe\xba\xbe")
    x = seed
    for _ in range(size):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        b.append(x & 0xFF)
    return bytes(b)


def _high_entropy_class(seed, size=2000):
    # near-random bytes -> entropy > 7.2
    b = bytearray()
    x = seed | 1
    for _ in range(size):
        x = (6364136223846793005 * x + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        b.append((x >> 33) & 0xFF)
    return bytes(b)


def build_jar(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            z.writestr(name, data)


def make_cheat_doomsday(d):
    """chainlibs/ccbluex-style obfuscated crystal client."""
    p = os.path.join(d, "Doomsday-b7.jar")
    entries = {
        "net/ccbluex/liquidbounce/Main.class": _fake_class(1),
        "org/chainlibs/module/impl/modules/Crystal.class": _high_entropy_class(2),
    }
    # obfuscated single-letter + fullwidth + numeric class names
    for i, c in enumerate("abcdefghij"):
        entries[f"org/chainlibs/{c}.class"] = _high_entropy_class(10 + i)
    entries["org/chainlibs/ａｂｃ.class"] = _high_entropy_class(50)
    entries["org/chainlibs/12345.class"] = _high_entropy_class(51)
    entries["assets/mod/lang.txt"] = "AutoCrystal dontPlaceCrystal KillAura TriggerBot AutoAnchor"
    entries["fabric.mod.json"] = '{"id":"doomsdaycrystal","name":"Sodium"}'  # fake identity
    build_jar(p, entries)
    return p


def make_ghost_loader(d):
    """The shape of a real ghost-client loader, measured from one.

    Not the file - this repo ships no cheat binaries - but every structural thing
    that file actually had, reproduced so it is proven on every build:

      * three loader manifests at once (fabric.mod.json, mcmod.info, mods.toml),
        which is not a compatibility choice but a dropper making sure SOMETHING
        picks it up;
      * Premain-Class with Can-Retransform-Classes: true, so it attaches as a Java
        agent and can rewrite game classes as they load;
      * four extensionless entries of near-maximum entropy - the encrypted payload,
        which is why the bytecode reader finds no cheat behaviour in the jar itself;
      * a 175 KB entry of pure zeros. That one is the vendor's own "Randomize size"
        option: padding has no function except to change the file's size and with it
        its SHA1, so a hash from somebody else's download does not match this copy;
      * every class named with a single letter.

    The real one scored Confirmed 90/100, on the hard rules rather than the model -
    the model alone gave it 24%, which is the whole reason the hard rules exist.
    """
    p = os.path.join(d, "gzfjalsrvp.jar")
    entries = {
        "fabric.mod.json": '{"schemaVersion":1,"id":"dd","version":"1.0.0"}',
        "mcmod.info": '[{"modid":"dd","url":"","description":""}]',
        "META-INF/mods.toml": 'modLoader="javafml"\nloaderVersion="[25,)"\n[[mods]]\nmodId="dd"\n',
        "META-INF/MANIFEST.MF": ("Manifest-Version: 1.0\nPremain-Class: net.java.f\n"
                                 "Can-Retransform-Classes: true\nMain-Class: net.java.n\n"),
        "pack.mcmeta": '{"pack":{"description": "","pack_format": 1}}',
        # the encrypted payload: extensionless, near-maximum entropy
        "net/java/a": os.urandom(214590),
        "net/java/b": os.urandom(17474),
        "net/java/d": os.urandom(106215),
        "net/java/e": os.urandom(14152),
        # the "Randomize size" padding, which is what makes a hash useless here
        "000": b"\x00" * 175875,
    }
    for i, c in enumerate("abcdefghijk"):
        entries["net/java/%s.class" % c] = _fake_class(60 + i)
    build_jar(p, entries)
    return p


def make_token_grabber(d):
    p = os.path.join(d, "helper-mod.jar")
    entries = {
        "com/x/Grab.class": _high_entropy_class(3),
        "com/x/Send.class": _high_entropy_class(4),
        "payload.txt": ("java/lang/Runtime getRuntime exec openConnection setDoOutput "
                        "getOutputStream getProperty webhookurl discordwebhook grabToken"),
    }
    for i, c in enumerate("abcdef"):
        entries[f"com/x/{c}.class"] = _high_entropy_class(20 + i)
    build_jar(p, entries)
    return p


def make_clean_sodium(d):
    p = os.path.join(d, "sodium-fabric-0.6.jar")
    entries = {
        "me/jellysquid/mods/sodium/SodiumClientMod.class": _fake_class(5),
        "net/caffeinemc/mods/sodium/Renderer.class": _fake_class(6),
        "fabric.mod.json": '{"id":"sodium","name":"Sodium"}',
    }
    for i in range(30):
        entries[f"net/caffeinemc/mods/sodium/render/Chunk{i}.class"] = _fake_class(100 + i)
    build_jar(p, entries)
    return p


def make_legit_anticheat(d):
    """anticheat full of detection-name strings — must NOT flag."""
    p = os.path.join(d, "GrimAC.jar")
    entries = {
        "ac/grim/GrimAPI.class": _fake_class(7),
        "checks.txt": ("KillAura AutoCrystal reach AutoTotem TriggerBot AimAssist "
                       "Scaffold Antiknockback detection check"),
        "fabric.mod.json": '{"id":"grimac","name":"GrimAC"}',
    }
    for i in range(40):
        entries[f"ac/grim/checks/Check{i}.class"] = _fake_class(200 + i)
    build_jar(p, entries)
    return p


def make_clean_reflection_lib(d):
    """reflection-heavy but clean library (gson/bytebuddy style): real libraries
    have normal class names, so obfuscation ratios stay low."""
    p = os.path.join(d, "some-lib.jar")
    names = ["JsonReader", "JsonWriter", "TypeAdapter", "ReflectiveAccessor",
             "MethodResolver", "FieldBinder", "ClassScanner", "ProxyFactory",
             "BeanSerializer", "TokenStream", "GenericArrayTypeImpl",
             "ConstructorConstructor", "LinkedTreeMap", "TypeToken"]
    entries = {
        "com/lib/gson/internal/Reflect.txt": (
            "Class.forName getDeclaredMethod setAccessible invoke "
            "java/lang/reflect MethodHandle defineClass ByteBuddy javassist"),
    }
    for i, nm in enumerate(names):
        entries[f"com/lib/gson/internal/{nm}.class"] = _fake_class(300 + i)
    build_jar(p, entries)
    return p


def analyze(path, verified=False):
    raw = features.extract_from_jar(path)
    base = os.path.basename(path)
    stem = re.sub(r"[^a-z0-9]", "", os.path.splitext(base)[0].lower())
    modid = re.sub(r"[^a-z0-9]", "", (raw.get("modid") or "").lower())
    raw["legit_modid"] = 1 if modid in LEGIT_MODIDS else 0
    raw["filename_client"] = 1 if any(t in stem for t in CLIENT_TOKENS) else 0
    raw["verified"] = 1 if verified else 0
    return verdict.verdict(raw)


CASES = [
    # (builder, verified, expected-bands-allowed, label)
    (make_cheat_doomsday, False, {"Confirmed", "Likely"}, "Doomsday cheat"),
    (make_ghost_loader, False, {"Confirmed"}, "Ghost-client loader (real shape)"),
    (make_token_grabber, False, {"Confirmed", "Likely"}, "Token grabber"),
    (make_clean_sodium, False, {"Clean"}, "Clean Sodium (legit modid)"),
    (make_legit_anticheat, False, {"Clean"}, "Anticheat w/ detection names"),
    (make_clean_reflection_lib, False, {"Clean", "Review"}, "Reflection-heavy lib"),
]


def main():
    d = tempfile.mkdtemp(prefix="aa_test_")
    passed = failed = 0

    print("=== Synthetic jars (end-to-end: extract -> model -> verdict) ===")
    for builder, verified, allowed, label in CASES:
        path = builder(d)
        v = analyze(path, verified=verified)
        ok = v["band"] in allowed
        passed += ok
        failed += not ok
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label:32s} score={v['score']:3d} p={v['probability']:3d}%"
              f" band={v['band']:9s} (want {sorted(allowed)})")

    # random / hash-style filename on an unverified mod must surface as Review
    # (never slip through as unknown); the same file, once verified, is Clean again.
    print("\n=== Random-named jar provenance floor ===")
    rp = os.path.join(d, "hb4zz1xxrd4.jar")
    build_jar(rp, {"com/x/Main.class": _fake_class(9), "com/x/Util.class": _fake_class(10)})
    for is_verified, allowed, label in [
        (False, {"Review"}, "random name, unverified"),
        (True, {"Clean"}, "random name, verified"),
    ]:
        raw = features.extract_from_jar(rp, verified=1 if is_verified else 0, random_name=1)
        v = verdict.verdict(raw)
        ok = v["band"] in allowed
        passed += ok
        failed += not ok
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label:32s} score={v['score']:3d} band={v['band']:9s} (want {sorted(allowed)})")

    # A cheat that hides behind a VALID mod identity. The mod id lives in
    # fabric.mod.json, which the jar writes itself - so it must never be able to
    # buy immunity. Hash-verified files still get their cap (they ARE that mod).
    print("\n=== Impersonation: cheat hiding inside/behind a legit mod ===")
    CH = dict(pkgpath=1, java_agent=1, agent_retransform=1, hidden_payload=3,
              strong_count=5, high_entropy_pct=0.4, singlechar_cls_pct=0.3,
              avg_entropy=7.0, reflection_count=4, runtime_exec=1)
    IMP = [
        ("cheat declaring itself 'sodium'", dict(CH, legit_modid=1), {"Confirmed"}),
        ("legit mod tampered with (agent added)", dict(java_agent=1, legit_modid=1, reflection_count=3), {"Confirmed"}),
        ("cheat with no identity claim", dict(CH), {"Confirmed"}),
        ("REAL Sodium, hash-verified", dict(verified=1, legit_modid=1, reflection_count=3, avg_entropy=6.3), {"Clean"}),
        ("real mod from a mirror, unverified+clean", dict(legit_modid=1, reflection_count=3, avg_entropy=6.3), {"Clean"}),
        ("anticheat: legit id + detection strings", dict(legit_modid=1, strong_count=5, reflection_count=3), {"Clean"}),
        ("architectury: legit id + 2 loaders", dict(legit_modid=1, loader_ids=["fabric", "forge"], reflection_count=2), {"Clean"}),
        ("verified mod shipping its own agent", dict(verified=1, java_agent=1), {"Clean"}),
    ]
    for label, raw, allowed in IMP:
        v = verdict.verdict(raw)
        ok = v["band"] in allowed
        passed += ok
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:42s} score={v['score']:3d} band={v['band']:9s}"
              f" (want {sorted(allowed)})")

    # Real library jars. Split, the same way ml/benchmark.py splits them and for
    # the same reason: a handful of these ARE Java agents - aspectjweaver,
    # byte-buddy-agent, opentelemetry-javaagent, spring-instrument - and the agent
    # rule flagging them is correct rather than a false positive. The rule is scoped
    # to a jar sitting in a MODS FOLDER, where an agent is abnormal; in an ordinary
    # application classpath it is the library's whole job.
    #
    # This split only appeared when features.py learned to read the manifest. Before
    # that the Python extractor never computed java_agent at all, so this test was
    # passing on rules it was not reaching - which is worth stating plainly rather
    # than quietly widening the expectation.
    jars = os.path.join(HERE, "jars_legit")
    if os.path.isdir(jars):
        print("\n=== Real library jars ===")
        worst = 0.0
        agents = []
        for f in sorted(os.listdir(jars)):
            if not f.endswith(".jar"):
                continue
            path = os.path.join(jars, f)
            raw = features.extract_from_jar(path)
            v = analyze(path)
            if raw.get("java_agent") and v["band"] != "Clean":
                # genuinely an agent, and nothing else about it fired
                agents.append(f)
                continue
            ok = v["band"] == "Clean"
            passed += ok
            failed += not ok
            worst = max(worst, v["score"])
            if not ok:
                print(f"  [FAIL] {f:32s} score={v['score']} band={v['band']}")
        n = len([x for x in os.listdir(jars) if x.endswith('.jar')])
        print(f"  {n} real jars, {n - len(agents)} judged on the non-agent rules, "
              f"worst score {worst} -> {'all Clean' if worst < 30 else 'SOME NOT CLEAN'}")
        print(f"  {len(agents)} are real Java agents and are flagged as such, correctly: "
              + ", ".join(agents))
        # ...but an agent must not be flagged for anything BESIDES being an agent,
        # or the split above would be hiding a genuine false positive behind it.
        for f in agents:
            raw = features.extract_from_jar(os.path.join(jars, f))
            other = (raw.get("padding_entry", 0) > 0 or raw.get("hidden_payload", 0) > 0
                     or len(raw.get("loader_ids", [])) >= 3
                     or raw.get("pkgpath") or raw.get("cheatsite"))
            passed += not other
            failed += bool(other)
            if other:
                print(f"  [FAIL] {f} is flagged for more than being an agent")

    print(f"\n=== RESULT: {passed} passed, {failed} failed ===")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
