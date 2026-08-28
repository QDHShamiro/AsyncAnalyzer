"""
Proves the reader for the parts of a Minecraft install that are not the mods folder.

A .minecraft directory is full of files every normal player has, so the negatives
matter more than the positives here: a modpack's version profile, a shader pack, a
config folder for an ordinary mod. None of them may ever be an accusation.

Run:  python3 ml/test_instscan.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import instscan

PKGS = ["net/ccbluex", "meteordevelopment", "wtf/moonlight", "doomsdayclient"]
TOKS = ["doomsday", "liquidbounce", "meteorclient", "wurstclient", "impactclient",
        "rusherhack", "sigmaclient"]

# ------------------------------------------------------------------ evidence ---
VERSIONS_BAD = [
    ("the launcher starts a cheat's own class", "mainclass",
     '{"id":"1.8.9-LB","mainClass":"net.ccbluex.liquidbounce.LiquidBounce"}'),
    ("a cheat passed as a LaunchWrapper tweaker", "tweakclass",
     '{"mainClass":"net.minecraft.launchwrapper.Launch",'
     ' "minecraftArguments":"--tweakClass wtf.moonlight.MoonlightTweaker"}'),
    ("a Java agent attached at launch", "javaagent",
     '{"mainClass":"net.minecraft.client.main.Main",'
     ' "jvmArguments":"-Xmx4G -javaagent:C:/Users/x/AppData/Roaming/.mc/dd.jar"}'),
]

# ------------------------------------------------------------------ negatives ---
VERSIONS_OK = [
    ("plain vanilla", '{"id":"1.20.4","mainClass":"net.minecraft.client.main.Main"}'),
    ("Fabric", '{"id":"fabric-loader-1.20.4",'
               '"mainClass":"net.fabricmc.loader.impl.launch.knot.KnotClient"}'),
    ("Forge 1.20", '{"id":"1.20.1-forge","mainClass":"cpw.mods.bootstraplauncher.BootstrapLauncher"}'),
    ("legacy Forge / OptiFine", '{"id":"1.8.9-forge","mainClass":"net.minecraft.launchwrapper.Launch",'
                                '"minecraftArguments":"--tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker"}'),
    ("Quilt", '{"mainClass":"org.quiltmc.loader.impl.launch.knot.KnotClient"}'),
    ("an ordinary big heap", '{"mainClass":"net.minecraft.client.main.Main","jvmArguments":"-Xmx8G -XX:+UseG1GC"}'),
]

PACKS_BAD = [
    ("a resource pack carrying bytecode",
     ["pack.mcmeta", "assets/minecraft/textures/block/dirt.png", "me/x/Loader.class"]),
    ("a resource pack carrying a jar",
     ["pack.mcmeta", "payload.jar"]),
]
PACKS_OK = [
    ("an ordinary texture pack",
     ["pack.mcmeta", "pack.png", "assets/minecraft/textures/block/stone.png",
      "assets/minecraft/lang/en_us.json"]),
    ("a shader pack",
     ["shaders/shaders.properties", "shaders/gbuffers_terrain.fsh",
      "shaders/gbuffers_terrain.vsh", "shaders/lib/common.glsl"]),
    ("a pack with sounds and a readme",
     ["pack.mcmeta", "assets/minecraft/sounds/click.ogg", "README.txt", "credits.md"]),
]

CONFIG_BAD = ["meteorclient", "wurstclient", "rusherhack", "Impactclient"]
CONFIG_OK = ["sodium", "jei", "impactful-additions", "journeymap", "fabric",
             "iris", "modmenu", "doomsday-realms-datapack-helper" ]


def main():
    passed = failed = 0

    def check(label, ok, detail=""):
        nonlocal passed, failed
        passed += ok
        failed += not ok
        print("  [%s] %-48s %s" % ("PASS" if ok else "FAIL", label, detail))

    print("=== version profiles that ARE evidence ===")
    for label, want, text in VERSIONS_BAD:
        got = instscan.classify_version_json(text, PKGS, TOKS)
        check(label, any(k == want for k, _ in got), str(got))

    print("\n=== version profiles every normal player has ===")
    for label, text in VERSIONS_OK:
        got = instscan.classify_version_json(text, PKGS, TOKS)
        check(label, got == [], str(got))

    print("\n=== packs that carry executable content ===")
    for label, names in PACKS_BAD:
        check(label, bool(instscan.classify_pack(names)), str(instscan.classify_pack(names)))

    print("\n=== ordinary packs ===")
    for label, names in PACKS_OK:
        check(label, instscan.classify_pack(names) == [], str(instscan.classify_pack(names)))

    print("\n=== config folders ===")
    for n in CONFIG_BAD:
        check("'%s' is a cheat's config folder" % n, bool(instscan.is_cheat_config_dir(n, TOKS)))
    for n in CONFIG_OK:
        check("'%s' is an ordinary config folder" % n,
              not instscan.is_cheat_config_dir(n, TOKS))

    # ---- parity with the shipped PowerShell -----------------------------------
    print("\n=== PowerShell / Python parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "10-signatures.ps1"), encoding="utf-8").read()
    m = re.search(r"\$script:instKnownMain = @\(([^)]*)\)", ps, re.S)
    ps_main = set(re.findall(r"'([^']+)'", m.group(1))) if m else set()
    check("known mainClass list matches (%d)" % len(instscan.KNOWN_MAIN),
          ps_main == instscan.KNOWN_MAIN,
          "" if ps_main == instscan.KNOWN_MAIN else "ps-only=%s py-only=%s" % (
              sorted(ps_main - instscan.KNOWN_MAIN), sorted(instscan.KNOWN_MAIN - ps_main)))
    for name, rx in (("instJavaAgent", instscan.JAVAAGENT),
                     ("instMainClass", instscan.MAIN_CLASS),
                     ("instTweakClass", instscan.TWEAK_CLASS),
                     ("instPackExec", instscan.EXECUTABLE_IN_PACK)):
        m = re.search(r"\$script:%s\s*=\s*'((?:[^']|'')*)'" % name, ps)
        got = m.group(1).replace("''", "'") if m else None
        check("%s matches Python" % name, got == rx.pattern,
              "" if got == rx.pattern else "\n        ps=%r\n        py=%r" % (got, rx.pattern))

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
