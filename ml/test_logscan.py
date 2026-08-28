"""
Proves the log reader on realistic Minecraft log lines.

The reason this file is mostly negatives: latest.log contains the chat. Someone
typing "killaura" into chat writes the word killaura into the log, and a scanner
that matches module names there accuses people for what they SAID. That is the
worst false flag this tool could produce, because it looks like hard evidence and
comes with a timestamp.

So the rule is: chat lines are dropped before anything is tested, module names are
never matched at all, and a client name only counts inside a stack frame, a
classloader line, a mixin config or a jar name.

Run:  python3 ml/test_logscan.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logscan

PKGS = ["net/ccbluex", "meteordevelopment", "wtf/moonlight", "doomsdayclient",
        "me/zeroeightsix/kami"]
TOKS = ["doomsday", "liquidbounce", "meteorclient", "wurstclient", "sigmaclient",
        "kamiblue", "rusherhack", "impactclient"]

# ------------------------------------------------------------------ evidence ---
HITS = [
    ("stack frame from a cheat package", "package",
     "\tat net.ccbluex.liquidbounce.features.module.modules.combat.KillAura.onUpdate(KillAura.kt:88)"),
    ("classloader failure names the package", "package",
     "[16:04:11] [main/ERROR]: java.lang.NoClassDefFoundError: meteordevelopment/meteorclient/MeteorClient"),
    ("mixin config from a cheat", "package",
     "[16:04:09] [main/WARN]: Mixin config doomsdayclient.mixins.json requires mixin 0.8.5"),
    ("crash report frame", "package",
     "    at wtf.moonlight.Moonlight.startClient(Moonlight.java:41)"),
    ("jar filename in the mod loader line", "client",
     "[16:04:08] [main/INFO]: Loading 3 mods: wurstclient 7.36, fabricloader 0.15.7"),
    ("a shaded package written with dots", "package",
     "[16:04:12] [Render thread/INFO]: me.zeroeightsix.kami.KamiMod initialised"),
]

# ------------------------------------------------------------------ negatives ---
# Every one of these is a line a completely innocent player's log contains.
CLEAN = [
    ("someone typed a cheat name in chat",
     "[20:14:02] [Render thread/INFO]: [CHAT] <Shamiro> bro he has killaura for sure"),
    ("someone typed a client name in chat",
     "[20:14:44] [Render thread/INFO]: [CHAT] <Luis> wurstclient is banned here"),
    ("a server broadcast about cheating",
     "[20:15:01] [Render thread/INFO]: [CHAT] [Staff] banned Player123 for killaura"),
    ("a whisper",
     "[20:15:30] [Render thread/INFO]: [CHAT] Player123 whispers to you: do you use doomsday"),
    ("a command the player issued",
     "[20:16:00] [Server thread/INFO]: Shamiro issued server command: /report Luis killaura"),
    ("ordinary startup",
     "[16:04:07] [main/INFO]: Loading Minecraft 1.20.4 with Fabric Loader 0.15.7"),
    ("an ordinary mod loading",
     "[16:04:08] [main/INFO]: Loading 42 mods: sodium 0.5.8, lithium 0.12.1, iris 1.6.17"),
    ("an ordinary stack trace",
     "\tat net.minecraft.client.MinecraftClient.render(MinecraftClient.java:1210)"),
    ("a resource pack warning",
     "[16:04:20] [Worker-Main-3/WARN]: Unable to load texture: minecraft:textures/block/x.png"),
    ("a chat line that also looks like a package",
     "[20:17:00] [Render thread/INFO]: [CHAT] <Luis> net.ccbluex is the liquidbounce package lol"),
    ("a server MOTD mentioning anticheat",
     "[20:18:00] [Render thread/INFO]: [CHAT] Anticheat: Vulcan detected suspicious movement"),
    ("the word appears inside an ordinary sentence",
     "[16:05:00] [Render thread/INFO]: Sound engine started, impact of the change is minimal"),
]


def main():
    passed = failed = 0
    print("=== log lines that ARE evidence ===")
    for label, want, line in HITS:
        kind, ev = logscan.classify_line(line, PKGS, TOKS)
        ok = kind == want
        passed += ok
        failed += not ok
        print("  [%s] %-38s -> %-8s (want %s) %s" % (
            "PASS" if ok else "FAIL", label, kind or "-", want, ev))

    print("\n=== log lines that must NEVER be evidence ===")
    for label, line in CLEAN:
        kind, ev = logscan.classify_line(line, PKGS, TOKS)
        ok = kind is None
        passed += ok
        failed += not ok
        print("  [%s] %-42s -> %s" % ("PASS" if ok else "FAIL", label, kind or "clean"))

    print("\n=== the mod list the log says was loaded ===")
    lines = [
        "[16:04:08] [main/INFO]: Loading 4 mods:",
        "[16:04:08] [main/INFO]: \t- fabricloader 0.15.7",
        "[16:04:08] [main/INFO]: \t- sodium 0.5.8",
        "[16:04:08] [main/INFO]: \t- minecraft 1.20.4",
        "[16:04:09] [main/INFO]: Loaded 4 mods",
    ]
    got = logscan.parse_mod_list(lines)
    want = [("fabricloader", "0.15.7"), ("sodium", "0.5.8"), ("minecraft", "1.20.4")]
    ok = got == want
    passed += ok
    failed += not ok
    print("  [%s] mod ids read out of the loader banner -> %s" % (
        "PASS" if ok else "FAIL", got))

    # ---- the pre-filter must not narrow detection -----------------------------
    # Run-LogScan skips a whole file, and then each line, unless one compiled
    # alternation of every cheat name matches it first. That is what makes the log
    # scan affordable - Test-LogLine costs ~75 string operations per line and there
    # can be a million of them. But a pre-filter is also the perfect place for a
    # silent gap: anything it misses is never looked at, and a miss reads exactly
    # like a clean file. So every line that IS evidence has to survive it.
    print("\n=== the pre-filter must not hide anything ===")
    parts = []
    for pkg in PKGS:
        parts.append(re.escape(pkg))
        parts.append(re.escape(pkg.replace("/", ".")))
    parts += [re.escape(t) for t in TOKS if len(t) >= 5]
    prefilter = re.compile("|".join(sorted(set(parts))), re.I)
    for label, want, line in HITS:
        ok = bool(prefilter.search(line))
        passed += ok
        failed += not ok
        print("  [%s] survives the pre-filter: %s" % ("PASS" if ok else "FAIL", label))
    # and it must actually reject the ordinary lines, or it buys nothing
    skipped = sum(1 for _, line in CLEAN if not prefilter.search(line))
    ok = skipped >= len(CLEAN) - 3
    passed += ok
    failed += not ok
    print("  [%s] pre-filter skips %d of %d ordinary lines outright" % (
        "PASS" if ok else "FAIL", skipped, len(CLEAN)))

    # ---- parity with the shipped PowerShell -----------------------------------
    print("\n=== PowerShell / Python log-reader parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "10-signatures.ps1"), encoding="utf-8").read()
    # The builder itself lives in PowerShell only (it is assembled from the two
    # signature lists at load time, and again after a signature update). What can
    # be checked here is that it IS rebuilt when those lists grow - a new client
    # name that never enters the pre-filter is unsearchable in logs, silently.
    rt = open(os.path.join(root, "src", "30-runtime.ps1"), encoding="utf-8").read()
    grew = re.search(r"if \(\$sigGrew\) \{ Build-LogPreFilter \}", rt)
    passed += bool(grew)
    failed += (not grew)
    print("  [%s] the pre-filter is rebuilt after a signature update" % (
        "PASS" if grew else "FAIL"))

    for name, rx in (("logChatLine", logscan.CHAT),
                     ("logCodeContext", logscan.CODE_CONTEXT)):
        m = re.search(r"\$script:%s\s*=\s*'((?:[^']|'')*)'" % name, ps)
        got = m.group(1).replace("''", "'") if m else None
        ok = got == rx.pattern
        passed += ok
        failed += not ok
        print("  [%s] %s matches Python%s" % (
            "PASS" if ok else "FAIL", name,
            "" if ok else "\n        ps=%r\n        py=%r" % (got, rx.pattern)))

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
