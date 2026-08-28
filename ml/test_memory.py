"""
Reference + tests for the memory-vs-disk cross-check in AsyncAnalyzer.ps1.

The idea: a ghost client is injected into the running game rather than loaded
from the mods folder. So if a cheat's classes are live in memory and NO jar on
disk contains that package, the tool can say something much stronger than "a
cheat string appeared in RAM" - it can say the cheat was injected, which is
exactly why deleting files before a screenshare does not help.

The claim is deliberately gated. A short word can appear in RAM by coincidence -
a chat message, a server MOTD, a resource-pack name - so the strong wording needs
a distinctive token AND repeated hits, which is what loaded code looks like as
opposed to one stray string. Mirrors Test-LoadedFromDisk and its call site.

Run:  python3 test_memory.py
"""
import re
import sys


def loaded_from_disk(token, disk_packages):
    """Could anything on disk have supplied classes for this name?"""
    if not disk_packages:
        return True          # nothing was scanned - never claim anything
    t = re.sub(r"[^A-Za-z0-9]", "", token).lower()
    if len(t) < 4:
        return True
    return any(t in re.sub(r"[^A-Za-z0-9]", "", p).lower() for p in disk_packages)


def claims_injected(token, hits, disk_packages):
    """The strong 'injected, nothing on disk could have loaded it' claim."""
    return (len(token) >= 6 and hits >= 3
            and not loaded_from_disk(token, disk_packages))


# ---------------------------------------------------------------------------
# Which of the live-process observations may raise jvm_inject.
#
# jvm_inject is a HARD rule: one point of it forces the whole scan to at least
# "Likely", whatever else the scan found. So the only things allowed to raise it
# are things with no innocent explanation. Everything else is reported as a NOTE
# (visible, counted as a system issue, never decisive) or as a GAP (something the
# scan could not look at, which proves nothing in either direction).
#
# Mirrors Run-JVMScan in src/90-jvm.ps1.
# ---------------------------------------------------------------------------
FINDING, NOTE, GAP = "finding", "note", "gap"

LEGIT_AGENTS = ("jmxremote", "yjp", "jrebel", "newrelic", "jacoco", "theseus")


def classify_jvm(kind, **kw):
    """Sort one live-process observation into finding / note / gap."""
    if kind == "javaagent":
        name = kw["name"].lower()
        # Whitelisted by FILE NAME only, which anyone can copy - so it is still
        # said out loud, just not counted as proof.
        return NOTE if any(a in name for a in LEGIT_AGENTS) else FINDING
    if kind == "jvm_flag":
        flag = kw["flag"]
        if flag.startswith("-agentlib:jdwp") or flag.startswith("-agentpath:"):
            return FINDING
        if flag.startswith("-Xbootclasspath"):
            return NOTE      # legacy launchers patch authlib this way
        return NOTE
    if kind == "listener":
        # Gradle daemons, launcher OAuth redirect catchers and web-map mods all
        # listen on 127.0.0.1. Worth a look; never an accusation.
        return NOTE
    if kind == "mem":
        # A word in RAM can be chat, a MOTD, a sign or a scoreboard. Loaded code
        # repeats its own name; conversation does not.
        return FINDING if (len(kw["token"]) >= 6 and kw["hits"] >= 3) else NOTE
    if kind in ("budget", "no_handle", "no_cmdline", "not_64bit"):
        return GAP
    raise AssertionError("unclassified observation: " + kind)


JVM_CASES = [
    ("javaagent",  dict(name="doomsday-loader.jar"),      FINDING, "unknown agent on the game"),
    ("javaagent",  dict(name="theseus.jar"),              NOTE,    "Modrinth App's own agent"),
    ("javaagent",  dict(name="jacoco-agent.jar"),         NOTE,    "coverage agent, known-good name"),
    ("jvm_flag",   dict(flag="-agentlib:jdwp=transport"), FINDING, "remote debugger into a game"),
    ("jvm_flag",   dict(flag="-agentpath:x.dll"),         FINDING, "native agent, no sandbox"),
    ("jvm_flag",   dict(flag="-Xbootclasspath/a:x.jar"),  NOTE,    "legacy launchers do this"),
    ("listener",   dict(port=8080),                       NOTE,    "gradle / web map / OAuth"),
    ("mem",        dict(token="doomsday", hits=37),       FINDING, "loaded code repeats its name"),
    ("mem",        dict(token="killaura", hits=1),        NOTE,    "one hit is a chat message"),
    ("mem",        dict(token="baritone", hits=2),        NOTE,    "two hits is still chat"),
    ("mem",        dict(token="freecam", hits=9),         FINDING, "repeated: a live module"),
    ("mem",        dict(token="vape", hits=99),           NOTE,    "4 chars is too generic"),
    ("budget",     dict(),                                GAP,     "ran out of time budget"),
    ("no_handle",  dict(),                                GAP,     "could not open the process"),
    ("no_cmdline", dict(),                                GAP,     "command line unreadable"),
    ("not_64bit",  dict(),                                GAP,     "32-bit PowerShell host"),
]


def jvm_inject_count(observations):
    """What Evidence.JvmInject is set to. Only findings count."""
    return sum(1 for k, kw in observations if classify_jvm(k, **kw) == FINDING)


NORMAL = {"net/minecraft", "me/jellysquid", "net/caffeinemc", "xaero/minimap",
          "mezz/jei", "journeymap/client", "net/fabricmc"}

CASES = [
    ("doomsday", 37, NORMAL, True, "ghost client, many hits, absent from disk"),
    ("liquidbounce", 12, NORMAL, True, "distinctive + repeated + absent"),
    ("doomsday", 1, NORMAL, False, "a single hit could be a chat mention"),
    ("vape", 50, NORMAL, False, "4-char token is too generic for the strong claim"),
    ("wurstclient", 40, NORMAL | {"net/wurstclient"}, False, "the cheat IS installed as a jar"),
    ("meteorclient", 22, NORMAL | {"meteordevelopment/meteorclient"}, False, "installed, not injected"),
    ("novoline", 8, set(), False, "nothing scanned - must never claim"),
    ("xaero", 30, NORMAL, False, "legit minimap is on disk"),
    ("prestigeclient", 15, NORMAL, True, "absent from disk"),
]


def main():
    passed = failed = 0
    print("=== Memory-vs-disk cross-check (injected ghost clients) ===")
    for token, hits, disk, want, why in CASES:
        got = claims_injected(token, hits, disk)
        ok = got == want
        passed += ok
        failed += not ok
        print("  [%s] %-15s hits=%3d claim=%-5s  %s" % (
            "PASS" if ok else "FAIL", token, hits, got, why))
    print()
    print("=== Live-process observations: what may force a verdict ===")
    for kind, kw, want, why in JVM_CASES:
        got = classify_jvm(kind, **kw)
        ok = got == want
        passed += ok
        failed += not ok
        arg = next(iter(kw.values())) if kw else ""
        print("  [%s] %-10s %-24s -> %-8s %s" % (
            "PASS" if ok else "FAIL", kind, str(arg)[:24], got, why))

    print()
    print("=== The bug this split fixes ===")
    # A clean PC whose memory sweep hit its time budget, with a Gradle daemon
    # listening and a chat message mentioning a cheat. Under the old flat list
    # that was 3 "injection traces" -> jvm_inject=3 -> hard rule -> Likely.
    clean_pc = [("budget", {}), ("listener", {"port": 8080}),
                ("mem", {"token": "killaura", "hits": 1})]
    got = jvm_inject_count(clean_pc)
    ok = got == 0
    passed += ok
    failed += not ok
    print("  [%s] clean PC, slow sweep + gradle + chat -> jvm_inject=%d (want 0)"
          % ("PASS" if ok else "FAIL", got))

    # And the real thing still counts, so the fix did not buy safety with blindness.
    injected = [("javaagent", {"name": "gzfjalsrvp.jar"}),
                ("mem", {"token": "doomsday", "hits": 37}),
                ("budget", {})]
    got = jvm_inject_count(injected)
    ok = got == 2
    passed += ok
    failed += not ok
    print("  [%s] injected loader + live client + slow sweep -> jvm_inject=%d (want 2)"
          % ("PASS" if ok else "FAIL", got))

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
