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
    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
