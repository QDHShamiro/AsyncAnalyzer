"""
Mirrors the autonomous decision logic in AsyncAnalyzer.ps1 (Set-AutoDepth,
Request-DeepEscalation, Get-ScanTargets) and pins its behaviour.

The tool now runs with no prompts and no flags, so these decisions ARE the
product: which folders get scanned, how deep to go, and - just as important -
what it admits it could not check. A tool that decides for itself must not be
able to quietly report "clean" for a check it skipped.

Run:  python3 test_autoscan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

passed = failed = 0


def check(label, got, want):
    global passed, failed
    ok = got == want
    passed += ok
    failed += not ok
    print("  [%s] %-52s got=%s" % ("PASS" if ok else "FAIL", label, got))


# ---------------------------------------------------------------- depth ---
def auto_depth(mc_running):
    """Set-AutoDepth: running game means someone is being checked right now."""
    if mc_running:
        return {"deep": True, "deep_scan": True, "bc_classes": 400, "gaps": []}
    return {"deep": False, "deep_scan": False, "bc_classes": 40,
            "gaps": ["Minecraft was not running"]}


def escalate(state, flagged, review, hard_confirmed, random_named):
    """Request-DeepEscalation: widen the SEARCH, never move a threshold."""
    if flagged > 0 or review > 0 or hard_confirmed > 0 or random_named > 0:
        state = dict(state, deep=True, deep_scan=True, bc_classes=400, escalated=True)
    return state


# -------------------------------------------------------------- targets ---
def alt_client_dirs(tree, root, max_depth=4):
    """Find-AltClientModDirs: every directory named mods or addons under a client
    root, to a bounded depth. Deliberately NOT the loose jars a client ships itself -
    Lunar's own jars render entities and read the entity list, because that is what
    nametags and waypoints are, and treating them as mods would put a server-rule
    finding on the report of every Lunar user alive."""
    out, queue = [], [(root, 0)]
    while queue:
        cur, d = queue.pop(0)
        for sub in sorted(tree.get(cur, [])):
            leaf = sub.rsplit("/", 1)[-1].lower()
            if leaf in ("mods", "addons"):
                out.append(sub)
                continue
            if d < max_depth:
                queue.append((sub, d + 1))
    return out


def scan_targets(installs, configured, explicit_path=None):
    """Get-ScanTargets: what is OPEN is the ground truth; configured paths add to it."""
    if explicit_path:
        return [explicit_path], []
    gaps, targets = [], []
    running = [i for i in installs if i["running"]]
    if running:
        targets = [i["path"] for i in running]
        idle = [i for i in installs if not i["running"] and not i.get("alt")]
        if idle:
            gaps.append("%d other install(s) not open" % len(idle))
    elif [i for i in installs if not i.get("alt")]:
        targets = [[i for i in installs if not i.get("alt")][0]["path"]]
        plain = [i for i in installs if not i.get("alt")]
        if len(plain) > 1:
            gaps.append("%d installs, none open" % len(plain))
    # An alternative client's mods/addons folder is always scanned, open or not: it
    # holds a handful of jars rather than a modpack, and it is exactly where a jar
    # gets parked when the vanilla folder is the one being watched.
    for a in installs:
        if a.get("alt") and a["jars"] > 0 and a["path"] not in targets:
            targets.append(a["path"])
    for c in configured:
        if c not in targets:
            targets.append(c)
    if not targets:
        targets = [r"%APPDATA%\.minecraft\mods"]
    return targets, gaps


# ---------------------------------------------------------------------------
# The bug this closes: every launcher root the discovery knows is anchored to
# %APPDATA% / %LOCALAPPDATA% / %USERPROFILE%, all on C:. With two instances
# open under E:\ModrinthApp\profiles\, the scan printed "Nothing open" and fell
# back to C:\Users\...\.minecraft\mods - which was not the install being played.
MODRINTH_A = (r'"E:\ModrinthApp\meta\java\bin\javaw.exe" -Xmx4G '
              r'-Djava.library.path=E:\ModrinthApp\meta\natives\1.21 '
              r'net.minecraft.client.main.Main --username X '
              r'--gameDir "E:\ModrinthApp\profiles\Cheats test" '
              r'--assetsDir E:\ModrinthApp\meta\assets')
MODRINTH_B = (r'javaw.exe -cp E:\ModrinthApp\profiles\1.21.11\mods\sodium.jar;lib.jar '
              r'net.minecraft.client.main.Main --gameDir E:\ModrinthApp\profiles\1.21.11')
VANILLA = (r'"C:\Program Files\Java\bin\javaw.exe" -Xmx2G net.minecraft.client.main.Main '
           r'--gameDir C:\Users\s\AppData\Roaming\.minecraft')
PRISM = r'javaw.exe --gameDir=D:\PrismLauncher\instances\1.8.9\.minecraft'


def running_instance_cases():
    """(label, got, want) for the running-instance reader."""
    import autoscan as A
    dirs = A.running_game_dirs([MODRINTH_A, MODRINTH_B])
    yield ("both open instances are found",
           [d for d in dirs if "profiles" in d],
           [r"E:\ModrinthApp\profiles\Cheats test", r"E:\ModrinthApp\profiles\1.21.11"])
    yield ("a path with a space survives",
           r"E:\ModrinthApp\profiles\Cheats test" in dirs, True)
    yield ("the classpath alone names an instance",
           r"E:\ModrinthApp\profiles\1.21.11" in A.running_game_dirs([MODRINTH_B]), True)
    yield ("--gameDir= with an equals sign works too",
           A.running_game_dirs([PRISM]), [r"D:\PrismLauncher\instances\1.8.9\.minecraft"])
    yield ("vanilla on C: is still found",
           A.running_game_dirs([VANILLA]), [r"C:\Users\s\AppData\Roaming\.minecraft"])
    yield ("nothing running yields nothing", A.running_game_dirs(["", None]), [])
    # The natives path is a fallback, and in Modrinth's layout it points at
    # meta\natives rather than at the profile. It is a CANDIDATE: the caller
    # keeps only directories that really contain a mods folder.
    yield ("the natives fallback is only a candidate",
           r"E:\ModrinthApp\meta\natives" in dirs, True)
    # A running instance means its siblings are instances too - and the one that
    # is NOT open is exactly where a jar gets parked while the open one is watched.
    yield ("siblings of a profile are found",
           A.sibling_instances(r"E:\ModrinthApp\profiles\Cheats test"),
           r"E:\ModrinthApp\profiles")
    yield ("...and of an instances folder",
           A.sibling_instances(r"D:\PrismLauncher\instances\1.8.9"),
           r"D:\PrismLauncher\instances")
    yield ("vanilla stands alone",
           A.sibling_instances(r"C:\Users\s\AppData\Roaming\.minecraft"), "")


def main():
    print("=== Finding the instances that are actually OPEN ===")
    for label, got, want in running_instance_cases():
        check(label, got, want)

    print("\n=== Depth decided without any flag ===")
    check("game running -> full depth", auto_depth(True)["deep"], True)
    check("game running -> all classes parsed", auto_depth(True)["bc_classes"], 400)
    check("game closed -> quick", auto_depth(False)["deep"], False)
    check("game closed -> records that as a gap", len(auto_depth(False)["gaps"]), 1)

    print("\n=== Escalating on its own ===")
    quick = auto_depth(False)
    check("nothing found -> stays quick",
          escalate(quick, 0, 0, 0, 0)["deep"], False)
    check("a flagged mod -> goes deep",
          escalate(quick, 1, 0, 0, 0)["deep"], True)
    check("only a review-band mod -> goes deep",
          escalate(quick, 0, 1, 0, 0)["deep"], True)
    check("a random-named jar -> goes deep",
          escalate(quick, 0, 0, 0, 1)["deep"], True)
    # escalation must widen the search WITHOUT touching how anything is scored
    before = auto_depth(False)
    after = escalate(before, 1, 0, 0, 0)
    check("escalation changes only search breadth",
          sorted(k for k in after if before.get(k) != after.get(k)),
          ["bc_classes", "deep", "deep_scan", "escalated"])

    print("\n=== Which folders get scanned ===")
    two_open = [{"path": "A", "running": True}, {"path": "B", "running": True},
                {"path": "C", "running": False}]
    t, g = scan_targets(two_open, [])
    check("both open instances scanned", t, ["A", "B"])
    check("the idle one is admitted as a gap", len(g), 1)

    none_open = [{"path": "A", "running": False}, {"path": "B", "running": False}]
    t, g = scan_targets(none_open, [])
    check("nothing open -> best guess only", t, ["A"])
    check("and says so", len(g), 1)

    t, _ = scan_targets(none_open, [r"D:\alt\mods"])
    check("configured path is added", t, ["A", r"D:\alt\mods"])

    t, g = scan_targets([], [])
    check("nothing found at all -> default folder", len(t), 1)

    t, _ = scan_targets(two_open, ["X"], explicit_path="P")
    check("-Path wins over everything", t, ["P"])

    print("\n=== Alternative clients (Lunar / Badlion / Feather / LabyMod) ===")
    # LabyMod has no mods folder at all - its extensions are jars in addons/, which
    # is why an exact-path lookup for "mods" missed them completely.
    tree = {
        "/laby": ["/laby/addons", "/laby/assets", "/laby/versions"],
        "/laby/versions": ["/laby/versions/1.20"],
        "/laby/versions/1.20": ["/laby/versions/1.20/mods"],
        "/laby/assets": [],
    }
    check("addons/ and a nested mods/ are both found",
          sorted(alt_client_dirs(tree, "/laby")),
          ["/laby/addons", "/laby/versions/1.20/mods"])
    # Lunar ships its own client jars in offline/multiver. They render entities and
    # read the entity list because that is what nametags and waypoints are, so
    # collecting them would put a server-rule finding on every Lunar user's report.
    lunar = {
        "/lunar": ["/lunar/offline", "/lunar/profiles"],
        "/lunar/offline": ["/lunar/offline/multiver"],
        "/lunar/offline/multiver": [],
        "/lunar/profiles": ["/lunar/profiles/main"],
        "/lunar/profiles/main": ["/lunar/profiles/main/mods"],
    }
    check("a client's own jar folder is NOT taken as mods",
          alt_client_dirs(lunar, "/lunar"), ["/lunar/profiles/main/mods"])
    # the walk is bounded, so a deep tree cannot turn into a whole-disk scan
    deep = {"/r": ["/r/a"], "/r/a": ["/r/a/b"], "/r/a/b": ["/r/a/b/c"],
            "/r/a/b/c": ["/r/a/b/c/d"], "/r/a/b/c/d": ["/r/a/b/c/d/e"],
            "/r/a/b/c/d/e": ["/r/a/b/c/d/e/mods"]}
    check("the walk stops at the depth limit", alt_client_dirs(deep, "/r"), [])

    # an alt client is scanned whether or not it is the one that is open
    mixed = [{"path": "vanilla", "running": True},
             {"path": "laby/addons", "running": False, "alt": True, "jars": 3}]
    t, g = scan_targets(mixed, [])
    check("alt client scanned alongside the open instance", t, ["vanilla", "laby/addons"])
    check("and is not counted as a skipped install", len(g), 0)

    idle_only = [{"path": "vanilla", "running": False},
                 {"path": "laby/addons", "running": False, "alt": True, "jars": 2}]
    t, _ = scan_targets(idle_only, [])
    check("alt client scanned even when nothing is open", t, ["vanilla", "laby/addons"])

    empty_alt = [{"path": "vanilla", "running": True},
                 {"path": "laby/addons", "running": False, "alt": True, "jars": 0}]
    t, _ = scan_targets(empty_alt, [])
    check("an empty addons folder is not a target", t, ["vanilla"])

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
