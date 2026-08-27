"""
Mirrors the autonomous decision logic in AsyncAnalyzer.ps1 (Set-AutoDepth,
Request-DeepEscalation, Get-ScanTargets) and pins its behaviour.

The tool now runs with no prompts and no flags, so these decisions ARE the
product: which folders get scanned, how deep to go, and - just as important -
what it admits it could not check. A tool that decides for itself must not be
able to quietly report "clean" for a check it skipped.

Run:  python3 test_autoscan.py
"""
import sys

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
def scan_targets(installs, configured, explicit_path=None):
    """Get-ScanTargets: what is OPEN is the ground truth; configured paths add to it."""
    if explicit_path:
        return [explicit_path], []
    gaps, targets = [], []
    running = [i for i in installs if i["running"]]
    if running:
        targets = [i["path"] for i in running]
        idle = [i for i in installs if not i["running"]]
        if idle:
            gaps.append("%d other install(s) not open" % len(idle))
    elif installs:
        targets = [installs[0]["path"]]
        if len(installs) > 1:
            gaps.append("%d installs, none open" % len(installs))
    for c in configured:
        if c not in targets:
            targets.append(c)
    if not targets:
        targets = [r"%APPDATA%\.minecraft\mods"]
    return targets, gaps


def main():
    print("=== Depth decided without any flag ===")
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

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
