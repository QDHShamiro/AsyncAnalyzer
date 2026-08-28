"""
Proves the macro / autoclicker classifier on realistic script files.

The point it has to demonstrate is the same one the bytecode corpus demonstrates:
the individual ingredients appear in both. Ordinary AutoHotkey scripts click. Mouse
drivers run Lua. Minecraft mods are written in Lua. Only the COMBINATION - a click
LOOP that names the game - is an accusation, and everything short of that is
reported as what it is instead.

The legitimate samples are the load-bearing half. A recoil script for a shooter is
a real click loop in a real mouse driver and it is not a Minecraft cheat; if it
ever comes back as "cheat", this file is what says so.

Run:  python3 ml/test_macro.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macro

# ---------------------------------------------------------------- positives ---
CHEAT = [
    ("mcclicker.ahk", "cheat", r'''
#IfWinActive ahk_exe javaw.exe
$*LButton::
Loop {
    if not GetKeyState("LButton", "P")
        break
    Click
    Random, d, 35, 85
    Sleep %d%
}
return
#IfWinActive
'''),
    # no window scoping at all - caught by the filename, which names the technique
    ("butterflyclick.ahk", "named", r'''
$*XButton1::
Loop {
    if not GetKeyState("XButton1", "P")
        break
    Click
    Sleep 20
    Click
    Sleep 18
}
return
'''),
    ("blockhit.ahk", "cheat", r'''
#IfWinActive Minecraft
~*LButton::
SetTimer, Hit, 30
return
Hit:
Click right
Sleep 12
Click right up
return
'''),
    ("clicker.au3", "cheat", r'''
While 1
    If WinActive("Minecraft") Then
        MouseClick("left")
        Sleep(Random(30, 70, 1))
    EndIf
WEnd
'''),
    # the one people assume cannot be seen: it runs inside the mouse driver
    ("mc_auto.lua", "cheat", r'''
EnablePrimaryMouseButtonEvents(true)
function OnEvent(event, arg)
    if event == "MOUSE_BUTTON_PRESSED" and arg == 1 then
        -- Minecraft
        while IsMouseButtonPressed(1) do
            PressMouseButton(1)
            Sleep(math.random(20, 40))
            ReleaseMouseButton(1)
            Sleep(math.random(20, 40))
        end
    end
end
'''),
    ("autoclicker.lua", "named", r'''
function OnEvent(event, arg)
    if event == "G_PRESSED" and arg == 4 then
        repeat
            PressAndReleaseMouseButton(1)
            Sleep(25)
        until not IsMouseButtonPressed(4)
    end
end
'''),
    ("mcmacro.vbs", "cheat", r'''
Set sh = CreateObject("WScript.Shell")
sh.AppActivate "Minecraft"
Do While True
    sh.SendKeys "{LEFT}"
    WScript.Sleep 50
Loop
'''),
]

# ---------------------------------------------------------------- negatives ---
# Every one of these is a real thing people have on their PC. None may come back
# as "cheat" or "named"; the ones marked macro=True are click loops with nothing
# tying them to Minecraft, and are reported as that rather than accused.
CLEAN = [
    ("expand.ahk", False, r'''
::btw::by the way
::sig::Kind regards,`nShamiro
#z::Run, https://github.com
'''),
    ("windows.ahk", False, r'''
#Left::WinMove, A, , 0, 0, A_ScreenWidth//2, A_ScreenHeight
#Right::WinMove, A, , A_ScreenWidth//2, 0, A_ScreenWidth//2, A_ScreenHeight
^!v::Send, %Clipboard%
'''),
    # a single remap: one click, no loop
    ("remap.ahk", False, r'''
CapsLock::LButton
XButton2::MButton
'''),
    ("volume.ahk", False, r'''
Loop {
    Sleep 1000
    SoundGet, v
    ToolTip % "volume " v
}
'''),
    ("installer.au3", False, r'''
Run("setup.exe")
WinWaitActive("Setup")
Send("{ENTER}")
WinWaitActive("Finished")
Send("{ENTER}")
'''),
    # Minecraft's OWN Lua: ComputerCraft. Names the game constantly and is not a
    # macro at all - it never reaches the driver API, which is why .lua is safe
    # to scan in the first place.
    ("turtle.lua", False, r'''
-- Minecraft ComputerCraft mining turtle
while turtle.detect() do
    turtle.dig()
    turtle.forward()
    for i = 1, 16 do
        turtle.select(i)
        turtle.dropDown()
    end
end
'''),
    ("gmod_addon.lua", False, r'''
hook.Add("PlayerSpawn", "give", function(ply)
    for i = 1, 5 do
        ply:Give("weapon_crowbar")
    end
end)
'''),
    # G HUB lighting profile: the driver API, no mouse buttons
    ("lighting.lua", False, r'''
function OnEvent(event, arg)
    if event == "PROFILE_ACTIVATED" then
        OutputLogMessage("profile on\n")
        for i = 1, 10 do
            Sleep(100)
        end
    end
end
'''),
    # A recoil script for a shooter. A real click loop in a real mouse driver, and
    # not a Minecraft cheat. This must be "macro" and must never be "cheat".
    ("recoil.lua", True, r'''
EnablePrimaryMouseButtonEvents(true)
function OnEvent(event, arg)
    if event == "MOUSE_BUTTON_PRESSED" and arg == 1 then
        while IsMouseButtonPressed(1) do
            MoveMouseRelative(0, 3)
            PressMouseButton(1)
            Sleep(10)
            ReleaseMouseButton(1)
        end
    end
end
'''),
    ("logon.vbs", False, r'''
Set net = CreateObject("WScript.Network")
For Each d In Array("H:", "S:")
    net.MapNetworkDrive d, "\\server\share"
Next
'''),
    ("conf.lua", False, r'''
function love.conf(t)
    t.window.width = 800
    for i = 1, 3 do t.modules.joystick = true end
end
'''),
    ("build.lua", False, r'''
local files = {}
for _, name in ipairs(arg) do
    files[#files + 1] = name
end
'''),
]


def main():
    passed = failed = 0
    print("=== macro scripts that ARE a cheat (must classify 'cheat' or 'named') ===")
    for name, want_lvl, text in CHEAT:
        lvl, why = macro.classify(name, text)
        ok = lvl == want_lvl
        passed += ok
        failed += not ok
        print("  [%s] %-22s -> %-6s (want %s) %s" % (
            "PASS" if ok else "FAIL", name, lvl or "-", want_lvl, "; ".join(why)))

    print("\n=== real scripts that are NOT a cheat (must never classify 'cheat') ===")
    for name, want_macro, text in CLEAN:
        lvl, why = macro.classify(name, text)
        ok = lvl not in ("cheat", "named") and (lvl == "macro") == want_macro
        passed += ok
        failed += not ok
        print("  [%s] %-22s -> %-6s (want %s) %s" % (
            "PASS" if ok else "FAIL", name, lvl or "-",
            "macro" if want_macro else "clean", "; ".join(why)))

    # ---- parity with the shipped PowerShell -----------------------------------
    print("\n=== PowerShell / Python macro parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "10-signatures.ps1"), encoding="utf-8").read()
    m = re.search(r"\$script:macroLangs = \[ordered\]@\{(.*?)\n\}\n", ps, re.S)
    if not m:
        print("  FAIL  no $script:macroLangs table in the PowerShell source")
        failed += 1
    else:
        ps_langs = {}
        for lm in re.finditer(r"^\s*'(\.\w+)'\s*=\s*@\{(.*?)^\s*\}", m.group(1), re.S | re.M):
            ps_langs[lm.group(1)] = dict(
                re.findall(r"'(\w+)'\s*=\s*'(.*)'\s*$", lm.group(2), re.M))
        py_langs = {ext: {k: v for k, v in tbl.items()} for ext, tbl in macro.LANGS.items()}
        if set(ps_langs) != set(py_langs):
            print("  FAIL  languages differ: ps=%s py=%s" % (sorted(ps_langs), sorted(py_langs)))
            failed += 1
        for ext in sorted(set(ps_langs) & set(py_langs)):
            a, b = py_langs[ext], ps_langs[ext]
            bad = [k for k in a if a[k] != b.get(k)]
            passed += len(a) - len(bad)
            failed += len(bad)
            print("  %-6s %d pattern(s), %d mismatch(es)%s" % (
                ext, len(a), len(bad), (" -> " + ", ".join(bad)) if bad else ""))

    n = re.search(r"\$script:macroCheatNames = @\(([^)]*)\)", ps)
    ps_names = set(re.findall(r"'([^']+)'", n.group(1))) if n else set()
    ok = ps_names == set(macro.CHEAT_NAMES)
    passed += ok
    failed += not ok
    print("  %s  cheat-name list matches (%d names)%s" % (
        "PASS" if ok else "FAIL", len(macro.CHEAT_NAMES),
        "" if ok else " -> ps-only=%s py-only=%s" % (
            sorted(ps_names - set(macro.CHEAT_NAMES)),
            sorted(set(macro.CHEAT_NAMES) - ps_names))))

    d = re.search(r"\$script:macroDriverPaths = @\((.*?)\n\)", ps, re.S)
    ps_drv = set(re.findall(r"@\('([^']*)',\s*'([^']*)'", d.group(1))) if d else set()
    py_drv = {(nm, p) for nm, p, _ in macro.DRIVER_PATHS}
    ok = ps_drv == py_drv
    passed += ok
    failed += not ok
    print("  %s  driver macro paths match (%d)%s" % (
        "PASS" if ok else "FAIL", len(py_drv),
        "" if ok else " -> ps-only=%s py-only=%s" % (sorted(ps_drv - py_drv), sorted(py_drv - ps_drv))))

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
