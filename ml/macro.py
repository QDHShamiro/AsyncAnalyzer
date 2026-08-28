"""
Macro / autoclicker file classification - the source of truth for the patterns.

Why this is its own module: the mods folder is not where a click macro lives. An
autoclicker is an AutoHotkey script on the desktop, an AutoIt binary, or - the case
people assume is invisible - a Lua script running inside the mouse driver, where
the clicks are generated below the game entirely.

The rule this has to hold is the same one the rest of the tool holds: it must not
accuse anyone. "Clicks the mouse" is not a cheat. Millions of AutoHotkey scripts
expand text, remap keys and tile windows, and a Logitech G HUB profile with a
recoil script in it belongs to a shooter, not to Minecraft. So there are two
levels and the difference between them is evidence, not confidence:

  cheat   the macro clicks IN A LOOP and names Minecraft - the game window, javaw,
          a known client. There is no innocent reading of a click loop scoped to
          the Minecraft window.
  named   the macro clicks in a loop and the FILE is named after the technique
          (blockhit, butterflyclick, autocrystal). Strong, but one step weaker:
          the file says what it is, it does not prove where it was used.
  macro   the macro clicks in a loop and nothing ties it to the game. Reported as
          what it is, with that limitation stated, and never as an accusation.

What this cannot see is stated rather than papered over: a macro burned into a
mouse's ONBOARD memory (Bloody, A4Tech, the onboard profiles of Razer/Logitech
devices) leaves nothing on the PC at all. That is recorded as a gap in coverage on
every scan, because it can never be ruled out from the PC side.
"""

import re

# --- AutoHotkey ---------------------------------------------------------------
# Mouse-specific on purpose. A text expander or a window-tiling script uses Send
# with text and never names a mouse button, which is what keeps those out.
AHK = {
    "click":  r"\bClick\b|\bMouseClick\b|\bLButton\b|\bRButton\b|\bMouseClickDrag\b",
    # a real repeat construct, not Sleep - "Click then Sleep" once is a hotkey
    "repeat": r"(?im)^\s*Loop\b|\bLoop\s*,|\bSetTimer\b|\bWhile\b|\bLoop\s*\{",
    # scoped to the game: the window, the launcher, or the JVM that runs it
    "mc":     (r"ahk_exe\s+javaw?\.exe|ahk_class\s+LWJGL|ahk_class\s+GLFW"
               r"|\bMinecraft\b|lunarclient|badlion|feather\s*client|labymod|prismlauncher"),
    # a click loop that randomises its delay is imitating a human hand
    "human":  r"\bRandom\b|RandomSleep|jitter|humaniz",
}

# --- AutoIt -------------------------------------------------------------------
AU3 = {
    "click":  r"\bMouseClick\b|\bMouseDown\b|\bMouseUp\b|\{LBUTTON|\{RBUTTON",
    "repeat": r"(?im)^\s*While\b|^\s*For\b|\bAdlibRegister\b|\bDo\b",
    "mc":     (r"WinActivate.*Minecraft|WinActive.*Minecraft|javaw?\.exe|LWJGL"
               r"|\bMinecraft\b|lunarclient|badlion"),
    "human":  r"\bRandom\b|jitter|humaniz",
}

# --- Lua inside a gaming mouse / keyboard driver ------------------------------
# These names exist ONLY in the Logitech G HUB / G-series and Razer scripting APIs.
# That is what makes .lua safe to scan at all: Minecraft's own Lua mods
# (ComputerCraft and friends), Garry's Mod and Roblox share none of this
# vocabulary, so an ordinary Lua file cannot reach these rules.
LUA = {
    "click":  (r"\bPressMouseButton\b|\bReleaseMouseButton\b|\bPressAndReleaseMouseButton\b"
               r"|\bMouseClick\b|\bIsMouseButtonPressed\b"),
    "repeat": r"(?im)^\s*while\b|^\s*repeat\b|^\s*for\b|\bSetTimer\b",
    "mc":     r"\bMinecraft\b|javaw|lunarclient|badlion|labymod",
    "human":  r"\bmath\.random\b|\brandom\b|jitter|humaniz",
    # the driver API itself - present in every G HUB script, cheat or not
    "driver": (r"\bOnEvent\b|\bGetMKeyState\b|\bOutputLogMessage\b|\bPlayMacro\b"
               r"|\bEnablePrimaryMouseButtonEvents\b|\bMoveMouseRelative\b"),
}

# --- VBScript -----------------------------------------------------------------
# Narrow on purpose. VBScript cannot click a mouse without an external object, so
# the only shape worth reading is SendKeys in a loop against the game window.
VBS = {
    "click":  r"\bSendKeys\b|\bAppActivate\b",
    "repeat": r"(?im)^\s*Do\b|^\s*While\b|^\s*For\b",
    "mc":     r"\bMinecraft\b|javaw?\.exe|lunarclient|badlion",
    "human":  r"\bRnd\b|\bRandomize\b",
}

LANGS = {".ahk": AHK, ".ahk2": AHK, ".au3": AU3, ".lua": LUA, ".vbs": VBS}

# A filename is evidence too, but only these - they name the TECHNIQUE, and none of
# them is a word an ordinary script is called. "macro" alone is deliberately absent:
# it is what people call any automation, including the harmless kind.
CHEAT_NAMES = [
    "autoclick", "autoclicker", "auto_click", "auto-click", "clicker",
    "dragclick", "drag_click", "butterflyclick", "butterfly_click",
    "jitterclick", "jitter_click", "blockhit", "block_hit", "autotool",
    "aimassist", "aim_assist", "triggerbot", "autocrystal", "auto_crystal",
    "killaura", "autoaim", "auto_aim", "autobridge", "auto_bridge",
    "bhop", "autosprint", "autototem", "auto_totem", "reachmacro",
    "anchormacro", "anchorbot", "autoanchor", "cpsmacro", "clickermacro",
]

# Where a mouse or keyboard driver keeps the macros it runs. Presence is NOT a
# finding - these ship with hardware millions of people own. What is worth
# recording is that a macro profile exists and when it was last changed, plus the
# scripts themselves where the driver stores them as plain files.
DRIVER_PATHS = [
    # name, path template, what is there
    ("Logitech G HUB", r"%LOCALAPPDATA%\LGHUB\scripts", "Lua macro scripts, one per profile"),
    ("Logitech G HUB", r"%LOCALAPPDATA%\LGHUB\settings.db", "profile database - can hold macros"),
    ("Logitech LGS", r"%LOCALAPPDATA%\Logitech\Logitech Gaming Software\profiles", "profile XML with macros"),
    ("Razer Synapse 3", r"%PROGRAMDATA%\Razer\Synapse3\Accounts", "device profiles with macros"),
    ("Razer Synapse 2", r"%APPDATA%\Razer\Synapse\Accounts", "device profiles with macros"),
    ("Corsair iCUE", r"%APPDATA%\Corsair\CUE4", "profile database - can hold macros"),
    ("SteelSeries GG", r"%APPDATA%\SteelSeries\SteelSeries Engine 3", "device profiles with macros"),
    ("Bloody / A4Tech", r"%PROGRAMDATA%\A4TECH", "onboard macro profiles"),
    ("Bloody / A4Tech", r"%PROGRAMDATA%\Bloody7", "onboard macro profiles"),
    ("Glorious Core", r"%APPDATA%\GloriousCore", "device profiles with macros"),
]

_C = {ext: {k: re.compile(v, re.I) for k, v in tbl.items()} for ext, tbl in LANGS.items()}


def classify(filename, text):
    """Return (level, reasons). level is "cheat", "named", "macro" or None.

    "cheat" needs a click loop AND the file naming Minecraft. "named" is a click
    loop in a file named after the technique - strong, but it does not prove where
    it was used. "macro" is a click loop with nothing tying it to the game.
    """
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    tbl = _C.get(ext)
    if not tbl:
        return None, []
    stem = filename.rsplit(".", 1)[0].lower()
    named = next((n for n in CHEAT_NAMES if n in stem.replace(" ", "")), None)

    clicks = bool(tbl["click"].search(text))
    loops = bool(tbl["repeat"].search(text))
    mc = bool(tbl["mc"].search(text))
    human = bool(tbl["human"].search(text))
    # A driver script that does not touch the mouse buttons is a lighting or
    # key-remap profile, and there are a great many of those.
    if ext == ".lua" and not tbl["driver"].search(text):
        return None, []

    if not (clicks and loops):
        # a file named after the technique, with no click loop in it, is worth a
        # line but is not a macro - it could be a readme or a leftover config
        if named and clicks:
            return "macro", ["named after '%s' and sends mouse input" % named]
        return None, []

    reasons = ["repeats mouse input in a loop"]
    if human:
        reasons.append("randomises its own delay - imitating a human hand")
    if ext == ".lua":
        reasons.insert(0, "runs inside the mouse driver, below the game")
    if mc:
        reasons.append("scoped to Minecraft (window, launcher or JVM named in the file)")
    if named:
        reasons.append("file is named after the technique ('%s')" % named)
    if mc:
        return "cheat", reasons
    return ("named" if named else "macro"), reasons


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        lvl, why = classify(p.rsplit("/", 1)[-1], open(p, encoding="utf-8", errors="replace").read())
        print("%-10s %s  %s" % (lvl or "-", p, "; ".join(why)))
