"""Where a running Minecraft actually is.

Every launcher root the discovery knows is anchored to %APPDATA%,
%LOCALAPPDATA% or %USERPROFILE% - all of them on C:. An install on another
drive cannot be found by that list at all: with two instances open under
E:\\ModrinthApp\\profiles\\, the scan reported "Nothing open" and fell back to
C:\\Users\\...\\.minecraft\\mods, which was not the install being played.

The running process already carries the answer. Minecraft is launched with
--gameDir, and the natives path and the classpath name the same install. So
rather than guessing at locations, ask the processes.

Run:  python3 test_autoscan.py
"""
import re

# --gameDir "E:\Modrinth App\profiles\Cheats test"  or  --gameDir E:\mc\inst
_GAMEDIR = re.compile(r'--gameDir(?:\s+|=)(?:"([^"]+)"|([^\s"]+))', re.I)
# -Djava.library.path=<...>  points at the natives folder of the same install
_NATIVES = re.compile(r'-Djava\.library\.path=(?:"([^"]+)"|([^\s"]+))', re.I)
# a jar on the classpath that sits inside a mods folder
_MODSJAR = re.compile(r'(?i)([A-Za-z]:\\(?:[^\s";]+\\)?mods)\\[^\s";\\]+\.jar')

# Folder names a launcher uses to hold ONE instance among many. Finding a
# running game inside one of these means its siblings are instances too - and a
# second instance that is not open right now is exactly where a jar gets parked
# while the open one is being watched.
INSTANCE_PARENTS = ("profiles", "instances", "modpacks")


def running_game_dirs(command_lines):
    """Every game directory named by a running java command line, in order."""
    out = []
    for cl in command_lines:
        if not cl:
            continue
        for rx in (_GAMEDIR, _NATIVES, _MODSJAR):
            for m in rx.finditer(cl):
                p = next((g for g in m.groups() if g), "")
                if not p:
                    continue
                p = p.rstrip("\\").rstrip()
                if rx is _NATIVES:
                    # ...\natives  or  ...\<instance>\natives-1.21
                    parent = p.rsplit("\\", 1)[0] if "\\" in p else ""
                    if not parent:
                        continue
                    p = parent
                elif rx is _MODSJAR:
                    p = p.rsplit("\\", 1)[0]     # strip the trailing \mods
                if len(p) > 3 and p not in out:
                    out.append(p)
    return out


def sibling_instances(game_dir):
    """If this install sits among siblings, name the parent that holds them.

    E:\\ModrinthApp\\profiles\\1.21.11  ->  E:\\ModrinthApp\\profiles
    C:\\Users\\s\\AppData\\Roaming\\.minecraft -> "" (it stands alone)
    """
    if "\\" not in game_dir:
        return ""
    parent = game_dir.rsplit("\\", 1)[0]
    leaf = parent.rsplit("\\", 1)[-1].lower() if "\\" in parent else parent.lower()
    return parent if leaf in INSTANCE_PARENTS else ""
