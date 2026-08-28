"""Reference for the Windows system checks in AsyncAnalyzer.ps1 (src/91-system.ps1).

This is the oldest part of the tool and the one part the false-flag discipline
never reached. Every check in it decided by GUESSING AT NAMES:

    hosts:      the line contains "aac"        -> a pi-hole blocklist trips it
    tasks:      the name contains "updater"    -> Discord, OneDrive, Razer, Epic
    Defender:   the path contains "mod"        -> C:\\Games\\ModernWarfare
    prefetch:   the name contains "LOADER"     -> fabric-loader
    startup:    the value contains "java"      -> every Java application

Each of those fires on an ordinary gaming PC. None of them is evidence of
anything. What follows replaces every one of them with a STRUCTURAL test - what
the entry actually does, not what it is called - so a check either says something
or is not there.

The rule throughout: a hosts line only counts if it really blackholes a domain
that matters; a task or startup entry only counts if its ACTION is one no
launcher performs; a file name only counts through the same boundary-anchored
client matcher the rest of the tool uses.

Mirrors Test-HostsBlock / Test-DefenderExclusion / Test-AutostartAction /
Get-PrefetchImage in src/91-system.ps1.

Run:  python3 test_sysscan.py
"""
import re

# An address that sends the name nowhere. A hosts line pointing at a real IP is
# a redirect and can be a LAN setup, a mirror, a corporate split-horizon - so it
# is not read as blocking anything.
BLACKHOLE = {"127.0.0.1", "0.0.0.0", "::", "::1", "0:0:0:0:0:0:0:0", "255.255.255.255"}

# The game's own login servers. Blackholing these while playing is not a
# preference; it is the client being kept from talking to Mojang.
AUTH_HOSTS = (
    "sessionserver.mojang.com",
    "authserver.mojang.com",
    "api.mojang.com",
    "api.minecraftservices.com",
)

# Folders a launcher actually keeps a Minecraft install in. Used to decide
# whether a Defender exclusion is about Minecraft at all - the old check matched
# the substring "mod", which covers ModernWarfare, \\Models\\ and \\Modules\\.
MC_MARKERS = (
    "\\.minecraft", "\\.lunarclient", "\\badlion", "\\feather", "\\labymod",
    "\\prismlauncher", "\\multimc", "\\polymc", "\\atlauncher", "\\modrinthapp",
    "\\curseforge\\minecraft", "\\.technic", "\\.tlauncher", "\\gdlauncher",
)

# A base64 blob long enough to be a real command, after a PowerShell -e / -enc /
# -EncodedCommand switch. Matching the switch alone would hit "-Execute".
_ENCODED = re.compile(r"(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{40,}")
_JAVA_EXE = re.compile(r"(?i)(?:^|[\\\\/\"\s])javaw?(?:\.exe)?(?:\"|\s|$)")
_JAR = re.compile(r"(?i)\.jar(?:\"|\s|$)")
_PREFETCH = re.compile(r"(?i)^(.+)-[0-9A-F]{8}\.pf$")


def hosts_block(line, cheat_domains):
    """(kind, host) for a hosts line that blackholes something that matters.

    kind is "cheatsite" (a cheat vendor's own domain is redirected on this PC -
    that domain has no business being in a hosts file at all) or "auth" (the
    game's login servers are blackholed). Everything else returns (None, "").
    """
    line = line.split("#", 1)[0].strip()
    if not line:
        return None, ""
    parts = line.split()
    if len(parts) < 2 or parts[0] not in BLACKHOLE:
        return None, ""
    for name in parts[1:]:
        host = name.strip(".").lower()
        for d in cheat_domains:
            d = d.lower()
            if host == d or host.endswith("." + d):
                return "cheatsite", host
        for a in AUTH_HOSTS:
            if host == a or host.endswith("." + a):
                return "auth", host
    return None, ""


def defender_relevant(path):
    """Is this Defender exclusion about Minecraft, rather than about the word 'mod'?"""
    p = path.lower().replace("/", "\\")
    if any(m in p for m in MC_MARKERS):
        return True
    if p.rstrip("\\").endswith("\\mods"):
        return True
    # A process exclusion on the game's own runtime: nothing inside Minecraft is
    # ever scanned again, which is the point of adding it.
    if re.search(r"(?:^|\\)javaw?\.exe$", p):
        return True
    return False


def autostart_action(command, names_hit):
    """Why this startup entry or scheduled task is worth reporting, or "".

    Structural: what the command DOES. The old check flagged any value containing
    "java", which is every Java application ever installed.

    names_hit is the tool's own boundary-anchored client-name matcher, passed in
    so this file and the PowerShell agree on one list.
    """
    c = command.lower()
    hit = names_hit(command)
    if hit:
        return "names a known cheat client (%s)" % hit
    if "-javaagent:" in c:
        return "attaches a Java agent to the process it starts"
    if _ENCODED.search(command):
        return "runs a base64-encoded PowerShell command"
    if _JAR.search(command) and _JAVA_EXE.search(command):
        return "starts a .jar with Java at login"
    return ""


def prefetch_image(fname):
    """FOO.EXE-1A2B3C4D.pf -> foo.exe. The hash suffix is not part of the name."""
    m = _PREFETCH.match(fname)
    return (m.group(1) if m else fname).lower()
