#!/usr/bin/env python3
"""Tests for the Windows system checks.

Every case marked CLEAN below is something that exists on ordinary PCs and that
the OLD check flagged. They are the point of the file: this part of the tool
used to accuse people for owning Discord.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sysscan as S
from sysscan import FINDING, NOTE

# The tool's own client-name matcher, boundary-anchored, as instscan/logscan use
# it. Passed into autostart_action so both sides share one list.
TOKENS = ["doomsday", "wurstclient", "meteorclient", "liquidbounce", "vape",
          "impactclient", "sigma", "baritone"]
PACKAGES = ["doomsdayclient", "net/wurstclient", "meteordevelopment"]
CHEAT_DOMAINS = ["doomsdayclient.com", "vape.gg", "wurstclient.net"]


def names_hit(value):
    low = value.lower()
    for p in PACKAGES:
        for form in (p.lower(), p.lower().replace("/", ".")):
            if form in low:
                return form
    for t in TOKENS:
        if len(t) < 4:
            continue
        if re.search(r"(?:^|[/.\\_\- ])%s(?:$|[/.\\_\- ])" % re.escape(t), low):
            return t
    return ""


# ---------------------------------------------------------------- hosts file --
HOSTS = [
    ("127.0.0.1 doomsdayclient.com", "cheatsite",
     "a cheat vendor's domain, redirected to nowhere"),
    ("0.0.0.0 auth.vape.gg", "cheatsite", "a subdomain of one counts too"),
    ("127.0.0.1 sessionserver.mojang.com", "auth",
     "the game's own login server, blackholed"),
    # --- everything below is CLEAN and the old check flagged all of it ---
    ("0.0.0.0 ads.isaac-analytics.com", None,
     "CLEAN: a pi-hole blocklist line - the old check matched 'aac' inside it"),
    ("0.0.0.0 pilgrimage-tracker.net", None,
     "CLEAN: contains 'grim', which the old list matched unanchored"),
    ("0.0.0.0 telemetry.watchdog-analytics.io", None,
     "CLEAN: an ad domain containing 'watchdog'"),
    ("0.0.0.0 curseforge.com", None,
     "CLEAN: a parental or corporate filter blocking a mod site is not cheating"),
    ("# 127.0.0.1 doomsdayclient.com", None, "CLEAN: a commented-out line"),
    ("192.168.1.40 doomsdayclient.com", None,
     "CLEAN: pointed at a real host, so it is a redirect and not a block"),
    ("127.0.0.1", None, "CLEAN: an address with no hostname"),
    ("", None, "CLEAN: a blank line"),
    ("127.0.0.1 localhost # doomsdayclient.com", None,
     "CLEAN: the cheat domain is inside the comment"),
]

# --------------------------------------------------------- Defender exclusions --
DEFENDER = [
    ("C:\\Users\\s\\AppData\\Roaming\\.minecraft", True, "the Minecraft folder itself"),
    ("C:\\Users\\s\\AppData\\Roaming\\.minecraft\\mods", True, "the mods folder"),
    ("D:\\Instances\\1.8.9\\mods", True, "any folder actually called mods"),
    ("C:\\Users\\s\\.lunarclient", True, "an alternative client's folder"),
    ("C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe", True,
     "a process exclusion on the game's own runtime"),
    ("C:\\Games\\ModernWarfare", False,
     "CLEAN: the old check matched the substring 'mod'"),
    ("C:\\Blender\\Models", False, "CLEAN: 'Models' is not 'mods'"),
    ("C:\\Python312\\Lib\\Modules", False, "CLEAN: 'Modules' is not 'mods'"),
    ("C:\\Program Files\\Java", False,
     "CLEAN: excluding a JDK for build speed is a developer, not a cheater"),
    ("C:\\Games\\EpicLauncher", False, "CLEAN: the old check matched 'launcher'"),
]

# ------------------------------------------- startup entries & scheduled tasks --
AUTOSTART = [
    ("javaw.exe -javaagent:C:\\Users\\s\\AppData\\Local\\Temp\\x.jar -jar mc.jar",
     True, "attaches a Java agent"),
    ("powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
     True, "a base64-encoded PowerShell command"),
    ("\"C:\\Program Files\\Java\\bin\\javaw.exe\" -jar \"C:\\Users\\s\\loader.jar\"",
     True, "starts a .jar with Java at login"),
    ("C:\\Users\\s\\Downloads\\doomsday-loader.exe", True, "names a known client"),
    # --- CLEAN: all of these were flagged by 'java|\\.jar|...' ---
    ("\"C:\\Program Files\\Java\\jre\\bin\\jusched.exe\"", False,
     "CLEAN: the Java updater - the old check matched 'java' in the path"),
    ("C:\\Program Files\\Discord\\Update.exe --processStart Discord.exe", False,
     "CLEAN: Discord's updater"),
    ("C:\\Users\\s\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
     False, "CLEAN: OneDrive"),
    ("\"C:\\Program Files\\Razer\\Synapse3\\RazerSynapse.exe\" -silent", False,
     "CLEAN: a peripheral driver, which the old task check flagged as 'service'"),
    ("powershell -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", False,
     "CLEAN: a plain PowerShell script is not an encoded command"),
    ("C:\\Program Files\\JetBrains\\IDEA\\bin\\idea64.exe", False,
     "CLEAN: an IDE"),
    ("C:\\Games\\Java\\jarfixer.exe", False,
     "CLEAN: mentions jar and java but starts neither"),
]

# ------------------------------------------------------------------- prefetch --
PREFETCH = [
    ("VAPE.EXE-1A2B3C4D.pf", "vape.exe", True, "a client, named"),
    ("DOOMSDAY-LOADER.EXE-0011AABB.pf", "doomsday-loader.exe", True, "hyphenated"),
    ("FABRIC-LOADER.EXE-99887766.pf", "fabric-loader.exe", False,
     "CLEAN: the old check matched 'LOADER'"),
    ("EXAMINER.EXE-12341234.pf", "examiner.exe", False,
     "CLEAN: the old check matched 'MINER'"),
    ("PROJECTOR.EXE-AABBCCDD.pf", "projector.exe", False,
     "CLEAN: the old check matched 'INJECT'... in 'PROJECTOR'"),
    ("JAVAW.EXE-DEADBEEF.pf", "javaw.exe", False, "CLEAN: the game itself"),
]


def main():
    passed = failed = 0

    def report(ok, fmt, *args):
        nonlocal passed, failed
        passed += ok
        failed += not ok
        print(("  [%s] " % ("PASS" if ok else "FAIL")) + fmt % args)

    print("=== hosts file: does the line actually blackhole something? ===")
    for line, want, why in HOSTS:
        kind, host = S.hosts_block(line, CHEAT_DOMAINS)
        report(kind == want, "%-46s -> %-9s %s", line[:46], kind or "-", why)

    print("\n=== Defender exclusions: is it about Minecraft, or about 'mod'? ===")
    for path, want, why in DEFENDER:
        got = S.defender_relevant(path)
        report(got == want, "%-46s -> %-5s %s", path[:46], got, why)

    print("\n=== autostart: what the entry DOES, not what it is called ===")
    for cmd, want, why in AUTOSTART:
        got = S.autostart_action(cmd, names_hit)
        report(bool(got) == want, "%-46s -> %-5s %s", cmd[:46], bool(got), why)

    print("\n=== prefetch: the image name, through the same client matcher ===")
    for fname, want_img, want_hit, why in PREFETCH:
        img = S.prefetch_image(fname)
        got = bool(names_hit(img))
        ok = (img == want_img) and (got == want_hit)
        report(ok, "%-30s -> %-22s %-5s %s", fname, img, got, why)

    print("\n=== DLLs inside the game process: signed, or not ===")
    # The old check searched the whole path for substrings. Six of these nine
    # real DLLs were flagged by it, including the one OBS injects into every
    # game it records - so the person most likely to trip it was the one
    # recording the screenshare.
    DLL = [
        (r"C:\Program Files\obs-studio\data\obs-plugins\win-capture\graphics-hook64.dll",
         True, None, "CLEAN: OBS game capture, signed - the old check matched 'hook'"),
        (r"C:\Program Files (x86)\RivaTuner Statistics Server\RTSSHooks64.dll",
         True, None, "CLEAN: the MSI Afterburner FPS overlay, signed"),
        (r"C:\Users\s\AppData\Local\Overwolf\OWClientHook.dll",
         True, None, "CLEAN: Overwolf, signed even though it sits in AppData"),
        (r"C:\Games\Desperados III\bin\engine.dll",
         True, None, "CLEAN: a game with 'esp' in its name"),
        (r"C:\Program Files\NVIDIA Corporation\NvContainer\nvinject.dll",
         True, None, "CLEAN: an NVIDIA component, signed"),
        (r"C:\Users\s\AppData\Local\Temp\doomsday-inject.dll",
         False, FINDING, "unsigned AND named after a known client"),
        (r"C:\Users\s\Downloads\vape.dll",
         False, FINDING, "unsigned AND named"),
        (r"C:\Users\s\AppData\Local\Temp\a1b2c3.dll",
         False, NOTE, "unsigned in a user-writable folder, but the name says nothing"),
        (r"C:\Windows\System32\somethingodd.dll",
         False, None, "unsigned but in System32 - not the player's doing"),
    ]
    for path, signed, want, why in DLL:
        got = S.dll_verdict(path, signed, names_hit)
        report(got == want, "%-52s -> %-8s %s", path[-52:], got or "-", why)

    print("\n=== Running processes: a location is not evidence ===")
    # Measured: with Zoom running, a scan of 25 mods that were all verified and
    # nothing else wrong came out Likely 60 - because the count fed cheat_procs,
    # which is a hard rule.
    KNOWN = {"doomsday", "vape", "wurstclient"}
    PROC = [
        ("doomsday.exe", r"C:\Users\s\Downloads\doomsday.exe", False, FINDING,
         "a known cheat process name"),
        ("Zoom.exe", r"C:\Users\s\AppData\Roaming\Zoom\bin\Zoom.exe", True, NOTE,
         "CLEAN: Zoom is where a screenshare call happens"),
        ("slack.exe", r"C:\Users\s\AppData\Roaming\Slack\slack.exe", True, NOTE,
         "CLEAN: Slack"),
        ("Signal.exe", r"C:\Users\s\AppData\Roaming\Signal\Signal.exe", True, NOTE,
         "CLEAN: Signal"),
        ("winlogon.exe", r"C:\Windows\System32\winlogon.exe", False, None,
         "CLEAN: Windows itself, which the old NAME patterns matched"),
        ("explorer.exe", r"C:\Windows\explorer.exe", False, None, "CLEAN: Explorer"),
    ]
    for name, path, odd, want, why in PROC:
        got = S.process_verdict(name, path, KNOWN, odd)
        report(got == want, "%-24s -> %-8s %s", name, got or "-", why)
    # The property that makes the Note safe: nothing here may raise cheat_procs.
    counted = sum(1 for n, p, o, _w, _y in PROC if S.process_verdict(n, p, KNOWN, o) == FINDING)
    report(counted == 1, "exactly %d of those six may raise cheat_procs (want 1)", counted)

    # ---- parity with the shipped PowerShell ---------------------------------
    print("\n=== PowerShell / Python parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "91-system.ps1"), encoding="utf-8").read()
    sig = open(os.path.join(root, "src", "10-signatures.ps1"), encoding="utf-8").read()

    # The old guessing checks must be GONE, not merely supplemented - a name-guess
    # left in place next to a structural check still fires on the same clean PC.
    # Comments are stripped first: this file explains what it removed, and the
    # explanation naming the old pattern is not the old pattern.
    ps_code = "\n".join(l for l in ps.split("\n") if not l.lstrip().startswith("#"))
    pc = open(os.path.join(root, "src", "96-pcscan.ps1"), encoding="utf-8").read()
    pc_code = "\n".join(l for l in pc.split("\n") if not l.lstrip().startswith("#"))
    for gone, what in (
            (r"'aac'|\"aac\"|,aac,", "the 'aac' substring in the hosts list"),
            (r"updater\|java", "the scheduled-task name guess"),
            (r"jre\|mod\\b|jre\|mod\|", "the 'mod' substring in the Defender check"),
            (r"MINER\|PAYLOAD", "the prefetch name guess"),
    ):
        hit = re.search(gone, ps_code)
        report(not hit, "removed: %s", what)

    # The DLL check used to search the whole path for substrings, two of which
    # were "hook" and "esp". OBS injects graphics-hook64.dll into every game it
    # records - so the person most likely to trip it was the one recording the
    # screenshare - and RTSSHooks64.dll is the MSI Afterburner FPS counter.
    for gone, what in (
            (r"hook\|bypass", "the DLL name-substring list"),
            (r"dllSafePrefixes", "the twelve-vendor DLL whitelist that replaced thinking"),
    ):
        report(not re.search(gone, pc_code), "removed: %s", what)
    report("Get-AuthenticodeSignature" in pc_code,
           "a DLL is judged by its signature, not by its name")
    report("Test-UserWritablePath" in pc_code,
           "and only modules outside system folders are checked at all")
    # A location alone must not be able to raise cheat_procs any more.
    _proc = re.search(r"if \(\$isSuspiciousName -or \$isSuspiciousPath\)(.{0,400})", pc_code, re.S)
    report(bool(_proc) and "flaggedProcs" not in (_proc.group(1) if _proc else "x"),
           "a process is not flagged for WHERE it runs from (Zoom, Slack, Signal)")
    report("$script:Evidence.CheatProcs   = $flaggedProcs.Count" in pc_code
           and "unknownProcs" not in re.search(
               r"\$script:Evidence\.CheatProcs.*", pc_code).group(0),
           "only a known cheat process name reaches cheat_procs")
    # The game jar is checked against Mojang's own hash, with no heuristic.
    report("Run-ClientJarScan" in pc_code and '"sha1"' in pc,
           "the game jar is compared against the SHA1 in the launcher JSON")

    for var, want in (("sysBlackhole", S.BLACKHOLE),
                      ("sysAuthHosts", set(S.AUTH_HOSTS)),
                      ("sysMcMarkers", set(S.MC_MARKERS))):
        m = re.search(r"\$script:%s\s*=\s*@\(([^)]*)\)" % var, sig)
        got = set(re.findall(r"'((?:[^']|'')*)'", m.group(1))) if m else None
        if got:
            got = {g.replace("''", "'") for g in got}
        report(got == want, "%s matches Python%s", var,
               "" if got == want else "\n        ps=%r\n        py=%r" % (got, want))

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed else 1


if __name__ == "__main__":
    sys.exit(main())
