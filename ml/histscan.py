"""Two things Windows remembers that a deleted file does not erase.

The mods folder can be emptied in three seconds. What takes longer to think of:

  The Recycle Bin keeps a $I file per deleted item holding the ORIGINAL PATH,
  the size and the exact deletion time. Emptying the bin removes it; pressing
  Delete does not.

  UserAssist keeps, per user, the path of every program started from Explorer -
  a double-click, a Start-menu entry, a desktop shortcut - with how many times
  and when it last ran. It is ROT13-encoded, which is not encryption, and it
  survives deleting the program.

Both are readable without administrator rights, which matters: the tool offers
to elevate and the answer can be no.

Neither is an accusation on its own. A deleted jar can be a mod somebody
uninstalled last month, and the date is what separates that from a jar deleted
while the screenshare was being arranged - so the date is carried through to the
report, and only a deletion inside the current session may reach the hard rule
that says jars were wiped with the game running.

Mirrors Read-RecycleEntry / Convert-Rot13 / Test-DeletedDuringSession in
src/92-history.ps1.
"""
import codecs
import datetime
import re
import struct

# FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(value):
    """A Windows FILETIME as a datetime, or None if it is not a real time."""
    if not 0 < value < 0x7FFF_FFFF_FFFF_FFFF:
        return None
    try:
        return _EPOCH + datetime.timedelta(microseconds=value // 10)
    except (OverflowError, OSError):
        return None


def parse_recycle_i(data):
    """One $I file from the Recycle Bin -> {path, size, deleted} or None.

    Two layouts exist and both are still found on a live PC:
      version 1 (Vista..8.1): a fixed 260-character path at offset 24.
      version 2 (Windows 10+): a character count at offset 24, then the path.
    Reading v2 with the v1 layout yields a path with a 4-byte number glued to
    the front, which is the kind of thing that turns into a wrong accusation.
    """
    if len(data) < 24:
        return None
    version, size, deleted = struct.unpack_from("<qqq", data, 0)
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            return None
        (nchars,) = struct.unpack_from("<I", data, 24)
        if not 0 < nchars <= 32768:
            return None
        raw = data[28:28 + nchars * 2]
    else:
        return None
    try:
        path = raw.decode("utf-16-le", "ignore").split("\x00", 1)[0]
    except Exception:
        return None
    if not path:
        return None
    return {"path": path, "size": size, "deleted": filetime(deleted)}


def rot13(text):
    """UserAssist value names are ROT13. That is obfuscation, not encryption."""
    return codecs.decode(text, "rot_13")


# The UserAssist entry: run count at offset 4, last-run FILETIME at offset 60.
# Windows XP used a different, shorter record; anything below 68 bytes is not
# one of these and is skipped rather than guessed at.
def parse_userassist(name, data):
    """A UserAssist value -> {path, runs, last} or None."""
    path = rot13(name)
    if len(data) < 68:
        return None
    (runs,) = struct.unpack_from("<I", data, 4)
    (last,) = struct.unpack_from("<Q", data, 60)
    # Explorer records the two counters it uses to draw the Start menu under
    # these same keys. They are not programs.
    if path.upper().startswith("UEME_"):
        return None
    return {"path": path, "runs": runs, "last": filetime(last)}


# A KNOWNFOLDERID prefix, which Explorer writes instead of the real directory.
_KF = re.compile(r"^\{[0-9A-Fa-f-]{36}\}\\")


def strip_known_folder(path):
    """{GUID}\\sub\\x.exe -> sub\\x.exe. The GUID is a folder id, not a name."""
    return _KF.sub("", path)


def deleted_during_session(deleted, session_start, game_started=None):
    """May this deletion reach the rule that says jars were wiped mid-session?

    The Recycle Bin holds months of history. Feeding all of it to a rule whose
    text is "deleted while Minecraft is still running" would accuse somebody for
    tidying up a modpack in May. The window is the running game if there is one,
    and otherwise the hour before the scan - short enough that the claim stays
    true.
    """
    if deleted is None:
        return False
    start = game_started or session_start
    return deleted >= start


# ---------------------------------------------------------------------------
# An injected client that has no name.
#
# The memory scan looks for NAMES - "doomsday", "vape", the community list. An
# obfuscated loader has none: the real DoomsDay jar's classes are net/java/a,
# net/java/b, net/java/d. Searching for names cannot see it.
#
# What it cannot hide is that it is LOADED. Every class the JVM has loaded came
# from somewhere, and for a mod that somewhere is a jar on disk. A package that
# is live in the game's memory and belongs to no jar anywhere on the disk was not
# loaded from a file - which is the definition of injected.
#
# The whole claim rests on the disk side being COMPLETE. If the tool only knows
# the mods folder, every launcher library looks injected. So the caller must feed
# it the mods folders AND the libraries folder AND the version jar first, and
# must refuse to claim anything if that set is thin.
#
# Mirrors Test-InjectedPackage in src/90-jvm.ps1.

# net/java/a  or  me/foo/Bar  - at least three segments, java-identifier shaped.
_CLASSPATH = re.compile(r"\b([a-z][a-z0-9_]{1,20}(?:/[A-Za-z0-9_$]{1,40}){2,6})\b")

# Runtime roots. These are inside the JVM itself or generated by it, and no jar
# on disk contains them - so without this list every one of them reads as
# injected.
RUNTIME_ROOTS = (
    "java/", "javax/", "jdk/", "sun/", "com/sun/", "oracle/", "netscape/",
    "org/w3c/", "org/xml/", "org/ietf/", "jrt/", "module-info",
)

# Generated at runtime by the JVM, by Mixin or by any bytecode library. They have
# no file either, and they are not somebody's cheat.
_GENERATED = re.compile(r"\$\$|\$Proxy|GeneratedConstructorAccessor|GeneratedMethodAccessor"
                        r"|Lambda\$|/ASM\$|MixinSquashed|\$\d+$")

# Below this the disk side is not trustworthy enough to call anything injected.
# A real Minecraft install yields thousands of package prefixes.
MIN_DISK_PACKAGES = 200


def injected_packages(hits, disk_packages, min_repeats=3):
    """Packages loaded in memory that no jar on disk accounts for.

    hits: {package -> how many times it was seen in the heap}
    disk_packages: every package prefix found in every jar that was scanned
    """
    if len(disk_packages) < MIN_DISK_PACKAGES:
        return []                       # the disk side is too thin to claim anything
    out = []
    for pkg, n in sorted(hits.items()):
        if n < min_repeats:
            continue                    # one string is not loaded code
        if any(pkg.startswith(r) for r in RUNTIME_ROOTS):
            continue
        if _GENERATED.search(pkg):
            continue
        # Any prefix of the package being on disk means a jar could have supplied
        # it. net/java/a is covered by "net/java" being in some jar.
        parts = pkg.split("/")
        covered = any("/".join(parts[:i]) in disk_packages for i in range(1, len(parts) + 1))
        if not covered:
            out.append((pkg, n))
    return out
