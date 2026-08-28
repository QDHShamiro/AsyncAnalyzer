#!/usr/bin/env python3
"""Tests for the Recycle Bin and UserAssist readers.

The fixtures are real bytes, assembled here to the documented layouts, because
a parser that is only tested against its own idea of the format is tested
against nothing. Both layouts of $I are covered: reading a Windows 10 file with
the Vista layout produces a path with a length field glued to the front, which
is exactly the sort of thing that becomes a wrong accusation.
"""
import datetime
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import histscan as H

UTC = datetime.timezone.utc
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=UTC)


def ft(dt):
    """A datetime as a Windows FILETIME."""
    return int((dt - EPOCH).total_seconds() * 10_000_000)


def make_i(path, size, when, version=2):
    """Build a $I file exactly as Windows writes it."""
    out = struct.pack("<qqq", version, size, ft(when))
    raw = (path + "\x00").encode("utf-16-le")
    if version == 1:
        out += raw.ljust(520, b"\x00")[:520]
    else:
        out += struct.pack("<I", len(path) + 1) + raw
    return out


def make_ua(path, runs, when):
    """Build a UserAssist value: ROT13 name, 72-byte record."""
    blob = bytearray(72)
    struct.pack_into("<I", blob, 4, runs)
    struct.pack_into("<Q", blob, 60, ft(when))
    return H.rot13(path), bytes(blob)


NOW = datetime.datetime(2026, 8, 28, 14, 30, tzinfo=UTC)
GAME_START = datetime.datetime(2026, 8, 28, 14, 5, tzinfo=UTC)
SCAN_START = datetime.datetime(2026, 8, 28, 14, 28, tzinfo=UTC)
LAST_MONTH = datetime.datetime(2026, 7, 3, 19, 12, tzinfo=UTC)


def main():
    passed = failed = 0

    def report(ok, fmt, *args):
        nonlocal passed, failed
        passed += ok
        failed += not ok
        print(("  [%s] " % ("PASS" if ok else "FAIL")) + fmt % args)

    print("=== Recycle Bin: the original path survives the delete ===")
    CASES = [
        (r"C:\Users\s\AppData\Roaming\.minecraft\mods\gzfjalsrvp.jar", 558324, NOW, 2,
         "a Windows 10 $I file"),
        (r"C:\Users\s\AppData\Roaming\.minecraft\mods\aura.jar", 4096, LAST_MONTH, 1,
         "the older fixed-width layout is still found on live PCs"),
        (r"D:\Instances\1.8.9\mods\x.jar", 1024, NOW, 2, "a second instance"),
        (r"C:\Users\M\u00fcller\Downloads\vape.jar", 900, NOW, 2,
         "a path with a character outside latin-1"),
    ]
    for path, size, when, version, why in CASES:
        got = H.parse_recycle_i(make_i(path, size, when, version))
        ok = (got and got["path"] == path and got["size"] == size
              and got["deleted"] == when)
        report(ok, "v%d  %-52s %s", version, path[-52:], why)

    # The failure this guards against: parsing a v2 file with the v1 layout puts
    # the 4-byte length in front of the path.
    v2 = make_i(r"C:\mods\x.jar", 10, NOW, 2)
    wrong = v2[:0] + struct.pack("<q", 1) + v2[8:]      # claim v1, keep v2 body
    got = H.parse_recycle_i(wrong)
    ok = bool(got) and got["path"] != r"C:\mods\x.jar"
    report(ok, "a mislabelled file yields a WRONG path, so the version matters (%r)",
           (got or {}).get("path", "")[:24])

    for bad, why in ((b"", "empty"), (b"\x00" * 8, "too short"),
                     (struct.pack("<qqq", 7, 1, ft(NOW)), "an unknown version"),
                     (struct.pack("<qqq", 2, 1, ft(NOW)) + struct.pack("<I", 0),
                      "a zero-length path")):
        report(H.parse_recycle_i(bad) is None, "rejected: %s", why)

    print("\n=== ...and only a FRESH deletion may reach the hard rule ===")
    WINDOW = [
        (NOW, GAME_START, True, "deleted while the game was already running"),
        (LAST_MONTH, GAME_START, False,
         "deleted in July - tidying a modpack is not evidence"),
        (GAME_START - datetime.timedelta(minutes=1), GAME_START, False,
         "one minute before the game started is still before"),
        (None, GAME_START, False, "no timestamp at all - never claim"),
    ]
    for when, gstart, want, why in WINDOW:
        got = H.deleted_during_session(when, SCAN_START, gstart)
        report(got == want, "%-24s -> %-5s %s",
               when.strftime("%Y-%m-%d %H:%M") if when else "(none)", got, why)
    # With no game running the window is the scan itself, not all of history.
    got = H.deleted_during_session(LAST_MONTH, SCAN_START, None)
    report(got is False, "%-24s -> False no game running, so the window is the scan",
           "last month")

    print("\n=== UserAssist: what the user double-clicked, and when ===")
    UA = [
        (r"C:\Users\s\Downloads\doomsday-loader.exe", 4, NOW, True, "run four times"),
        (r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe", 12, NOW, True,
         "a KNOWNFOLDER prefix, which is a folder id and not a name"),
    ]
    for path, runs, when, want, why in UA:
        name, blob = make_ua(path, runs, when)
        got = H.parse_userassist(name, blob)
        ok = bool(got) == want and got and got["path"] == path and got["runs"] == runs and got["last"] == when
        report(ok, "%-52s runs=%-3s %s", H.strip_known_folder(path)[-52:],
               (got or {}).get("runs"), why)

    # ROT13 has to survive a round trip on real paths, including digits and
    # punctuation, which it must leave alone.
    for p in (r"C:\Program Files (x86)\Java\bin\javaw.exe",
              r"D:\PvP\1.8.9\vape-v4.exe"):
        report(H.rot13(H.rot13(p)) == p, "rot13 round-trips %s", p[-34:])

    report(H.strip_known_folder(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe")
           == r"cmd.exe", "the folder id is stripped, the name is kept")
    report(H.strip_known_folder(r"C:\x\y.exe") == r"C:\x\y.exe",
           "a plain path is left alone")

    # Explorer's own counters live under the same key and are not programs.
    name, blob = make_ua("UEME_CTLSESSION", 99, NOW)
    report(H.parse_userassist(name, blob) is None,
           "Explorer's own session counter is not a program")
    name, blob = make_ua(r"C:\x.exe", 1, NOW)
    report(H.parse_userassist(name, blob[:40]) is None,
           "a record too short to hold the fields is skipped, not guessed at")

    # ---- parity with the shipped PowerShell ---------------------------------
    print("\n=== PowerShell / Python parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "92-history.ps1"), encoding="utf-8").read()
    for needle, what in (
            ("$version -eq 1", "the Vista $I layout"),
            ("$version -eq 2", "the Windows 10 $I layout"),
            ("Test-DeletedDuringSession", "the freshness window"),
            ("UEME_", "Explorer's own counters are skipped"),
            ("Convert-Rot13", "the UserAssist decoder"),
            ("60", "the last-run offset in the UserAssist record"),
    ):
        report(needle in ps, "PowerShell has %s", what)

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
