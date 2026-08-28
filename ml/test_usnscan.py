#!/usr/bin/env python3
"""Tests for the USN journal and ShimCache readers.

The ShimCache fixtures are real bytes assembled to the documented layout. The
important cases are the CORRUPT ones: a binary blob mis-parsed by one field
yields plausible-looking garbage, and garbage here is a filename shown to a
moderator as a deleted cheat. Every one of them must end the parse and say so,
not produce a name.
"""
import datetime
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usnscan as U

UTC = datetime.timezone.utc
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=UTC)


def ft(dt):
    return int((dt - EPOCH).total_seconds() * 10_000_000)


def entry(path, when, data=b""):
    raw = path.encode("utf-16-le")
    return (U.SIG_10TS + b"\x00" * 4 + struct.pack("<I", 0)
            + struct.pack("<H", len(raw)) + raw
            + struct.pack("<Q", ft(when)) + struct.pack("<I", len(data)) + data)


def blob(entries, header=0x34):
    return struct.pack("<I", header) + b"\x00" * (header - 4) + b"".join(entries)


WHEN = datetime.datetime(2026, 8, 20, 11, 15, tzinfo=UTC)


def main():
    passed = failed = 0

    def report(ok, fmt, *args):
        nonlocal passed, failed
        passed += ok
        failed += not ok
        print(("  [%s] " % ("PASS" if ok else "FAIL")) + fmt % args)

    print("=== ShimCache: paths of executables, including ones now gone ===")
    good = blob([entry(r"\??\C:\Users\s\Downloads\vape.exe", WHEN),
                 entry(r"\??\C:\Windows\System32\cmd.exe", WHEN),
                 entry(r"C:\Games\launcher.exe", WHEN, b"\x01\x02")])
    got, why = U.parse_shimcache(good)
    report(len(got) == 3 and not why, "three entries read cleanly (%d, %r)", len(got), why)
    report(got and got[0]["path"] == r"C:\Users\s\Downloads\vape.exe",
           "the \\??\\ device prefix is stripped: %s", got[0]["path"] if got else "-")
    report(got and got[0]["modified"] == WHEN, "the timestamp survives the round trip")
    for h in (0x30, 0x80):
        g, w = U.parse_shimcache(blob([entry(r"C:\x.exe", WHEN)], header=h))
        report(len(g) == 1 and not w, "header 0x%X is a layout this reads", h)

    print("\n=== ...and every corrupt shape STOPS, rather than inventing a name ===")
    CORRUPT = [
        (b"", "an empty value"),
        (b"\x00" * 4, "too short to hold a header"),
        (struct.pack("<I", 0x99) + b"\x00" * 200, "an unknown layout"),
        (blob([b"XXXX" + b"\x00" * 20]), "a wrong entry signature"),
        (blob([U.SIG_10TS + b"\x00" * 8 + struct.pack("<H", 0xFFFE) + b"AB"]),
         "a path length that runs off the end"),
        (blob([U.SIG_10TS + b"\x00" * 8 + struct.pack("<H", 7) + b"ABCDEFG" + b"\x00" * 12]),
         "an odd path length, which UTF-16 cannot have"),
        (blob([entry("not a path at all", WHEN)]), "text that is not a path"),
        (blob([U.SIG_10TS + b"\x00" * 8 + struct.pack("<H", 12)
               + r"C:\x.exe".encode("utf-16-le")[:12]
               + struct.pack("<Q", 1) + struct.pack("<I", 0)],),
         "a timestamp from the year 1601"),
    ]
    for data, why in CORRUPT:
        got, reason = U.parse_shimcache(data)
        report(not got and bool(reason), "%-46s -> %s", why, (reason or "SILENT")[:44])

    # A truncated blob must return what it safely read AND say it stopped.
    part = good[:len(good) - 30]
    got, reason = U.parse_shimcache(part)
    report(len(got) >= 1 and bool(reason),
           "a truncated value returns %d entr(y/ies) and says it stopped", len(got))

    print("\n=== USN journal: deletes and the old name of a rename ===")
    def rec(name, reason, when="8/28/2026 2:30:15 PM"):
        return ("Usn                : 0x12345678\n"
                "File name          : %s\n"
                "File name length   : %d\n"
                "Reason             : %s\n"
                "Time stamp         : %s\n" % (name, len(name) * 2, reason, when))

    USN = [
        (rec("gzfjalsrvp.jar", "0x80000200: Close  File Delete"), True,
         "a delete, which Shift+Delete leaves no Recycle Bin record of"),
        (rec("aura.jar", "0x00001000: Rename Old Name"), True,
         "renaming a jar out of the mods folder is the quiet version of deleting it"),
        (rec("sodium.jar", "0x00000100: File Create"), False,
         "CLEAN: creating a file is not deleting one"),
        (rec("latest.log", "0x00000002: Data Extend"), False,
         "CLEAN: the game writing to its log"),
        ("Usn : 0x1\nReason : File Delete\n", False,
         "CLEAN: a record with no file name is not a finding"),
    ]
    for block, want, why in USN:
        got = U.parse_usn_record(block)
        report(bool(got) == want, "%-24s -> %-5s %s",
               (got or {}).get("name", "-"), bool(got), why)
    got = U.parse_usn_record(USN[0][0])
    report(got and got["when"] == "8/28/2026 2:30:15 PM",
           "the timestamp is carried through: %s", (got or {}).get("when"))

    print("\n=== ...read from the END of the ring buffer, not the start ===")
    # Records are appended in order, so reading from the start and stopping early
    # returns the OLDEST - the opposite of what a screenshare needs.
    report(U.usn_window(500 * 1024 * 1024, 64) == 500 * 1024 * 1024 - 64 * 1024 * 1024,
           "a big journal is read from 64 MB before its end")
    report(U.usn_window(1000, 64) == 0, "a young journal is read from the beginning")

    print("\n=== PowerShell / Python parity ===")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps = open(os.path.join(root, "src", "93-usn.ps1"), encoding="utf-8").read()
    for needle, what in (
            ("10ts", "the ShimCache entry signature"),
            ("queryjournal", "the journal is queried for its end before reading"),
            ("startusn", "and read from an offset, not from the beginning"),
            ("Rename Old Name", "a rename counts as a delete"),
            ("Read-ShimCache", "the ShimCache reader"),
            ("AppCompatCache", "read as a registry value, with nothing mounted"),
    ):
        report(needle in ps, "PowerShell has %s", what)
    # The promise in the transparency notice has to stay true.
    for forbidden, what in (("reg load", "mounting a registry hive"),
                            ("esentutl", "copying a locked system file")):
        report(forbidden not in ps.lower(), "does NOT do %s", what)

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
