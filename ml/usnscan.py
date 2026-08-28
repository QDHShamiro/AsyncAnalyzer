"""Two records of files that are gone, for the case the Recycle Bin cannot cover.

Shift+Delete leaves no $I file. Two things still see it:

  The NTFS change journal (USN) records every create, rename and delete on the
  volume, with a timestamp. It is a ring buffer, so it holds the recent past
  rather than all of it - which is exactly the window a screenshare cares about.

  ShimCache (AppCompatCache) holds up to about a thousand executable PATHS with
  the file's last-modified time. It lives in the SYSTEM hive, which is already
  mounted, so it is read as an ordinary registry value - no file copying and no
  mounting anything.

Both need administrator rights. Both are read-only.

The parser below is deliberately distrustful of its own input. A binary blob
mis-parsed by one field yields plausible-looking garbage, and garbage here means
a filename presented to a moderator as a deleted cheat. So every entry is
validated - signature, a sane length, a path that looks like a path, a timestamp
inside the era Windows has existed - and the first entry that fails ENDS the
parse rather than being skipped past. A short honest answer beats a long invented
one.

Mirrors Read-ShimCache / Test-UsnDelete in src/93-usn.ps1.
"""
import datetime
import re
import struct

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
# Nothing on a Windows PC was modified in 1604, and nothing will be in 2200.
_SANE_FROM = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
_SANE_TO = datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)

# Windows 8.1 / 10 / 11 entry signature.
SIG_10TS = b"10ts"
# The header length tells the two apart; both use the same entry layout.
HEADER_SIZES = (0x30, 0x34, 0x80)

_PATHISH = re.compile(r"^(?:\\\?\?\\)?[A-Za-z]:\\|^\\\\")


def filetime(value):
    if not 0 < value < 0x7FFF_FFFF_FFFF_FFFF:
        return None
    try:
        t = _EPOCH + datetime.timedelta(microseconds=value // 10)
    except (OverflowError, OSError):
        return None
    return t if _SANE_FROM <= t <= _SANE_TO else None


def parse_shimcache(blob, max_entries=1024):
    """AppCompatCache -> [{path, modified}], newest first as Windows stores it.

    Returns (entries, reason). reason is "" on a clean read, otherwise why the
    parse stopped - which the caller reports as a coverage gap rather than
    presenting a partial list as the whole truth.
    """
    if len(blob) < 8:
        return [], "the AppCompatCache value is too short to be one"
    (header,) = struct.unpack_from("<I", blob, 0)
    if header not in HEADER_SIZES:
        return [], "an AppCompatCache layout this tool does not know (header 0x%X)" % header
    off = header
    out = []
    while off + 12 <= len(blob) and len(out) < max_entries:
        sig = blob[off:off + 4]
        if sig != SIG_10TS:
            return out, ("stopped at an unrecognised entry signature %r" % sig
                         if not out else "")
        # 4 sig, 4 unknown, 4 cache-entry size, 2 path length
        (path_len,) = struct.unpack_from("<H", blob, off + 12)
        if path_len == 0 or path_len % 2 or off + 14 + path_len + 12 > len(blob):
            return out, "stopped at an entry whose path length does not fit"
        raw = blob[off + 14:off + 14 + path_len]
        try:
            path = raw.decode("utf-16-le")
        except Exception:
            return out, "stopped at an entry whose path is not text"
        if not _PATHISH.match(path):
            return out, "stopped at an entry that does not look like a path"
        p = off + 14 + path_len
        (mtime,) = struct.unpack_from("<Q", blob, p)
        when = filetime(mtime)
        if when is None:
            return out, "stopped at an entry with an impossible timestamp"
        (data_len,) = struct.unpack_from("<I", blob, p + 8)
        if data_len > len(blob):
            return out, "stopped at an entry with an impossible data length"
        out.append({"path": path.replace("\\??\\", "", 1), "modified": when})
        off = p + 12 + data_len
    return out, ""


# --------------------------------------------------------------- USN journal --
# fsutil prints one block per record. The two reasons that matter are a file
# being deleted and the OLD name of a rename - renaming a jar out of the mods
# folder is the quiet version of deleting it.
_USN_NAME = re.compile(r"(?im)^\s*File name\s*:\s*(.+?)\s*$")
_USN_REASON = re.compile(r"(?im)^\s*Reason\s*:\s*(.+?)\s*$")
_USN_TIME = re.compile(r"(?im)^\s*Time ?stamp\s*:\s*(.+?)\s*$")
DELETE_REASONS = ("file delete", "rename old name")


def parse_usn_record(block):
    """One fsutil record block -> {name, reason, when} for deletes and renames."""
    m = _USN_NAME.search(block)
    r = _USN_REASON.search(block)
    if not m or not r:
        return None
    reason = r.group(1).lower()
    if not any(d in reason for d in DELETE_REASONS):
        return None
    t = _USN_TIME.search(block)
    return {"name": m.group(1), "reason": r.group(1),
            "when": t.group(1) if t else ""}


def usn_window(next_usn, megabytes=64):
    """Where to start reading so only the recent tail is read.

    The journal is a ring buffer measured in bytes and records are appended in
    order, so the newest are at the END. Reading from the start and stopping
    early - the obvious way to bound the cost - returns the OLDEST records,
    which is the opposite of what a screenshare needs.
    """
    start = next_usn - megabytes * 1024 * 1024
    return start if start > 0 else 0
