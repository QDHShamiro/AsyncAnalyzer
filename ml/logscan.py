"""
Reading Minecraft's own logs as evidence - the source of truth for the patterns.

Why this matters more than it sounds: a log line survives the jar. Deleting a
cheat before a screenshare removes the file, not the record that it loaded, and a
log line is DATED - it says the cheat was running at 20:14, which a file on disk
never says.

The whole difficulty is one thing: latest.log contains the chat. Somebody typing
"killaura" in chat writes the word killaura into the log, and a scanner that
matches module names there accuses people for what they said. So this never
matches module names at all, and the two things it does match are both structural:

  package path   net/wurstclient, meteordevelopment - a Java package, written
                 with dots or slashes, in a stack frame or a classloader line.
                 Not something anyone types in chat.
  client token   only in a context that is code: a stack frame ("at ..."), a
                 class name, a mixin config, a jar filename. Never bare.

And any line the game marked as chat is dropped before either test runs.
"""

import re

# A line the game logged as chat, or as a message from another player. Anything in
# here is something a HUMAN typed, and it is never evidence of anything.
CHAT = re.compile(
    r"\[CHAT\]|/INFO\]: <[^>]{1,32}>|\[Server thread/INFO\]: <|"
    r"issued server command|\[Async Chat Thread|commands\.message|"
    r"\bwhispers to you\b|\bwhispers:\b", re.I)

# A stack frame, a classloader line, a mixin config, a jar filename - the places a
# class name legitimately appears in a log.
CODE_CONTEXT = re.compile(
    r"^\s*at\s+[\w$.]+\(|"                       # stack frame
    r"\bClassNotFoundException\b|\bNoClassDefFoundError\b|"
    r"\bLoading\b.*\bmods?\b|\bmixin\b|\bMixin\b|"
    r"\.jar\b|\bClassLoader\b|\bTransformer\b|"
    r"\bCaused by:|\bjava\.lang\.|\bcom\.|\bnet\.|\borg\.|\bme\.|\bdev\.",
    re.I)

# "Loading 42 mods:" then "- modid 1.2.3" - Fabric and Forge both print this.
MOD_LIST = re.compile(r"^\s*[-│|]\s*([a-z0-9_-]{2,64})\s+([\w.+-]{1,32})\s*$")
MOD_LIST_HEADER = re.compile(r"Loading \d+ mods?:|Mod List:|Loading Minecraft .* with", re.I)

# A crash report names every mod it found, in its own format.
CRASH_MOD = re.compile(r"^\s*([a-z0-9_-]{2,64})\s*:\s*[^,]{1,60},\s*(?:DONE|ERROR|[\w.+-]+)", re.I)


def classify_line(line, package_paths, client_tokens):
    """Return (kind, evidence) for one log line, or (None, "").

    kind is "package" (a cheat package path in a code context) or "client" (a
    known client name in a code context). Chat is dropped first, always.
    """
    if not line or CHAT.search(line):
        return None, ""
    low = line.lower()
    for p in package_paths:
        # package paths are written with slashes in the tables and with dots in a
        # log, so both spellings are checked
        for form in (p.lower(), p.lower().replace("/", ".")):
            if form in low:
                return "package", form
    if CODE_CONTEXT.search(line):
        for t in client_tokens:
            tl = t.lower()
            if len(tl) < 5:
                continue
            # must sit next to a package or class separator, not float in prose
            if re.search(r"(?:^|[/.\\_\-\s\"'()\[\]])%s(?:$|[/.\\_\-\s\"'()\[\]:])"
                         % re.escape(tl), low):
                return "client", tl
    return None, ""


def parse_mod_list(lines):
    """Mod ids the log says were LOADED. Evidence, never an accusation: a mod id
    can come from a jar nested inside another jar, or from an instance this scan
    did not look at."""
    out, armed = [], False
    for line in lines:
        if MOD_LIST_HEADER.search(line):
            armed = True
            continue
        if armed:
            m = MOD_LIST.match(line.split("]: ")[-1])
            if m:
                out.append((m.group(1), m.group(2)))
            elif out:
                armed = False
    return out


if __name__ == "__main__":
    import sys, json
    pkgs = ["net/wurstclient", "meteordevelopment", "doomsdayclient"]
    toks = ["wurstclient", "doomsday", "liquidbounce", "meteorclient"]
    for path in sys.argv[1:]:
        for line in open(path, encoding="utf-8", errors="replace"):
            k, ev = classify_line(line.rstrip("\n"), pkgs, toks)
            if k:
                print("%-8s %s" % (k, line.strip()[:140]))
