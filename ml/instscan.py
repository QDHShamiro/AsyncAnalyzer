"""
The parts of a Minecraft install that are not the mods folder.

Four things live here, all of them structural rather than fuzzy, because this
folder is full of files a normal player has and none of them may be accused:

  version profile   .minecraft/versions/<v>/<v>.json says which mainClass the
                    launcher starts and which --tweakClass it passes. An injected
                    client installs itself as a custom version profile, and its own
                    class name is written there in plain text.
  launcher profile  launcher_profiles.json can carry JVM arguments, and
                    -javaagent: is how a ghost client gets attached to the game.
  resource pack     a .zip in resourcepacks/ or shaderpacks/ that contains .class
                    or .jar entries. A resource pack is textures, sounds, json and
                    shader source; Java classes in one are not a thing.
  config folder     .minecraft/config/<name> named after a known cheat client. A
                    config folder outlives the jar - it is what is left after
                    somebody deletes the mod and not its settings.

None of these needs a heuristic. Either the launcher starts a cheat's class or it
does not; either the pack contains bytecode or it does not.
"""

import re

from logscan import TOKEN_FLOOR

# What a normal Minecraft version profile starts. Anything else is worth reading -
# but the LIST is not the test: the test is whether a cheat's own name is in there.
KNOWN_MAIN = {
    "net.minecraft.client.main.Main",
    "net.minecraft.launchwrapper.Launch",
    "cpw.mods.bootstraplauncher.BootstrapLauncher",
    "cpw.mods.modlauncher.Launcher",
    "net.fabricmc.loader.impl.launch.knot.KnotClient",
    "org.quiltmc.loader.impl.launch.knot.KnotClient",
    "io.github.zekerzhayard.forgewrapper.installer.Main",
}

JAVAAGENT = re.compile(r"-javaagent:\s*([^\"',\s\]]+)", re.I)
MAIN_CLASS = re.compile(r'"mainClass"\s*:\s*"([^"]+)"')
TWEAK_CLASS = re.compile(r'--tweakClass["\s,:]+([\w.$]+)', re.I)

# Entries a resource pack has no business containing. .jar is included because a
# pack that ships one is a jar in a costume.
EXECUTABLE_IN_PACK = re.compile(r"\.(class|jar|dll|so|dylib|exe)$", re.I)


def _names_hit(value, package_paths, client_tokens):
    """Does this class or path name a known cheat? Exact-ish, not fuzzy: a package
    path is matched as a substring (it IS a path), a client token only on a
    separator boundary so 'impactclient' cannot be found inside 'impactful'."""
    low = (value or "").lower()
    for p in package_paths:
        for form in (p.lower(), p.lower().replace("/", ".")):
            if form in low:
                return form
    for t in client_tokens:
        tl = t.lower()
        if len(tl) < TOKEN_FLOOR:
            continue
        if re.search(r"(?:^|[/.\\_\-])%s(?:$|[/.\\_\-])" % re.escape(tl), low):
            return tl
    return ""


def classify_version_json(text, package_paths, client_tokens):
    """Return a list of (kind, evidence) for one versions/<v>/<v>.json."""
    out = []
    for m in MAIN_CLASS.finditer(text or ""):
        cls = m.group(1)
        hit = _names_hit(cls, package_paths, client_tokens)
        if hit:
            out.append(("mainclass", cls))
        elif cls not in KNOWN_MAIN:
            # not an accusation - the launcher starts something this tool does not
            # recognise, which a moderator should look at rather than be told about
            out.append(("unknownmain", cls))
    for m in TWEAK_CLASS.finditer(text or ""):
        if _names_hit(m.group(1), package_paths, client_tokens):
            out.append(("tweakclass", m.group(1)))
    for m in JAVAAGENT.finditer(text or ""):
        out.append(("javaagent", m.group(1)))
    return out


def classify_pack(entry_names):
    """Executable entries inside a resource or shader pack."""
    return [n for n in entry_names if EXECUTABLE_IN_PACK.search(n)]


def is_cheat_config_dir(name, client_tokens):
    """A config folder named after a known client.

    EXACT on the normalised name, not a substring - and the difference is not
    academic. A boundary match reads "doomsday-realms-datapack-helper" as the
    Doomsday client, because "doomsday" is also an English word with a hyphen after
    it. A config folder is named after the client and nothing else
    (meteor-client, wurst, rusherhack), so stripping the punctuation and comparing
    the whole name is both tighter and closer to how they are actually named.
    """
    n = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    if len(n) < TOKEN_FLOOR:
        return ""
    for t in client_tokens:
        if n == re.sub(r"[^a-z0-9]", "", t.lower()):
            return t.lower()
    return ""


if __name__ == "__main__":
    import sys, json
    for p in sys.argv[1:]:
        print(p, classify_version_json(open(p, encoding="utf-8", errors="replace").read(),
                                       ["net/ccbluex"], ["wurstclient", "doomsday"]))


# ------------------------------------------------- the game jar itself --------
# Until now versions/<v>/ was read for its .json only. The <v>.jar next to it -
# the game's own code - was never hashed and never analysed, so a patched client
# jar with an aura compiled straight into it was invisible: not in the mods
# folder, not scanned, not hashed.
#
# It does not need a heuristic. Mojang's own launcher JSON carries the official
# SHA1 of the client jar it describes, so the tool can PROVE whether the file on
# disk is the one Mojang shipped. Zero false positives by construction: either
# the hash matches or it does not.


def client_jar_check(version_json, jar_sha1):
    """(verdict, official_sha1) for one versions/<v>/<v>.json.

    verdict is:
      "official"  the jar is byte-for-byte what Mojang published
      "patched"   there is an official hash and the file does not match it
      "no-hash"   this profile carries no hash of its own (Forge, Fabric and
                  OptiFine profiles inherit the jar from a parent version and
                  describe only what to add), so there is nothing to compare
                  and nothing may be claimed
    """
    dl = (version_json or {}).get("downloads") or {}
    client = dl.get("client") or {}
    official = (client.get("sha1") or "").lower()
    if not official:
        return "no-hash", ""
    if not jar_sha1:
        return "no-hash", official
    return ("official" if jar_sha1.lower() == official else "patched"), official
