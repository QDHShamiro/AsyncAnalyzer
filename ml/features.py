"""
AsyncAnalyzer ML — shared feature schema.

This defines the EXACT feature vector the model consumes. The order of
FEATURE_NAMES is the contract: index i in the vector maps to weight i in the
exported model, and the PowerShell inference code in AsyncAnalyzer.ps1 must
build the vector in this same order.

A jar is reduced to a small set of "raw signals" (counts / booleans / ratios),
then raw_to_vector() turns those into the normalised numeric feature vector.
extract_from_jar() computes the raw signals for a real .jar so we can train on
real, known-clean library jars (the negative class).
"""

import io
import json
import math
import re
import zipfile

# ---- The feature contract (order matters, keep in sync with PowerShell) ----
FEATURE_NAMES = [
    "pkgpath",        # 0/1  known cheat-client package path present
    "cheatsite",      # 0/1  downloaded from a known cheat site (Zone.Identifier)
    "strong_sig",     # 0..1 distinctive cheat strings + patterns (min(n,5)/5)
    "weak_sig",       # 0..1 generic indicator strings (min(n,10)/10)
    "fullwidth_str",  # 0/1  fullwidth-disguised cheat strings present
    "fullwidth_cls",  # 0..1 fullwidth class-name ratio
    "japanese_cls",   # 0..1 hiragana/katakana/CJK class-name ratio
    "singlechar_cls", # 0..1 single-letter class-name ratio
    "numeric_cls",    # 0..1 numeric-only class-name ratio
    "novowel_cls",    # 0..1 no-vowel short class-name ratio
    "avg_entropy",    # 0..1 average class byte-entropy / 8
    "high_entropy",   # 0..1 ratio of classes above 7.2 bits
    "reflection",     # 0..1 reflection/bytecode API usage (min(n,6)/6)
    "runtime_exec",   # 0/1  Runtime.getRuntime().exec present
    "http_download",  # 0/1  openConnection + HttpURLConnection + FileOutputStream
    "http_exfil",     # 0/1  openConnection + setDoOutput + getOutputStream + getProperty
    "nested_hollow",  # 0/1  wraps a nested jar with almost no own code
    "fake_identity",  # 0/1  metadata claims a known mod but filename disagrees
    "filename_client",# 0/1  filename is a distinctive cheat-client name
    "random_name",    # 0/1  randomly generated filename pattern
    "verified",       # 0/1  hash verified on Modrinth/CurseForge/known-good
    "legit_modid",    # 0/1  modid is in the legit/anticheat whitelist
]

N_FEATURES = len(FEATURE_NAMES)


def raw_to_vector(raw):
    """Turn a raw-signals dict into the ordered, normalised feature vector."""
    def clip01(x):
        return 0.0 if x < 0 else (1.0 if x > 1 else float(x))

    return [
        1.0 if raw.get("pkgpath") else 0.0,
        1.0 if raw.get("cheatsite") else 0.0,
        clip01(min(raw.get("strong_count", 0), 5) / 5.0),
        clip01(min(raw.get("weak_count", 0), 10) / 10.0),
        1.0 if raw.get("fullwidth_str") else 0.0,
        clip01(raw.get("fullwidth_cls_pct", 0.0)),
        clip01(raw.get("japanese_cls_pct", 0.0)),
        clip01(raw.get("singlechar_cls_pct", 0.0)),
        clip01(raw.get("numeric_cls_pct", 0.0)),
        clip01(raw.get("novowel_cls_pct", 0.0)),
        clip01(raw.get("avg_entropy", 0.0) / 8.0),
        clip01(raw.get("high_entropy_pct", 0.0)),
        clip01(min(raw.get("reflection_count", 0), 6) / 6.0),
        1.0 if raw.get("runtime_exec") else 0.0,
        1.0 if raw.get("http_download") else 0.0,
        1.0 if raw.get("http_exfil") else 0.0,
        1.0 if raw.get("nested_hollow") else 0.0,
        1.0 if raw.get("fake_identity") else 0.0,
        1.0 if raw.get("filename_client") else 0.0,
        1.0 if raw.get("random_name") else 0.0,
        1.0 if raw.get("verified") else 0.0,
        1.0 if raw.get("legit_modid") else 0.0,
    ]


# ---- Signature lists used only to derive features from REAL jars ----
# (The authoritative cheat lists live in AsyncAnalyzer.ps1; these mirror the
#  content-level definitions so real library jars get realistic features.)
STRONG_STRINGS = [
    "AutoCrystal", "AutoAnchor", "AutoTotem", "InventoryTotem", "KillAura",
    "TriggerBot", "AimAssist", "SilentAim", "ShieldBreaker", "ShieldDisabler",
    "dontPlaceCrystal", "dontBreakCrystal", "canPlaceCrystalServer",
    "WalksyOptimizer", "HoverTotem", "AxeSpam", "WebMacro", "MaceSwap",
    "AntiKnockback", "Antiknockback", "PacketFly", "Scaffold", "BaseFinder",
]
WEAK_STRINGS = [
    "Reach Distance", "Min Height", "Fast Mode", "Attack Delay", "Hit Delay",
    "arrayOfString", "setSelectedSlot", "Runtime.exec", "cmd.exe",
    "powershell.exe", "ClassLoader", "defineClass", "Particle Chance",
]
PACKAGE_PATHS = [
    "net/ccbluex", "meteordevelopment", "org/chainlibs", "wtf/moonlight",
    "today/opai", "cc/novoline", "com/alan/clients", "club/maxstats",
    "me/zeroeightsix/kami", "net/minecraft/injection", "xyz/greaj",
    "com/cheatbreaker", "dev/krypton", "dev/gambleclient",
]
REFLECTION_PATTERNS = [
    r"Class\.forName", r"getMethod", r"getDeclaredMethod", r"getDeclaredField",
    r"setAccessible", r"java/lang/reflect", r"MethodHandle", r"sun/misc/Unsafe",
    r"defineClass", r"ByteBuddy", r"javassist", r"ASM\d",
]

_FW = re.compile(r"[Ａ-Ｚａ-ｚ０-９]")
_JP = re.compile(r"[぀-ゟ゠-ヿ㐀-䶿一-鿿]")
_VOWELS = set("aeiouAEIOU")


def _entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    e = 0.0
    for c in freq.values():
        p = c / n
        e -= p * math.log2(p)
    return e


def extract_from_jar(path, verified=0, legit_modid=0, filename_client=0,
                     random_name=0, cheatsite=0):
    """Compute raw signals for a real jar on disk. Content features are real;
    the provenance flags (verified/legit/filename/etc.) are passed in by the
    caller because they are not derivable from the jar body alone."""
    raw = {
        "verified": verified, "legit_modid": legit_modid,
        "filename_client": filename_client, "random_name": random_name,
        "cheatsite": cheatsite,
    }
    total_cls = 0
    numeric = fullwidth = japanese = single = novowel = 0
    ent_sum = 0.0
    ent_cnt = 0
    high_ent = 0
    text_blob = io.StringIO()
    text_len = 0
    strong = set()
    weak = set()
    pkg = set()
    refl = set()
    nested = 0

    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return raw

    names = z.namelist()
    for n in names:
        if re.search(r"^META-INF/jars/.+\.jar$", n):
            nested += 1
        for p in PACKAGE_PATHS:
            if p in n:
                pkg.add(p)

    for info in z.infolist():
        n = info.filename
        if n.endswith(".class"):
            total_cls += 1
            base = n.split("/")[-1][:-6]
            if base.isdigit():
                numeric += 1
            if _FW.search(base):
                fullwidth += 1
            if _JP.search(base):
                japanese += 1
            if len(base) == 1 and base.isalpha():
                single += 1
            if 3 <= len(base) <= 8 and base.isalpha():
                if sum(1 for c in base if c in _VOWELS) == 0:
                    novowel += 1
            if 200 < info.file_size < 500000:
                try:
                    data = z.read(n)
                    e = _entropy(data)
                    ent_sum += e
                    ent_cnt += 1
                    if e > 7.2:
                        high_ent += 1
                    if text_len < 500000:
                        ascii_txt = data.decode("latin-1")
                        text_blob.write(ascii_txt)
                        text_len += len(ascii_txt)
                except Exception:
                    pass
        elif re.search(r"\.(json|txt|cfg|properties|toml|mf|xml)$", n) or "MANIFEST.MF" in n:
            try:
                data = z.read(n)
                text = data.decode("utf-8", "ignore")
                if text_len < 500000:
                    text_blob.write(text)
                    text_len += len(text)
            except Exception:
                pass

    z.close()
    blob = text_blob.getvalue()
    for s in STRONG_STRINGS:
        if s in blob:
            strong.add(s)
    for s in WEAK_STRINGS:
        if s in blob:
            weak.add(s)
    for pat in REFLECTION_PATTERNS:
        if re.search(pat, blob):
            refl.add(pat)

    raw["strong_count"] = len(strong)
    raw["weak_count"] = len(weak)
    raw["pkgpath"] = 1 if pkg else 0
    raw["reflection_count"] = len(refl)
    raw["fullwidth_str"] = 0
    raw["runtime_exec"] = 1 if ("java/lang/Runtime" in blob and "getRuntime" in blob and "exec" in blob) else 0
    raw["http_download"] = 1 if ("openConnection" in blob and "HttpURLConnection" in blob and "FileOutputStream" in blob) else 0
    raw["http_exfil"] = 1 if ("openConnection" in blob and "setDoOutput" in blob and "getOutputStream" in blob and "getProperty" in blob) else 0
    raw["nested_hollow"] = 1 if (nested == 1 and total_cls < 3) else 0
    raw["fake_identity"] = 0
    if total_cls > 0:
        raw["numeric_cls_pct"] = numeric / total_cls
        raw["fullwidth_cls_pct"] = fullwidth / total_cls
        raw["japanese_cls_pct"] = japanese / total_cls
        raw["singlechar_cls_pct"] = single / total_cls
        raw["novowel_cls_pct"] = novowel / total_cls
    if ent_cnt > 0:
        raw["avg_entropy"] = ent_sum / ent_cnt
        raw["high_entropy_pct"] = high_ent / ent_cnt
    return raw


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        r = extract_from_jar(p)
        print(p)
        print(json.dumps(raw_to_vector(r)))
