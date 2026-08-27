"""
Java class-file constant-pool parser + behavioural feature extraction.

Why this exists: the original extractor scraped ASCII out of the raw jar bytes.
Any cheat that encrypts its strings defeats that completely. The constant pool is
different - it is the class's symbol table. To CALL a Minecraft method you must
reference it there, by name. You can obfuscate your own names; you cannot
obfuscate the API you call. So this reads behaviour, not text.

Grounded in real cheat source (Meteor Client, read at commit 8038a0a): the
combat modules import ServerboundMovePlayerPacket and rewrite yaw/pitch on the
outgoing packet. No legitimate mod fakes its own movement packets. That pair -
move-packet reference + rotation write - is the aim-cheat fingerprint, and it
survives string encryption because both are structural constant-pool entries.

Only the constant pool is read (it sits at the very start of a class file), so
this stays cheap enough to run over a whole mods folder.
"""

import math
import re
import struct
import zipfile

# Constant pool tags that carry a fixed payload size (tag -> bytes to skip)
_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
          16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
_LONG_TAGS = {5, 6}   # take two constant-pool slots


class ClassParseError(Exception):
    pass


def parse_constant_pool(data):
    """Return (utf8_strings, class_names, member_refs) for one .class file.

    member_refs is a list of "Owner.member" strings resolved through
    Fieldref/Methodref -> Class + NameAndType.
    """
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ClassParseError("not a class file")
    count = struct.unpack_from(">H", data, 8)[0]
    pos = 10
    entries = {}          # index -> (tag, payload)
    i = 1
    while i < count:
        if pos >= len(data):
            raise ClassParseError("truncated pool")
        tag = data[pos]
        pos += 1
        if tag == 1:                                   # Utf8
            ln = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            raw = data[pos:pos + ln]
            pos += ln
            entries[i] = (1, raw)
        elif tag == 15:                                # MethodHandle
            entries[i] = (15, data[pos:pos + 3])
            pos += 3
        elif tag in _FIXED:
            n = _FIXED[tag]
            entries[i] = (tag, data[pos:pos + n])
            pos += n
        else:
            raise ClassParseError("bad tag %d" % tag)
        i += 2 if tag in _LONG_TAGS else 1

    def utf8(idx):
        e = entries.get(idx)
        if not e or e[0] != 1:
            return ""
        try:
            return e[1].decode("utf-8", "replace")
        except Exception:
            return ""

    strings, classes, refs = [], [], []
    for idx, (tag, payload) in entries.items():
        if tag == 1:
            strings.append(entries[idx][1])
        elif tag == 7:                                  # Class
            classes.append(utf8(struct.unpack(">H", payload)[0]))
        elif tag in (9, 10, 11):                        # Field/Method/Interface ref
            ci, nti = struct.unpack(">HH", payload)
            cls = entries.get(ci)
            nt = entries.get(nti)
            if cls and cls[0] == 7 and nt and nt[0] == 12:
                owner = utf8(struct.unpack(">H", cls[1])[0])
                nidx = struct.unpack(">HH", nt[1])[0]
                refs.append("%s.%s" % (owner, utf8(nidx)))
    return strings, classes, refs


# --- behaviour categories, each grounded in what real cheat code actually calls ---
BEHAVIOUR = {
    # the aim / killaura fingerprint: rewriting your own outgoing movement packet
    "bc_movepacket": [r"ServerboundMovePlayerPacket", r"PlayerMoveC2SPacket", r"class_2828"],
    "bc_rotation":   [r"\.setYRot", r"\.setXRot", r"\.setYaw", r"\.setPitch",
                      r"\.method_36456", r"\.method_36457"],
    "bc_attack":     [r"MultiPlayerGameMode\.attack", r"ServerboundInteractPacket",
                      r"PlayerInteractEntityC2SPacket", r"\.swing", r"class_2824"],
    "bc_pktlisten":  [r"ClientPacketListener", r"ClientPlayNetworkHandler", r"class_634"],
    "bc_entityscan": [r"entitiesForRendering", r"getEntities", r"method_18112", r"\.getEntityList"],
    "bc_render":     [r"VertexConsumer", r"RenderSystem", r"BufferBuilder", r"MatrixStack",
                      r"PoseStack", r"Tessellator", r"class_4587"],
    "bc_input":      [r"KeyMapping", r"KeyBinding", r"GLFW\.glfwGetKey", r"\.isPressed",
                      r"client/input", r"class_304"],
    # malware / loader side
    "bc_reflect":    [r"java/lang/reflect", r"\.getDeclaredMethod", r"\.setAccessible",
                      r"Class\.forName", r"MethodHandles", r"\.getDeclaredField"],
    "bc_classload":  [r"\.defineClass", r"URLClassLoader", r"defineAnonymousClass",
                      r"\.defineHiddenClass"],
    "bc_crypto":     [r"javax/crypto", r"Cipher\.", r"SecretKeySpec", r"IvParameterSpec"],
    "bc_exec":       [r"Runtime\.getRuntime", r"ProcessBuilder", r"Runtime\.exec"],
    "bc_net":        [r"java/net/Socket", r"HttpURLConnection", r"\.openConnection",
                      r"java/net/http", r"URL\.openStream"],
    "bc_unsafe":     [r"sun/misc/Unsafe", r"jdk/internal/misc/Unsafe"],
    "bc_instrument": [r"java/lang/instrument", r"Instrumentation\."],
}
_COMPILED = {k: re.compile("|".join(v)) for k, v in BEHAVIOUR.items()}

# Names a dropper almost always reaches REFLECTIVELY, so they land in a string
# constant rather than a Methodref. Kept deliberately tiny: broad names like
# setAccessible are everyday library code and would drag legit jars in.
_REFLECTIVE_NAMES = {
    "bc_classload": re.compile(r"^(defineClass|defineAnonymousClass|defineHiddenClass)$"),
    "bc_instrument": re.compile(r"^(premain|agentmain|retransformClasses)$"),
}

_WORDY = re.compile(rb"^[\x20-\x7e]{4,}$")


def _shannon(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = float(len(b))
    return -sum((c / n) * math.log(c / n, 2) for c in counts if c)


def extract_jar(path, max_classes=0):
    """Parse the classes in a jar and return raw behavioural counts.

    max_classes=0 -> every class (deep mode); >0 -> stop after that many (fast mode).
    """
    out = {k: 0 for k in BEHAVIOUR}
    out.update({k + "_ratio": 0.0 for k in BEHAVIOUR})
    out.update(classes_parsed=0, classes_failed=0, obf_name_ratio=0.0,
               str_readable_ratio=0.0, str_entropy=0.0)
    short_names = total_names = 0
    readable = total_str = 0
    ent_sum = ent_n = 0.0

    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return out
    with z:
        names = [n for n in z.namelist() if n.endswith(".class")]
        if max_classes:
            names = names[:max_classes]
        for n in names:
            try:
                data = z.read(n)
                strings, classes, refs = parse_constant_pool(data)
            except Exception:
                out["classes_failed"] += 1
                continue
            out["classes_parsed"] += 1
            blob = "\n".join(classes + refs)
            hit_here = set()
            for k, rx in _COMPILED.items():
                if rx.search(blob):
                    hit_here.add(k)
            for k, rx in _REFLECTIVE_NAMES.items():
                if k in hit_here:
                    continue
                for raw in strings:
                    try:
                        if rx.match(raw.decode("utf-8", "ignore")):
                            hit_here.add(k)
                            break
                    except Exception:
                        pass
            for k in hit_here:
                out[k] += 1
            # structural obfuscation: measured on the symbol table, not raw bytes
            simple = n.rsplit("/", 1)[-1][:-6]
            total_names += 1
            if len(simple) <= 2:
                short_names += 1
            for s in strings:
                total_str += 1
                if _WORDY.match(s):
                    readable += 1
                elif len(s) >= 8:
                    ent_sum += _shannon(s)
                    ent_n += 1
    # Counts must become RATIOS. netty-handler does crypto in 2 of 120 classes
    # (it is a TLS library); a packed loader does it in nearly all of them. The
    # raw count hides that difference and was the cause of a netty false positive.
    n = out["classes_parsed"]
    for k in BEHAVIOUR:
        out[k + "_ratio"] = (out[k] / float(n)) if n else 0.0
    if total_names:
        out["obf_name_ratio"] = short_names / float(total_names)
    if total_str:
        out["str_readable_ratio"] = readable / float(total_str)
    if ent_n:
        out["str_entropy"] = ent_sum / ent_n
    return out


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        r = extract_jar(p)
        hits = {k: v for k, v in r.items() if k.startswith("bc_") and v}
        print(p.rsplit("/", 1)[-1])
        print("   classes=%d obf=%.2f readable=%.2f ent=%.2f %s" % (
            r["classes_parsed"], r["obf_name_ratio"], r["str_readable_ratio"],
            r["str_entropy"], hits))
