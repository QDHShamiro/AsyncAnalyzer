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
                      r"PlayerInteractEntityC2SPacket", r"class_2824",
                      # A bare "\.swing" matched javax/swing and any field called
                      # swingGui - rhino's debugger UI tripped it. Qualify it to the
                      # actual Minecraft method so a Swing app cannot look like combat.
                      r"(?:LocalPlayer|Player|LivingEntity)\.swing\b", r"\.swingHand\b",
                      r"\.method_6104\b"],
    # Both Wurst and Meteor hook the network layer itself, not just the listener.
    # Qualified on purpose - a bare "Connection" is an everyday identifier.
    "bc_pktlisten":  [r"ClientPacketListener", r"ClientPlayNetworkHandler", r"class_634",
                      r"net/minecraft/network/Connection", r"class_2535"],
    "bc_entityscan": [r"entitiesForRendering", r"getEntities", r"method_18112", r"\.getEntityList"],
    "bc_render":     [r"VertexConsumer", r"RenderSystem", r"BufferBuilder", r"MatrixStack",
                      r"PoseStack", r"Tessellator", r"class_4587"],
    "bc_input":      [r"KeyMapping", r"KeyBinding", r"GLFW\.glfwGetKey", r"\.isPressed",
                      r"client/input", r"class_304",
                      r"client/KeyboardHandler", r"client/MouseHandler"],
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
    # Minecraft-specific API names on purpose. A behaviour category only earns its
    # place if a real Maven library cannot match it by accident - these name packets
    # and interaction-manager methods that exist nowhere outside the game.
    "bc_blockplace": [r"ServerboundUseItemOnPacket", r"PlayerInteractBlockC2SPacket",
                      r"class_2885", r"\.useItemOn", r"\.interactBlock", r"\.method_2896"],
    "bc_blockbreak": [r"ServerboundPlayerActionPacket", r"PlayerActionC2SPacket",
                      r"class_2846", r"\.startDestroyBlock", r"\.destroyBlock", r"\.method_2910"],
    "bc_container":  [r"ServerboundContainerClickPacket", r"ClickSlotC2SPacket",
                      r"class_2813", r"AbstractContainerMenu", r"ScreenHandler", r"class_1703"],
    "bc_motion":     [r"\.setDeltaMovement", r"\.getDeltaMovement", r"\.setVelocity",
                      r"\.method_18800", r"\.method_18798"],
    # A jar working out where its own file is. Ordinary code has no reason to -
    # it is how something finds itself in order to delete itself.
    "bc_selfpath":   [r"\.getProtectionDomain", r"\.getCodeSource", r"ProtectionDomain",
                      r"CodeSource"],
    "bc_filedelete": [r"File\.delete", r"\.deleteOnExit", r"Files\.delete",
                      r"Files\.deleteIfExists"],
    # Unpacking a bundled native library and cleaning up the copy afterwards. This
    # is the innocent reason a class locates its own jar and then deletes a file,
    # and naming it is what lets the self-wipe signal exclude it.
    "bc_nativetemp": [r"createTempFile", r"createTempDirectory", r"System\.load",
                      r"\.loadLibrary", r"java\.io\.tmpdir"],
}

# Derived per-class signals. Not regexes: they are combinations that only mean
# something when ONE class does all of it. Jar-level ratios cannot express that -
# in a big library "something locates its own jar" and "something deletes a file"
# are usually unrelated classes, which is exactly how the first version of the
# self-wipe rule matched sixteen bytecode libraries.
DERIVED = {
    # a class that finds its own jar and deletes a file, and is not unpacking a
    # native library: that is a jar removing itself
    "bc_selfwipe": lambda hits: ("bc_selfpath" in hits and "bc_filedelete" in hits
                                 and "bc_nativetemp" not in hits),
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

# Cheap pre-filter run over the RAW decompressed bytes of every class.
#
# Fully parsing every constant pool is not affordable on the PowerShell side: a
# 200-mod pack is ~44k classes, which measured out at minutes. But sampling is
# worse than slow, it is wrong - a cheat whose aura module sits at class #150 is
# invisible to a 40-class sample, and real jars run to a median of 218 classes.
#
# So: search all classes cheaply, parse precisely only where something matched.
# This is sound because these are API names. The JVM resolves classes and methods
# BY NAME, so they must appear literally in the pool - a cheat cannot encrypt the
# Minecraft API it calls, only its own symbols.
_PREFILTER = re.compile(b"|".join(
    re.escape(t) for t in [
        b"ServerboundMovePlayerPacket", b"PlayerMoveC2SPacket", b"class_2828",
        b"setYRot", b"setXRot", b"setYaw", b"setPitch", b"method_36456", b"method_36457",
        b"MultiPlayerGameMode", b"ServerboundInteractPacket", b"PlayerInteractEntityC2SPacket",
        b"class_2824", b"ClientPacketListener", b"ClientPlayNetworkHandler", b"class_634",
        b"net/minecraft/network/Connection", b"class_2535", b"KeyboardHandler", b"MouseHandler",
        b"entitiesForRendering", b"getEntities", b"method_18112", b"getEntityList",
        b"VertexConsumer", b"RenderSystem", b"BufferBuilder", b"MatrixStack", b"PoseStack",
        b"Tessellator", b"class_4587", b"KeyMapping", b"KeyBinding", b"glfwGetKey",
        b"isPressed", b"client/input", b"class_304", b"java/lang/reflect",
        b"getDeclaredMethod", b"setAccessible", b"forName", b"MethodHandles",
        b"getDeclaredField", b"defineClass", b"URLClassLoader", b"defineAnonymousClass",
        b"defineHiddenClass", b"javax/crypto", b"Cipher", b"SecretKeySpec",
        b"IvParameterSpec", b"getRuntime", b"ProcessBuilder", b"java/net/Socket",
        b"HttpURLConnection", b"openConnection", b"java/net/http", b"openStream",
        b"sun/misc/Unsafe", b"jdk/internal/misc/Unsafe", b"java/lang/instrument",
        b"Instrumentation", b"premain", b"agentmain", b"retransformClasses",
        b"ServerboundUseItemOnPacket", b"PlayerInteractBlockC2SPacket", b"class_2885",
        b"useItemOn", b"interactBlock", b"method_2896",
        b"ServerboundPlayerActionPacket", b"PlayerActionC2SPacket", b"class_2846",
        b"startDestroyBlock", b"destroyBlock", b"method_2910",
        b"ServerboundContainerClickPacket", b"ClickSlotC2SPacket", b"class_2813",
        b"AbstractContainerMenu", b"ScreenHandler", b"class_1703",
        b"setDeltaMovement", b"getDeltaMovement", b"setVelocity",
        b"method_18800", b"method_18798",
        b"getProtectionDomain", b"getCodeSource", b"ProtectionDomain", b"CodeSource",
        b"deleteOnExit", b"deleteIfExists", b"createTempFile", b"createTempDirectory",
        b"loadLibrary", b"tmpdir",
    ]))


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

    Behaviour is detected across EVERY class via the cheap pre-filter; max_classes
    only bounds how many classes get their string statistics measured, which is an
    average and does not need full coverage.
    """
    out = {k: 0 for k in list(BEHAVIOUR) + list(DERIVED)}
    out.update({k + "_ratio": 0.0 for k in list(BEHAVIOUR) + list(DERIVED)})
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
        # Stratified, not first-N: spreading the sample across the jar matters because
        # nothing says a cheat's modules sit at the front of the archive.
        if max_classes and len(names) > max_classes:
            step = len(names) / float(max_classes)
            stat_idx = {int(i * step) for i in range(max_classes)}
        else:
            stat_idx = set(range(len(names)))
        for ni, n in enumerate(names):
            try:
                # The pool sits at the head of a class file, so the pre-filter only needs
                # a bounded prefix - decompressing whole classes is the dominant cost and
                # most of a large class is method bytecode we never look at.
                with z.open(n) as fh:
                    head = fh.read(65536)
            except Exception:
                out["classes_failed"] += 1
                continue
            # every class gets the cheap scan; only matches (or the stat sample) are parsed
            hot = _PREFILTER.search(head) is not None
            data = head
            if not hot and ni not in stat_idx:
                out["classes_parsed"] += 1
                total_names += 1
                if len(n.rsplit("/", 1)[-1][:-6]) <= 2:
                    short_names += 1
                continue
            try:
                if len(head) == 65536:      # may have been truncated mid-pool
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
            for k, fn in DERIVED.items():
                if fn(hit_here):
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
    for k in list(BEHAVIOUR) + list(DERIVED):
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
