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
    "bc_movepacket": [r"ServerboundMovePlayerPacket", r"PlayerMoveC2SPacket", r"class_2828",
                      r"C03PacketPlayer", r"CPacketPlayer"],
    "bc_rotation":   [r"\.setYRot", r"\.setXRot", r"\.setYaw", r"\.setPitch",
                      r"\.method_36456", r"\.method_36457",
                      r"\.rotationYaw\b", r"\.rotationPitch\b", r"\.rotationYawHead\b"],
    "bc_attack":     [r"MultiPlayerGameMode\.attack", r"ServerboundInteractPacket",
                      r"PlayerInteractEntityC2SPacket", r"class_2824",
                      # A bare "\.swing" matched javax/swing and any field called
                      # swingGui - rhino's debugger UI tripped it. Qualify it to the
                      # actual Minecraft method so a Swing app cannot look like combat.
                      r"(?:LocalPlayer|Player|LivingEntity)\.swing\b", r"\.swingHand\b",
                      r"\.method_6104\b",
                      r"C02PacketUseEntity", r"CPacketUseEntity", r"PlayerControllerMP", r"\.swingItem\b", r"\.attackEntity\b"],
    # Both Wurst and Meteor hook the network layer itself, not just the listener.
    # Qualified on purpose - a bare "Connection" is an everyday identifier.
    "bc_pktlisten":  [r"ClientPacketListener", r"ClientPlayNetworkHandler", r"class_634",
                      r"net/minecraft/network/Connection", r"class_2535",
                      r"NetHandlerPlayClient", r"net/minecraft/network/NetworkManager"],
    "bc_entityscan": [r"entitiesForRendering", r"getEntities", r"method_18112", r"\.getEntityList",
                      r"\.loadedEntityList\b", r"\.getLoadedEntityList\b", r"\.playerEntities\b"],
    "bc_render":     [r"VertexConsumer", r"RenderSystem", r"BufferBuilder", r"MatrixStack",
                      r"PoseStack", r"Tessellator", r"class_4587",
                      r"GlStateManager", r"WorldRenderer"],
    "bc_input":      [r"KeyMapping", r"KeyBinding", r"GLFW\.glfwGetKey", r"\.isPressed",
                      r"client/input", r"class_304",
                      r"client/KeyboardHandler", r"client/MouseHandler",
                      r"Keyboard\.isKeyDown", r"GameSettings\."],
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
                      r"class_2885", r"\.useItemOn", r"\.interactBlock", r"\.method_2896",
                      r"C08PacketPlayerBlockPlacement", r"CPacketPlayerTryUseItemOnBlock", r"\.onPlayerRightClick\b"],
    "bc_blockbreak": [r"ServerboundPlayerActionPacket", r"PlayerActionC2SPacket",
                      r"class_2846", r"\.startDestroyBlock", r"\.destroyBlock", r"\.method_2910",
                      r"C07PacketPlayerDigging", r"CPacketPlayerDigging", r"\.onPlayerDamageBlock\b", r"\.clickBlock\b"],
    "bc_container":  [r"ServerboundContainerClickPacket", r"ClickSlotC2SPacket",
                      r"class_2813", r"AbstractContainerMenu", r"ScreenHandler", r"class_1703",
                      r"C0EPacketClickWindow", r"CPacketClickWindow", r"\.windowClick\b", r"InventoryPlayer"],
    "bc_motion":     [r"\.setDeltaMovement", r"\.getDeltaMovement", r"\.setVelocity",
                      r"\.method_18800", r"\.method_18798",
                      r"\.motionX\b", r"\.motionY\b", r"\.motionZ\b"],
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
    # Opening or writing an archive. A mod loader, a remapper or a shader cache
    # legitimately locates its own jar and deletes files - it is tooling that
    # processes archives for a living. A client deleting itself has no reason to
    # open one.
    "bc_archive":    [r"java/util/jar", r"java/util/zip", r"JarFile", r"ZipFile",
                      r"JarOutputStream", r"ZipOutputStream", r"JarInputStream",
                      r"ZipInputStream", r"JarEntry", r"ZipEntry"],
    # This class is a Mixin - it does not call the game, it is COMPILED INTO it.
    # Neutral on its own: Sodium, Lithium and the Fabric API itself are nothing
    # but mixins. It matters because of what it does to the evidence, below.
    "bc_mixin":      [r"org/spongepowered/asm/mixin"],
    # The third way into the game's code, next to Mixin and a Java agent: a Forge
    # coremod or a LaunchWrapper tweaker installs a CLASS TRANSFORMER that runs
    # before the game and can rewrite any class on the way in. Neutral on its own -
    # OptiFine is a tweaker - and, like a mixin, it names its targets as strings.
    "bc_transformer": [r"IClassTransformer", r"IFMLLoadingPlugin", r"ITransformer",
                       r"net/minecraftforge/coremod", r"cpw/mods/modlauncher",
                       r"net/minecraft/launchwrapper", r"LaunchClassLoader"],
}

# Derived per-class signals. Not regexes: they are combinations that only mean
# something when ONE class does all of it. Jar-level ratios cannot express that -
# in a big library "something locates its own jar" and "something deletes a file"
# are usually unrelated classes, which is exactly how the first version of the
# self-wipe rule matched sixteen bytecode libraries.
DERIVED = {
    # set when a behaviour was found only through reflection - worth surfacing on
    # its own, because deliberately hiding which Minecraft API you call is not
    # something an ordinary mod has a reason to do
    "bc_hiddenapi": lambda hits: False,   # set directly, not derived from others
    # a class that finds its own jar and deletes a file, and is not unpacking a
    # native library: that is a jar removing itself
    "bc_selfwipe": lambda hits: ("bc_selfpath" in hits and "bc_filedelete" in hits
                                 and "bc_nativetemp" not in hits
                                 and "bc_archive" not in hits),
    # set when a behaviour was found through a mixin's declared target rather than
    # through a call - see _MIXIN_API
    "bc_mixintarget": lambda hits: False,   # set directly, not derived from others
    # same, for a class transformer: the game class it rewrites is a string it
    # compares against, never a call
    "bc_coretarget": lambda hits: False,    # set directly, not derived from others
}
_COMPILED = {k: re.compile("|".join(v)) for k, v in BEHAVIOUR.items()}

# Names a dropper almost always reaches REFLECTIVELY, so they land in a string
# constant rather than a Methodref. Kept deliberately tiny: broad names like
# setAccessible are everyday library code and would drag legit jars in.
_REFLECTIVE_NAMES = {
    "bc_classload": re.compile(r"^(defineClass|defineAnonymousClass|defineHiddenClass)$"),
    "bc_instrument": re.compile(r"^(premain|agentmain|retransformClasses)$"),
}

# --- reflective use of the same API ------------------------------------------
#
# The behaviour categories above read the constant pool's SYMBOL TABLE - Class
# entries and member refs. That is what makes them survive obfuscation of a cheat's
# own names: to call a Minecraft method you must name it there.
#
# You can, however, avoid naming it there at all. Class.forName("net.minecraft...")
# plus getDeclaredMethod("setYRot") moves every one of those names into STRING
# constants, and the rules stop seeing them. Measured: an aim cheat rewritten that
# way scored Clean, 3/100 - one refactor evades all twelve rules.
#
# So the same vocabulary is matched against strings too. The tokens are the same,
# minus the leading "\." that anchors them to a member ref, because a reflective
# call names the method bare: getDeclaredMethod("setYRot").
#
# Kept to the categories a cheat needs and a compatibility shim does not. A mod
# doing Class.forName on some class to check whether another mod is installed is
# ordinary; one that reflectively assembles a movement packet is not.
# The tokens are chosen, not derived by stripping the qualifiers off the table
# above: a reflective call names the class and the method SEPARATELY, so
# "MultiPlayerGameMode\.attack" has no reflective form, and the bare word "attack"
# would match anything. What is listed here is the part that is distinctively
# Minecraft on its own - a packet class, an intermediary name, a method that
# exists nowhere else.
_REFLECTIVE_API = {
    "bc_movepacket": r"ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828"
                     r"|C03PacketPlayer|CPacketPlayer",
    "bc_rotation":   r"\bsetYRot\b|\bsetXRot\b|\bmethod_36456\b|\bmethod_36457\b"
                     r"|\brotationYaw\b|\brotationPitch\b",
    "bc_attack":     r"ServerboundInteractPacket|PlayerInteractEntityC2SPacket|class_2824"
                     r"|MultiPlayerGameMode|\bswingHand\b|\bmethod_6104\b"
                     r"|C02PacketUseEntity|CPacketUseEntity|PlayerControllerMP|\bswingItem\b",
    "bc_motion":     r"\bsetDeltaMovement\b|\bgetDeltaMovement\b|\bmethod_18800\b"
                     r"|\bmethod_18798\b"
                     r"|\bmotionX\b|\bmotionY\b|\bmotionZ\b",
    "bc_blockplace": r"ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885"
                     r"|\bmethod_2896\b"
                     r"|C08PacketPlayerBlockPlacement|CPacketPlayerTryUseItemOnBlock",
    "bc_blockbreak": r"ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846"
                     r"|\bmethod_2910\b"
                     r"|C07PacketPlayerDigging|CPacketPlayerDigging",
    "bc_container":  r"ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813"
                     r"|AbstractContainerMenu"
                     r"|C0EPacketClickWindow|CPacketClickWindow",
    "bc_pktlisten":  r"ClientPacketListener|ClientPlayNetworkHandler|class_634|class_2535"
                     r"|NetHandlerPlayClient",
}
_REFLECTIVE_API = {k: re.compile(v) for k, v in _REFLECTIVE_API.items()}

# --- what a mixin names, and why the symbol table does not see it -------------
#
# A Mixin is not a mod calling the game. It is code the loader COMPILES INTO a
# game class. That changes where the evidence lives, and it opens the same hole
# reflection did.
#
# A mixin names its target in an ANNOTATION - @Mixin(ServerboundMovePlayerPacket.class)
# or @Mixin(targets = "net.minecraft...") - and its injection point by method NAME
# in @Inject(method = "aiStep"). Annotation values are Utf8 constants, not Class
# entries or member refs, so none of it reaches the symbol table. Everything it
# touches inside the target it reaches through @Shadow members declared on ITSELF,
# so those resolve to the mixin class, not to Minecraft.
#
# Worked example, and the reason this exists: silent rotations. Mixin into
# ServerboundMovePlayerPacket, shadow the yRot field, overwrite it in the
# constructor. The player's view never turns, the server is told it did. Read
# through the symbol table that class calls nothing - bc_movepacket 0,
# bc_rotation 0 - and every combat rule is blind to it.
#
# So the same vocabulary is matched against a mixin's strings, exactly as it is
# against a reflecting class's strings. Two additions on top of the shared table,
# both only meaningful inside a mixin: shadowed field names, and the movement
# methods of the player that an injection point names.
_MIXIN_MARK = re.compile(rb"org/spongepowered/asm/mixin")
_MIXIN_API = dict(_REFLECTIVE_API)
_MIXIN_API.update({
    # The player's own movement tick. @Inject(method = "aiStep") is where a
    # movement mixin has to go, and the shadowed field it moves. "tick" alone is
    # far too common a word to include; these two name the movement path itself.
    "bc_motion": re.compile(
        r"\bsetDeltaMovement\b|\bgetDeltaMovement\b|\bmethod_18800\b"
        r"|\bmethod_18798\b|\bdeltaMovement\b|\baiStep\b|\bmethod_6091\b"),
})

# Shadowed rotation FIELD names - and only for a mixin that targets an outgoing
# movement packet.
#
# The narrowing is the whole point. Plenty of legitimate mods shadow yRot: any
# camera, freelook or perspective mod names the same field, and reading a bare
# "yRot" as "writes rotation" would accuse all of them. But a mixin whose target
# is the packet that REPORTS your rotation to the server, naming that packet's
# rotation fields, is rewriting what the server is told you are looking at. That
# is silent rotations, and it is the one shape a camera mod never has - a camera
# mixes into the player or the renderer, never into the outgoing packet.
_MIXIN_PACKET_API = {
    "bc_rotation": re.compile(r"\byRot\b|\bxRot\b|\bfield_5982\b|\bfield_6031\b"),
}

# Which part of the game a mixin injects into. Not a rule and not scored - it is
# for the moderator reading the report, because "rewrites the network handler and
# the player's movement" and "rewrites the options screen" are different mods and
# the score alone does not say which one is on the screen.
_MIXIN_AREA = [
    ("player movement", re.compile(
        r"LocalPlayer|ClientPlayerEntity|class_746|LivingEntity|class_1309"
        r"|\baiStep\b|\btravel\b|\bdeltaMovement\b|MovementInput|class_744"
        r"|EntityPlayerSP|EntityLivingBase|\bmotionX\b|\brotationYaw\b")),
    ("network handler", re.compile(
        r"ClientPacketListener|ClientPlayNetworkHandler|class_634|class_2535"
        r"|net/minecraft/network|Serverbound|C2SPacket|ClientboundS2CPacket|S2CPacket"
        r"|NetHandlerPlayClient|C0[0-9A-F]Packet|CPacketPlayer")),
    ("world / blocks", re.compile(
        r"ClientLevel|ClientWorld|class_638|BlockState|class_2680|ChunkRenderer|LevelChunk"
        r"|WorldClient|RenderChunk|ChunkRenderDispatcher")),
    ("rendering", re.compile(
        r"LevelRenderer|WorldRenderer|GameRenderer|EntityRenderer|class_761|class_757"
        r"|RenderSystem|GuiGraphics|class_332|RenderGlobal|GlStateManager|GuiIngame")),
    ("inventory / containers", re.compile(
        r"AbstractContainerMenu|ScreenHandler|class_1703|Inventory|class_1661"
        r"|InventoryPlayer|GuiContainer")),
    ("menus / screens", re.compile(
        r"net/minecraft/client/gui/screens|client/gui/screen|class_437|OptionsScreen|TitleScreen"
        r"|GuiScreen|GuiMainMenu|GuiOptions")),
]

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
        b"loadLibrary", b"tmpdir", b"java/util/jar", b"java/util/zip", b"JarFile",
        b"ZipFile", b"JarOutputStream", b"ZipOutputStream", b"JarInputStream",
        b"ZipInputStream", b"JarEntry", b"ZipEntry",
        b"org/spongepowered/asm/mixin",
        # Found by the reachability check below, not by reading: these three
        # were named in a behaviour pattern and missing here, so a class whose
        # only Minecraft reference was one of them was never parsed at all and
        # the rule above it silently did nothing.
        b"swingHand", b"method_6104", b"getLoadedEntityList",
        b"IClassTransformer", b"IFMLLoadingPlugin", b"ITransformer",
        b"net/minecraftforge/coremod", b"cpw/mods/modlauncher",
        b"net/minecraft/launchwrapper", b"LaunchClassLoader",
        # 1.7.10 - 1.12.2 MCP names. The tables above only knew 1.13+ Mojang,
        # Yarn and intermediary names, so a 1.8.9 killaura - which is most of
        # Minecraft PvP cheating - was invisible to all twelve rules.
        b"C03PacketPlayer", b"CPacketPlayer", b"rotationYaw", b"rotationPitch",
        b"C02PacketUseEntity", b"CPacketUseEntity", b"PlayerControllerMP",
        b"swingItem", b"attackEntity", b"NetHandlerPlayClient", b"NetworkManager",
        b"loadedEntityList", b"playerEntities", b"GlStateManager", b"WorldRenderer",
        b"isKeyDown", b"GameSettings", b"C08PacketPlayerBlockPlacement",
        b"CPacketPlayerTryUseItemOnBlock", b"onPlayerRightClick",
        b"C07PacketPlayerDigging", b"CPacketPlayerDigging", b"onPlayerDamageBlock",
        b"clickBlock", b"C0EPacketClickWindow", b"CPacketClickWindow",
        b"windowClick", b"InventoryPlayer", b"motionX", b"motionY", b"motionZ",
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
    mixin_areas = set()

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
            sblob = None
            # Reflective use of the same API. Only counts when this class actually
            # reflects - a string alone is a mention, reflection makes it a call.
            if "bc_reflect" in hit_here:
                sblob = "\n".join(
                    x.decode("utf-8", "ignore") for x in strings if len(x) < 200)
                for k, rx in _REFLECTIVE_API.items():
                    if k not in hit_here and rx.search(sblob):
                        hit_here.add(k)
                        hit_here.add("bc_hiddenapi")
            # A mixin declares its target in an annotation, so the target reaches
            # the pool as a string and never as a symbol. Same vocabulary, same
            # treatment - but NOT flagged as hiding anything: naming your target in
            # an annotation is how mixins are written, not evasion.
            # The marker is a literal byte sequence in the pool, so the raw head the
            # pre-filter already read finds it in one search.
            if "bc_mixin" not in hit_here and _MIXIN_MARK.search(data):
                hit_here.add("bc_mixin")
            if "bc_mixin" in hit_here:
                if sblob is None:
                    sblob = "\n".join(
                        x.decode("utf-8", "ignore") for x in strings if len(x) < 200)
                for k, rx in _MIXIN_API.items():
                    if k not in hit_here and rx.search(sblob):
                        hit_here.add(k)
                        hit_here.add("bc_mixintarget")
                if "bc_movepacket" in hit_here:
                    for k, rx in _MIXIN_PACKET_API.items():
                        if k not in hit_here and rx.search(sblob):
                            hit_here.add(k)
                            hit_here.add("bc_mixintarget")
                for area, rx in _MIXIN_AREA:
                    if rx.search(sblob):
                        mixin_areas.add(area)
            # A class transformer decides what to rewrite by COMPARING the class name
            # it is handed against string constants. Same shape as a mixin's
            # annotation and reflection's getDeclaredMethod, third door, same key.
            if "bc_transformer" in hit_here:
                if sblob is None:
                    sblob = "\n".join(
                        x.decode("utf-8", "ignore") for x in strings if len(x) < 200)
                for k, rx in _MIXIN_API.items():
                    if k not in hit_here and rx.search(sblob):
                        hit_here.add(k)
                        hit_here.add("bc_coretarget")
                for area, rx in _MIXIN_AREA:
                    if rx.search(sblob):
                        mixin_areas.add(area)
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
    # Evidence for the report, not a feature: which parts of the game this jar
    # compiles itself into. Ordered as declared so the line reads the same way twice.
    out["mixin_areas"] = [a for a, _ in _MIXIN_AREA if a in mixin_areas]
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
