"""
Build the behavioural dataset. BOTH classes are real compiled bytecode.

Negatives: real library jars from Maven Central (fetch_jars.py) - the "scary but
legitimate" families a naive scanner false-flags.

Positives: cheat behaviours reconstructed from real cheat-client source (Meteor
Client @8038a0a) and compiled by javac. They are reconstructions, not captured
samples - this repo does not ship cheat binaries - but the constant pools are
produced by a real compiler, so the structure the detector reads is genuine.

Variants deliberately vary behaviour mix, symbol obfuscation, string encryption
and jar size, so the model cannot separate the classes on jar size or on any
single behaviour alone.
"""
import csv, glob, os, random, re, shutil, subprocess, sys, tempfile
import bytecode

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(20260827)

# Derived signals belong here too - leaving them out silently produced a column
# of zeroes, which reads exactly like "this rule catches nothing".
FEATURES = ([k + "_ratio" for k in sorted(list(bytecode.BEHAVIOUR) + list(bytecode.DERIVED))] +
            ["obf_name_ratio", "str_readable_ratio", "str_entropy", "log_classes"])

MC_STUB = '''package mc;
public class MC {
  public static class Entity { public double x,y,z; public boolean onGround;
    public void setYRot(float y){} public void setXRot(float x){} public float getYRot(){return 0;}
    public void setDeltaMovement(double a,double b,double c){} public double getDeltaMovement(){return 0;} }
  public static class LivingEntity extends Entity { public float health; }
  public static class LocalPlayer extends LivingEntity { public void swing(int h){} }
  public static class Level { public java.util.List<Entity> entitiesForRendering(){return null;}
    public Object getBlockState(int x,int y,int z){return null;} }
  public static class ServerboundMovePlayerPacket { public ServerboundMovePlayerPacket(double x,double y,double z,float a,float b,boolean g){} }
  public static class ServerboundInteractPacket { public ServerboundInteractPacket(Entity e){} }
  public static class ClientPacketListener { public void send(Object p){} }
  public static class MultiPlayerGameMode { public void attack(LocalPlayer p, Entity t){}
    public void useItemOn(int x,int y,int z){} public void startDestroyBlock(int x,int y,int z){} }
  public static class VertexConsumer { public VertexConsumer vertex(double x,double y,double z){return this;} }
  public static class PoseStack { public void pushPose(){} public void popPose(){} }
  public static class RenderSystem { public static void setShader(){} }
  public static class KeyMapping { public boolean isPressed(){return false;} }
  public static class ServerboundUseItemOnPacket { public ServerboundUseItemOnPacket(int x,int y,int z){} }
  public static class ServerboundPlayerActionPacket { public ServerboundPlayerActionPacket(int x,int y,int z){} }
  public static class ServerboundContainerClickPacket { public ServerboundContainerClickPacket(int slot,int btn){} }
  public static class ServerboundChatPacket { public ServerboundChatPacket(String m){} }
  public static class HitResult { public Entity entity; public double dist; }
  public static class Camera { public HitResult getCrosshairTarget(){return null;} }
  public static class Options { public boolean fancyGraphics; }
  public static class AbstractContainerMenu { public int slots; public void clicked(int s,int b){} }
}
'''

# The Mixin annotations, declared in their real package. Nothing is imported from
# the actual Mixin library - it is not needed and this repo does not vendor it.
# What the detector reads is the constant pool, and javac writes exactly the same
# Utf8 constants for these as for the real ones: the annotation descriptor
# Lorg/spongepowered/asm/mixin/Mixin; and the target named as a string. Same
# reasoning as the MC stub - reconstructed source, real compiler, genuine shape.
MIXIN_STUB = {
    "org/spongepowered/asm/mixin/Mixin.java":
        "package org.spongepowered.asm.mixin;\n"
        "import java.lang.annotation.*;\n"
        "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)\n"
        "public @interface Mixin { String[] targets() default {}; }\n",
    "org/spongepowered/asm/mixin/Shadow.java":
        "package org.spongepowered.asm.mixin;\n"
        "import java.lang.annotation.*;\n"
        "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.FIELD, ElementType.METHOD})\n"
        "public @interface Shadow { }\n",
    "org/spongepowered/asm/mixin/injection/Inject.java":
        "package org.spongepowered.asm.mixin.injection;\n"
        "import java.lang.annotation.*;\n"
        "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)\n"
        "public @interface Inject { String[] method() default {}; String at() default \"\"; }\n",
}

# Mixin-shaped variants: kind -> (target class, injection point, shadow fields).
# A mixin is not a mod calling the game, it is code compiled INTO a game class,
# so its target and its injection point are annotation VALUES - strings - and
# never reach the symbol table. That is why these are declared here rather than
# written as statements: the point of each one is what it does NOT call.
MIXIN = {
    # --- cheats ---------------------------------------------------------------
    # Silent rotations. Mixin into the packet that reports where you are looking,
    # shadow its rotation fields, overwrite them. Your view never turns; the server
    # is told it did. Through the symbol table this class calls nothing at all.
    "mixrot":  ("net.minecraft.network.protocol.game.ServerboundMovePlayerPacket",
                "<init>", ["private float yRot;", "private float xRot;"]),
    # Anti-knockback as a mixin: injected into the network handler, zeroing the
    # motion the server just applied.
    "mixvel":  ("net.minecraft.client.multiplayer.ClientPacketListener",
                "handleSetEntityMotion", ["private double deltaMovement;"]),
    # Scaffold as a mixin: the move packet is the target, the block-place packet is
    # named at the injection point.
    "mixscaf": ("net.minecraft.network.protocol.game.ServerboundMovePlayerPacket",
                "net.minecraft.network.protocol.game.ServerboundUseItemOnPacket",
                ["private float yRot;"]),
    # --- legitimate mixins ----------------------------------------------------
    # These exist to be NOT flagged. Every one of them is how an ordinary mod is
    # built; mixins are not a cheat technique, they are how Fabric mods work at all.
    "mixhud":  ("net.minecraft.client.gui.GuiGraphics", "renderHotbar", []),
    "mixtitle": ("net.minecraft.client.gui.screens.TitleScreen", "init", []),
    "mixperf": ("net.minecraft.client.renderer.LevelRenderer", "renderLevel", []),
    # protocol translation hooks the connection itself, not the packet records
    "mixvia":  ("net.minecraft.network.Connection", "channelRead0", []),
    # The negative the narrowing exists for: a freelook / perspective mod shadows
    # exactly the same rotation fields the silent-rotation cheat does, and renders.
    # It targets the player, not the outgoing packet - which is the difference, and
    # if that difference ever stops working, this jar is what says so.
    "mixfree": ("net.minecraft.client.player.LocalPlayer", "turn",
                ["private float yRot;", "private float xRot;"]),
    # sprint / elytra / jetpack mods live in aiStep and move the player
    "mixsprint": ("net.minecraft.client.player.LocalPlayer", "aiStep",
                  ["private double deltaMovement;"]),
}


def enc_str(n):
    """opaque blob standing in for an encrypted string constant"""
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                   for _ in range(n))

def body(kind, obf):
    """returns java statements for one behaviour"""
    if kind == "aim":
        return '''    if (!bind.isPressed()) return;
    for (MC.Entity t : level.entitiesForRendering()) {
      float a = (float)Math.atan2(t.z - me.z, t.x - me.x);
      float b = (float)Math.atan2(t.y - me.y, 1.0);
      me.setYRot(a); me.setXRot(b);
      net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, a, b, me.onGround));
      net.send(new MC.ServerboundInteractPacket(t));
      gm.attack(me, t); me.swing(0);
    }'''
    if kind == "esp":
        return '''    MC.RenderSystem.setShader(); stack.pushPose();
    for (MC.Entity e : level.entitiesForRendering()) buf.vertex(e.x, e.y, e.z);
    stack.popPose();'''
    if kind == "fly":
        return '''    if (!bind.isPressed()) return;
    me.onGround = false; me.setYRot(me.getYRot());
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y + 0.42, me.z, me.getYRot(), 0f, false));'''
    if kind == "load":
        return '''    try {
      javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
      c.init(2, new javax.crypto.spec.SecretKeySpec(k, "AES"));
      byte[] p = c.doFinal(blob);
      java.lang.reflect.Method d = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
      d.setAccessible(true);
      Class<?> z = (Class<?>) d.invoke(getClass().getClassLoader(), null, p, 0, p.length);
      z.getDeclaredMethod("run").invoke(z.getDeclaredConstructor().newInstance());
      ((java.net.HttpURLConnection) new java.net.URL("http://h/p").openConnection()).getInputStream().close();
    } catch (Exception e) {}'''
    # ---- combat -----------------------------------------------------------
    if kind == "reach":
        # attacks a target picked out of a full entity sweep at a distance the game
        # would refuse. The legit counterpart (reachdisp) measures the same distance
        # and never attacks - that is the whole difference.
        return '''    for (MC.Entity t : level.entitiesForRendering()) {
      double d = Math.sqrt((t.x-me.x)*(t.x-me.x) + (t.z-me.z)*(t.z-me.z));
      if (d < 6.0) { gm.attack(me, t); me.swing(0); }
    }'''
    if kind == "trigger":
        # triggerbot: attacks whatever is under the crosshair without the key ever
        # being read. A legit combat mod reacts to input; this one reacts to the world.
        return '''    for (MC.Entity t : level.entitiesForRendering()) {
      net.send(new MC.ServerboundInteractPacket(t)); gm.attack(me, t);
    }'''
    if kind == "crystal":
        return '''    for (MC.Entity t : level.entitiesForRendering()) {
      gm.useItemOn((int)t.x, (int)t.y, (int)t.z);
      net.send(new MC.ServerboundUseItemOnPacket((int)t.x, (int)t.y, (int)t.z));
      gm.attack(me, t); me.swing(0);
    }'''
    if kind == "velocity":
        # anti-knockback: intercepts the incoming packet and zeroes the motion the
        # server just gave you. replay (clean) also listens - and never writes motion.
        return '''    if (net == null) return;
    me.setDeltaMovement(0.0, me.getDeltaMovement(), 0.0);'''
    # ---- movement ---------------------------------------------------------
    if kind == "scaffold":
        return '''    me.setYRot(180f); me.setXRot(90f);
    gm.useItemOn((int)me.x, (int)me.y - 1, (int)me.z);
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, 180f, 90f, true));'''
    if kind == "nofall":
        # tells the server it is standing while it falls. No rotation, no input -
        # just a movement packet the game did not produce.
        return '''    me.setDeltaMovement(0.0, -0.08, 0.0);
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, 0f, 0f, true));'''
    if kind == "blink":
        return '''    if (net == null) return;
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, 0f, 0f, me.onGround));
    me.setDeltaMovement(0.0, 0.0, 0.0);'''
    if kind == "speed":
        return '''    me.setDeltaMovement(me.getDeltaMovement() * 1.8, 0.0, me.getDeltaMovement() * 1.8);
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, me.getYRot(), 0f, me.onGround));'''
    if kind == "path":
        # Baritone-shaped pathing: computes a heading, writes the rotation and sends
        # its own movement packet. clean/AutoWalk drives the input system instead.
        return '''    float yaw = (float)Math.atan2(1.0, 1.0);
    me.setYRot(yaw); me.setXRot(0f);
    if (level.getBlockState((int)me.x, (int)me.y, (int)me.z) != null) me.onGround = true;
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, yaw, 0f, me.onGround));'''
    # ---- world ------------------------------------------------------------
    if kind == "nuker":
        # breaks every block in a radius with no key held. veinmine (clean) breaks
        # connected blocks and only while the player is actually mining.
        return '''    for (int x=-4;x<4;x++) for (int y=-4;y<4;y++) for (int z=-4;z<4;z++) {
      if (level.getBlockState((int)me.x+x,(int)me.y+y,(int)me.z+z) == null) continue;
      gm.startDestroyBlock((int)me.x+x,(int)me.y+y,(int)me.z+z);
      net.send(new MC.ServerboundPlayerActionPacket((int)me.x+x,(int)me.y+y,(int)me.z+z));
    }'''
    if kind == "fastplace":
        return '''    gm.useItemOn((int)me.x, (int)me.y, (int)me.z);
    net.send(new MC.ServerboundUseItemOnPacket((int)me.x, (int)me.y, (int)me.z));
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, 0f, 0f, true));'''
    # ---- utility / ghost --------------------------------------------------
    if kind == "invmove":
        # walking while an inventory screen is open: the game blocks that, so it
        # forges the movement packet. invsort (clean) only clicks slots.
        return '''    menu.clicked(0, 0);
    net.send(new MC.ServerboundContainerClickPacket(0, 0));
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, 0f, 0f, me.onGround));'''
    if kind == "httpcfg":
        # pulls its module list off a server and applies it reflectively - how a
        # ghost client stays updated without shipping the modules in the jar.
        return '''    try {
      java.io.InputStream in = ((java.net.HttpURLConnection) new java.net.URL("http://c/f").openConnection()).getInputStream();
      for (java.lang.reflect.Field f : getClass().getDeclaredFields()) { f.setAccessible(true); f.set(this, null); }
      in.close();
    } catch (Exception e) {}'''
    if kind == "selfdel":
        # The wipe: the jar asks the JVM where its own file is, then deletes it.
        # Shelling out to `del` was the old model and it is not what this actually
        # looks like - and "runs another program" matched 59 real libraries, so it
        # could never ship. Locating yourself in order to delete yourself is a
        # combination ordinary code has no reason to perform.
        return '''    try {
      java.security.CodeSource cs = getClass().getProtectionDomain().getCodeSource();
      java.io.File self = new java.io.File(cs.getLocation().toURI());
      self.deleteOnExit();
      java.nio.file.Files.deleteIfExists(self.toPath());
    } catch (Exception e) {}'''
    if kind == "freecam":
        # the camera detaches: it keeps its OWN position, updated from input, while
        # the player entity stays put. shoulder (clean) derives the camera from the
        # player every frame and cannot leave the body behind.
        return '''    if (bind.isPressed()) { camX += 0.5; camY += 0.1; camZ += 0.5; }
    me.setYRot(me.getYRot() + 1.0f); me.setXRot(0.5f);
    MC.RenderSystem.setShader(); stack.pushPose(); buf.vertex(camX, camY, camZ); stack.popPose();'''
    if kind == "autoclick":
        # swings on its own schedule. A legit combat HUD reads the key; this never
        # does - the attack is not caused by the player.
        return '''    hit++;
    if (hit % 3 == 0) { gm.attack(me, me); me.swing(0); }'''
    # clean behaviours
    if kind == "jetpack":
        # A tech mod's jetpack writes the player's velocity directly - the same
        # bc_motion the velocity and speed rules read. It never forges a packet and
        # never listens to one, which is what keeps it apart from them.
        return '''    if (!bind.isPressed()) return;
    me.setDeltaMovement(0.0, 0.6, 0.0);'''
    if kind == "grapple":
        return '''    if (!bind.isPressed()) return;
    me.setDeltaMovement(me.getDeltaMovement() * 1.2, 0.4, 0.0);
    MC.RenderSystem.setShader(); stack.pushPose(); buf.vertex(me.x, me.y, me.z); stack.popPose();'''
    if kind == "elytraboost":
        return '''    if (!bind.isPressed()) return;
    if (!me.onGround) me.setDeltaMovement(0.0, 0.1, 0.0);'''
    if kind == "bigutility":
        # One large QoL mod doing several ordinary things at once - reads keys,
        # clicks slots, draws a HUD, walks the entity list for a nameplate. Every
        # ingredient of several cheat rules, none of the combinations.
        return '''    if (!bind.isPressed()) return;
    for (int i = 0; i < menu.slots; i++) menu.clicked(i, 0);
    MC.RenderSystem.setShader(); stack.pushPose();
    for (MC.Entity e : level.entitiesForRendering()) buf.vertex(e.x, e.y + 2.0, e.z);
    stack.popPose();'''
    if kind == "updatecheck":
        # Fetches its own version over HTTP and applies the answer reflectively -
        # exactly the shape of a ghost client's config pull. This is why that rule
        # does not ship: this mod is completely ordinary.
        return '''    try {
      java.io.InputStream in = ((java.net.HttpURLConnection) new java.net.URL("https://api/v").openConnection()).getInputStream();
      for (java.lang.reflect.Field f : getClass().getDeclaredFields()) { f.setAccessible(true); f.get(this); }
      in.close();
    } catch (Exception e) {}'''
    if kind == "resourceclean":
        # A mod that tidies up its own cache directory on shutdown. It deletes
        # files - but never asks where its own jar is.
        return '''    try {
      java.io.File cache = new java.io.File("cache/tmp");
      java.nio.file.Files.deleteIfExists(cache.toPath());
    } catch (Exception e) {}'''
    if kind == "modloader":
        # A loader-style mod that reads its own jar location to enumerate what it
        # ships - the other half of the self-delete pair, on its own and harmless.
        return '''    try {
      java.security.CodeSource cs = getClass().getProtectionDomain().getCodeSource();
      if (cs.getLocation() != null) hit++;
    } catch (Exception e) {}'''
    if kind == "reflaim":
        # The same aim cheat, reaching Minecraft reflectively so none of its API
        # names land in the symbol table. Before this was detected, this exact
        # shape scored Clean at 3/100.
        return '''    try {
      Class<?> pk = Class.forName("net.minecraft.network.protocol.game.ServerboundMovePlayerPacket");
      Class<?> pl = Class.forName("net.minecraft.client.player.LocalPlayer");
      pl.getDeclaredMethod("setYRot", float.class).invoke(me, 1.0f);
      pl.getDeclaredMethod("setXRot", float.class).invoke(me, 0.5f);
      Object o = pk.getDeclaredConstructors()[0].newInstance();
      hit += o.hashCode();
    } catch (Exception e) {}'''
    if kind == "reflspeed":
        return '''    try {
      Class<?> e2 = Class.forName("net.minecraft.world.entity.Entity");
      e2.getDeclaredMethod("setDeltaMovement", double.class).invoke(me, 1.8);
      Class.forName("net.minecraft.network.protocol.game.ServerboundMovePlayerPacket");
    } catch (Exception e) {}'''
    if kind == "compat":
        # A legitimate compatibility shim: it reflects, and it names a Minecraft
        # class, to find out whether another mod is installed. It never names a
        # packet, a rotation setter or a motion write - which is the whole
        # difference, and why this rule is scoped to those and not to any MC name.
        return '''    try {
      Class<?> c = Class.forName("net.minecraft.client.Minecraft");
      c.getDeclaredMethod("getInstance");
      for (java.lang.reflect.Field f : c.getDeclaredFields()) { f.setAccessible(true); }
    } catch (Exception e) {}'''
    if kind == "printer":
        # Litematica-style schematic printer: places blocks through the game's own
        # interaction manager while a key is held. No forged movement, no forged
        # rotation - which is exactly what separates it from scaffold.
        return '''    if (!bind.isPressed()) return;
    for (int x=0;x<4;x++) if (level.getBlockState(x,64,0) != null) gm.useItemOn(x,64,0);
    MC.RenderSystem.setShader(); stack.pushPose(); buf.vertex(0,64,0); stack.popPose();'''
    if kind == "veinmine":
        return '''    if (!bind.isPressed()) return;
    for (int x=0;x<3;x++) if (level.getBlockState(x,64,0) != null) gm.startDestroyBlock(x,64,0);'''
    if kind == "invsort":
        return '''    if (!bind.isPressed()) return;
    for (int i=0;i<menu.slots;i++) menu.clicked(i, 0);'''
    if kind == "reachdisp":
        # A reach / ping / CPS display reads the ONE entity under the crosshair and
        # draws a number. It was first modelled here as a full entity sweep, which is
        # wrong and made it indistinguishable from a mob radar - the real thing never
        # enumerates entities at all, and that is why it stays clean while a radar
        # does not.
        return '''    MC.HitResult h = cam.getCrosshairTarget();
    if (h != null && h.entity != null) {
      double d = Math.sqrt((h.entity.x-me.x)*(h.entity.x-me.x));
      if (d > 0) hit++;
    }
    MC.RenderSystem.setShader(); stack.pushPose(); stack.popPose();'''
    if kind == "replay":
        return '''    if (net == null) return;
    try { ((java.net.HttpURLConnection) new java.net.URL("https://r/u").openConnection()).getInputStream().close(); } catch (Exception e) {}
    hit++;'''
    if kind == "shoulder":
        # third-person camera: position is a function of the player's position, so
        # it can never leave the body behind the way freecam does.
        return '''    MC.RenderSystem.setShader(); stack.pushPose();
    buf.vertex(me.x - 2.0, me.y + 1.0, me.z - 2.0);
    stack.popPose();'''
    if kind == "sprint":
        return '''    if (bind.isPressed()) hit++; else hit = 0;'''
    if kind == "map":
        return '''    MC.RenderSystem.setShader(); stack.pushPose();
    for (int x=0;x<16;x++) for (int z=0;z<16;z++) if (level.getBlockState(x,64,z)!=null) buf.vertex(x,64,z);
    stack.popPose();'''
    if kind == "cfg":
        return '''    try {
      for (java.lang.reflect.Field f : getClass().getDeclaredFields()) { f.setAccessible(true); f.get(this); }
      java.lang.reflect.Method m = getClass().getDeclaredMethod("go"); m.setAccessible(true);
    } catch (Exception e) {}'''
    if kind == "key":
        return '''    if (bind.isPressed()) hit++;'''
    if kind == "radar":
        # minimap mob radar: renders from a full entity sweep - identical shape to ESP
        return '''    MC.RenderSystem.setShader(); stack.pushPose();
    for (MC.Entity e : level.entitiesForRendering()) buf.vertex(e.x, e.y, e.z);
    for (int x=0;x<16;x++) if (level.getBlockState(x,64,0)!=null) buf.vertex(x,64,0);
    stack.popPose();'''
    if kind == "freecam":
        # freecam / camera mods write rotation - but never touch the movement packet
        return '''    if (!bind.isPressed()) return;
    me.setYRot(me.getYRot() + 1.0f); me.setXRot(0.5f);
    MC.RenderSystem.setShader(); stack.pushPose(); buf.vertex(me.x, me.y, me.z); stack.popPose();'''
    if kind == "macro":
        # A chat macro sends CHAT on a keybind. It used to be modelled with an entity
        # interact packet, which is not what a chat macro does at all - and that one
        # wrong line was enough to make an unrelated rule look like it false-flagged.
        return '''    if (!bind.isPressed()) return;
    net.send(new MC.ServerboundChatPacket("hello"));
    hit++;'''
    if kind == "zoom":
        return '''    if (bind.isPressed()) { MC.RenderSystem.setShader(); stack.pushPose(); stack.popPose(); }'''
    if kind == "net":
        return '''    try { ((java.net.HttpURLConnection) new java.net.URL("https://api/x").openConnection()).getInputStream().close(); } catch (Exception e) {}'''
    if kind in MIXIN:
        # A mixin body reaches the game through its own @Shadow members, so it
        # calls nothing outside itself. That is not a shortcut in the model - it
        # is the entire reason a mixin cheat is invisible to the symbol table.
        _t, _m, shadows = MIXIN[kind]
        w = []
        for d in shadows:
            var = d.rstrip(";").rsplit(" ", 1)[-1]
            cast = "float" if "float" in d else "double"
            w.append("    this.%s = (%s) (hit %% 3);" % (var, cast))
        w.append("    hit++;")
        return "\n".join(w)
    return "    hit++;"

# Declaring every field on every class was silently ruining the corpus. A field's
# TYPE lands in the constant pool, and four categories match a bare class name -
# KeyMapping, ClientPacketListener, VertexConsumer, AbstractContainerMenu - so
# every generated jar looked like it read input, hooked packets, rendered and
# touched containers. 450 of 452 jars were identical on those four features, which
# makes any rule involving them untestable rather than merely noisy.
#
# So: emit only the fields the chosen behaviours actually reference. Detected from
# the generated statements rather than from a hand-kept table, because a hand-kept
# table is exactly the thing that drifts back out of sync.
FIELDS = [
    ("net",   "  private MC.ClientPacketListener net;"),
    ("gm",    "  private MC.MultiPlayerGameMode gm;"),
    ("me",    "  private MC.LocalPlayer me;"),
    ("level", "  private MC.Level level;"),
    ("bind",  "  private MC.KeyMapping bind;"),
    ("buf",   "  private MC.VertexConsumer buf;"),
    ("stack", "  private MC.PoseStack stack;"),
    ("menu",  "  private MC.AbstractContainerMenu menu;"),
    ("cam",   "  private MC.Camera cam;"),
    ("opts",  "  private MC.Options opts;"),
    ("blob",  "  private byte[] blob = new byte[16];"),
    ("k",     "  private byte[] k = new byte[16];"),
    ("hit",   "  private int hit;"),
    ("camX",  "  private double camX, camY, camZ;"),
]


def gen_class(pkg, name, kinds, obf, nstr):
    strs = "".join('  static final String S%d = "%s";\n' % (i, enc_str(random.randint(20, 60)))
                   for i in range(nstr)) if obf else \
           "".join('  static final String S%d = "module %s option %d enabled";\n' % (i, name, i)
                   for i in range(nstr))
    stmts = "\n".join(body(k, obf) for k in kinds)
    decls = "\n".join(d for var, d in FIELDS
                      if re.search(r"\b%s\b" % re.escape(var), stmts))
    if decls:
        decls += "\n"
    # A mixin declares what it rewrites in ANNOTATIONS, which is the whole point:
    # the target class and the injected method are string constants, so nothing
    # about them reaches the symbol table the behaviour rules normally read.
    head, inj = "", ""
    mixed = [k for k in kinds if k in MIXIN]
    if mixed:
        targets = []
        shadows = []
        points = []
        for k in mixed:
            tgt, point, sh = MIXIN[k]
            if tgt not in targets:
                targets.append(tgt)
            if point not in points:
                points.append(point)
            for d in sh:
                if d not in shadows:
                    shadows.append(d)
        head = "@org.spongepowered.asm.mixin.Mixin(targets = {%s})\n" % ", ".join(
            '"%s"' % t for t in targets)
        inj = "  @org.spongepowered.asm.mixin.injection.Inject(method = {%s})\n" % ", ".join(
            '"%s"' % m for m in points)
        decls += "".join("  @org.spongepowered.asm.mixin.Shadow %s\n" % d for d in shadows)
    return f'''package {pkg};
import mc.MC;
{head}public class {name} {{
{decls}{strs}{inj}  public void go() {{
{stmts}
  }}
}}
'''

# (label, behaviour kinds, obfuscated?, n classes)
def variants():
    v = []
    cheat_mixes = [
        # the families the corpus already proved
        ["aim"], ["aim", "esp"], ["fly"], ["esp"], ["aim", "fly"],
        ["load"], ["load", "aim"], ["aim", "esp", "fly"],
        # combat
        ["reach"], ["trigger"], ["crystal"], ["velocity"], ["autoclick"],
        ["reach", "trigger"], ["crystal", "aim"], ["velocity", "fly"],
        # movement
        ["scaffold"], ["nofall"], ["blink"], ["speed"], ["path"],
        ["scaffold", "nofall"], ["speed", "nofall"], ["path", "aim"],
        # world
        ["nuker"], ["fastplace"], ["nuker", "fastplace"],
        # utility / ghost
        ["invmove"], ["httpcfg"], ["selfdel"], ["freecam"],
        ["httpcfg", "selfdel"], ["invmove", "aim"], ["freecam", "esp"],
        ["selfdel", "httpcfg", "load"],
        # the same cheats, reaching Minecraft reflectively so their API names
        # never enter the symbol table
        ["reflaim"], ["reflspeed"], ["reflaim", "esp"], ["reflspeed", "nofall"],
        # the same cheats written as MIXINS, where the target is an annotation
        # value and so never reaches the symbol table at all
        ["mixrot"], ["mixvel"], ["mixscaf"], ["mixrot", "esp"],
        ["mixrot", "mixvel"], ["mixscaf", "nofall"],
        # a ghost client is a bundle, not one module
        ["aim", "scaffold", "velocity"], ["reach", "nofall", "freecam"],
        ["httpcfg", "load", "invmove"],
    ]
    for mix in cheat_mixes:
        for obf in (False, True):
            for n in (3, 8, 16):
                v.append((1, mix, obf, n))
    clean_mixes = [
        ["map"], ["cfg"], ["key"], ["net"], ["map", "key"],
        ["cfg", "net"], ["map", "cfg"], ["key", "net"], ["map", "cfg", "key"],
        # hard negatives: legit mods that LOOK like cheats behaviourally. These are
        # what the detector is actually judged on - anything can separate a cheat
        # from a config parser, the question is whether it separates a schematic
        # printer from scaffold.
        ["radar"], ["radar", "key"],
        ["macro"], ["macro", "net"], ["zoom"], ["macro", "zoom"], ["radar", "macro"],
        ["printer"], ["printer", "key"], ["printer", "zoom"],
        ["veinmine"], ["veinmine", "key"],
        ["invsort"], ["invsort", "key"], ["invsort", "map"],
        ["reachdisp"], ["reachdisp", "key"], ["reachdisp", "map"],
        ["replay"], ["replay", "cfg"],
        ["shoulder"], ["shoulder", "zoom"], ["shoulder", "map"],
        ["sprint"], ["sprint", "key"],
        # Legit mods that touch the SAME Minecraft APIs the new rules read. Every
        # other negative in this corpus is a Maven library that never calls the
        # Minecraft API at all, so it cannot test an MC-specific rule - these can.
        ["jetpack"], ["jetpack", "key"], ["grapple"], ["elytraboost"],
        ["bigutility"], ["bigutility", "zoom"],
        ["updatecheck"], ["updatecheck", "cfg"],
        ["resourceclean"], ["modloader"], ["modloader", "cfg"],
        ["jetpack", "grapple", "elytraboost"],
        ["compat"], ["compat", "cfg"], ["compat", "updatecheck"],
        # Ordinary mods built the ordinary way. Mixins are not a cheat technique -
        # Sodium, Lithium and the Fabric API are nothing but mixins - so every one
        # of these has to stay clean or the mixin reading is worse than useless.
        ["mixhud"], ["mixtitle"], ["mixperf"], ["mixvia"],
        ["mixfree"], ["mixfree", "zoom"], ["mixsprint"], ["mixsprint", "key"],
        ["mixperf", "mixhud"], ["mixvia", "cfg"], ["mixfree", "shoulder"],
        # realistic packs: several legit utilities in one jar
        ["printer", "invsort", "key"], ["radar", "reachdisp", "zoom"],
        ["shoulder", "sprint", "map"], ["veinmine", "invsort", "cfg"],
    ]
    for mix in clean_mixes:
        for obf in (False, True):
            for n in (3, 8, 16):
                v.append((0, mix, obf, n))
    return v

def build(tmp):
    src = os.path.join(tmp, "src"); out = os.path.join(tmp, "out"); jars = os.path.join(tmp, "jars")
    for d in (src, out, jars): os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(src, "mc"), exist_ok=True)
    open(os.path.join(src, "mc", "MC.java"), "w").write(MC_STUB)
    for rel, text in MIXIN_STUB.items():
        fp = os.path.join(src, *rel.split("/"))
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        open(fp, "w").write(text)
    meta = []
    for vi, (label, mix, obf, n) in enumerate(variants()):
        pkg = "v%d" % vi
        os.makedirs(os.path.join(src, pkg), exist_ok=True)
        for ci in range(n):
            nm = ("%s" % chr(97 + ci % 26)) * (1 if obf else 1) if obf else "Mod%d" % ci
            nm = ("C%d" % ci) if obf else "Module%d" % ci
            if obf: nm = chr(97 + ci % 26) + ("" if ci < 26 else str(ci))
            nm = nm[0].upper() + nm[1:]
            open(os.path.join(src, pkg, nm + ".java"), "w").write(
                gen_class(pkg, nm, mix, obf, 2 if obf else 6))
        meta.append((vi, pkg, label))
    srcs = glob.glob(os.path.join(src, "**", "*.java"), recursive=True)
    r = subprocess.run(["javac", "-nowarn", "-d", out] + srcs, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-1500:]); return None, None
    rows = []
    for vi, pkg, label in meta:
        jp = os.path.join(jars, "%s.jar" % pkg)
        subprocess.run(["jar", "cf", jp, pkg], cwd=out, check=False)
        rows.append((jp, label))
    return rows, jars

def main():
    tmp = tempfile.mkdtemp(prefix="aa_ds_")
    try:
        cheat_jars, _ = build(tmp)
        if cheat_jars is None: return 1
        clean = sorted(glob.glob(os.path.join(HERE, "jars_legit", "*.jar")))
        rows = []
        for jp, label in cheat_jars:
            rows.append((bytecode.extract_jar(jp), label, os.path.basename(jp)))
        for jp in clean:
            rows.append((bytecode.extract_jar(jp, max_classes=150), 0, os.path.basename(jp)))
        import math
        path = os.path.join(HERE, "dataset_bytecode.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f); w.writerow(FEATURES + ["label", "name"])
            for r, label, nm in rows:
                r["log_classes"] = math.log1p(r["classes_parsed"]) / 6.0
                w.writerow(["%.6f" % float(r.get(k, 0.0)) for k in FEATURES] + [label, nm])
        pos = sum(1 for _, l, _ in rows if l == 1)
        print("wrote %s: %d rows (%d cheat / %d clean), %d features" % (
            path, len(rows), pos, len(rows) - pos, len(FEATURES)))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
