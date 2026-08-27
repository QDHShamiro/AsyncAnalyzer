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
import csv, glob, os, random, shutil, subprocess, sys, tempfile
import bytecode

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(20260827)

FEATURES = ([k + "_ratio" for k in sorted(bytecode.BEHAVIOUR)] +
            ["obf_name_ratio", "str_readable_ratio", "str_entropy", "log_classes"])

MC_STUB = '''package mc;
public class MC {
  public static class Entity { public double x,y,z; public boolean onGround;
    public void setYRot(float y){} public void setXRot(float x){} public float getYRot(){return 0;} }
  public static class LivingEntity extends Entity { public float health; }
  public static class LocalPlayer extends LivingEntity { public void swing(int h){} }
  public static class Level { public java.util.List<Entity> entitiesForRendering(){return null;}
    public Object getBlockState(int x,int y,int z){return null;} }
  public static class ServerboundMovePlayerPacket { public ServerboundMovePlayerPacket(double x,double y,double z,float a,float b,boolean g){} }
  public static class ServerboundInteractPacket { public ServerboundInteractPacket(Entity e){} }
  public static class ClientPacketListener { public void send(Object p){} }
  public static class MultiPlayerGameMode { public void attack(LocalPlayer p, Entity t){} }
  public static class VertexConsumer { public VertexConsumer vertex(double x,double y,double z){return this;} }
  public static class PoseStack { public void pushPose(){} public void popPose(){} }
  public static class RenderSystem { public static void setShader(){} }
  public static class KeyMapping { public boolean isPressed(){return false;} }
}
'''

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
    # clean behaviours
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
        # auto-reconnect / chat macro: sends packets on a keybind - but forges no rotation
        return '''    if (!bind.isPressed()) return;
    net.send(new MC.ServerboundInteractPacket(me));
    hit++;'''
    if kind == "zoom":
        return '''    if (bind.isPressed()) { MC.RenderSystem.setShader(); stack.pushPose(); stack.popPose(); }'''
    if kind == "net":
        return '''    try { ((java.net.HttpURLConnection) new java.net.URL("https://api/x").openConnection()).getInputStream().close(); } catch (Exception e) {}'''
    return "    hit++;"

def gen_class(pkg, name, kinds, obf, nstr):
    strs = "".join('  static final String S%d = "%s";\n' % (i, enc_str(random.randint(20, 60)))
                   for i in range(nstr)) if obf else \
           "".join('  static final String S%d = "module %s option %d enabled";\n' % (i, name, i)
                   for i in range(nstr))
    stmts = "\n".join(body(k, obf) for k in kinds)
    return f'''package {pkg};
import mc.MC;
public class {name} {{
  private MC.ClientPacketListener net; private MC.MultiPlayerGameMode gm;
  private MC.LocalPlayer me; private MC.Level level; private MC.KeyMapping bind;
  private MC.VertexConsumer buf; private MC.PoseStack stack;
  private byte[] blob = new byte[16]; private byte[] k = new byte[16]; private int hit;
{strs}  public void go() {{
{stmts}
  }}
}}
'''

# (label, behaviour kinds, obfuscated?, n classes)
def variants():
    v = []
    cheat_mixes = [["aim"], ["aim", "esp"], ["fly"], ["esp"], ["aim", "fly"],
                   ["load"], ["load", "aim"], ["aim", "esp", "fly"]]
    for mix in cheat_mixes:
        for obf in (False, True):
            for n in (3, 8, 16):
                v.append((1, mix, obf, n))
    clean_mixes = [["map"], ["cfg"], ["key"], ["net"], ["map", "key"],
                   ["cfg", "net"], ["map", "cfg"], ["key", "net"], ["map", "cfg", "key"],
                   # hard negatives: legit mods that LOOK like cheats behaviourally
                   ["radar"], ["radar", "key"], ["freecam"], ["freecam", "key"],
                   ["macro"], ["macro", "net"], ["zoom"], ["radar", "freecam"],
                   ["macro", "zoom"], ["radar", "macro"]]
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
