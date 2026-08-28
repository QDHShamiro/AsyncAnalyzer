package mc;

// The 1.7.10 - 1.12.2 side of the Minecraft API, under its MCP names.
//
// This exists because the behaviour tables only ever knew 1.13+ Mojang, Yarn and
// intermediary names. 1.8.9 is where most Minecraft PvP - and most Minecraft PvP
// cheating - actually happens, and a 1.8.9 killaura calls none of the names the
// rules were looking for. Same stub reasoning as MC.java: the game's own API,
// which lives in Minecraft and never inside a mod jar.
public class MC18 {
  public static class Entity {
    public double posX, posY, posZ;
    public double motionX, motionY, motionZ;
    public float rotationYaw, rotationPitch;
    public boolean onGround;
  }
  public static class EntityLivingBase extends Entity { public float health; }
  public static class EntityPlayerSP extends EntityLivingBase { public void swingItem() {} }
  public static class WorldClient { public java.util.List<Entity> loadedEntityList;
    public Object getBlockState(int x, int y, int z) { return null; } }
  public static class C03PacketPlayer { public C03PacketPlayer(double x, double y, double z, float a, float b, boolean g) {} }
  public static class C02PacketUseEntity { public C02PacketUseEntity(Entity e) {} }
  public static class C08PacketPlayerBlockPlacement { public C08PacketPlayerBlockPlacement(int x, int y, int z) {} }
  public static class C07PacketPlayerDigging { public C07PacketPlayerDigging(int x, int y, int z) {} }
  public static class C0EPacketClickWindow { public C0EPacketClickWindow(int slot, int btn) {} }
  public static class NetHandlerPlayClient { public void addToSendQueue(Object p) {} }
  public static class PlayerControllerMP {
    public void attackEntity(EntityPlayerSP p, Entity t) {}
    public void onPlayerRightClick() {}
    public void clickBlock(int x, int y, int z) {}
  }
  public static class KeyBinding { public boolean isKeyDown() { return false; } }
  public static class GlStateManager { public static void pushMatrix() {} public static void popMatrix() {} }
  public static class WorldRenderer { public WorldRenderer pos(double x, double y, double z) { return this; } }
}
