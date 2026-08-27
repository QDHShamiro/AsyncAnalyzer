package mc;
public class MC {
  public static class Entity { public double x,y,z; public boolean onGround;
    public void setYRot(float y){} public void setXRot(float x){} public float getYRot(){return 0;} }
  public static class LivingEntity extends Entity { public float health; }
  public static class LocalPlayer extends LivingEntity { public void swing(int h){} }
  public static class Level { public java.util.List<Entity> entitiesForRendering(){return null;}
    public Object getBlockState(int x,int y,int z){return null;} }
  public static class ServerboundMovePlayerPacket { public ServerboundMovePlayerPacket(double x,double y,double z,float yaw,float pitch,boolean g){} }
  public static class ServerboundInteractPacket { public ServerboundInteractPacket(Entity e){} }
  public static class ClientPacketListener { public void send(Object p){} }
  public static class MultiPlayerGameMode { public void attack(LocalPlayer p, Entity t){} }
  public static class VertexConsumer { public VertexConsumer vertex(double x,double y,double z){return this;} }
  public static class PoseStack { public void pushPose(){} public void popPose(){} }
  public static class RenderSystem { public static void setShader(){} }
  public static class KeyMapping { public boolean isPressed(){return false;} }
}
