package cheat;
import mc.MC;
public class KillAura5 {
  private MC.ClientPacketListener net; private MC.MultiPlayerGameMode gm;
  private MC.LocalPlayer me; private MC.Level level; private MC.KeyMapping bind;
  public void onTick() {
    if (!bind.isPressed()) return;
    for (MC.Entity t : level.entitiesForRendering()) {
      float yaw = (float)Math.atan2(t.z - me.z, t.x - me.x);
      float pitch = (float)Math.atan2(t.y - me.y, 1.0);
      me.setYRot(yaw); me.setXRot(pitch);
      net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, yaw, pitch, me.onGround));
      net.send(new MC.ServerboundInteractPacket(t));
      gm.attack(me, t); me.swing(0);
    }
  }
}