package cheat;
import mc.MC;
public class Flight2 {
  private MC.ClientPacketListener net; private MC.LocalPlayer me; private MC.KeyMapping bind;
  public void tick() {
    if (!bind.isPressed()) return;
    me.onGround = false;
    me.setYRot(me.getYRot());
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y + 0.42, me.z, me.getYRot(), 0f, false));
  }
}