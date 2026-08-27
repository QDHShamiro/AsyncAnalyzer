package cheat;
import mc.MC;
// Timer / velocity bypass: several movement packets per tick so the server sees more
// motion than the client actually performed.
public class Timer {
  private MC.ClientPacketListener net; private MC.LocalPlayer me;
  public void tick(int mult) {
    for (int i = 0; i < mult; i++) {
      me.setYRot(me.getYRot());
      net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, me.getYRot(), 0f, me.onGround));
    }
  }
}
