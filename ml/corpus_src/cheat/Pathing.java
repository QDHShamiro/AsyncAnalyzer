package cheat;
import mc.MC;
// Movement automation in the shape Baritone uses (@aa30ad7): it computes a heading,
// writes the rotation and then sends its OWN movement packet. The legit counterpart
// (clean/AutoWalk) drives the game's input system instead and never touches a packet -
// that is the line between automation and cheating, and it is visible in the bytecode.
public class Pathing {
  private MC.ClientPacketListener net; private MC.LocalPlayer me; private MC.Level level;
  public void step(double tx, double tz) {
    float yaw = (float)Math.atan2(tz - me.z, tx - me.x);
    me.setYRot(yaw); me.setXRot(0f);
    if (level.getBlockState((int)tx, (int)me.y, (int)tz) != null) me.onGround = true;
    net.send(new MC.ServerboundMovePlayerPacket(tx, me.y, tz, yaw, 0f, me.onGround));
  }
}
