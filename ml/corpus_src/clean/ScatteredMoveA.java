package clean;
import mc.MC;
// Half of the regression fixture for the same-class pairing rules (see
// bytecode.PAIR_DEFS / $script:bcPairDefs). This class forges a movement
// packet on its own - a lag-compensation resync utility - and never writes
// rotation. Bundled with ScatteredMoveB into one jar so the two behaviours
// exist in the SAME FILE but never the SAME CLASS, which is exactly the shape
// a real report (Feather, a Fabric utility client) scored Likely 60 by mistake.
public class ScatteredMoveA {
  private MC.ClientPacketListener net; private MC.LocalPlayer me;
  public void resync() {
    net.send(new MC.ServerboundMovePlayerPacket(me.x, me.y, me.z, me.getYRot(), 0f, me.onGround));
  }
}
