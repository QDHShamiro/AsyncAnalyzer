package clean;
import mc.MC;
// The other half: writes rotation on an unrelated entity (a look-at helper for
// a screenshot / cinematic mod) and never touches a movement packet.
public class ScatteredMoveB {
  public void lookAt(MC.Entity target, float yaw, float pitch) {
    target.setYRot(yaw); target.setXRot(pitch);
  }
}
