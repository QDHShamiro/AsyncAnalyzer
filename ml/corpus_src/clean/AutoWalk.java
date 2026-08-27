package clean;
import mc.MC;
// A legitimate auto-walk / afk mod: it holds the movement key through the game's own
// input system. No rotation is forged and no packet is written by hand, so the game
// produces the movement itself. Behaviourally this is what separates it from Pathing.
public class AutoWalk {
  private MC.KeyMapping forward; private int held;
  public void tick() { if (forward.isPressed()) held++; else held = 0; }
  public boolean isWalking() { return held > 0; }
}
