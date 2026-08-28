package clean;
import mc.MC18;

// A 1.8.9 sprint / toggle mod: reads the key, moves the player through the game's
// own fields, and never touches the movement packet. That is the line between
// automating the game and lying to the server, in 1.8's names.
public class Legacy18Sprint {
  private MC18.EntityPlayerSP me;
  private MC18.KeyBinding bind;
  private int held;

  public void onTick() {
    if (bind.isKeyDown()) { held++; me.motionX *= 1.02; } else { held = 0; }
  }
}
