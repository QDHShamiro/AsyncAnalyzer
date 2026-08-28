package clean;
import mc.MC18;

// A 1.8.9 minimap with a mob radar. Reads the same entity list the aura does and
// renders from it - the ESP/radar ambiguity, in 1.8's names this time. Must come
// out as a server-rule finding, never as an accusation, exactly like the 1.13+ one.
public class Legacy18Minimap {
  private MC18.WorldClient world;
  private MC18.WorldRenderer buf;

  public void drawMap() {
    MC18.GlStateManager.pushMatrix();
    for (MC18.Entity e : world.loadedEntityList) buf.pos(e.posX, e.posY, e.posZ);
    for (int x = 0; x < 16; x++) if (world.getBlockState(x, 64, 0) != null) buf.pos(x, 64, 0);
    MC18.GlStateManager.popMatrix();
  }
}
