package clean;
import mc.MC;
public class Minimap9 {
  private MC.Level level; private MC.VertexConsumer buf; private MC.PoseStack stack;
  public void drawMap() {
    MC.RenderSystem.setShader(); stack.pushPose();
    for (int x = 0; x < 16; x++) for (int z = 0; z < 16; z++) {
      Object st = level.getBlockState(x, 64, z);
      if (st != null) buf.vertex(x, 64, z);
    }
    stack.popPose();
  }
}