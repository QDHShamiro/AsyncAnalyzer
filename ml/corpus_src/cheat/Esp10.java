package cheat;
import mc.MC;
public class Esp10 {
  private MC.Level level; private MC.VertexConsumer buf; private MC.PoseStack stack;
  public void render() {
    MC.RenderSystem.setShader(); stack.pushPose();
    for (MC.Entity e : level.entitiesForRendering()) {
      buf.vertex(e.x, e.y, e.z).vertex(e.x+1, e.y+2, e.z+1);
    }
    stack.popPose();
  }
}