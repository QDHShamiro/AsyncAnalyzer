package clean;
import net.minecraft.launchwrapper.IClassTransformer;

// An ordinary Forge coremod: a performance mod rewriting the chunk renderer. Same
// mechanism as the cheat above and the same power, which is exactly why the
// mechanism cannot be the finding - what it rewrites is.
public class CoreModPerf implements IClassTransformer {
  private byte[] patch(byte[] b) { return b; }

  public byte[] transform(String name, String transformedName, byte[] basicClass) {
    if ("net.minecraft.client.renderer.chunk.RenderChunk".equals(transformedName)) {
      return patch(basicClass);
    }
    if ("net.minecraft.client.gui.GuiIngame".equals(transformedName)) {
      return patch(basicClass);
    }
    return basicClass;
  }
}
