package clean;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.Inject;

// An ordinary mod, built the ordinary way. Mixins are not a cheat technique -
// Sodium, Lithium and the Fabric API are nothing but mixins - so this has to stay
// clean or reading mixins is worse than not reading them.
@Mixin(targets = "net.minecraft.client.renderer.LevelRenderer")
public class MixinRender {
  private int frames;

  @Inject(method = "renderLevel", at = "HEAD")
  public void onRender() { frames++; }
}
