package clean;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.Inject;

// The negative that the whole narrowing exists for.
//
// A freelook / perspective mod shadows exactly the same rotation fields the
// silent-rotation cheat does, and it renders. The one difference is its target:
// it mixes into the PLAYER, not into the outgoing movement packet. A camera has
// no reason to rewrite what the server is told you are aiming at, and a cheat
// that spoofs rotation has no other place to do it.
//
// If that distinction ever stops holding, this jar is what says so.
@Mixin(targets = "net.minecraft.client.player.LocalPlayer")
public class MixinFreelook {
  @Shadow private float yRot;
  @Shadow private float xRot;
  private float camYaw, camPitch;

  @Inject(method = "turn", at = "HEAD")
  public void freeLook() {
    camYaw = this.yRot;
    camPitch = this.xRot;
  }
}
