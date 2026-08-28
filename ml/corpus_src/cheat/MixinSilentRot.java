package cheat;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.Inject;

// Silent rotations, written the way cheats actually write them now.
//
// This class calls NOTHING. It does not import mc.MC, it constructs no packet and
// it invokes no setter, so its symbol table is empty of Minecraft. What it does is
// get compiled into the packet that reports where you are looking, and overwrite
// that packet's rotation fields on the way out. Your view never turns; the server
// is told it did.
//
// Read through the symbol table alone this is a class with two floats in it.
@Mixin(targets = "net.minecraft.network.protocol.game.ServerboundMovePlayerPacket")
public class MixinSilentRot {
  @Shadow private float yRot;
  @Shadow private float xRot;
  private float aimYaw, aimPitch;

  @Inject(method = "<init>", at = "TAIL")
  public void spoof() {
    this.yRot = aimYaw;
    this.xRot = aimPitch;
  }
}
