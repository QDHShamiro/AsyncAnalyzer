package cheat;
import net.minecraft.launchwrapper.IClassTransformer;

// A coremod cheat. It calls nothing: a class transformer is handed every class
// name the game loads and decides what to rewrite by COMPARING that name against
// string constants. So the class it attacks - and the packet it makes that class
// send - are strings, and never reach the symbol table at all. Third door into the
// game's code after reflection and Mixin, same key.
public class CoreModAura implements IClassTransformer {
  private byte[] patch(byte[] b) { return b; }

  public byte[] transform(String name, String transformedName, byte[] basicClass) {
    if ("net.minecraft.client.entity.EntityPlayerSP".equals(transformedName)) {
      // rewrite the movement packet write so the rotation sent is not the one shown
      String target = "C03PacketPlayer";
      String field = "rotationYaw";
      if (target.length() + field.length() > 0) return patch(basicClass);
    }
    return basicClass;
  }
}
