package net.minecraft.launchwrapper;

// The LaunchWrapper transformer interface, declared here rather than vendored.
// Same reasoning as the Mixin annotations and the MC stubs: what the detector
// reads is the constant pool, and javac writes the same interface reference for
// this as for the real one.
public interface IClassTransformer {
  byte[] transform(String name, String transformedName, byte[] basicClass);
}
