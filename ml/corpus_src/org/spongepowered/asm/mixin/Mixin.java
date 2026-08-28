package org.spongepowered.asm.mixin;
import java.lang.annotation.*;
// The Mixin annotations, declared in their real package. The Mixin library itself
// is not vendored here and is not needed: what the detector reads is the constant
// pool, and javac writes the same Utf8 constants for these as for the real ones -
// the descriptor Lorg/spongepowered/asm/mixin/Mixin; and the target as a string.
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
public @interface Mixin { String[] targets() default {}; }
