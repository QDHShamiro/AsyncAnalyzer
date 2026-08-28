package clean;

import java.io.File;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;

// Mixin's own RuntimeDecompiler, reduced to the two things that matter.
//
// This is not a hypothetical: sponge-mixin - the framework nearly every Minecraft
// mod is built on - came out of the scan as "a jar that deletes itself", and the
// reason was a regex, not a judgement call. The class resolves its own CodeSource
// (to find the jar whose classes it is decompiling) and clears its debug output
// directory through Guava's MoreFiles.deleteRecursively. The literal string
// "Files.delete" is a SUBSTRING of "MoreFiles.deleteRecursively", so an unanchored
// pattern read a Guava helper as java.nio.file.Files.
//
// It never showed up locally because sponge-mixin only exists on maven.fabricmc.net,
// which is unreachable from the machine this was written on. CI could download it
// and did. This file is the part of that jar that mattered, kept as source so the
// case survives without the download.
//
// If this file is ever flagged, the anchoring in bc_filedelete has come undone.
public class DebugDecompiler {

  // Stands in for com.google.common.io.MoreFiles, which is what Mixin actually
  // shades. The point is the class NAME: a constant-pool reference to
  // "clean/MoreFiles.deleteRecursively" contains "Files.delete" and must not
  // count as one.
  static final class MoreFiles {
    static void deleteRecursively(Path p) { }
  }

  public Path outputPath() throws Exception {
    ProtectionDomain pd = DebugDecompiler.class.getProtectionDomain();
    CodeSource cs = pd.getCodeSource();
    File here = new File(cs.getLocation().toURI());
    return here.getParentFile().toPath().resolve("mixin.debug.out");
  }

  public void clean() throws Exception {
    MoreFiles.deleteRecursively(outputPath());
  }
}
