package clean;

import java.io.File;
import java.nio.file.Files;

// The legitimate lookalike, and the reason the self-destruct rule was never
// scored: this also locates a path and deletes a file. LWJGL, SQLite's JDBC
// driver, JNA and half of the native-binding world do exactly this - unpack a
// .dll or .so out of the jar into a temp directory, load it, and clean up.
//
// What separates it from SelfWipe: it creates the file it deletes, in the temp
// directory, and it loads a native library. It never deletes the jar it came
// from. The rule excludes anything that unpacks natives for this reason, and if
// this file ever starts being flagged the exclusion has stopped working.
public class NativeUnpack {
  public void load() throws Exception {
    File tmp = File.createTempFile("lib", ".dll");
    Files.copy(NativeUnpack.class.getResourceAsStream("/native/lib.dll"), tmp.toPath());
    System.load(tmp.getAbsolutePath());
    tmp.deleteOnExit();
    Files.deleteIfExists(tmp.toPath());
  }
}
