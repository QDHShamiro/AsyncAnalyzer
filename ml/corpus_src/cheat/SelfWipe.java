package cheat;

import java.io.File;

// A mod that removes itself after it has run.
//
// There is no innocent version of this shape: the class asks the JVM where its
// OWN jar is (getProtectionDomain -> getCodeSource -> getLocation) and then
// deletes that exact file. A mod does not uninstall itself; a cheat that wants
// the mods folder to be empty by the time somebody looks does.
//
// It is the pattern the tool measured but refused to score, because the same two
// halves - "find a file path" and "delete a file" - also appear in libraries that
// unpack a native library to temp and clean it up afterwards. That is why
// NativeUnpack.java sits next to this one: the exclusion has to hold, or this
// rule accuses real code.
public class SelfWipe {
  public void onLoad() {
    try {
      File self = new File(SelfWipe.class.getProtectionDomain()
                             .getCodeSource().getLocation().toURI());
      // and it is gone before anyone opens the folder
      self.delete();
      self.deleteOnExit();
    } catch (Exception ignored) {
    }
  }
}
