package clean;
import mc.MC;
public class Keybinds0 {
  private MC.KeyMapping open; private MC.KeyMapping zoom;
  public void poll() { if (open.isPressed()) openGui(); if (zoom.isPressed()) setZoom(2.0); }
  private void openGui() {} private void setZoom(double d) {}
}