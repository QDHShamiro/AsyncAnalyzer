package cheat;
import mc.MC18;

// 1.8.9 flight / speed: write your own motion, then forge the packet to match.
public class Legacy18Fly {
  private MC18.NetHandlerPlayClient net;
  private MC18.EntityPlayerSP me;

  public void onTick() {
    me.motionY = 0.42;
    me.motionX *= 1.6;
    me.motionZ *= 1.6;
    me.onGround = false;
    net.addToSendQueue(new MC18.C03PacketPlayer(me.posX, me.posY + 0.42, me.posZ,
                                                me.rotationYaw, me.rotationPitch, false));
  }
}
