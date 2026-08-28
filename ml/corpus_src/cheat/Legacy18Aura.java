package cheat;
import mc.MC18;

// A 1.8.9 killaura, in 1.8.9's own names. Structurally identical to KillAura0 -
// pick a target out of the entity list, write the rotation, forge the movement
// packet - but every name it calls is an MCP name, and until those were added to
// the tables this class matched nothing at all.
public class Legacy18Aura {
  private MC18.NetHandlerPlayClient net;
  private MC18.PlayerControllerMP gm;
  private MC18.EntityPlayerSP me;
  private MC18.WorldClient world;
  private MC18.KeyBinding bind;

  public void onTick() {
    if (!bind.isKeyDown()) return;
    for (MC18.Entity t : world.loadedEntityList) {
      float yaw = (float) Math.atan2(t.posZ - me.posZ, t.posX - me.posX);
      float pitch = (float) Math.atan2(t.posY - me.posY, 1.0);
      me.rotationYaw = yaw;
      me.rotationPitch = pitch;
      net.addToSendQueue(new MC18.C03PacketPlayer(me.posX, me.posY, me.posZ, yaw, pitch, me.onGround));
      net.addToSendQueue(new MC18.C02PacketUseEntity(t));
      gm.attackEntity(me, t);
      me.swingItem();
    }
  }
}
