package clean;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
public class ConfigBinder3 {
  public void bind(Object target, java.util.Map<String,Object> cfg) throws Exception {
    for (Field f : target.getClass().getDeclaredFields()) {
      f.setAccessible(true);
      Object v = cfg.get(f.getName());
      if (v != null) f.set(target, v);
    }
    Method m = target.getClass().getDeclaredMethod("onLoad");
    m.setAccessible(true); m.invoke(target);
  }
}