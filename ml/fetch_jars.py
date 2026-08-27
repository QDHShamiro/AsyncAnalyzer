"""Download real library jars from Maven Central as the CLEAN class.

Real bytecode only - these are the "scary but legitimate" libraries a naive
scanner false-flags: bytecode manipulators, reflection frameworks, networking,
crypto, class loaders. If the detector stays quiet on these it will stay quiet
on real mods.
"""
import os, sys, urllib.request

BASE = "https://repo1.maven.org/maven2"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jars_legit")

LIBS = [
 # bytecode / reflection / codegen - the classic false-flag family
 ("org/ow2/asm","asm","9.7"),("org/ow2/asm","asm-tree","9.7"),("org/ow2/asm","asm-commons","9.7"),
 ("org/ow2/asm","asm-analysis","9.7"),("org/ow2/asm","asm-util","9.7"),
 ("net/bytebuddy","byte-buddy","1.14.12"),("net/bytebuddy","byte-buddy-agent","1.14.12"),
 ("org/javassist","javassist","3.30.2-GA"),("cglib","cglib","3.3.0"),
 ("org/objenesis","objenesis","3.3"),("org/reflections","reflections","0.10.2"),
 ("com/esotericsoftware","reflectasm","1.11.9"),
 # serialization / data
 ("com/google/code/gson","gson","2.10.1"),("com/fasterxml/jackson/core","jackson-databind","2.17.0"),
 ("com/fasterxml/jackson/core","jackson-core","2.17.0"),("com/fasterxml/jackson/core","jackson-annotations","2.17.0"),
 ("org/yaml","snakeyaml","2.2"),("com/moandjiezana/toml","toml4j","0.7.2"),
 ("com/electronwill/night-config","core","3.6.7"),("com/electronwill/night-config","toml","3.6.7"),
 ("org/json","json","20240303"),("com/esotericsoftware","kryo","5.6.0"),
 # networking - crypto + sockets, must not look like exfiltration
 ("io/netty","netty-all","4.1.108.Final"),("io/netty","netty-handler","4.1.108.Final"),
 ("io/netty","netty-buffer","4.1.108.Final"),("io/netty","netty-codec","4.1.108.Final"),
 ("io/netty","netty-transport","4.1.108.Final"),("io/netty","netty-common","4.1.108.Final"),
 ("com/squareup/okhttp3","okhttp","4.12.0"),("org/apache/httpcomponents","httpclient","4.5.14"),
 ("org/apache/httpcomponents","httpcore","4.4.16"),
 # logging
 ("org/apache/logging/log4j","log4j-core","2.23.1"),("org/apache/logging/log4j","log4j-api","2.23.1"),
 ("org/slf4j","slf4j-api","2.0.13"),("ch/qos/logback","logback-classic","1.5.6"),
 ("ch/qos/logback","logback-core","1.5.6"),
 # minecraft ecosystem
 ("com/mojang","brigadier","1.0.18"),("com/mojang","datafixerupper","8.0.16"),
 ("com/mojang","authlib","6.0.54"),("com/mojang","logging","1.2.7"),
 # kotlin / language runtimes
 ("org/jetbrains/kotlin","kotlin-stdlib","1.9.23"),("org/jetbrains/kotlin","kotlin-reflect","1.9.23"),
 ("org/jetbrains","annotations","24.1.0"),("org/scala-lang","scala-library","2.13.13"),
 # guava / commons / utils
 ("com/google/guava","guava","33.0.0-jre"),("org/apache/commons","commons-lang3","3.14.0"),
 ("org/apache/commons","commons-compress","1.26.1"),("commons-io","commons-io","2.16.1"),
 ("org/apache/commons","commons-text","1.11.0"),("commons-codec","commons-codec","1.16.1"),
 ("org/apache/commons","commons-math3","3.6.1"),("commons-cli","commons-cli","1.6.0"),
 # db / pooling / crypto-adjacent
 ("com/zaxxer","HikariCP","5.1.0"),("org/xerial","sqlite-jdbc","3.45.3.0"),
 ("mysql","mysql-connector-java","8.0.33"),("org/bouncycastle","bcprov-jdk18on","1.78"),
 ("org/bouncycastle","bcpkix-jdk18on","1.78"),
 # di / bytecode-heavy frameworks
 ("com/google/inject","guice","7.0.0"),("org/apache/maven","maven-model","3.9.6"),
 ("org/ow2/asm","asm-tree","9.6"),("io/projectreactor","reactor-core","3.6.5"),
 ("org/immutables","value","2.10.1"),
 # testing / instrumentation (agents! must not be confused with cheat agents)
 ("org/mockito","mockito-core","5.11.0"),("org/junit/jupiter","junit-jupiter-api","5.10.2"),
 ("org/jacoco","org.jacoco.agent","0.8.12"),("net/bytebuddy","byte-buddy-dep","1.14.12"),
 # adventure / text (minecraft server side)
 ("net/kyori","adventure-api","4.17.0"),("net/kyori","adventure-nbt","4.17.0"),
 ("net/kyori","examination-api","1.3.0"),("net/kyori","adventure-key","4.17.0"),
 # caching / concurrency
 ("com/github/ben-manes/caffeine","caffeine","3.1.8"),("org/jctools","jctools-core","4.0.3"),
 ("io/reactivex/rxjava3","rxjava","3.1.8"),
 # compression / io
 ("org/lz4","lz4-java","1.8.0"),("com/github/luben","zstd-jni","1.5.6-3"),
 ("org/tukaani","xz","1.9"),
 # --- second wave: more of the families that look alarming but are ordinary ---
 # agents + instrumentation (these genuinely ship Premain-Class)
 ("org/aspectj","aspectjweaver","1.9.22"),("org/aspectj","aspectjrt","1.9.22"),
 ("io/opentelemetry/javaagent","opentelemetry-javaagent","2.4.0"),
 ("org/springframework","spring-instrument","6.1.6"),
 # class generation / proxies
 ("org/springframework","spring-core","6.1.6"),("org/springframework","spring-beans","6.1.6"),
 ("org/springframework","spring-context","6.1.6"),("org/springframework","spring-aop","6.1.6"),
 ("org/apache/groovy","groovy","4.0.21"),("org/codehaus/janino","janino","3.1.12"),
 ("org/codehaus/janino","commons-compiler","3.1.12"),
 # crypto-heavy
 ("org/bouncycastle","bcutil-jdk18on","1.78"),("com/nimbusds","nimbus-jose-jwt","9.37.3"),
 ("io/jsonwebtoken","jjwt-impl","0.12.5"),("org/apache/santuario","xmlsec","4.0.2"),
 # networking / protocol
 ("io/netty","netty-codec-http","4.1.108.Final"),("io/netty","netty-resolver","4.1.108.Final"),
 ("io/grpc","grpc-core","1.63.0"),("org/eclipse/jetty","jetty-server","11.0.20"),
 ("org/eclipse/jetty","jetty-util","11.0.20"),("com/squareup/okio","okio-jvm","3.9.0"),
 ("org/java-websocket","Java-WebSocket","1.5.6"),
 # serialization / scripting (dynamic class loading is normal here)
 ("org/mozilla","rhino","1.7.14"),("org/luaj","luaj-jse","3.0.1"),
 ("com/fasterxml/jackson/dataformat","jackson-dataformat-yaml","2.17.0"),
 ("org/msgpack","msgpack-core","0.9.8"),
 # data / db
 ("org/postgresql","postgresql","42.7.3"),("com/h2database","h2","2.2.224"),
 ("org/mongodb","mongodb-driver-core","5.0.1"),("redis/clients","jedis","5.1.2"),
 ("org/mariadb/jdbc","mariadb-java-client","3.3.3"),
 # utility / collections
 ("it/unimi/dsi","fastutil","8.5.13"),("org/apache/commons","commons-collections4","4.4"),
 ("com/google/protobuf","protobuf-java","4.26.1"),("org/checkerframework","checker-qual","3.42.0"),
 ("com/google/errorprone","error_prone_annotations","2.27.0"),
 ("org/apache/commons","commons-pool2","2.12.0"),("joda-time","joda-time","2.12.7"),
 # graphics / native binding (LWJGL is what Minecraft itself uses for input + GL)
 ("org/lwjgl","lwjgl","3.3.3"),("org/lwjgl","lwjgl-glfw","3.3.3"),
 ("org/lwjgl","lwjgl-opengl","3.3.3"),("org/lwjgl","lwjgl-stb","3.3.3"),
 ("net/java/dev/jna","jna","5.14.0"),("net/java/dev/jna","jna-platform","5.14.0"),
 # build / analysis tooling
 ("org/apache/maven","maven-core","3.9.6"),("org/ow2/asm","asm-tree","9.7"),
 ("com/puppycrawl/tools","checkstyle","10.15.0"),("com/github/spotbugs","spotbugs","4.8.4"),
 ("org/pitest","pitest","1.16.1"),
 # --- third wave: breadth, because a false-flag count of 0 means more the bigger
 #     the negative corpus is ---
 ("org/apache/logging/log4j","log4j-slf4j2-impl","2.23.1"),("org/slf4j","jul-to-slf4j","2.0.13"),
 ("org/apache/commons","commons-configuration2","2.10.1"),("commons-beanutils","commons-beanutils","1.9.4"),
 ("org/apache/commons","commons-csv","1.11.0"),("org/apache/commons","commons-exec","1.4.0"),
 ("com/google/code/findbugs","jsr305","3.0.2"),("org/jetbrains/kotlinx","kotlinx-coroutines-core-jvm","1.8.0"),
 ("org/jetbrains/kotlin","kotlin-stdlib-jdk8","1.9.23"),("io/github/classgraph","classgraph","4.8.172"),
 ("org/apache/xbean","xbean-reflect","4.24"),("cglib","cglib-nodep","3.3.0"),
 ("org/springframework","spring-expression","6.1.6"),("org/springframework","spring-web","6.1.6"),
 ("org/springframework","spring-jdbc","6.1.6"),("org/hibernate/orm","hibernate-core","6.4.4.Final"),
 ("jakarta/persistence","jakarta.persistence-api","3.1.0"),
 ("org/eclipse/jetty","jetty-http","11.0.20"),("org/eclipse/jetty","jetty-io","11.0.20"),
 ("io/netty","netty-codec-http2","4.1.108.Final"),
 ("io/grpc","grpc-api","1.63.0"),("io/grpc","grpc-netty","1.63.0"),
 ("org/apache/kafka","kafka-clients","3.7.0"),("org/apache/zookeeper","zookeeper","3.9.2"),
 ("io/lettuce","lettuce-core","6.3.2.RELEASE"),("com/rabbitmq","amqp-client","5.21.0"),
 ("org/quartz-scheduler","quartz","2.5.0"),("com/cronutils","cron-utils","9.2.1"),
 ("org/apache/velocity","velocity-engine-core","2.3"),("org/freemarker","freemarker","2.3.32"),
 ("org/thymeleaf","thymeleaf","3.1.2.RELEASE"),("org/jsoup","jsoup","1.17.2"),
 ("org/apache/pdfbox","pdfbox","3.0.2"),("org/apache/poi","poi","5.2.5"),
 ("org/apache/tika","tika-core","2.9.2"),("com/opencsv","opencsv","5.9"),
 ("org/imgscalr","imgscalr-lib","4.2"),("com/twelvemonkeys/imageio","imageio-core","3.10.1"),
 ("org/openjdk/jmh","jmh-core","1.37"),("org/openjdk/jol","jol-core","0.17"),
 ("org/assertj","assertj-core","3.25.3"),("org/hamcrest","hamcrest","2.2"),
 ("net/jqwik","jqwik","1.8.4"),("org/testcontainers","testcontainers","1.19.7"),
 ("io/rest-assured","rest-assured","5.4.0"),("org/wiremock","wiremock","3.5.2"),
 ("org/xerial/snappy","snappy-java","1.1.10.5"),("org/brotli","dec","0.1.2"),
 ("com/auth0","java-jwt","4.4.0"),("org/keycloak","keycloak-core","24.0.3"),
 ("org/apache/mina","mina-core","2.2.3"),
 ("com/github/oshi","oshi-core","6.6.0"),("org/openjdk/nashorn","nashorn-core","15.4"),
 ("info/picocli","picocli","4.7.5"),("com/beust","jcommander","1.82"),
 ("org/apache/ant","ant","1.10.14"),("org/codehaus/plexus","plexus-utils","4.0.1"),
]

def fetch(g, a, v):
    p = os.path.join(OUT, "%s-%s.jar" % (a, v))
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        return "cached"
    url = "%s/%s/%s/%s/%s-%s.jar" % (BASE, g, a, v, a, v)
    try:
        with urllib.request.urlopen(url, timeout=45) as r:
            data = r.read()
        if len(data) < 1000:
            return "tiny"
        open(p, "wb").write(data)
        return "ok"
    except Exception as e:
        return "fail(%s)" % str(e)[:30]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    ok = cached = fail = 0
    for g, a, v in LIBS:
        s = fetch(g, a, v)
        if s == "ok": ok += 1
        elif s == "cached": cached += 1
        else:
            fail += 1
            print("  ", a, v, s)
    print("downloaded=%d cached=%d failed=%d  total jars=%d" % (
        ok, cached, fail, len([f for f in os.listdir(OUT) if f.endswith('.jar')])))
