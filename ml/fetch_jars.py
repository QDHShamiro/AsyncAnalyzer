"""Download real library jars from Maven Central as the CLEAN class.

Real bytecode only - these are the "scary but legitimate" libraries a naive
scanner false-flags: bytecode manipulators, reflection frameworks, networking,
crypto, class loaders. If the detector stays quiet on these it will stay quiet
on real mods.
"""
import os, sys, urllib.request, zipfile

BASE = "https://repo1.maven.org/maven2"

# Mojang, Sponge and Fabric publish to their own repositories, not to Maven
# Central. An entry may name one with a 4th element; everything else defaults to
# Central. These are the closest thing to a real Minecraft mod that is publicly
# downloadable - Mixin in particular is the framework nearly every mod is built on
# AND it rewrites bytecode for a living, so if instrumentation detection is ever
# going to false-flag something, it flags that first.
REPOS = {
    "mojang": "https://libraries.minecraft.net",
    "sponge": "https://repo.spongepowered.org/repository/maven-public",
    "fabric": "https://maven.fabricmc.net",
}
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
 ("io/netty","netty-handler","4.1.108.Final"),
 ("io/netty","netty-buffer","4.1.108.Final"),("io/netty","netty-codec","4.1.108.Final"),
 ("io/netty","netty-transport","4.1.108.Final"),("io/netty","netty-common","4.1.108.Final"),
 ("com/squareup/okhttp3","okhttp","4.12.0"),("org/apache/httpcomponents","httpclient","4.5.14"),
 ("org/apache/httpcomponents","httpcore","4.4.16"),
 # logging
 ("org/apache/logging/log4j","log4j-core","2.23.1"),("org/apache/logging/log4j","log4j-api","2.23.1"),
 ("org/slf4j","slf4j-api","2.0.13"),("ch/qos/logback","logback-classic","1.5.6"),
 ("ch/qos/logback","logback-core","1.5.6"),
 # minecraft ecosystem. These come from Mojang's, Sponge's and Fabric's own
 # repositories, not Maven Central. This sandbox's network policy blocks all
 # three, so they only resolve in CI - which is why the fetcher reports what it
 # could not get rather than assuming a coordinate is right because it looks it.
 ("com/mojang","brigadier","1.0.18","mojang"),
 ("com/mojang","datafixerupper","8.0.16","mojang"),
 ("com/mojang","authlib","6.0.54","mojang"),("com/mojang","logging","1.2.7","mojang"),
 ("com/mojang","blocklist","1.0.10","mojang"),("com/mojang","patchy","2.2.10","mojang"),
 ("com/mojang","text2speech","1.17.9","mojang"),
 # Mixin: the framework nearly every mod is built on, and it rewrites bytecode for
 # a living - the single most valuable negative in this list. It is NOT on Maven
 # Central (probed: 404), only on Sponge's own repository, whose layout could not be
 # verified from the sandbox and which two guesses failed to hit. Fabric ships a
 # fork of it on the repository CI already fetches access-widener and mapping-io
 # from, so that is the grounded attempt rather than a third guess at Sponge's path.
 # If this one does not land either, leave it: the fetcher reports it as missing,
 # 13 genuine instrumentation libraries are already in the corpus, and guessing
 # coordinates in a loop is not measurement.
 # Mixin is on Maven Central too, and that matters: fetched only from
 # maven.fabricmc.net it is missing on any machine that cannot reach that host,
 # and this is the ONE library a self-wipe or instrumentation rule is most
 # likely to false-flag. It did - see corpus_src/clean/DebugDecompiler.java -
 # and it was caught by CI rather than locally for exactly this reason.
 ("net/fabricmc","sponge-mixin","0.13.2+mixin.0.8.5"),
 ("net/fabricmc","tiny-mappings-parser","0.3.0+build.17","fabric"),
 ("net/fabricmc","tiny-remapper","0.8.6","fabric"),
 ("net/fabricmc","access-widener","2.1.0"),
 ("net/fabricmc","mapping-io","0.5.1"),
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
 ("com/mysql","mysql-connector-j","9.1.0"),("org/bouncycastle","bcprov-jdk18on","1.78"),
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
 ("io/github/classgraph","classgraph","4.8.172"),
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
 ("net/jqwik","jqwik-engine","1.10.1"),("org/testcontainers","testcontainers","1.19.7"),
 ("io/rest-assured","rest-assured","5.4.0"),("org/wiremock","wiremock","3.5.2"),
 ("org/xerial/snappy","snappy-java","1.1.10.5"),("org/brotli","dec","0.1.2"),
 ("com/auth0","java-jwt","4.4.0"),("org/keycloak","keycloak-core","24.0.3"),
 ("org/apache/mina","mina-core","2.2.3"),
 ("com/github/oshi","oshi-core","6.6.0"),("org/openjdk/nashorn","nashorn-core","15.4"),
 ("info/picocli","picocli","4.7.5"),("com/beust","jcommander","1.82"),
 ("org/apache/ant","ant","1.10.14"),("org/codehaus/plexus","plexus-utils","4.0.1"),
]

def usable(path):
    """A real library, not an error page or a POM-only aggregator.

    Both were sitting in the corpus and being counted: brigadier had saved a
    554-byte error response as a .jar, and netty-all is metadata with no classes
    in it. The benchmark headline is "0 false flags on N real libraries", so N has
    to mean N libraries.
    """
    try:
        if os.path.getsize(path) < 1000:
            return False
        with zipfile.ZipFile(path) as z:
            return any(n.endswith(".class") for n in z.namelist())
    except Exception:
        return False


def fetch(g, a, v, repo=None):
    p = os.path.join(OUT, "%s-%s.jar" % (a, v))
    if os.path.exists(p):
        if usable(p):
            return "cached"
        os.remove(p)          # error page or empty jar - do not leave it to be counted
    base = REPOS.get(repo, BASE)
    url = "%s/%s/%s/%s/%s-%s.jar" % (base, g, a, v, a, v)
    try:
        with urllib.request.urlopen(url, timeout=45) as r:
            data = r.read()
        open(p, "wb").write(data)
        if not usable(p):
            os.remove(p)
            return "not-a-library"
        return "ok"
    except Exception as e:
        return "fail(%s)" % str(e)[:30]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    ok = cached = fail = 0
    missing = []
    for entry in LIBS:
        g, a, v = entry[0], entry[1], entry[2]
        repo = entry[3] if len(entry) > 3 else None
        s = fetch(g, a, v, repo)
        if s == "ok": ok += 1
        elif s == "cached": cached += 1
        else:
            fail += 1
            missing.append("%s:%s (%s)" % (a, v, repo or "central"))
            print("  ", a, v, s)
    have = len([f for f in os.listdir(OUT) if f.endswith(".jar")])
    print("downloaded=%d cached=%d failed=%d  total jars=%d" % (ok, cached, fail, have))
    # Failures used to be printed and forgotten, so the declared list drifted away
    # from what is actually on disk - twelve libraries had silently stopped
    # downloading, and the corpus shrank without anything saying so.
    if missing:
        print("\nNOT IN THE CORPUS (%d of %d declared):" % (len(missing), len(LIBS)))
        for m in missing:
            print("   ", m)
        print("The benchmark counts what is on disk, so its numbers stay honest -")
        print("but these families are not being tested. Fix the coordinates or drop them.")
