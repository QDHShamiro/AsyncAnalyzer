"""
AsyncAnalyzer ML — build the labelled training set.

Negative class (label 0):
  * REAL library jars pulled from Maven Central. These include the exact
    "scary but clean" libraries the old detector false-flagged: ASM,
    ByteBuddy, Javassist, Gson, Netty, Kotlin, log4j. Their real feature
    vectors teach the model that reflection / bytecode-manipulation /
    short obfuscated class names / high entropy are NOT by themselves cheats.
  * Synthetic legit profiles (anticheat mods full of detection names,
    verified mods, http update-checkers, proguarded libs).

Positive class (label 1):
  * Synthetic cheat profiles derived from documented cheat behaviour
    (Doomsday/chainlibs, combat clients, obfuscated/renamed cheats, token
    grabbers, injectors, filename-clients, hollow-shell droppers). We do NOT
    download or ship real cheat jars.

Output: ml/dataset.csv  (columns = FEATURE_NAMES + label + source)
Re-run any time with real samples added under ml/jars_legit to improve it.
"""

import csv
import os
import random
import subprocess
import sys

import features
from features import FEATURE_NAMES, raw_to_vector, extract_from_jar

HERE = os.path.dirname(os.path.abspath(__file__))
JARS = os.path.join(HERE, "jars_legit")
CA = "/root/.ccr/ca-bundle.crt"
random.seed(1337)

# group, artifact, version  ->  Maven Central coordinate
MAVEN = [
    ("net.kyori", "adventure-api", "4.17.0"),
    ("net.kyori", "adventure-nbt", "4.17.0"),
    ("org.ow2.asm", "asm", "9.7"),
    ("org.ow2.asm", "asm-tree", "9.7"),
    ("org.ow2.asm", "asm-commons", "9.7"),
    ("it.unimi.dsi", "fastutil", "8.5.13"),
    ("io.netty", "netty-common", "4.1.108.Final"),
    ("io.netty", "netty-buffer", "4.1.108.Final"),
    ("org.jetbrains.kotlin", "kotlin-stdlib", "1.9.23"),
    ("com.google.code.gson", "gson", "2.10.1"),
    ("com.google.guava", "guava", "33.0.0-jre"),
    ("org.apache.logging.log4j", "log4j-core", "2.23.1"),
    ("net.bytebuddy", "byte-buddy", "1.14.12"),
    ("org.javassist", "javassist", "3.30.2-GA"),
    ("com.zaxxer", "HikariCP", "5.1.0"),
    ("com.github.ben-manes.caffeine", "caffeine", "3.1.8"),
    ("org.yaml", "snakeyaml", "2.2"),
    ("com.fasterxml.jackson.core", "jackson-databind", "2.17.0"),
    ("org.apache.commons", "commons-lang3", "3.14.0"),
    ("commons-io", "commons-io", "2.16.1"),
    ("org.slf4j", "slf4j-api", "2.0.13"),
    ("org.apache.commons", "commons-compress", "1.26.1"),
    # more real Minecraft-ecosystem libraries that mods bundle (stronger negatives)
    ("org.apache.commons", "commons-text", "1.11.0"),
    ("org.apache.commons", "commons-collections4", "4.4"),
    ("com.electronwill.night-config", "core", "3.6.7"),
    ("com.electronwill.night-config", "toml", "3.6.7"),
    ("org.ow2.asm", "asm-util", "9.7"),
    ("org.ow2.asm", "asm-analysis", "9.7"),
    ("io.netty", "netty-codec", "4.1.108.Final"),
    ("io.netty", "netty-handler", "4.1.108.Final"),
    ("io.netty", "netty-transport", "4.1.108.Final"),
    ("net.sf.jopt-simple", "jopt-simple", "5.0.4"),
    ("org.jline", "jline", "3.25.1"),
    ("com.fasterxml.jackson.core", "jackson-core", "2.17.0"),
    ("com.fasterxml.jackson.core", "jackson-annotations", "2.17.0"),
    ("org.checkerframework", "checker-qual", "3.42.0"),
    ("com.mojang", "brigadier", "1.0.18"),
]


def download(group, artifact, version):
    path = os.path.join(JARS, f"{artifact}-{version}.jar")
    if os.path.exists(path) and os.path.getsize(path) > 1000:
        return path
    url = "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (
        group.replace(".", "/"), artifact, version, artifact, version)
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", "60", "--cacert", CA, "-o", path, url],
            capture_output=True, timeout=90)
        if r.returncode == 0 and os.path.exists(path) and os.path.getsize(path) > 1000:
            return path
    except Exception as e:
        print("  ! download failed", artifact, e, file=sys.stderr)
    return None


def jitter(v, lo=0.0, hi=1.0, sd=0.06):
    return max(lo, min(hi, v + random.gauss(0, sd)))


def zeros():
    return {k: 0 for k in (
        "pkgpath", "cheatsite", "strong_count", "weak_count", "fullwidth_str",
        "fullwidth_cls_pct", "japanese_cls_pct", "singlechar_cls_pct",
        "numeric_cls_pct", "novowel_cls_pct", "avg_entropy", "high_entropy_pct",
        "reflection_count", "runtime_exec", "http_download", "http_exfil",
        "nested_hollow", "fake_identity", "filename_client", "random_name",
        "verified", "legit_modid")}


def synth(profile):
    r = zeros()
    r.update(profile)
    # add realistic noise to the ratio-style features
    for k in ("fullwidth_cls_pct", "japanese_cls_pct", "singlechar_cls_pct",
              "numeric_cls_pct", "novowel_cls_pct", "high_entropy_pct"):
        r[k] = round(jitter(r[k]), 3)
    r["avg_entropy"] = round(jitter(r["avg_entropy"] / 8.0) * 8.0, 3)
    return r


# ---- synthetic profile generators (mean values; jitter added per-sample) ----
def pos_profiles():
    return [
        # Doomsday / chainlibs obfuscated crystal client
        dict(pkgpath=1, strong_count=4, weak_count=3, singlechar_cls_pct=0.35,
             numeric_cls_pct=0.15, high_entropy_pct=0.35, avg_entropy=6.9,
             reflection_count=3, fullwidth_str=1, japanese_cls_pct=0.08),
        # combat client with package path (liquidbounce-like)
        dict(pkgpath=1, strong_count=5, weak_count=4, reflection_count=4,
             avg_entropy=6.2, high_entropy_pct=0.15, singlechar_cls_pct=0.2),
        # renamed / obfuscated cheat, no package path
        dict(strong_count=3, weak_count=3, singlechar_cls_pct=0.6,
             numeric_cls_pct=0.4, novowel_cls_pct=0.3, high_entropy_pct=0.5,
             avg_entropy=7.1, fullwidth_cls_pct=0.2),
        # token grabber
        dict(http_exfil=1, runtime_exec=1, weak_count=6, strong_count=1,
             high_entropy_pct=0.5, avg_entropy=7.0, reflection_count=2),
        # injector jar
        dict(runtime_exec=1, http_download=1, singlechar_cls_pct=0.5,
             high_entropy_pct=0.4, avg_entropy=6.8, reflection_count=3,
             strong_count=2),
        # filename-client cheat (name gives it away)
        dict(filename_client=1, strong_count=3, weak_count=2,
             reflection_count=2, avg_entropy=6.0),
        # cheat from a known cheat site
        dict(cheatsite=1, strong_count=3, weak_count=2, singlechar_cls_pct=0.3,
             high_entropy_pct=0.25, avg_entropy=6.5),
        # fake-identity cheat (pretends to be sodium)
        dict(fake_identity=1, strong_count=2, http_download=1,
             singlechar_cls_pct=0.3, avg_entropy=6.4, reflection_count=2),
        # hollow-shell dropper
        dict(nested_hollow=1, http_download=1, weak_count=2, avg_entropy=6.6),
        # heavily obfuscated fullwidth/japanese cheat
        dict(strong_count=3, fullwidth_cls_pct=0.4, japanese_cls_pct=0.3,
             fullwidth_str=1, singlechar_cls_pct=0.4, high_entropy_pct=0.4,
             avg_entropy=7.0),
    ]


def neg_profiles():
    return [
        # anticheat mod — FULL of detection-name strings but legit
        dict(strong_count=5, weak_count=5, legit_modid=1, reflection_count=3,
             avg_entropy=6.0, high_entropy_pct=0.1),
        # anticheat, verified on modrinth
        dict(strong_count=4, weak_count=4, verified=1, reflection_count=2,
             avg_entropy=5.9),
        # optimization mod, verified (sodium-like)
        dict(verified=1, reflection_count=3, singlechar_cls_pct=0.15,
             avg_entropy=6.3, high_entropy_pct=0.08),
        # http update-checker mod, verified
        dict(verified=1, http_download=1, reflection_count=2, avg_entropy=5.8),
        # reflection-heavy library (gson/jackson), clean, not verified
        dict(reflection_count=6, avg_entropy=5.7, high_entropy_pct=0.05),
        # proguarded legit library (short names, high entropy), clean
        dict(singlechar_cls_pct=0.45, novowel_cls_pct=0.3, numeric_cls_pct=0.05,
             high_entropy_pct=0.25, avg_entropy=6.7, reflection_count=2),
        # plain small mod, verified, boring
        dict(verified=1, avg_entropy=5.5, reflection_count=1),
        # bytecode lib bundled in a mod (bytebuddy/asm), clean
        dict(reflection_count=6, singlechar_cls_pct=0.25, avg_entropy=6.1,
             legit_modid=0),
        # I/O library (commons-io style): does HTTP + file streams, clean
        dict(http_download=1, http_exfil=1, reflection_count=1, weak_count=1,
             avg_entropy=6.5, high_entropy_pct=0.02),
        # runtime/cache library (caffeine/netty style): calls exec, clean
        dict(runtime_exec=1, reflection_count=1, novowel_cls_pct=0.2,
             avg_entropy=6.6, high_entropy_pct=0.05),
        # verified mod that pulls resources over HTTP at runtime
        dict(verified=1, http_download=1, http_exfil=1, runtime_exec=1,
             reflection_count=2, avg_entropy=5.9),
    ]


def main():
    os.makedirs(JARS, exist_ok=True)
    rows = []

    print("[1/3] Downloading real library jars from Maven Central...")
    real = 0
    for g, a, v in MAVEN:
        p = download(g, a, v)
        if not p:
            print("   skip", a, v)
            continue
        raw = extract_from_jar(p, verified=0, legit_modid=0)
        # weight real, known-clean jars heavily (they are the FP traps)
        rows.append((raw_to_vector(raw), 0, f"real:{a}"))
        rows.append((raw_to_vector(raw), 0, f"real:{a}"))
        rows.append((raw_to_vector(raw), 0, f"real:{a}"))
        real += 1
        # augment: same content, but as if it were a verified mod
        raw2 = dict(raw)
        raw2["verified"] = 1
        rows.append((raw_to_vector(raw2), 0, f"real+verified:{a}"))
        print("   ok  ", a, "->",
              " ".join(f"{n}={x:.2f}" for n, x in zip(FEATURE_NAMES, raw_to_vector(raw)) if x))
    print(f"   {real} real jars extracted")

    print("[2/3] Generating synthetic profiles...")
    for prof in pos_profiles():
        for _ in range(14):
            rows.append((raw_to_vector(synth(prof)), 1, "synth:cheat"))
    for prof in neg_profiles():
        for _ in range(14):
            rows.append((raw_to_vector(synth(prof)), 0, "synth:legit"))

    npos = sum(1 for _, y, _ in rows if y == 1)
    nneg = sum(1 for _, y, _ in rows if y == 0)
    print(f"   total {len(rows)} rows  (cheat={npos}  legit={nneg})")

    print("[3/3] Writing dataset.csv...")
    out = os.path.join(HERE, "dataset.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(FEATURE_NAMES + ["label", "source"])
        for vec, y, src in rows:
            w.writerow([round(x, 4) for x in vec] + [y, src])
    print("   wrote", out)


if __name__ == "__main__":
    main()
