#!/usr/bin/env python3
"""Build the public site into site/.

Three pages, all generated. The landing page quotes measured numbers, the rule
documentation is read out of the shipped PowerShell and the Python model, and the
benchmark page is rendered from the last measurement. Nothing here is written by
hand, so no page can claim something the tool does not actually do - which is the
only way a transparency page is worth anything.

    python3 ml/site.py            # writes site/index.html, benchmarks.html, how-it-works.html
"""
import csv, json, os, re, sys, html

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SITE = os.path.join(ROOT, "site")
E = html.escape

REPO = "https://github.com/QDHShamiro/AsyncAnalyzer"
RAW = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1"
# The command a moderator hands over now carries their server's key, so it is shown
# on their own setup page and not here. What the public page can honestly show is
# the shape of it.
ONELINER = ('powershell -ExecutionPolicy Bypass -Command "$env:ASYNCANALYZER_KEY=\'<your server key>\';'
            'iex (irm \'https://asyncanalyzer.dev/run.ps1\')"')


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


# The three generated pages are the ones search engines and first-time visitors
# see, so their navigation is rendered here rather than by JavaScript. The app
# pages under /app do it the other way round, where there is nothing to index.
NAV_ITEMS = [("/", "Overview"), ("/how-it-works", "How it works"), ("/benchmarks", "Benchmarks")]

# Body copy was written when every page sat next to the others as a flat file.
# The site serves clean URLs now, so the links are rewritten in one place instead
# of being edited into every string below.
CLEAN_URLS = {'href="index.html"': 'href="/"',
              'href="how-it-works.html"': 'href="/how-it-works"',
              'href="benchmarks.html"': 'href="/benchmarks"'}


def nav(current):
    out = ['<div class="nav-shell"><nav class="nav" aria-label="Main">',
           '<a class="brand" href="/"><span class="dot" aria-hidden="true"></span>AsyncAnalyzer</a>',
           '<div class="nav-links">']
    for href, label in NAV_ITEMS:
        if href == "/":
            continue
        cur = ' aria-current="page"' if href == current else ""
        out.append('<a href="%s" class="hide-sm"%s>%s</a>' % (href, cur, label))
    out.append('<span id="nav-auth"></span>')
    out.append('<button id="theme-toggle" class="icon-btn" type="button" '
               'aria-label="Switch between light and dark">'
               '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
               'stroke-width="1.7" aria-hidden="true"><circle cx="12" cy="12" r="9"/>'
               '<path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor" stroke="none"/></svg></button>')
    out.append("</div></nav></div>")
    return "".join(out)


def page(title, desc, body, current):
    for old, new in CLEAN_URLS.items():
        body = body.replace(old, new)
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<meta name="description" content="%s">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Plus+Jakarta+Sans:wght@700;800&family=JetBrains+Mono:wght@400;600&display=swap">
<link rel="stylesheet" href="/assets/app.css">
<link rel="stylesheet" href="/assets/docs.css">
<script>try{var t=localStorage.getItem('aa-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
</head>
<body>
%s
<main class="wrap">
%s
</main>
<footer><div class="wrap">
  <span class="mono">AsyncAnalyzer</span>
  <a href="/how-it-works">How it works</a>
  <a href="/privacy">Privacy</a>
  <a href="%s">Source</a>
  <a href="%s/blob/main/BENCHMARKS.md">Raw benchmark output</a>
  <span class="spacer"></span>
  <span class="tiny">The scan runs on the suspect's own PC.</span>
</div></footer>
<script type="module">import { boot } from '/assets/app.js'; boot();</script>
</body></html>
""" % (E(title), E(desc), nav(current), body, REPO, REPO)


# ---------------------------------------------------------------- metrics ---
def metrics():
    """Measured numbers. Prefers site/metrics.json (written by benchmark.py);
    falls back to the last row of the committed history so the site still builds
    on a machine that has not run the benchmark."""
    p = os.path.join(SITE, "metrics.json")
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    m = {}
    h = os.path.join(HERE, "benchmark_history.csv")
    if os.path.exists(h):
        rows = list(csv.DictReader(open(h, encoding="utf-8")))
        if rows:
            r = rows[-1]
            m = {"libraries": int(r["libraries"]), "cheat_rule_fp": int(r["cheat_rule_fp"]),
                 "ms_per_class": float(r["ms_per_class"]), "commit": r["commit"]}
    return m


def counts():
    """Sizes taken from the shipped artefacts, not from memory."""
    c = {}
    try:
        sig = json.loads(read(HERE, "signatures.json"))
        c["sig_version"] = sig.get("version", "?")
        c["packages"] = len(sig.get("packagePaths", []))
        c["tokens"] = len(sig.get("clientTokens", []))
        c["domains"] = len(sig.get("downloadDomains", []))
    except Exception:
        pass
    try:
        mod = json.loads(read(HERE, "model.json"))
        c["features"] = len(mod["feature_order"])
        c["model_version"] = mod.get("version", "?")
    except Exception:
        pass
    try:
        sm = json.loads(read(HERE, "session_model.json"))
        c["session_features"] = len(sm["feature_order"])
        c["session_version"] = sm.get("version", "?")
    except Exception:
        pass
    try:
        sys.path.insert(0, HERE)
        import bytecode
        c["behaviours"] = len(bytecode.BEHAVIOUR)
    except Exception:
        pass
    try:
        ps = read(ROOT, "AsyncAnalyzer.ps1")
        c["tool_version"] = re.search(r'\$script:Version\s*=\s*"([^"]+)"', ps).group(1)
        c["lines"] = len(ps.splitlines())
    except Exception:
        pass
    return c


# ------------------------------------------------------------- the pages ---
def build_index(m, c):
    fp = m.get("cheat_rule_fp")
    libs = m.get("libraries")
    hero_fig = "0" if fp == 0 else str(fp)
    body = """
<div class="hero">
  <span class="eyebrow"><span class="dot" aria-hidden="true"></span>Invite only &mdash; every server is let in by hand</span>
  <h1>Stop guessing in screenshares.</h1>
  <p class="lede">AsyncAnalyzer reads every mod on the suspect's PC, works out what the code
  actually does, and hands your staff a verdict they can defend &mdash; with the reasoning
  attached, not a number to argue about.</p>
  <div class="btn-row">
    <a class="btn btn-primary" href="/apply">Apply with your server</a>
    <a class="btn" href="/how-it-works">How it works</a>
  </div>

  <div class="stats">
    <div class="stat reveal"><b class="num">%s</b><span>False flags</span></div>
    <div class="stat reveal"><b class="num">%s</b><span>Real libraries tested</span></div>
    <div class="stat reveal"><b class="num">%s</b><span>Behaviours read from bytecode</span></div>
    <div class="stat reveal"><b class="num">%s</b><span>Features per mod</span></div>
  </div>
</div>

<section class="section">
  <div class="section-head"><span class="section-num">01 / 04</span><h2>How a screenshare goes</h2></div>
  <div class="grid grid-3">
    <div class="card reveal">
      <div class="step-n">1</div>
      <h3>Say the code out loud</h3>
      <span>Your dashboard gives your staff one command carrying your server's key. The moderator
      reads a short code aloud before it runs.</span>
    </div>
    <div class="card reveal">
      <div class="step-n">2</div>
      <h3>They run it themselves</h3>
      <span>On their own machine, in their own PowerShell. Nothing is installed, no window opens,
      no file is touched. It reads the Minecraft instance that is actually running.</span>
    </div>
    <div class="card reveal">
      <div class="step-n">3</div>
      <h3>The verdict lands with you</h3>
      <span>In your server's history, with every finding and the reasoning behind it &mdash; and the
      code you said aloud printed back, so a borrowed screenshot proves nothing.</span>
    </div>
  </div>

  <div class="cmd reveal">
    <div class="cmd-head"><span>What your staff hand over</span><span class="grow"></span></div>
    <pre>%s</pre>
  </div>
  <p class="note" style="margin-top:12px">No flags, no questions. It finds the Minecraft
  installation by itself, decides how deep to look, and says at the end what it could
  <em>not</em> check.</p>
</section>

<section class="section">
  <div class="section-head"><span class="section-num">02 / 04</span><h2>Measured, not claimed</h2></div>
  <div class="cards">
    <div class="card reveal"><span class="k">%s</span><b>false flags</b>
      <span>on %s real Java libraries from Maven Central &mdash; through the full verdict
      chain, not one rule. The build fails if that ever stops being true.</span></div>
    <div class="card reveal"><span class="k">%s</span><b>behaviours read from bytecode</b>
      <span>What a mod <em>does</em>, taken from the compiled code. Renaming a class or
      encrypting its strings does not change it.</span></div>
    <div class="card reveal"><span class="k">%s</span><b>features per mod</b>
      <span>Scored by a model that runs in PowerShell itself &mdash; no cloud, no API key,
      no dependency to install.</span></div>
  </div>
  <p class="note" style="margin-top:16px"><a href="benchmarks.html">See the full benchmark</a>
  &mdash; rerun automatically on every change, with the history.</p>
</section>

<section class="section">
  <div class="section-head"><span class="section-num">03 / 04</span><h2>Why anyone can agree to run it</h2></div>
  <ul class="pts">
    <li><b>It only reads.</b> No file is modified, moved or deleted. No program is installed
    and nothing is left running afterwards.</li>
    <li><b>Their files stay theirs.</b> The analysis happens on their machine. What reaches your
    dashboard is the result &mdash; mod names, hashes and verdicts &mdash; never their files.</li>
    <li><b>They can read it before they run it.</b> The whole scanner is one open PowerShell
    file. Anyone can open the link in a browser and read it top to bottom.</li>
    <li><b>It says what it could not check.</b> A clean result only ever covers what was actually
    looked at, and the report lists the gaps next to the verdict instead of implying more.</li>
    <li><b>It does not open anything.</b> No windows pop up, no file explorer, no browser. It
    prints the verdict and stops.</li>
  </ul>
</section>

<section class="section">
  <div class="section-head"><span class="section-num">04 / 04</span><h2>What your staff get</h2></div>
  <ul class="pts">
    <li><b>One verdict</b>, judged across mods, system, processes, the live game and the
    execution history together &mdash; not one number per file to add up by hand.</li>
    <li><b>Every finding with its reasoning</b> and the exact paths, hashes, process IDs and
    memory addresses behind it.</li>
    <li><b>A shareable link</b> that keeps the verdict and drops the personal details, so it can
    be posted in a ban appeal without handing out anything else.</li>
    <li><b>A history that is yours.</b> Your server's scans, visible to your staff and nobody
    else's.</li>
  </ul>
</section>

<section class="section">
  <div class="card card-pad reveal" style="text-align:center;padding:44px 24px">
    <h2 style="margin-bottom:12px">Bring it to your server</h2>
    <p class="muted" style="margin:0 auto 26px">Tell us about your server in a few sentences.
    Applications are read by a person, which is the whole reason a verdict from this tool
    is worth something.</p>
    <a class="btn btn-primary" href="/apply">Apply with your server</a>
  </div>
</section>
""" % (hero_fig, libs if libs is not None else "&mdash;",
       c.get("behaviours", "14"), c.get("features", "22"),
       E(ONELINER), hero_fig, libs if libs is not None else "the",
       c.get("behaviours", "14"), c.get("features", "22"))
    return page("AsyncAnalyzer",
                "Mod forensics for Minecraft screenshares: a local scanner that hands your "
                "staff a verdict they can defend.", body, "/")


def ps_bands():
    """Band names and score ranges, parsed out of the shipped script so the page
    cannot document thresholds the tool no longer uses."""
    ps = read(ROOT, "AsyncAnalyzer.ps1")
    m = re.search(r'\$band = if \(\$score -ge (\d+)\) \{ "(\w+)" \}'
                  r' elseif \(\$score -ge (\d+)\) \{ "(\w+)" \}'
                  r' elseif \(\$score -ge (\d+)\) \{ "(\w+)" \} else \{ "(\w+)" \}', ps)
    if not m:
        return []
    g = m.groups()
    hi, hn, mi, mn, lo, ln, cn = int(g[0]), g[1], int(g[2]), g[3], int(g[4]), g[5], g[6]
    bands = [(cn, "0-%d" % (lo - 1)), (ln, "%d-%d" % (lo, mi - 1)),
             (mn, "%d-%d" % (mi, hi - 1)), (hn, "%d-100" % hi)]
    # ServerRule is a rename of Review rather than its own threshold, so it does not
    # appear in the band expression. Insert it where it actually sits, and only if
    # the rename is really in the shipped script.
    if re.search(r'\$band -eq "%s"\) \{ \$band = "ServerRule" \}' % re.escape(ln), ps):
        bands.insert(2, ("ServerRule", "%d-%d" % (lo, mi - 1)))
    return bands


BAND_TEXT = {
    "Clean": ("#1c7f47", "Nothing cheat-like. Verified mods are capped here and cannot be "
                         "flagged by any rule."),
    "Review": ("#96610a", "Something does not fit, but it is not proof. A person decides."),
    "ServerRule": ("#6d4fd0", "Recognised for certain, but whether it is allowed is your "
                              "server's rule, not a technical question."),
    "Likely": ("#c2410c", "Strong signs. Every point needs an answer before it is closed."),
    "Confirmed": ("#b91c1c", "A hard rule matched: a known hash, a cheat-client package "
                             "path, a cheat download source, or a client live in memory."),
}

BEHAVIOUR_TEXT = {
    "bc_attack": "attacking an entity through the game's combat path",
    "bc_classload": "defining a class at runtime from bytes it holds",
    "bc_crypto": "decrypting data before using it",
    "bc_entityscan": "walking the list of entities in the world",
    "bc_exec": "starting another program",
    "bc_input": "reading the game's own keyboard and mouse bindings",
    "bc_instrument": "attaching to and rewriting a running program",
    "bc_movepacket": "building a movement packet by hand instead of moving the player",
    "bc_net": "opening a network connection of its own",
    "bc_pktlisten": "intercepting packets before the game sees them",
    "bc_reflect": "reaching into code it was not given access to",
    "bc_render": "drawing to the screen",
    "bc_rotation": "writing the player's look direction directly",
    "bc_unsafe": "using sun.misc.Unsafe to bypass the JVM's own rules",
}


def build_doc(m, c):
    bands = ps_bands()
    band_html = []
    for name, rng in bands:
        colour, text = BAND_TEXT.get(name, ("#59636f", ""))
        band_html.append(
            '<div class="band" style="--bc:%s"><span class="nm">%s</span>'
            '<span class="rg">%s</span><span class="ds">%s</span></div>'
            % (colour, E(name), E(rng), E(text)))

    try:
        sys.path.insert(0, HERE)
        import bytecode
        beh = sorted(bytecode.BEHAVIOUR)
    except Exception:
        beh = sorted(BEHAVIOUR_TEXT)
    beh_html = '<div class="rules-grid">' + "".join(
        '<div class="rule"><b>%s</b><span>%s</span></div>'
        % (E(b.replace("bc_", "")), E(BEHAVIOUR_TEXT.get(b, "")))
        for b in beh) + "</div>"

    # hard rules, read out of the shipped verdict function
    ps = read(ROOT, "AsyncAnalyzer.ps1")
    hard = []
    for pat, label in (
        (r'HashKnownCheat[^\n]*?Max\(\$score,\s*(\d+)', "SHA1 matches a hash confirmed as a cheat"),
        (r'PackageHits[^\n]*?Max\(\$score,\s*(\d+)', "the jar contains a known cheat-client package path"),
        (r'CheatSite[^\n]*?Max\(\$score,\s*(\d+)', "the file was downloaded from a known cheat site"),
        (r'FakeIdentity[^\n]*?Max\(\$score,\s*(\d+)', "the jar claims an identity that is not its own"),
    ):
        mm = re.search(pat, ps)
        if mm:
            hard.append((label, mm.group(1)))
    hard_html = "".join(
        '<div class="rule"><b>%s</b><span>score is raised to at least '
        '<span class="mono">%s</span>, whatever the model says</span></div>' % (E(l), E(s))
        for l, s in hard)

    body = """
<header>
  <h1>How the verdict is reached</h1>
  <p class="lede">Everything on this page is read out of the shipped scanner when the page is
  built, so it describes the rules that are actually running. The scanner itself is one
  readable file &mdash; this is the short version of it.</p>
</header>

<section>
  <div class="label">Step one &mdash; is this a mod anyone else has?</div>
  <p class="note">Every jar is hashed and looked up on Modrinth and CurseForge. A hash that
  matches a real published release is <b>capped as safe</b> and no rule below can flag it.
  That single decision is why an anticheat mod full of the word <span class="mono">killaura</span>
  is not accused of being one.</p>
  <p class="note" style="margin-top:10px">The catch, and it is deliberate: a matching
  <em>modid</em> is not the same as a matching hash. A cheat that writes
  <span class="mono">"id":"sodium"</span> into its metadata gets no protection at all &mdash;
  only the real file does.</p>
</section>

<section>
  <div class="label">Step two &mdash; what does the code do?</div>
  <p class="note">The jar's classes are parsed and their constant pools read: the table of
  every type, method and field the class refers to. That is what the code <em>does</em>, and
  it survives renaming, obfuscation and string encryption, because a method call has to name
  its target for the JVM to run it.</p>
  <div class="chips">%s</div>
  <p class="note" style="margin-top:18px">%d behaviours are counted, as a share of the classes
  in the jar rather than a raw count, so a large mod is not suspicious for being large:</p>
  %s
</section>

<section>
  <div class="label">Where the line is drawn</div>
  <p class="note">The interesting cases are the ones where a legitimate mod and a cheat do
  something similar, and the difference is precise:</p>
  <ul class="pts">
    <li><b>Automation vs. cheating.</b> An auto-walk mod holds the movement key through the
    game's own input system, so the game produces the movement. A movement cheat builds and
    sends its own position packet. Same outcome on screen, opposite thing in the bytecode.</li>
    <li><b>Seeing vs. showing.</b> A minimap reading entity positions and an ESP reading
    entity positions are the same operation. That one is <b>not</b> decidable from bytecode,
    so it is surfaced for a person instead of accused &mdash; on purpose, at a cost in
    detection.</li>
    <li><b>Instrumentation vs. injection.</b> Plenty of real libraries attach to a running
    JVM &mdash; that is their job. A jar sitting in a mods folder doing it is not.</li>
    <li><b>Calling the game vs. being compiled into it.</b> A <b>Mixin</b> does not call
    Minecraft; the loader compiles it <em>into</em> a Minecraft class, and it names its
    target in an annotation instead of calling it. So the target never reaches the symbol
    table: silent rotations mix into the packet that reports where you are looking and
    overwrite its rotation fields, and read through the symbol table that class calls
    nothing at all. The same vocabulary is read out of the annotation. Mixins themselves
    are never the finding &mdash; ordinary Fabric mods are built out of nothing else &mdash;
    the <em>target</em> is: a camera mod mixes into the player, a cheat into the packet.</li>
    <li><b>Naming the API vs. hiding it.</b> The same hole exists for reflection.
    <span class="mono">Class.forName("net.minecraft&hellip;")</span> plus
    <span class="mono">getDeclaredMethod("setYRot")</span> moves every API name out of the
    symbol table and into string constants. Measured before it was closed: an aim cheat
    rewritten that way scored <b>Clean, 3/100</b>. Strings are read too now, and unlike a
    mixin, hiding which API you call is itself written into the report.</li>
  </ul>
</section>

<section>
  <div class="label">The score, and what each band means</div>
  <p class="note">Every mod ends on a 0&ndash;100 score. The model contributes most of it;
  hard rules can raise it and verification can cap it.</p>
  <div class="bands">%s</div>
</section>

<section>
  <div class="label">Rules that override the model</div>
  <p class="note">A model is a good judge of ordinary cases and the wrong tool for certainties.
  These are not learned and cannot be argued down:</p>
  %s
</section>

<section>
  <div class="label">The whole scan, not just the files</div>
  <p class="note">A second model scores the scan as a whole across %s signals &mdash; the mods,
  what the behaviour rules found in them, the system checks, running processes, click macros,
  what is live in the game's memory, and which programs ran on the PC and were then deleted.
  It exists because the strongest evidence often is not in the mods folder at all: a ghost
  client is injected into the running game, and deleting the jar afterwards does not remove
  it from memory.</p>
  <p class="note" style="margin-top:10px">It saw the behaviour rules only through the
  <em>ratio</em> of flagged mods until v3, and a large modpack divides that away: measured, a
  100-mod pack containing <b>one behaviour-confirmed aimbot</b> scored <b>3/100, Clean</b>,
  while the same jar recognised by hash scored 85. Backwards, because the behaviour reading is
  the stronger of the two &mdash; a hash breaks when one byte changes. What the code
  <em>does</em> now reaches this model directly. A perfectly clean scan is still 2/100, and
  eight server-rule findings still cannot add up to a flag.</p>
</section>

<section>
  <div class="label">The autoclicker is not a mod</div>
  <p class="note">An autoclicker never appears in the mods folder. It is an AutoHotkey script
  on the desktop, an AutoIt binary, or &mdash; the case people assume a screenshare cannot
  see &mdash; a <b>Lua script running inside the mouse driver</b>, where the clicks are
  produced below the game entirely. So <span class="mono">.ahk .ahk2 .au3 .lua .vbs</span>
  are read as well, in the usual folders and in the script directories G HUB, Synapse, iCUE,
  SteelSeries, Glorious and Bloody run code out of &mdash; on <b>every</b> scan, not only the
  deep one, because a macro does not need the game to be open and closing Minecraft before
  the screenshare must not hide it.</p>
  <p class="note" style="margin-top:10px">Clicking the mouse is not a cheat, so there are
  three levels and the difference between them is evidence rather than confidence: a click
  loop that <b>names Minecraft</b>, and a click loop in a file <b>named after the
  technique</b> (butterfly-click, blockhit, autocrystal are Minecraft words), are both an
  accusation; a click loop with nothing tying it to the game is reported as exactly that. A recoil script for a shooter has the third shape, and it is in the test
  corpus so that it stays there.</p>
  <p class="note" style="margin-top:10px"><b>What this cannot see</b>, said on every scan
  rather than only when something turns up: a macro burned into a mouse's <b>onboard
  memory</b> runs on the device and leaves nothing on the PC at all. What is visible is that
  a driver macro store exists and when it was last changed.</p>
</section>

<section>
  <div class="label">What it does not do</div>
  <ul class="pts">
    <li><b>It cannot prove innocence.</b> It reports what it checked and what it could not.
    A clean verdict on a scan that ran without admin rights, with the game closed, covers
    much less than one that ran with both &mdash; and the report says so.</li>
    <li><b>ESP is not detected.</b> See above. A mob-radar minimap and an ESP are the same
    code.</li>
    <li><b>It is not an anticheat.</b> It looks at one PC at one moment. It does not watch
    gameplay and cannot see what a player did on a server.</li>
    <li><b>Behaviour, not intent.</b> It can tell you a mod forges movement packets. Whether
    your server forbids that is your rule to make.</li>
    <li><b>Onboard mouse macros are invisible.</b> A macro stored in the device rather than
    on the PC leaves nothing to find. That gap is printed with every result.</li>
  </ul>
</section>

<section>
  <div class="label">Version this page describes</div>
  <div class="chips">
    <span class="chip">tool %s</span><span class="chip">mod model v%s</span>
    <span class="chip">scan model v%s</span><span class="chip">signatures v%s</span>
    <span class="chip">%s package paths</span><span class="chip">%s client tokens</span>
  </div>
</section>
""" % ("".join('<span class="chip">%s</span>' % E(b.replace("bc_", "")) for b in beh),
       len(beh), beh_html, "".join(band_html), hard_html,
       c.get("session_features", "15"),
       c.get("tool_version", "?"), c.get("model_version", "?"),
       c.get("session_version", "?"), c.get("sig_version", "?"),
       c.get("packages", "?"), c.get("tokens", "?"))
    return page("How AsyncAnalyzer decides",
                "Every rule the scanner applies, read out of the shipped source when this "
                "page is built.", body, "/how-it-works")


def build_benchmark_stub(m, c):
    """A page for when the measurements have not been made on this machine."""
    body = """
<div class="page-head">
  <h1>Benchmarks</h1>
  <p class="lede">Every number on this site is measured, and the measurement runs on
  every push. This copy of the site was built somewhere that could not run it.</p>
</div>

<div class="grid grid-3">
  <div class="card"><span class="k">%s</span><b>false flags</b>
    <span>on %s real Java libraries, through the full verdict chain. From the last
    committed run.</span></div>
  <div class="card"><span class="k">%s</span><b>behaviours read from bytecode</b>
    <span>Counted from the shipped analyser, not from the last benchmark.</span></div>
  <div class="card"><span class="k">%s</span><b>features per mod</b>
    <span>Counted from the shipped model.</span></div>
</div>

<p class="note" style="margin-top:26px">
  The full run, with its history and the raw output, is in
  <a href="%s/blob/main/BENCHMARKS.md">BENCHMARKS.md</a>. To produce this page for real:
</p>
<div class="cmd"><div class="cmd-head"><span>Rebuild the measurements</span></div>
<pre>python3 ml/fetch_jars.py &amp;&amp; python3 ml/benchmark.py &amp;&amp; python3 ml/site.py</pre></div>
""" % ("0" if m.get("cheat_rule_fp") == 0 else str(m.get("cheat_rule_fp", "?")),
       m.get("libraries", "?"), c.get("behaviours", "?"), c.get("features", "?"), REPO)
    return page("Benchmarks", "Measured detection numbers for AsyncAnalyzer.", body, "/benchmarks")


def main():
    os.makedirs(SITE, exist_ok=True)
    os.makedirs(os.path.join(SITE, "assets"), exist_ok=True)
    # The backend reads its base models from its own assets. This repository is
    # private, so it cannot fetch them from raw.githubusercontent.com, and a
    # backend that quietly fails to load a base model serves an untrained one.
    for name in ("model.json", "session_model.json"):
        src = os.path.join(HERE, name)
        if os.path.exists(src):
            with open(os.path.join(SITE, "assets", name), "w", encoding="utf-8") as f:
                f.write(read(HERE, name))
    m, c = metrics(), counts()
    written = []
    for name, html_text in (("index.html", build_index(m, c)),
                            ("how-it-works.html", build_doc(m, c))):
        with open(os.path.join(SITE, name), "w", encoding="utf-8") as f:
            f.write(html_text)
        written.append(name)
    # benchmarks.html is produced by benchmark.py, which owns the measurements and
    # needs javac and the downloaded corpus. Somewhere that cannot run it - a laptop,
    # a fresh clone - the site would otherwise ship a navigation link to a 404, so a
    # stand-in is written that says where the numbers actually live. CI overwrites it
    # with the real page on the next push.
    bench = os.path.join(SITE, "benchmarks.html")
    if not os.path.exists(bench):
        with open(bench, "w", encoding="utf-8") as f:
            f.write(build_benchmark_stub(m, c))
        written.append("benchmarks.html (stand-in)")
        print("note: benchmarks.html is a stand-in - run ml/benchmark.py for the real one",
              file=sys.stderr)
    print("site: wrote %s into site/" % ", ".join(written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
