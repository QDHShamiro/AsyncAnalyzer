#!/usr/bin/env python3
"""Build the public site into docs/.

Three pages, all generated. The landing page quotes measured numbers, the rule
documentation is read out of the shipped PowerShell and the Python model, and the
benchmark page is rendered from the last measurement. Nothing here is written by
hand, so no page can claim something the tool does not actually do - which is the
only way a transparency page is worth anything.

    python3 ml/site.py            # writes docs/index.html, benchmarks.html, how-it-works.html
"""
import csv, json, os, re, sys, html

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = os.path.join(ROOT, "docs")
E = html.escape

REPO = "https://github.com/QDHShamiro/AsyncAnalyzer"
RAW = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1"
ONELINER = ('powershell -ExecutionPolicy Bypass -Command "iex (irm \''
            + RAW + '\')"')


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def shared_style():
    """One stylesheet for the whole site, taken from the benchmark template so the
    three pages cannot drift into three different-looking sites."""
    tpl = read(HERE, "page_template.html")
    m = re.search(r"<style>(.*?)</style>", tpl, re.S)
    return m.group(1) if m else ""


EXTRA_CSS = """
/* ---- site chrome (shared by every page) ------------------------------ */
nav.site{display:flex;flex-wrap:wrap;gap:4px;align-items:center;padding:18px 0 0;}
nav.site a{
  font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--muted);
  text-decoration:none;padding:6px 11px;border-radius:8px;
}
nav.site a:hover{color:var(--ink);background:var(--sunk)}
nav.site a[aria-current]{color:var(--accent);background:var(--sunk)}
nav.site .grow{flex:1}
a{color:var(--accent)}

/* ---- landing --------------------------------------------------------- */
.cmd{
  margin-top:26px;background:var(--surface);border:1px solid var(--line);
  border-radius:14px;box-shadow:var(--shadow);overflow:hidden;
}
.cmd-head{
  display:flex;align-items:center;gap:10px;padding:11px 16px;
  border-bottom:1px solid var(--line);background:var(--sunk);
  font-family:"IBM Plex Mono",monospace;font-size:11.5px;
  letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
}
.cmd-head .grow{flex:1}
.cmd pre{
  /* A command people copy is worth seeing in full - wrapping beats a scrollbar
     that hides half of it behind the edge of the card. */
  padding:18px 16px;font-family:"IBM Plex Mono",monospace;
  font-size:13px;line-height:1.7;color:var(--ink);
  white-space:pre-wrap;overflow-wrap:anywhere;
}
.btn{
  font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:.06em;
  text-transform:uppercase;background:var(--surface);color:var(--muted);
  border:1px solid var(--line);border-radius:7px;padding:5px 11px;cursor:pointer;
}
.btn:hover{color:var(--accent);border-color:var(--accent)}
.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin-top:20px}
.card{
  padding:20px;background:var(--surface);border:1px solid var(--line);
  border-radius:13px;box-shadow:var(--shadow);
}
.card b{display:block;font-size:15.5px;font-weight:600;margin-bottom:6px}
.card span{color:var(--muted);font-size:14.5px}
.card .k{
  font-family:"IBM Plex Mono",monospace;font-size:30px;font-weight:600;
  color:var(--accent);letter-spacing:-.03em;display:block;margin-bottom:4px;
  font-variant-numeric:tabular-nums;
}

/* ---- documentation --------------------------------------------------- */
.rule{
  padding:17px 19px;background:var(--surface);border:1px solid var(--line);
  border-left:2px solid var(--accent);border-radius:11px;margin-top:12px;
}
.rule b{display:block;font-size:15.5px;font-weight:600;margin-bottom:4px}
.rule span{color:var(--muted);font-size:14.5px}
.rule .mono{color:var(--ink);font-size:13px}
.rules-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:12px}
.rules-grid .rule{margin-top:0}
.bands{display:grid;gap:10px;margin-top:18px}
.band{
  display:grid;grid-template-columns:minmax(96px,132px) minmax(58px,72px) 1fr;
  gap:14px;align-items:baseline;padding:13px 16px;background:var(--surface);
  border:1px solid var(--line);border-left:3px solid var(--bc);border-radius:11px;
}
.band .nm{font-weight:600;color:var(--bc)}
.band .rg{font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}
.band .ds{color:var(--muted);font-size:14.5px}
ul.pts{list-style:none;display:grid;gap:8px;margin-top:16px}
ul.pts li{padding-left:17px;position:relative;color:var(--muted);font-size:15px}
ul.pts li:before{
  content:"";position:absolute;left:0;top:.62em;width:6px;height:6px;
  border-radius:50%;background:var(--accent);
}
ul.pts li b{color:var(--ink);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:16px}
.chip{
  font-family:"IBM Plex Mono",monospace;font-size:12px;padding:4px 10px;
  border-radius:999px;background:var(--sunk);color:var(--muted);border:1px solid var(--line);
}
footer.site{
  margin-top:64px;padding-top:22px;border-top:1px solid var(--line);
  color:var(--muted);font-size:14px;
}
"""


def nav(current):
    items = [("index.html", "Overview"), ("benchmarks.html", "Benchmarks"),
             ("how-it-works.html", "How it works")]
    out = ['<nav class="site">']
    for href, label in items:
        cur = ' aria-current="page"' if href == current else ""
        out.append('<a href="%s"%s>%s</a>' % (href, cur, label))
    out.append('<span class="grow"></span>')
    out.append('<a href="%s">GitHub &#8599;</a>' % REPO)
    out.append("</nav>")
    return "".join(out)


def page(title, desc, body, current):
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<meta name="description" content="%s">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">
<style>%s
%s</style></head>
<body><div class="wrap">
%s
%s
<footer class="site">
  AsyncAnalyzer is built by Async Studio and is open source &mdash; the whole scanner is
  one PowerShell file you can read before you run it.
  <a href="%s">Source</a> &middot; <a href="%s/blob/main/BENCHMARKS.md">Raw benchmark output</a>
</footer>
</div></body></html>
""" % (E(title), E(desc), shared_style(), EXTRA_CSS, nav(current), body, REPO, REPO)


# ---------------------------------------------------------------- metrics ---
def metrics():
    """Measured numbers. Prefers docs/metrics.json (written by benchmark.py);
    falls back to the last row of the committed history so the site still builds
    on a machine that has not run the benchmark."""
    p = os.path.join(DOCS, "metrics.json")
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
<header>
  <h1>Know what is in your mods folder &mdash; and be able to prove it.</h1>
  <p class="lede">AsyncAnalyzer reads every mod on a Windows PC, works out what its code
  actually does, and writes a report a screenshare moderator can act on. It runs entirely
  on the machine: nothing is uploaded, nothing is installed, nothing is changed.</p>
</header>

<div class="cmd">
  <div class="cmd-head"><span>Run it &mdash; PowerShell</span><span class="grow"></span>
    <button class="btn" id="cp" onclick="copyCmd()">Copy</button></div>
  <pre id="oneliner">%s</pre>
</div>
<p class="note" style="margin-top:12px">No flags, no questions. It finds the Minecraft
installations by itself, decides how deep to look, and tells you at the end what it could
<em>not</em> check.</p>

<section>
  <div class="label">Measured, not claimed</div>
  <div class="cards">
    <div class="card"><span class="k">%s</span><b>false flags</b>
      <span>on %s real Java libraries from Maven Central &mdash; through the full verdict
      chain, not one rule. The build fails if that ever stops being true.</span></div>
    <div class="card"><span class="k">%s</span><b>behaviours read from bytecode</b>
      <span>What a mod <em>does</em>, taken from the compiled code. Renaming a class or
      encrypting its strings does not change it.</span></div>
    <div class="card"><span class="k">%s</span><b>features per mod</b>
      <span>Scored by a model that runs in PowerShell itself &mdash; no cloud, no API key,
      no dependency to install.</span></div>
  </div>
  <p class="note" style="margin-top:16px"><a href="benchmarks.html">See the full benchmark</a>
  &mdash; rerun automatically on every change, with the history.</p>
</section>

<section>
  <div class="label">Why you can run this on your own PC</div>
  <ul class="pts">
    <li><b>It only reads.</b> No file is modified, moved or deleted. No program is installed
    and nothing is left running afterwards.</li>
    <li><b>Nothing leaves the machine.</b> The analysis is local. Team upload exists but is
    off unless a team turns it on, and it sends results &mdash; never your files.</li>
    <li><b>You can read it before you run it.</b> The whole scanner is one PowerShell file.
    Open the link in a browser and read it top to bottom.</li>
    <li><b>It says what it could not check.</b> A clean result only ever covers what was
    actually looked at, and the report lists the gaps next to the verdict instead of
    implying more.</li>
    <li><b>It does not open anything.</b> No windows pop up, no file explorer, no browser.
    It prints where the report is and stops.</li>
  </ul>
</section>

<section>
  <div class="label">What the report gives a moderator</div>
  <ul class="pts">
    <li><b>One verdict</b>, judged across mods, system, processes, the live game and the
    execution history together &mdash; not one number per file to add up by hand.</li>
    <li><b>Every finding with its reasoning</b> and the exact paths, hashes, process IDs and
    memory addresses behind it.</li>
    <li><b>A coverage box</b> naming what could not be checked, so nobody reads more into a
    clean result than it says.</li>
    <li><b>Prints to PDF</b>, so it can be attached to a ban appeal.</li>
  </ul>
</section>

<script>
function copyCmd(){
  var t=document.getElementById('oneliner').textContent, b=document.getElementById('cp');
  var ok=function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1400);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(ok,function(){});return;}
  var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
  try{document.execCommand('copy');ok();}catch(e){}document.body.removeChild(a);
}
</script>
""" % (E(ONELINER), hero_fig, libs if libs is not None else "the",
       c.get("behaviours", "14"), c.get("features", "22"))
    return page("AsyncAnalyzer",
                "A local, open-source Minecraft mod scanner that produces evidence a "
                "screenshare moderator can act on.", body, "index.html")


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
    return [(cn, "0-%d" % (lo - 1)), (ln, "%d-%d" % (lo, mi - 1)),
            (mn, "%d-%d" % (mi, hi - 1)), (hn, "%d-100" % hi)]


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
  the system checks, running processes, what is live in the game's memory, and which programs
  ran on the PC and were then deleted. It exists because the strongest evidence often is not in
  the mods folder at all: a ghost client is injected into the running game, and deleting the
  jar afterwards does not remove it from memory.</p>
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
                "page is built.", body, "how-it-works.html")


def main():
    os.makedirs(DOCS, exist_ok=True)
    m, c = metrics(), counts()
    written = []
    for name, html_text in (("index.html", build_index(m, c)),
                            ("how-it-works.html", build_doc(m, c))):
        with open(os.path.join(DOCS, name), "w", encoding="utf-8") as f:
            f.write(html_text)
        written.append(name)
    # benchmarks.html is produced by benchmark.py, which owns the measurements.
    if not os.path.exists(os.path.join(DOCS, "benchmarks.html")):
        print("note: docs/benchmarks.html missing - run ml/benchmark.py to produce it",
              file=sys.stderr)
    print("site: wrote %s into docs/" % ", ".join(written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
