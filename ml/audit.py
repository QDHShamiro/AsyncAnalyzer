"""
Dead-end detector: signals that are measured and never reach a decision.

This is the failure mode this project keeps producing, because every instance of
it looks like success. A signal that is computed but never read does not raise an
error - the scan just quietly scores lower than every test here says it should.
Three real ones so far:

  * bc_selfwipe and bc_hiddenapi were missing from the FEATURES list, so a whole
    column of the dataset was zeroes and the rule read as "catches nothing";
  * swingHand, method_6104 and getLoadedEntityList were named in a behaviour rule
    and missing from the pre-filter, so the class was never parsed at all;
  * macro_cheat could auto-label a scan as a cheat while not being a model
    feature, which pushes the intercept instead of a weight and drifts every
    later scan a little closer to "cheat".

None of the three failed a test. Each was found by looking. So this looks, on
every build, at the joins where a signal can go missing:

  Evidence field -> Get-SessionRaw -> vector or hard rule -> a band
  behaviour category -> a rule or a reason a moderator reads
  a function -> somebody calling it

Run:  python3 ml/audit.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")


def read(name):
    return open(os.path.join(SRC, name), encoding="utf-8").read()


ALL = {n: read(n) for n in sorted(os.listdir(SRC)) if n.endswith(".ps1")}
JOINED = "\n".join(ALL.values())

problems = []
notes = []


def fail(what, detail):
    problems.append((what, detail))


def ok(what, detail=""):
    notes.append((what, detail))


# --------------------------------------------------------------- evidence ---
# $script:Evidence.X is set during a scan and read by Get-SessionRaw. A field that
# is set and never read is a measurement that reaches no decision.
raw_block = JOINED[JOINED.index("function Get-SessionRaw"):]
raw_block = raw_block[:raw_block.index("function Get-SessionVector")]
read_fields = set(re.findall(r"\$ev\.(\w+)", raw_block))
init = re.search(r"\$script:Evidence = @\{([^}]*)\}", JOINED)
declared = set(re.findall(r"(\w+)\s*=", init.group(1))) if init else set()
written = set(re.findall(r"\$script:Evidence\.(\w+)\s*(?:\+\+|=)", JOINED))

# these are shown in the report and deliberately do not feed the model
REPORT_ONLY = {"MemModule", "MemInjectedOnly"}
orphan = sorted((declared | written) - read_fields - REPORT_ONLY)
if orphan:
    fail("Evidence fields that never reach Get-SessionRaw", ", ".join(orphan))
else:
    ok("every Evidence field reaches Get-SessionRaw", "%d field(s)" % len(read_fields))

# ------------------------------------------------------------ raw signals ---
# Every key Get-SessionRaw returns must be either a model feature or used by a
# hard rule. One that is neither is collected and thrown away.
raw_keys = set(re.findall(r"^\s*(\w+)\s*=", raw_block, re.M)) - {"return", "function"}
order = re.search(r"\$script:smFeatureOrder = @\(([^)]*)\)", JOINED)
features = set(re.findall(r"'(\w+)'", order.group(1))) if order else set()
# A raw key can also reach the model through Get-SessionVector under a different
# name - random_named becomes random_ratio there - so the vector counts as a use.
vector = JOINED[JOINED.index("function Get-SessionVector"):]
vector = vector[:vector.index("function Invoke-SessionModel")]
used_in_vector = set(re.findall(r"\$raw\.(\w+)", vector))
verdict = JOINED[JOINED.index("function Get-SessionVerdict"):]
verdict = verdict[:verdict.index("function Get-SessionVerdictCached")]
label = JOINED[JOINED.index("function Get-SessionLabel"):]
label = label[:label.index("function Update-SessionModelOnline")]
used_in_rules = set(re.findall(r"\$raw\.(\w+)", verdict + label))
dead = sorted(raw_keys - features - used_in_rules - used_in_vector)
if dead:
    fail("raw signals collected and never used", ", ".join(dead))
else:
    ok("every raw signal is a feature or a rule", "%d signal(s)" % len(raw_keys))

# The invariant that came out of the macro bug, checked from the PowerShell side
# too rather than only in ml/session_model.py.
label1 = label[:label.index("return 1")] if "return 1" in label else label
label1_keys = set(re.findall(r"\$raw\.(\w+)", label1))
not_features = sorted(label1_keys - features)
if not_features:
    fail("cheat-label signals that are not model features", ", ".join(not_features))
else:
    ok("every cheat-label signal is a model feature", "%d signal(s)" % len(label1_keys))

# ------------------------------------------------- behaviour categories ---
# A category that is measured on every jar and consumed by nothing is cost without
# a decision. Being named in a REASON counts: telling a moderator what the code
# does is a decision they make rather than one the tool makes.
beh = re.search(r"\$script:bcBehaviour = \[ordered\]@\{(.*?)\n\}", JOINED, re.S)
cats = re.findall(r"^\s*'(\w+)'\s*=", beh.group(1), re.M) if beh else []
der = re.search(r"\$script:bcDerived = @\(([^)]*)\)", JOINED)
cats += re.findall(r"'(\w+)'", der.group(1)) if der else []
analysis = ALL["50-analysis.ps1"]
direct = {c for c in cats if ("$bc.%sRatio" % c) in analysis}

# A category can also reach a decision INDIRECTLY, by being an input to a derived
# signal that a rule reads: selfpath, filedelete, nativetemp and archive exist only
# to work out selfwipe. That chain is legitimate, so follow it - but only one link,
# and only to a derived signal that is itself consumed. An input to a dead derived
# signal is just as dead as the signal.
bc_src = ALL["40-bytecode.ps1"]
indirect = set()
# the condition and the assignment sit on different lines, so match the whole
# if-block rather than scanning line by line
for cond, body in re.findall(
        r"if \(([^{]*?)\)\s*\{(.*?)\n\s*\}", bc_src, re.S):
    setters = re.findall(r"\$hit\['(\w+)'\]\s*=\s*\$true", body)
    if not any(t in direct for t in setters):
        continue
    for c in re.findall(r"\$hit\['(\w+)'\]", cond):
        indirect.add(c)

unconsumed = [c for c in cats if c not in direct and c not in indirect]
if unconsumed:
    fail("behaviour categories no rule or reason reads", ", ".join(unconsumed))
else:
    ok("every behaviour category reaches a rule or a reason",
       "%d direct, %d through a derived signal" % (len(direct & set(cats)), len(indirect & set(cats))))

# ------------------------------------------------------------- functions ---
# A function nobody calls is either dead or a call site that was renamed and
# missed. Both are worth seeing; only the second is a bug, so this reports.
defined = set(re.findall(r"^function ([\w-]+)", JOINED, re.M))
uncalled = []
for fn in sorted(defined):
    # a call is any mention that is not the definition itself
    n = len(re.findall(r"(?<![\w-])%s(?![\w-])" % re.escape(fn), JOINED))
    if n <= 1:
        uncalled.append(fn)
if uncalled:
    notes.append(("functions that are defined and never called",
                  ", ".join(uncalled)))
else:
    ok("every function is called somewhere", "%d function(s)" % len(defined))

# ----------------------------------------------------------- scan gaps ---
# The coverage box is the honesty mechanism. A gap message that can never be
# produced is a promise the report cannot keep.
gaps = re.findall(r"Add-ScanGap\s+[\"(]", JOINED)
ok("the coverage box has gap messages to print", "%d call site(s)" % len(gaps))

# ------------------------------------------------------- signature lists ---
# A client name shorter than the floor the readers use is in the list and skipped
# by three of the four places that read it. That is how "vape" - one of the
# most-used clients there is - was invisible to the log reader, the instance reader
# and the pre-filter while the filename and memory scans still saw it. Nothing
# errored; the name was simply never searched for.
sig = ALL["10-signatures.ps1"]
floor_m = re.search(r"\$script:tokenFloor = (\d+)", sig)
floor = int(floor_m.group(1)) if floor_m else 0
sys.path.insert(0, HERE)
try:
    import logscan as _ls
    py_floor = _ls.TOKEN_FLOOR
except Exception:
    py_floor = None
if not floor:
    fail("no $script:tokenFloor in the signatures", "the readers use bare literals")
elif py_floor is not None and py_floor != floor:
    fail("token floor differs between PowerShell and Python", "ps=%d py=%d" % (floor, py_floor))
else:
    ok("the token floor is one number in both languages", "%d characters" % floor)

tok_blk = sig[sig.index("$script:distinctiveClientTokens = "):]
tok_blk = tok_blk[:tok_blk.index(") | ForEach-Object")]
tokens = re.findall(r'"([^"]+)"', tok_blk)
short = [t for t in tokens if len(t) < floor] if floor else []
if short:
    fail("client names below the floor - the readers skip them", ", ".join(short))
else:
    ok("every client name is at or above the floor", "%d name(s)" % len(tokens))

# A name that is also a legitimate mod id would accuse the mod. None today, and
# this is the check that keeps it that way when the team adds one.
legit_blk = sig[sig.index("$script:legitModIds = "):]
legit_blk = legit_blk[:legit_blk.index(") | ForEach-Object")]
legit = {x.lower() for x in re.findall(r'"([^"]+)"', legit_blk)}
clash = sorted({t.lower() for t in tokens} & legit)
if clash:
    fail("a client name is also a known-good mod id", ", ".join(clash))
else:
    ok("no client name collides with a known-good mod id", "%d mod id(s)" % len(legit))

# ------------------------------------------------------------- mod model ---
# The 22 mod-model features have to be produced by the extractor, or the model is
# scoring on a zero it was not trained to see.
mod_order = re.search(r"\$script:mlFeatureOrder = @\(([^)]*)\)", JOINED)
mod_feats = set(re.findall(r"'(\w+)'", mod_order.group(1))) if mod_order else set()
vec = JOINED[JOINED.index("function Get-ModFeatureVector"):]
vec = vec[:vec.index("\n}\n", vec.index("function Get-ModFeatureVector"))]
produced = set(re.findall(r"^\s*(\w+)\s*=", vec, re.M))
missing = sorted(mod_feats - produced)
if missing:
    fail("mod-model features the extractor never produces", ", ".join(missing))
else:
    ok("every mod-model feature is produced", "%d feature(s)" % len(mod_feats))


# ------------------------------------------- script state nothing reads back ---
# A $script: variable that is written and never read is a measurement that reaches
# no decision - the same failure this whole file exists to catch, one level down.
# It looks like working code and produces nothing. Assignment does not count as a
# read, and neither does the declaration.
assign = re.compile(r"\$script:(\w+)\s*(?:=|\+=|\+\+)")
written = set(assign.findall(JOINED))
# Every $script: mention that is NOT the left-hand side of an assignment.
read_sites = set()
for m in re.finditer(r"\$script:(\w+)", JOINED):
    tail = JOINED[m.end():m.end() + 24]
    if re.match(r"\s*(=[^=]|\+=|\+\+)", tail):
        continue
    read_sites.add(m.group(1))
# Names the shipped script hands to the outside world (report, upload, summary)
# by string rather than by $script: reference are read for real.
for name in re.findall(r"[\"'](\w+)[\"']\s*=\s*\$script:", JOINED):
    read_sites.add(name)
write_only = sorted(n for n in written - read_sites
                    if not n.startswith("_") and n not in ("Version", "Author", "ToolName"))
if write_only:
    fail("script state written and never read back", ", ".join(write_only))
else:
    ok("every piece of script state is read somewhere", "%d name(s)" % len(written))


def main():
    print("=== dead-end audit ===")
    for what, detail in notes:
        print("  ok    %-52s %s" % (what, detail))
    print()
    for what, detail in problems:
        print("  DEAD  %-52s %s" % (what, detail))
    print("\n=== RESULT: %d check(s) clean, %d dead end(s) ===" % (len(notes), len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
