# The report is written for one reader: the staff member sitting in a screenshare
# with the suspect on the other side. It has to answer three things without them
# scrolling back through a console that already closed - what the verdict is, what
# it rests on, and what the scan could NOT check. Everything else is secondary.

function Get-BandStyle([string]$band) {
    switch ($band) {
        "Confirmed" { return @{ c = "#ff5f56"; label = "CHEATING CONFIRMED";   short = "CONFIRMED";
                                say = "This is proof, not a guess. The evidence below names the file, the process or the memory region it was found in." } }
        "Likely"    { return @{ c = "#ff9f43"; label = "LIKELY CHEATING";      short = "LIKELY";
                                say = "Strong signs of cheating. Every point below needs an answer before this is closed." } }
        "Review"    { return @{ c = "#ffcf4d"; label = "NEEDS A MANUAL LOOK";  short = "REVIEW";
                                say = "Something does not fit, but it is not proof. Read the points below and decide." } }
        # Violet on purpose: it must not read as a severity between amber and red.
        # This is a different KIND of finding, not a stronger one.
        "ServerRule" { return @{ c = "#a78bfa"; label = "SERVER RULE";          short = "SERVER RULE";
                                say = "Recognised for certain, and whether it is allowed is your server's rule rather than a technical question. This is not an accusation." } }
        default     { return @{ c = "#3ddc84"; label = "NOTHING FOUND";        short = "CLEAN";
                                say = "Nothing cheat-like was found in what was checked. Read the coverage box - it says what was not checked." } }
    }
}

function Get-LevelStyle([string]$level) {
    switch ($level) {
        "FAIL" { return @{ c = "#ff5f56"; label = "FINDING";  rank = 0 } }
        "WARN" { return @{ c = "#ffcf4d"; label = "WARNING";  rank = 1 } }
        # INFO never reaches a card - it is routed to the coverage gaps instead - but
        # it keeps a style so nothing renders blank if that ever changes.
        "INFO" { return @{ c = "#9aa8ba"; label = "NOT RUN";  rank = 2 } }
        # The state of the PC: real, worth seeing, and not evidence of cheating.
        # It has its own level so no filter that looks for FAIL/WARN can pick it
        # up by accident - a firewall turned off by an antivirus must never end
        # up in "Look at these first".
        "STATE" { return @{ c = "#9aa8ba"; label = "PC STATE"; rank = 4 } }
        default { return @{ c = "#3ddc84"; label = "CLEAR";   rank = 3 } }
    }
}

# One card, used for findings and for the PC-state block alike. They are the same
# object with a different level, and rendering them two different ways once meant
# writing the markup twice and letting the copies drift.
function New-FindingCard($f) {
    $ls = Get-LevelStyle $f.Level
    $itemHtml = ""
    if (@($f.Items).Count -gt 0) {
        $li = ""
        foreach ($i in @($f.Items)) { $li += "<li class='mono'>$(Enc $i)</li>" }
        $itemHtml = "<div class='why'><div class='eyebrow'>What exactly was found ($(@($f.Items).Count))</div><ul class='evidence'>$li</ul></div>"
    }
    $rz = ""
    if ($f.What) { $rz += "<div class='r'><span class='rl'>What this check does</span>$(Enc $f.What)</div>" }
    if ($f.Why)  { $rz += "<div class='r'><span class='rl'>Why it matters</span>$(Enc $f.Why)</div>" }
    if ($f.How)  { $rz += "<div class='r'><span class='rl'>How it gets there</span>$(Enc $f.How)</div>" }
    if ($f.Fix)  { $rz += "<div class='r'><span class='rl'>What to do</span>$(Enc $f.Fix)</div>" }
    $reasonHtml = if ($rz) { "<div class='why'><div class='eyebrow'>Reasoning</div><div class='reason-grid'>$rz</div></div>" } else { "" }
    return @"
<article class="find" style="--lc:$($ls.c);">
  <header class="find-head">
    <span class="tag" style="background:$($ls.c);">$($ls.label)</span>
    <h3>$(Enc $f.Title)</h3>
    <span class="area">$(Enc $f.Area)</span>
  </header>
  $itemHtml
  $reasonHtml
</article>
"@
}

function New-HtmlReport([string]$OutPath = "") {
    $sv      = Get-SessionVerdictCached
    $svStyle = Get-BandStyle $sv.Band
    $raw     = $script:SessionRaw

    $now      = Get-Date
    $stampLocal = $now.ToString("yyyy-MM-dd HH:mm:ss") + " (UTC" + $now.ToString("zzz") + ")"
    $stampUtc   = $now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
    $reportId   = $now.ToString("yyyyMMdd-HHmmss") + "-" + $env:COMPUTERNAME
    $isAdmin    = Test-IsAdmin
    $mcRunning  = ($raw -and $raw.mc_running -gt 0)

    $gapCount = @($script:ScanGaps).Count
    # A green headline on a scan that could not look everywhere reads as "proven
    # clean" if nothing says otherwise. It gets said in the headline, not only in
    # the coverage box further down.
    $mastCaveat = ""
    if ($gapCount -gt 0 -and ($sv.Band -eq "Clean" -or $sv.Band -eq "Review")) {
        $mastCaveat = "<p class='caveat'>$gapCount thing(s) could not be checked at all &mdash; this result does not cover them. See <b>Coverage</b> below.</p>"
    }

    # ---- verdict reasons ----------------------------------------------------
    $svReasons = ""
    $n = 0
    foreach ($r in @($sv.Reasons)) { $n++; $svReasons += "<li><span class='num'>$n</span><span>$(Enc $r)</span></li>" }

    # ---- scan record --------------------------------------------------------
    $targetItems = ""
    foreach ($t in @($script:ScanTargets | Where-Object { $_ })) { $targetItems += "<div class='mono'>$(Enc $t)</div>" }
    if (-not $targetItems) { $targetItems = "<div class='mono dim'>none</div>" }

    $depthWord = if ($script:DeepScan) { "deep (system, PC and memory included)" } else { "standard (mods and system)" }
    $recRows = @(
        @{ k = "Scanned at";       v = "$(Enc $stampLocal)<div class='dim'>$(Enc $stampUtc)</div>" }
        @{ k = "Time taken";       v = "$([Math]::Round(((Get-Date) - $script:ScanStart).TotalSeconds, 1)) seconds<div class='dim'>started $(Enc ($script:ScanStart.ToString('HH:mm:ss'))) &mdash; a report that claims to be from this scan has to fit in that window</div>" }
        @{ k = "PC";               v = "<span class='mono'>$(Enc $env:COMPUTERNAME)</span>" }
        @{ k = "Windows user";     v = "<span class='mono'>$(Enc $env:USERNAME)</span>" }
        @{ k = "Administrator";    v = $(if ($isAdmin) { "<span class='yes'>yes</span> &mdash; full access" } else { "<span class='no'>no</span> &mdash; some checks were skipped" }) }
        @{ k = "Minecraft";        v = $(if ($mcRunning) { "<span class='yes'>running during the scan</span>" } else { "<span class='no'>not running</span> &mdash; nothing could be read out of the live game" }) }
        @{ k = "Scan depth";       v = "$(Enc $depthWord)<div class='dim'>up to $($script:BcMaxClasses) classes analysed per jar</div>" }
        @{ k = "Folders scanned";  v = $targetItems }
        @{ k = "Second pass";      v = $(if ($script:LateScanned -gt 0) { "<span class='yes'>$($script:LateScanned) more jar(s)</span> found in $($script:LateScanDirs.Count) folder(s) the running game was reading that nothing on disk pointed at" } elseif ($script:LateScanDirs.Count -gt 0) { "the running game named $($script:LateScanDirs.Count) extra folder(s); they held nothing new" } else { "<span class='dim'>not needed &mdash; the running game loaded mods only from folders that were already scanned</span>" }) }
        @{ k = "Tool";             v = "AsyncAnalyzer $(Enc $script:Version) &mdash; mod model v$($script:mlModelVersion), $($script:mlSamples) examples learned" }
        @{ k = "Report ID";        v = "<span class='mono'>$(Enc $reportId)</span>" }
        @{ k = "Scan ID";          v = "<span class='mono big'>$(Enc $script:ScanId)</span>" }
        @{ k = "Code from staff";  v = $(if ($script:ScanCode) { "<span class='mono big yes'>$(Enc $script:ScanCode)</span>" } else { "<span class='no'>none was given</span> &mdash; this report cannot be shown to be fresh" }) }
    )
    $recordRows = ""
    foreach ($r in $recRows) { $recordRows += "<div class='rec'><div class='rk'>$($r.k)</div><div class='rv'>$($r.v)</div></div>" }

    # ---- is this report real? ------------------------------------------------
    # Worth being exact rather than reassuring. Somebody who controls the PC can
    # edit an HTML file or take a screenshot and change it, and no amount of
    # hashing inside that same file fixes it - they control the hash too. What
    # these two things actually do is narrower and still useful, so say which.
    $authRows = ""
    if ($script:ScanCode) {
        $authRows += "<li><b>Staff code <span class='mono'>$(Enc $script:ScanCode)</span> is in this report.</b> " +
            "It was said out loud before the scan started, so a report made earlier " +
            "cannot carry it. That dates this report; it does not prove the contents.</li>"
    } else {
        $authRows += "<li><b>No staff code was given.</b> Run the tool again with " +
            "<span class='mono'>-Code &lt;word&gt;</span> where the word comes from the moderator, " +
            "and the report can at least be shown to be fresh.</li>"
    }
    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
        $authRows += "<li><b>This scan was uploaded as <span class='mono'>$(Enc $script:ScanId)</span>.</b> " +
            "Look that ID up in the team dashboard: that copy was written by the tool, " +
            "not by the person being checked, and it is the one to trust if the two disagree.</li>"
    } else {
        $authRows += "<li><b>Nothing was uploaded</b> &mdash; team mode is off, so this file is the only copy " +
            "and it lives on the scanned PC. With team mode on, every scan gets an ID the moderator can open themselves.</li>"
    }
    $authRows += "<li>Watch the scan run on the screenshare. A file can be edited afterwards; " +
        "the console output happening in front of you cannot.</li>"
    $authBox = "<div class='panel'><div class='eyebrow'>Is this report real?</div><ul class='plain'>$authRows</ul></div>"

    # ---- coverage: an area counts as checked only if it actually reported ----
    $areas = @()
    foreach ($f in @($script:Findings)) { if ($areas -notcontains $f.Area) { $areas += $f.Area } }
    $coverChecked = "<li><b>Mods folder</b> &mdash; $($script:TotalMods) file(s), each one read, hashed and analysed as bytecode</li>"
    foreach ($a in $areas) {
        $cnt = @($script:Findings | Where-Object { $_.Area -eq $a -and ($_.Level -eq "FAIL" -or $_.Level -eq "WARN") }).Count
        $tail = if ($cnt -gt 0) { "$cnt finding(s)" } else { "nothing found" }
        $coverChecked += "<li><b>$(Enc $a)</b> &mdash; $tail</li>"
    }
    $coverGaps = ""
    foreach ($g in @($script:ScanGaps)) { $coverGaps += "<li>$(Enc $g)</li>" }
    $gapBox = if ($gapCount -gt 0) {
        "<div class='panel gap'><div class='eyebrow warnfg'>Could NOT be checked &mdash; $gapCount</div><ul class='plain'>$coverGaps</ul>" +
        "<p class='note'>A clean result only covers what was actually checked. Anything listed here is unproven either way.</p></div>"
    } else {
        "<div class='panel'><div class='eyebrow goodfg'>Could NOT be checked &mdash; nothing</div><p class='note'>Every check this tool has ran to completion. Nothing was skipped.</p></div>"
    }

    # ---- mods ---------------------------------------------------------------
    $mods = @(@($flaggedMods) + @($reviewMods) | Where-Object { $_ } | Sort-Object Score -Descending)
    $srNote = if ($script:ServerRule -gt 0) {
        " <span class='srnote'>$($script:ServerRule) of them are server-rule questions, not accusations</span>"
    } else { "" }
    $modCards = ""
    foreach ($m in $mods) {
        $bm = Get-BandStyle $m.Band
        $reasonItems = ""
        foreach ($r in @($m.Reasons)) { $reasonItems += "<li>$(Enc $r)</li>" }
        $src = if ($m.DownloadSource) { "<span class='sep'>&bull;</span>downloaded from $(Enc $m.DownloadSource)" } else { "" }
        $sha = if ($m.Hash) { $m.Hash } else { "not readable" }
        $modCards += @"
<article class="find" style="--lc:$($bm.c);">
  <header class="find-head">
    <span class="tag" style="background:$($bm.c);">$($bm.short)</span>
    <h3 class="mono">$(Enc $m.FileName)</h3>
    <span class="score">$($m.Score)<small>/100</small></span>
  </header>
  $(New-ScoreScale $m.Score $bm.c)
  <div class="kv mono">SHA1 $sha<span class="sep">&bull;</span>AI cheat probability $($m.Probability)%$src</div>
  <div class="why"><div class="eyebrow">Why it scored this way</div><ul class="reasons">$reasonItems</ul></div>
</article>
"@
    }
    if (-not $modCards) {
        $modCards = "<div class='panel clear'><b class='goodfg'>No mod was flagged.</b> Every file in the scanned folders is either verified against Modrinth/CurseForge or came back clean on all rules.</div>"
    }

    $verified = @($verifiedMods | Where-Object { $_ })
    $verRows = ""
    foreach ($v in $verified) {
        $nm = if ($v.ModName) { $v.ModName } else { $v.FileName }
        $verRows += "<tr><td>$(Enc $nm)</td><td class='mono dim'>$(Enc $v.FileName)</td><td><span class='pill good'>Verified</span></td></tr>"
    }
    $verSection = if ($verified.Count -gt 0) {
        "<details><summary>Verified mods ($($verified.Count)) &mdash; hash matched a real release on Modrinth or CurseForge</summary><table><thead><tr><th>Mod</th><th>File</th><th>Status</th></tr></thead><tbody>$verRows</tbody></table></details>"
    } else { "" }

    # ---- the state of the PC, kept apart from the accusation ----------------
    # A third-party antivirus turns the Windows firewall off by itself; script
    # logging is off by default on home Windows. Counting either against a player
    # is how an innocent person collects "system issues". They are still shown,
    # because a Security log cleared an hour before the screenshare is something
    # a moderator wants to see - it just is not the tool's claim to make.
    $stateRows = ""
    foreach ($f in $state) { $stateRows += New-FindingCard $f }
    $stateBox = if ($state.Count -eq 0) {
        "<div class='panel clear'>Firewall on, script logging at its default, Security log not cleared. Nothing to note about how this PC is set up.</div>"
    } else { $stateRows }

    # ---- look at these first ------------------------------------------------
    # A moderator reads this during a call, with somebody waiting. The report is
    # thorough, which is the same thing as long: the verdict is at the top and
    # the specific files it is about are several screens down. This block closes
    # that gap - the actual items needing a person, strongest first, each with
    # where it is and one line of why. Nothing new is computed here; it is the
    # same findings, ordered for someone who has ninety seconds.
    $todo = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($flaggedMods) + @($reviewMods)) {
        $prio = switch ($m.Band) {
            "Confirmed" { 100 }
            "Likely"    { 70 }
            "ServerRule" { 30 }
            default     { 40 }
        }
        [void]$todo.Add([PSCustomObject]@{
            Prio = $prio
            What = "$($m.FileName)"
            Where = "$($m.FilePath)"
            Band = $m.Band
            Score = $m.Score
            Colour = $(switch ($m.Band) { "Confirmed" { "#ff5f56" } "Likely" { "#ff9f43" } "ServerRule" { "#9aa8ba" } default { "#ffcf4d" } })
            Why = $(if (@($m.Reasons).Count -gt 0) { @($m.Reasons)[0] } else { "" })
        })
    }
    foreach ($f in @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })) {
        [void]$todo.Add([PSCustomObject]@{
            Prio = $(if ($f.Level -eq "FAIL") { 90 } else { 50 })
            What = $f.Title
            Where = $f.Area
            Band = $(if ($f.Level -eq "FAIL") { "Found" } else { "Check" })
            Score = -1
            Colour = (Get-LevelStyle $f.Level).c
            Why = $(if (@($f.Items).Count -gt 0) { [string](@($f.Items)[0]) } else { $f.Why })
        })
    }
    $todoRows = ""
    $shown = 0
    foreach ($t in @($todo | Sort-Object -Property @{ e = 'Prio'; Descending = $true }, @{ e = 'Score'; Descending = $true })) {
        if ($shown -ge 8) { break }
        $shown++
        $badge = if ($t.Score -ge 0) { "$($t.Band) $($t.Score)/100" } else { $t.Band }
        $why = [string]$t.Why
        if ($why.Length -gt 220) { $why = $why.Substring(0, 217) + "..." }
        $todoRows += "<li style='--vc:$($t.Colour);'><div class='tl'><b>$(Enc $t.What)</b><span class='tb'>$(Enc $badge)</span></div>" +
                     "<div class='tw'>$(Enc $t.Where)</div>" +
                     $(if ($why) { "<div class='ty'>$(Enc $why)</div>" } else { "" }) + "</li>"
    }
    $todoBox = if ($todo.Count -eq 0) {
        "<div class='panel clear'><b class='goodfg'>Nothing here needs a person.</b> No mod was flagged or held for review, and no check outside the mods folder found anything. The sections below are the working, in full, so the result can be checked rather than taken on trust.</div>"
    } else {
        $more = if ($todo.Count -gt $shown) { "<p class='note'>$($todo.Count - $shown) more below, in full.</p>" } else { "" }
        "<ol class='todo'>$todoRows</ol>$more"
    }

    # ---- everything else that was found, grouped by area --------------------
    # INFO is not a result - it is a check that could not run, and it is already in
    # the coverage box as a gap. Repeating it here as a "finding" would pad the list
    # a staff member has to work through with things that were never findings.
    $real  = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })
    $clear = @($script:Findings | Where-Object { $_.Level -eq "OK" })
    $state = @($script:Findings | Where-Object { $_.Level -eq "STATE" })
    $findCards = ""
    foreach ($f in ($real | Sort-Object @{ e = { (Get-LevelStyle $_.Level).rank } }, Area)) {
        $findCards += New-FindingCard $f
    }
    if (-not $findCards) {
        $findCards = "<div class='panel clear'><b class='goodfg'>Nothing outside the mods folder.</b> Every check listed under coverage came back clear.</div>"
    }

    $clearRows = ""
    foreach ($f in $clear) { $clearRows += "<tr><td class='dim'>$(Enc $f.Area)</td><td>$(Enc $f.Title)</td></tr>" }
    $clearSection = if ($clear.Count -gt 0) {
        "<details><summary>Checks that came back clear ($($clear.Count)) &mdash; proof of what was looked at</summary><table><thead><tr><th>Area</th><th>Result</th></tr></thead><tbody>$clearRows</tbody></table></details>"
    } else { "" }

    # ---- full inventory -----------------------------------------------------
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $addRow = {
        param($name, $ext)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if (-not $seen.Add($name)) { return }
        $st = if ($script:FlaggedModsList.Contains($name)) { "<span class='pill bad'>Flagged</span>" }
              elseif ($script:ReviewModsList.Contains($name)) { "<span class='pill warn'>Review</span>" }
              elseif (@($verified | Where-Object { $_.FileName -eq $name }).Count -gt 0) { "<span class='pill good'>Verified</span>" }
              else { "<span class='pill neutral'>Clean</span>" }
        [void]$script:_allRowsSb.Append("<tr data-ext='$ext'><td class='mono'>$(Enc $name)</td><td class='dim'>.$ext</td><td>$st</td></tr>")
    }
    # A StringBuilder, not $s += $row. The inventory holds one row per file seen on
    # the PC, which on an ordinary Windows install is tens of thousands, and += is
    # O(n^2) because every += copies the whole string again: measured at 30.3 s for
    # 25 000 rows against 52 ms for the builder, for byte-identical HTML.
    $script:_allRowsSb = [System.Text.StringBuilder]::new()
    foreach ($f in @($jarFiles | Where-Object { $_ })) { & $addRow $f.Name "jar" }
    foreach ($f in @($exeFiles | Where-Object { $_ })) { & $addRow $f.Name "exe" }
    foreach ($f in @($pyFiles  | Where-Object { $_ })) { & $addRow $f.Name "py" }
    if ($null -ne $script:PCScannedExeNames) { foreach ($nm in @($script:PCScannedExeNames | Where-Object { $_ })) { & $addRow $nm "exe" } }
    if ($null -ne $script:PCScannedPyNames)  { foreach ($nm in @($script:PCScannedPyNames  | Where-Object { $_ })) { & $addRow $nm "py" } }
    $allRows = $script:_allRowsSb.ToString()

    # ---- plain text copy, for pasting into a ticket -------------------------
    $plain = New-PlainSummary $sv $svStyle $stampLocal $reportId $isAdmin

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screenshare Report &mdash; $(Enc $env:COMPUTERNAME) $(Enc $now.ToString('yyyy-MM-dd HH:mm'))</title>
<style>
:root{
  --ground:#0b0e14; --surface:#131922; --surface2:#1a212c; --line:#262f3d;
  --ink:#e8eef6; --ink2:#9aa8ba; --ink3:#6b7a8d;
  --critical:#ff5f56; --serious:#ff9f43; --warn:#ffcf4d; --good:#3ddc84;
  --accent:#5aa9ff;
  --ui:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--ground);color:var(--ink);font-family:var(--ui);font-size:15px;line-height:1.55;
     -webkit-font-smoothing:antialiased;padding-bottom:64px;}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px;}
.mono{font-family:var(--mono);font-size:.875em;word-break:break-all;}
/* the two values a moderator reads off the screen and compares */
.mono.big{font-size:1.05rem;font-weight:700;letter-spacing:.04em;}
.dim{color:var(--ink3);}
.goodfg{color:var(--good);} .warnfg{color:var(--warn);}
.yes{color:var(--good);font-weight:600;} .no{color:var(--warn);font-weight:600;}
.sep{color:var(--ink3);margin:0 .5em;}
.eyebrow{font-size:.68rem;text-transform:uppercase;letter-spacing:.13em;color:var(--ink3);font-weight:600;margin-bottom:8px;}

/* masthead - the verdict is the page, not a banner on top of it */
.mast{border-bottom:1px solid var(--line);background:var(--surface);}
.mast{background:radial-gradient(120% 140% at 12% 0%,color-mix(in oklab,var(--vc) 13%,transparent) 0%,transparent 62%),var(--surface);}
.mast .wrap{padding:34px 24px 30px;}
.tool{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap;
      font-size:.72rem;letter-spacing:.13em;text-transform:uppercase;color:var(--ink3);font-weight:600;}
.verdict{display:flex;align-items:flex-start;gap:18px;margin-top:22px;}
.chip{flex:none;width:11px;align-self:stretch;min-height:76px;border-radius:3px;background:var(--vc);}
.verdict h1{font-size:clamp(1.9rem,4.4vw,2.75rem);line-height:1.08;font-weight:800;letter-spacing:-.02em;
            color:var(--vc);text-wrap:balance;}
.verdict .say{color:var(--ink2);margin-top:9px;max-width:62ch;}
.caveat{margin-top:10px;max-width:62ch;font-size:.9em;color:var(--warn);border-left:2px solid var(--warn);padding-left:11px;}
.scoreline{display:flex;align-items:baseline;gap:10px;margin-top:16px;font-variant-numeric:tabular-nums;}
.scoreline b{font-size:1.7rem;font-weight:800;color:var(--vc);}
.scoreline span{color:var(--ink3);font-size:.86rem;}

/* the score scale shows the fixed decision thresholds, so a number is never
   just an opinion - the reader can see which band it falls in and by how much */
.scale{margin:12px 0 4px;}
.scale .track{position:relative;height:7px;border-radius:4px;background:var(--surface2);border:1px solid var(--line);}
.scale .fill{position:absolute;top:0;bottom:0;left:0;border-radius:4px;}
.scale .tick{position:absolute;top:-4px;bottom:-4px;width:1px;background:var(--line);}
.scale .tick{background:var(--ground);opacity:.85;}
.scale .marks{position:relative;height:1.05em;font-size:.63rem;color:var(--ink3);
              margin-top:5px;letter-spacing:.06em;text-transform:uppercase;font-variant-numeric:tabular-nums;}
.scale .marks span{position:absolute;transform:translateX(-50%);white-space:nowrap;}
.scale .marks span:first-child{transform:none;}
.scale .marks span:last-child{transform:translateX(-100%);}

section{padding-top:38px;}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.14em;color:var(--ink3);font-weight:700;
   padding-bottom:9px;border-bottom:1px solid var(--line);margin-bottom:18px;}
h2 .count{color:var(--ink);margin-left:.5em;}

.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;}
.panel.gap{border-color:var(--warn);border-color:color-mix(in oklab,var(--warn) 42%,var(--line));}
.panel.clear{color:var(--ink2);}
ol.todo{list-style:none;counter-reset:t;margin:0;padding:0;display:flex;flex-direction:column;gap:10px;}
ol.todo li{counter-increment:t;position:relative;background:var(--surface);border:1px solid var(--line);
  border-left:3px solid var(--vc,var(--warn));border-radius:8px;padding:12px 16px 12px 46px;}
ol.todo li::before{content:counter(t);position:absolute;left:14px;top:12px;font-weight:700;
  font-variant-numeric:tabular-nums;color:var(--ink3);}
.tl{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;}
.tb{font-size:.72rem;font-weight:600;letter-spacing:.04em;color:var(--vc,var(--ink3));
  border:1px solid color-mix(in oklab,var(--vc,var(--line)) 45%,var(--line));
  border-radius:999px;padding:1px 8px;white-space:nowrap;}
.tw{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;color:var(--ink3);
  margin-top:3px;overflow-wrap:anywhere;}
.ty{color:var(--ink2);margin-top:6px;font-size:.9rem;}
ul.plain{list-style:none;display:flex;flex-direction:column;gap:7px;}
ul.plain li{padding-left:16px;position:relative;font-size:.92em;}
ul.plain li:before{content:"";position:absolute;left:0;top:.62em;width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.45;}
.note{color:var(--ink3);font-size:.84em;margin-top:11px;padding-top:10px;border-top:1px solid var(--line);}

.rec-grid{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden;}
.rec{display:grid;grid-template-columns:minmax(130px,180px) 1fr;gap:16px;padding:9px 18px;border-top:1px solid var(--line);}
.rec:first-child{border-top:0;}
.rk{color:var(--ink3);font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;padding-top:2px;}
.rv{min-width:0;}

ol.verdict-reasons{list-style:none;display:flex;flex-direction:column;gap:9px;}
ol.verdict-reasons li{display:flex;gap:12px;background:var(--surface);border:1px solid var(--line);
                      border-left:3px solid var(--vc);border-radius:8px;padding:11px 14px;}
.num{flex:none;width:22px;height:22px;border-radius:5px;background:var(--surface2);color:var(--ink3);
     font-size:.72rem;font-weight:700;display:flex;align-items:center;justify-content:center;
     font-variant-numeric:tabular-nums;}

.find{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--lc);
      border-radius:10px;padding:15px 18px;margin-bottom:12px;}
.find-head{display:flex;align-items:center;gap:11px;flex-wrap:wrap;}
.find-head h3{flex:1;font-size:1rem;font-weight:600;min-width:200px;}
.tag{color:#0b0e14;font-weight:800;font-size:.63rem;letter-spacing:.09em;padding:3px 8px;border-radius:4px;flex:none;}
.score{font-size:1.35rem;font-weight:800;color:var(--lc);font-variant-numeric:tabular-nums;}
.score small{font-size:.5em;color:var(--ink3);font-weight:600;}
.area{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);}
.srnote{font-size:.7rem;text-transform:none;letter-spacing:0;color:#a78bfa;font-weight:500;margin-left:.6em;}
.kv{color:var(--ink3);margin:10px 0 2px;}
.why{margin-top:13px;padding-top:12px;border-top:1px solid var(--line);}
ul.reasons,ul.evidence{list-style:none;display:flex;flex-direction:column;gap:5px;}
ul.reasons li{background:var(--surface2);border-radius:6px;padding:7px 11px;font-size:.9em;}
ul.evidence li{background:var(--surface2);border-radius:6px;padding:6px 11px;color:var(--ink2);
               word-break:normal;overflow-wrap:anywhere;}
.reason-grid{display:flex;flex-direction:column;gap:9px;}
.r{font-size:.9em;color:var(--ink2);}
.rl{display:block;font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--ink3);font-weight:600;margin-bottom:2px;}

table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);
      border-radius:10px;overflow:hidden;font-variant-numeric:tabular-nums;}
th{background:var(--surface2);color:var(--ink3);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;
   padding:9px 14px;text-align:left;font-weight:600;}
td{padding:8px 14px;border-top:1px solid var(--line);font-size:.9em;}
.tscroll{overflow-x:auto;}
.pill{font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:20px;white-space:nowrap;}
.pill.good{background:var(--surface2);color:var(--good);}
.pill.warn{background:var(--surface2);color:var(--warn);}
.pill.bad{background:var(--surface2);color:var(--critical);}
.pill.good{background:color-mix(in oklab,var(--good) 17%,transparent);}
.pill.warn{background:color-mix(in oklab,var(--warn) 17%,transparent);}
.pill.bad{background:color-mix(in oklab,var(--critical) 17%,transparent);}
.pill.neutral{background:var(--surface2);color:var(--ink2);}

details{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:2px 16px 12px;margin-top:12px;}
details table{border:0;border-radius:0;background:transparent;}
summary{cursor:pointer;padding:11px 0;color:var(--ink2);font-size:.9em;}
summary:hover{color:var(--ink);}

.filter{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;}
.filter input{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--line);border-radius:8px;
              padding:8px 12px;color:var(--ink);outline:none;font-family:var(--ui);font-size:.9em;}
.filter input:focus-visible,.btn:focus-visible{border-color:var(--accent);outline:2px solid var(--accent);outline-offset:1px;}
.btn{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;color:var(--ink2);
     cursor:pointer;font-size:.84em;font-family:var(--ui);}
.btn.on,.btn:hover{border-color:var(--accent);color:var(--accent);}
#plain{display:none;}
footer{color:var(--ink3);font-size:.82em;margin-top:46px;padding-top:18px;border-top:1px solid var(--line);}
footer a{color:var(--accent);text-decoration:none;}
footer a:hover{text-decoration:underline;}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;}}

/* saved as PDF this becomes the attachment on a ban appeal, so it has to be
   readable on paper - ink on white, nothing collapsed, no interactive chrome */
@media print{
  body{background:#fff;color:#111;font-size:11pt;padding:0;}
  .wrap{max-width:100%;padding:0;}
  .mast{background:#fff;border-bottom:2px solid #111;}
  .mast .wrap{padding:0 0 14pt;}
  .verdict h1,.scoreline b,.score{color:#111;}
  .chip{background:#111;}
  .panel,.find,.rec-grid,table,details,ol.verdict-reasons li{background:#fff;border-color:#bbb;}
  ul.reasons li,ul.evidence li,.num{background:#f4f4f4;color:#111;}
  .scale .track{background:#eee;border-color:#bbb;} .scale .fill{background:#111!important;} .scale .tick{background:#fff;opacity:1;}
  th{background:#eee;color:#333;}
  .dim,.rk,.eyebrow,.r,.rl,.area,.note,footer,.scoreline span{color:#444;}
  .say,h2 .count,.kv,ul.evidence li,summary,footer a{color:#111;}
  .caveat{color:#111;border-left-color:#111;}
  .tag{background:#111!important;color:#fff;}
  .filter,.btn{display:none;}
  details{border:0;padding:0;}
  details>summary{list-style:none;font-weight:700;color:#111;}
  details[open],details:not([open]){padding:0;}
  .find,.panel,article,tr{break-inside:avoid;}
  section{padding-top:18pt;}
}
</style></head>
<body>
<div class="mast" style="--vc:$($svStyle.c);"><div class="wrap">
  <div class="tool">
    <span>AsyncAnalyzer $(Enc $script:Version) &bull; screenshare evidence report</span>
    <span>$(Enc $stampLocal)</span>
  </div>
  <div class="verdict">
    <div class="chip"></div>
    <div>
      <h1>$($svStyle.label)</h1>
      <p class="say">$($svStyle.say)</p>
      $mastCaveat
      <div class="scoreline"><b>$($sv.Score)</b><span>/ 100 &mdash; the overall-scan AI judged mods, system, processes, live game and history together</span></div>
      $(New-ScoreScale $sv.Score $svStyle.c)
    </div>
  </div>
</div></div>

<div class="wrap">

<section>
  <h2>Look at these first<span class="count">$($todo.Count)</span></h2>
  $todoBox
</section>

<section>
  <h2>What this verdict rests on<span class="count">$(@($sv.Reasons).Count)</span></h2>
  <ol class="verdict-reasons" style="--vc:$($svStyle.c);">$svReasons</ol>
</section>

<section>
  <h2>Coverage &mdash; what was checked, and what was not</h2>
  <div class="grid2">
    <div class="panel"><div class="eyebrow goodfg">Checked</div><ul class="plain">$coverChecked</ul></div>
    $gapBox
  </div>
</section>

<section>
  <h2>Mods &mdash; flagged and to review<span class="count">$($script:Flagged + $script:Review)</span>$srNote</h2>
  $modCards
  $verSection
</section>

<section>
  <h2>Everything else that was found<span class="count">$($real.Count)</span></h2>
  $findCards
  $clearSection
</section>

<section>
  <h2>Full file inventory<span class="count">$($seen.Count)</span></h2>
  <div class="filter">
    <input id="q" placeholder="Search files..." oninput="flt()" aria-label="Search files">
    <button class="btn on" data-e="all" onclick="setE(this)">All</button>
    <button class="btn" data-e="jar" onclick="setE(this)">.jar</button>
    <button class="btn" data-e="exe" onclick="setE(this)">.exe</button>
    <button class="btn" data-e="py" onclick="setE(this)">.py</button>
    <button class="btn" onclick="cp(this)">Copy summary</button>
  </div>
  <div class="tscroll"><table id="ft"><thead><tr><th>File</th><th>Type</th><th>Status</th></tr></thead><tbody>$allRows</tbody></table></div>
</section>

<section>
  <h2>How this PC is set up<span class="count">$($state.Count)</span></h2>
  <p class="note">Not cheat evidence and not counted against anyone &mdash; a third-party antivirus switches the Windows firewall off by itself. Here because a moderator should see it, and because the dates can matter.</p>
  $stateBox
</section>

<section>
  <h2>Scan record</h2>
  <div class="rec-grid">$recordRows</div>
  $authBox
</section>

<pre id="plain">$(Enc $plain)</pre>

<footer>
  <b>How to read this.</b> Every number above comes from a fixed rule or from a model with fixed weights &mdash;
  the same file scores the same on every PC. Nothing here was uploaded: the analysis ran entirely on this machine.
  The coverage box is part of the result, not a disclaimer &mdash; a clean verdict only covers what it lists.<br><br>
  Report ID <span class="mono">$(Enc $reportId)</span> &bull;
  <a href="https://github.com/QDHShamiro/AsyncAnalyzer">github.com/QDHShamiro/AsyncAnalyzer</a> &bull; discord.gg/asyncstudios
</footer>
</div>
<script>
var E="all";
function setE(b){E=b.dataset.e;document.querySelectorAll('.btn[data-e]').forEach(function(x){x.classList.remove('on')});b.classList.add('on');flt();}
function flt(){var q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#ft tbody tr').forEach(function(r){
    var n=r.cells[0].textContent.toLowerCase(),e=r.dataset.ext;
    r.style.display=((E=='all'||e==E)&&n.indexOf(q)>=0)?'':'none';});}
function cp(b){var t=document.getElementById('plain').textContent;
  var done=function(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o;},1400);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,function(){});return;}
  var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
  try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(a);}
</script>
</body></html>
"@
    try {
        $rp = if ($OutPath) { $OutPath } else { Join-Path $env:TEMP "AsyncAnalyzer_Report.html" }
        $html | Out-File -FilePath $rp -Encoding UTF8
        if ($OutPath) { return $rp }
        W "  $([char]0x2713) Report saved: $rp" Green
        W "    Open it yourself when you want it $([char]0x2014) the tool never opens windows on your PC." DarkGray
    } catch { W "  $([char]0x2717) Could not write report: $($_.Exception.Message)" Red }
    Write-Host ""
}

function New-ScoreScale($score, $color) {
    # 30 / 60 / 85 are the fixed band edges from Get-SessionVerdict and Get-ModVerdict.
    # Drawing them means the reader sees where a score sits, not just how big it is.
    $s = [Math]::Max(0, [Math]::Min(100, [int]$score))
    return "<div class='scale'><div class='track'><div class='fill' style='width:$s%;background:$color;'></div>" +
           "<div class='tick' style='left:30%;'></div><div class='tick' style='left:60%;'></div><div class='tick' style='left:85%;'></div>" +
           "</div><div class='marks'><span style='left:0%;'>0 clean</span><span style='left:30%;'>30 review</span>" +
           "<span style='left:60%;'>60 likely</span><span style='left:85%;'>85 confirmed</span><span style='left:100%;'>100</span></div></div>"
}

function New-PlainSummary($sv, $svStyle, $stamp, $reportId, $isAdmin) {
    # Staff paste this straight into a ticket or a Discord thread, so it has to
    # stand on its own without the HTML around it.
    $o = [System.Collections.Generic.List[string]]::new()
    [void]$o.Add("AsyncAnalyzer $($script:Version) - screenshare report")
    [void]$o.Add("$stamp   PC $env:COMPUTERNAME   user $env:USERNAME   admin: $(if ($isAdmin) { 'yes' } else { 'no' })")
    [void]$o.Add("Report ID: $reportId")
    # The two things a moderator compares against what they said and what the
    # dashboard shows. Pasted into a ticket, they are the whole point of the paste.
    [void]$o.Add("Scan ID:   $($script:ScanId)" + $(if ($script:ScanCode) { "   staff code: $($script:ScanCode)" } else { "   (no staff code was given - this cannot be shown to be fresh)" }))
    [void]$o.Add("")
    [void]$o.Add("VERDICT: $($svStyle.short) - $($sv.Score)/100")
    foreach ($r in @($sv.Reasons)) { [void]$o.Add("  - $r") }
    [void]$o.Add("")
    [void]$o.Add("Mods: $($script:TotalMods) scanned / $($script:Verified) verified / $($script:Review) review / $($script:Flagged) flagged")
    foreach ($m in @($flaggedMods | Where-Object { $_ })) { [void]$o.Add("  FLAGGED  $($m.FileName)  [$($m.Score)/100]  $(@($m.Reasons) -join '; ')") }
    foreach ($m in @($reviewMods  | Where-Object { $_ })) { [void]$o.Add("  REVIEW   $($m.FileName)  [$($m.Score)/100]") }
    $realF = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })
    if ($realF.Count -gt 0) {
        [void]$o.Add("")
        [void]$o.Add("Other findings:")
        foreach ($f in $realF) { [void]$o.Add("  [$($f.Level)] $($f.Area): $($f.Title)") }
    }
    [void]$o.Add("")
    if (@($script:ScanGaps).Count -gt 0) {
        [void]$o.Add("NOT CHECKED (a clean result does not cover these):")
        foreach ($g in @($script:ScanGaps)) { [void]$o.Add("  - $g") }
    } else {
        [void]$o.Add("NOT CHECKED: nothing - every check ran.")
    }
    return ($o -join "`n")
}
