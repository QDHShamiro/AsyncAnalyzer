function New-HtmlReport {
    $bandMeta = @{
        "Confirmed" = @{ c = "#f85149"; l = "CONFIRMED CHEAT" }
        "Likely"    = @{ c = "#fb8500"; l = "LIKELY CHEAT" }
        "Review"    = @{ c = "#e3b341"; l = "REVIEW" }
        "Clean"     = @{ c = "#2ecc71"; l = "CLEAN" }
    }

    $mods = @()
    $mods += @($flaggedMods)
    $mods += @($reviewMods)
    $mods = @($mods | Sort-Object Score -Descending)

    $modCards = ""
    foreach ($m in $mods) {
        $bm = $bandMeta[$m.Band]; if (-not $bm) { $bm = $bandMeta["Review"] }
        $reasonItems = ""
        foreach ($r in @($m.Reasons)) { $reasonItems += "<li>$(Enc $r)</li>" }
        $src = if ($m.DownloadSource) { "Source: $(Enc $m.DownloadSource)" } else { "" }
        $sha = if ($m.Hash) { $m.Hash } else { "unknown" }
        $modCards += @"
<div class="mod" style="--band:$($bm.c);">
  <div class="mod-head">
    <span class="badge" style="background:$($bm.c);">$($bm.l)</span>
    <span class="mod-name">$(Enc $m.FileName)</span>
    <span class="mod-score">$($m.Score)<small>/100</small></span>
  </div>
  <div class="bar"><div class="bar-fill" style="width:$($m.Score)%;background:$($bm.c);"></div></div>
  <div class="mod-meta">AI cheat probability $($m.Probability)% &nbsp;&bull;&nbsp; SHA1 $sha &nbsp; $src</div>
  <ul class="reasons">$reasonItems</ul>
</div>
"@
    }
    if (-not $modCards) { $modCards = "<p class='ok-big'>&#10003; No cheats and nothing suspicious &mdash; every mod is clean or verified.</p>" }

    $verRows = ""
    foreach ($v in @($verifiedMods)) {
        $nm = if ($v.ModName) { $v.ModName } else { $v.FileName }
        $verRows += "<tr><td>$(Enc $nm)</td><td class='muted'>$(Enc $v.FileName)</td><td><span class='pill green'>Verified</span></td></tr>"
    }
    $verSection = if (@($verifiedMods).Count -gt 0) {
        "<details open><summary>Verified mods ($(@($verifiedMods).Count)) &mdash; matched on Modrinth / CurseForge, guaranteed safe</summary><table><thead><tr><th>Mod</th><th>File</th><th>Status</th></tr></thead><tbody>$verRows</tbody></table></details>"
    } else { "" }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allRows = ""
    $addRow = {
        param($name, $ext)
        if (-not $seen.Add($name)) { return }
        $st = if ($script:FlaggedModsList.Contains($name)) { "<span class='pill red'>Flagged</span>" }
              elseif ($script:ReviewModsList.Contains($name)) { "<span class='pill amber'>Review</span>" }
              elseif (@($verifiedMods | Where-Object { $_.FileName -eq $name }).Count -gt 0) { "<span class='pill green'>Verified</span>" }
              else { "<span class='pill green'>Clean</span>" }
        $script:_allRows += "<tr data-ext='$ext'><td>$(Enc $name)</td><td class='muted'>.$ext</td><td>$st</td></tr>"
    }
    $script:_allRows = ""
    foreach ($f in @($jarFiles)) { & $addRow $f.Name "jar" }
    foreach ($f in @($exeFiles)) { & $addRow $f.Name "exe" }
    foreach ($f in @($pyFiles))  { & $addRow $f.Name "py" }
    if ($null -ne $script:PCScannedExeNames) { foreach ($n in $script:PCScannedExeNames) { & $addRow $n "exe" } }
    if ($null -ne $script:PCScannedPyNames)  { foreach ($n in $script:PCScannedPyNames)  { & $addRow $n "py" } }
    $allRows = $script:_allRows

    $bamSection = ""
    if (@($script:BamDeleted).Count -gt 0) {
        $bamRows = ""
        foreach ($de in @($script:BamDeleted)) { $bamRows += "<tr><td>$(Enc $de.FileName)</td><td class='muted'>$(Enc $de.Path)</td><td>$(Enc $de.Time)</td></tr>" }
        $bamSection = "<h2>&#9888; Deleted executables (BAM history) &mdash; $(@($script:BamDeleted).Count)</h2><p class='muted'>Ran on this PC but no longer on disk.</p><table><thead><tr><th>File</th><th>Path</th><th>Last run</th></tr></thead><tbody>$bamRows</tbody></table>"
    }

    if ($script:Flagged -gt 0) { $vColor = "#f85149"; $vText = "$($script:Flagged) likely cheat$(if($script:Flagged -ne 1){'s'}) found"; $vIcon = "&#9888;" }
    elseif ($script:Review -gt 0) { $vColor = "#e3b341"; $vText = "$($script:Review) mod$(if($script:Review -ne 1){'s'}) to review"; $vIcon = "&#9873;" }
    else { $vColor = "#2ecc71"; $vText = "Clean &mdash; no cheats detected"; $vIcon = "&#10003;" }

    $sv = Get-SessionVerdictCached
    $svColor = switch ($sv.Band) { "Confirmed" { "#f85149" } "Likely" { "#fb8500" } "Review" { "#e3b341" } default { "#2ecc71" } }
    $svLabel = switch ($sv.Band) { "Confirmed" { "CHEATING CONFIRMED" } "Likely" { "LIKELY CHEATING" } "Review" { "NEEDS A MANUAL LOOK" } default { "CLEAN &mdash; NOTHING FOUND" } }
    $svReasons = ""
    foreach ($r in @($sv.Reasons)) { $svReasons += "<li>$(Enc $r)</li>" }
    $overallSection = @"
<div class="mod" style="--band:$svColor;">
  <div class="mod-head">
    <span class="badge" style="background:$svColor;">OVERALL SCAN VERDICT</span>
    <span class="mod-name">$svLabel</span>
    <span class="mod-score">$($sv.Score)<small>/100</small></span>
  </div>
  <div class="bar"><div class="bar-fill" style="width:$($sv.Score)%;background:$svColor;"></div></div>
  <div class="mod-meta">The AI judged the WHOLE scan &mdash; mods, system checks, processes, JVM and history &mdash; not just single files. AI probability $($sv.Probability)%</div>
  <ul class="reasons">$svReasons</ul>
</div>
"@

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm"
    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AsyncAnalyzer Report</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.5;padding:0 0 60px;}
.wrap{max-width:960px;margin:0 auto;padding:0 20px;}
.hero{background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid var(--border);padding:40px 0 30px;margin-bottom:28px;}
.brand{color:var(--muted);font-size:.85em;letter-spacing:.14em;text-transform:uppercase;}
.verdict{display:flex;align-items:center;gap:16px;margin:14px 0 6px;}
.verdict .dot{width:14px;height:14px;border-radius:50%;box-shadow:0 0 14px var(--vc);background:var(--vc);}
.verdict h1{font-size:2em;font-weight:800;color:var(--vc);}
.sub{color:var(--muted);font-size:.9em;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin:26px 0;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 16px;text-align:center;}
.card .n{font-size:2em;font-weight:800;line-height:1;}
.card .k{color:var(--muted);font-size:.78em;margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.green{color:#2ecc71;}.amber{color:#e3b341;}.red{color:#f85149;}.blue{color:var(--accent);}
h2{font-size:1.15em;margin:34px 0 14px;padding-top:10px;}
.mod{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--band);border-radius:12px;padding:18px;margin-bottom:14px;}
.mod-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.badge{color:#0d1117;font-weight:800;font-size:.7em;letter-spacing:.06em;padding:4px 9px;border-radius:6px;}
.mod-name{font-weight:600;flex:1;word-break:break-all;}
.mod-score{font-size:1.5em;font-weight:800;color:var(--band);}
.mod-score small{font-size:.5em;color:var(--muted);font-weight:600;}
.bar{height:8px;background:var(--surface2);border-radius:6px;overflow:hidden;margin:12px 0;}
.bar-fill{height:100%;border-radius:6px;transition:width .6s;}
.mod-meta{color:var(--muted);font-size:.8em;font-family:ui-monospace,Consolas,monospace;word-break:break-all;margin-bottom:8px;}
.reasons{list-style:none;display:flex;flex-direction:column;gap:5px;}
.reasons li{background:var(--surface2);border-radius:6px;padding:6px 10px;font-size:.86em;}
.reasons li:before{content:'\25B8';color:var(--accent);margin-right:8px;}
.ok-big{color:#2ecc71;font-size:1.3em;font-weight:700;padding:26px;text-align:center;background:var(--surface);border:1px solid var(--border);border-radius:12px;}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-top:10px;}
th{background:var(--surface2);color:var(--muted);font-size:.72em;text-transform:uppercase;letter-spacing:.06em;padding:11px 14px;text-align:left;}
td{padding:10px 14px;border-top:1px solid var(--border);font-size:.88em;}
.muted{color:var(--muted);}
.pill{font-size:.75em;font-weight:700;padding:3px 9px;border-radius:20px;}
.pill.green{background:rgba(46,204,113,.15);color:#2ecc71;}
.pill.amber{background:rgba(227,179,65,.15);color:#e3b341;}
.pill.red{background:rgba(248,81,73,.15);color:#f85149;}
details{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:6px 16px;margin-top:10px;}
summary{cursor:pointer;padding:10px 0;color:var(--muted);font-size:.9em;}
.filter{display:flex;gap:8px;margin:14px 0;flex-wrap:wrap;}
.filter input{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:9px 12px;color:var(--text);outline:none;}
.filter input:focus{border-color:var(--accent);}
.fbtn{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:9px 15px;color:var(--muted);cursor:pointer;font-size:.85em;}
.fbtn.on,.fbtn:hover{border-color:var(--accent);color:var(--accent);}
footer{color:var(--muted);font-size:.82em;text-align:center;margin-top:44px;padding-top:20px;border-top:1px solid var(--border);}
footer a{color:var(--accent);text-decoration:none;}
</style></head>
<body>
<div class="hero"><div class="wrap">
  <div class="brand">AsyncAnalyzer v$($script:Version) &bull; self-improving AI cheat scan</div>
  <div class="verdict" style="--vc:$vColor;"><span class="dot"></span><h1>$vIcon $vText</h1></div>
  <div class="sub">$scanDate &nbsp;&bull;&nbsp; $(Enc $ModPath)</div>
</div></div>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="n">$($script:TotalMods)</div><div class="k">Mods scanned</div></div>
    <div class="card"><div class="n green">$($script:Verified)</div><div class="k">Verified</div></div>
    <div class="card"><div class="n">$($script:Unknown)</div><div class="k">Clean / Unknown</div></div>
    <div class="card"><div class="n amber">$($script:Review)</div><div class="k">Review</div></div>
    <div class="card"><div class="n red">$($script:Flagged)</div><div class="k">Flagged</div></div>
    <div class="card"><div class="n $(if($script:SystemIssues -gt 0){'red'}else{'green'})">$($script:SystemIssues)</div><div class="k">System issues</div></div>
    <div class="card"><div class="n blue">$($script:mlSamples)</div><div class="k">AI learned (v$($script:mlModelVersion))</div></div>
  </div>

  $overallSection

  <h2>Flagged &amp; review</h2>
  $modCards

  $verSection

  <h2>All files ($(@($seen).Count))</h2>
  <div class="filter">
    <input id="q" placeholder="Search files..." oninput="flt()">
    <button class="fbtn on" data-e="all" onclick="setE(this)">All</button>
    <button class="fbtn" data-e="jar" onclick="setE(this)">.jar</button>
    <button class="fbtn" data-e="exe" onclick="setE(this)">.exe</button>
    <button class="fbtn" data-e="py" onclick="setE(this)">.py</button>
  </div>
  <table id="ft"><thead><tr><th>File</th><th>Type</th><th>Status</th></tr></thead><tbody>$allRows</tbody></table>

  $bamSection

  <footer>
    Generated by <b>AsyncAnalyzer</b> &mdash; a local, self-improving AI that learns from every scan.<br>
    No files were uploaded. <a href="https://github.com/QDHShamiro/AsyncAnalyzer">github.com/QDHShamiro/AsyncAnalyzer</a> &bull; discord.gg/asyncstudios
  </footer>
</div>
<script>
var E="all";
function setE(b){E=b.dataset.e;document.querySelectorAll('.fbtn').forEach(function(x){x.classList.remove('on')});b.classList.add('on');flt();}
function flt(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#ft tbody tr').forEach(function(r){var n=r.cells[0].textContent.toLowerCase();var e=r.dataset.ext;r.style.display=((E=='all'||e==E)&&n.indexOf(q)>=0)?'':'none';});}
</script>
</body></html>
"@
    try {
        $rp = Join-Path $env:TEMP "AsyncAnalyzer_Report.html"
        $html | Out-File -FilePath $rp -Encoding UTF8
        W "  $([char]0x2713) Report saved: $rp" Green
        W "    Open it yourself when you want it $([char]0x2014) the tool never opens windows on your PC." DarkGray
    } catch { W "  $([char]0x2717) Could not write report: $($_.Exception.Message)" Red }
    Write-Host ""
}
