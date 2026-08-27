function Add-ScanGap([string]$What) {
    if (-not $script:ScanGaps.Contains($What)) { [void]$script:ScanGaps.Add($What) }
}

function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-SelfElevate {
    # Without admin the BAM history (which executables ran and were then deleted),
    # the Defender exclusion list and scheduled tasks cannot be read - and those are
    # exactly what a screenshare check needs. So ask Windows for elevation once.
    if ($script:NoElevate -or $script:_DevMode -or $script:SelfTestMode) { return $false }
    if (Test-IsAdmin) { return $false }

    W "  $([char]0x2139) Some checks need Administrator: which programs ran and were deleted" DarkGray
    W "    (BAM), Defender exclusions and scheduled tasks. Asking Windows for it now." DarkGray
    W "    Windows will show a UAC prompt. Decline and the scan simply continues" DarkGray
    W "    without those checks $([char]0x2014) it is not required. Use -NoElevate to skip asking." DarkGray
    Write-Host ""
    try {
        # The one-liner has no file on disk, so the elevated process re-fetches the
        # script. Say so plainly rather than doing it quietly.
        $flags = @()
        if ($script:DeepScan)   { $flags += '-DeepScan' }
        if ($script:Deep)       { $flags += '-Deep' }
        if ($script:DeepMemory) { $flags += '-DeepMemory' }
        if ($script:NoUpdate)   { $flags += '-NoUpdate' }
        if ($script:NoLearn)    { $flags += '-NoLearn' }
        if ($script:Share)      { $flags += '-Share' }
        $flags += '-NoElevate'          # the elevated run must never try to elevate again
        $url = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1"
        $inner = "& ([scriptblock]::Create((irm '$url'))) " + ($flags -join ' ')
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $inner) -ErrorAction Stop
        W "  $([char]0x2713) Continuing in the elevated window." Green
        return $true
    } catch {
        Add-ScanGap "Ran without Administrator $([char]0x2014) deleted-program history (BAM), Defender exclusions and scheduled tasks were NOT checked"
        W "  $([char]0x2139) Continuing without Administrator." DarkGray
        Write-Host ""
        return $false
    }
}

function Request-DeepEscalation([string]$Reason) {
    # Something turned up, so look harder for the rest of the run. This widens the
    # SEARCH only - it never lowers a scoring threshold, because that is how a
    # detector starts inventing false flags.
    if ($script:Deep -and $script:DeepScan) { return }
    $script:Deep         = $true
    $script:DeepScan     = $true
    $script:BcMaxClasses = 400
    if (-not $script:Escalated) {
        $script:Escalated = $true
        Write-Host ""
        W "  $([char]0x25B2) Going deeper by itself $([char]0x2014) $Reason" Yellow
        W "    (searching harder from here on; the scoring rules are unchanged)" DarkGray
        Write-Host ""
    }
}

function Set-AutoDepth {
    # Minecraft running means someone is being checked right now, so be thorough.
    # Nothing running means this is a self-check, so stay quick.
    $running = @(Get-Process -Name javaw, java -ErrorAction SilentlyContinue).Count -gt 0
    if ($running) {
        $script:Deep         = $true
        $script:DeepScan     = $true
        $script:BcMaxClasses = 400
        W "  $([char]0x25CF) Minecraft is running $([char]0x2014) running the full check by itself." Cyan
    } else {
        Add-ScanGap "Minecraft was not running $([char]0x2014) an injected client leaves nothing to find once the game is closed"
        W "  $([char]0x25CF) Minecraft is not running $([char]0x2014) quick check. It goes deeper on its own if anything turns up." DarkGray
    }
    Write-Host ""
    return $running
}

function Get-LearnPath {
    $dir = Join-Path $env:APPDATA "AsyncAnalyzer"
    if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch {} }
    return (Join-Path $dir "learned.json")
}

function Load-LearnState {
    if ($script:Reset) {
        try { $rp = Get-LearnPath; if (Test-Path $rp) { Remove-Item $rp -Force } } catch {}
        return
    }
    try {
        $lp = Get-LearnPath
        if (-not (Test-Path $lp)) { return }
        $st = Get-Content -Raw $lp -ErrorAction Stop | ConvertFrom-Json
        if ($st.knownGood)  { foreach ($h in $st.knownGood)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        if ($st.goodMeta)   { foreach ($gp in $st.goodMeta.PSObject.Properties) { $script:goodMeta[$gp.Name] = [string]$gp.Value } }
        if ($st.knownCheat) { foreach ($h in $st.knownCheat) { [void]$script:knownCheatHashes.Add([string]$h) } }
        if ($st.weights -and $st.modelVersion -ge $script:mlModelVersion) {
            foreach ($k in $script:mlFeatureOrder) {
                $wv = $st.weights.$k
                if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv }
            }
            if ($null -ne $st.intercept) { $script:mlIntercept = [double]$st.intercept }
            if ($null -ne $st.samples)   { $script:mlSamples = [int]$st.samples }
        }
        if ($st.sweights -and $st.sessionModelVersion -ge $script:smModelVersion) {
            foreach ($k in $script:smFeatureOrder) {
                $sv = $st.sweights.$k
                if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv }
            }
            if ($null -ne $st.sintercept) { $script:smIntercept = [double]$st.sintercept }
            if ($null -ne $st.ssamples)   { $script:smSamples = [int]$st.ssamples }
        }
    } catch {}
}

function Save-LearnState {
    try {
        $wobj = @{}
        foreach ($k in $script:mlFeatureOrder) { $wobj[$k] = [Math]::Round([double]$script:mlWeights[$k], 6) }
        $swobj = @{}
        foreach ($k in $script:smFeatureOrder) { $swobj[$k] = [Math]::Round([double]$script:smWeights[$k], 6) }
        $obj = [ordered]@{
            v = 1
            modelVersion = $script:mlModelVersion
            intercept = [Math]::Round([double]$script:mlIntercept, 6)
            weights = $wobj
            knownGood = @($script:knownGoodHashes)
            goodMeta = $script:goodMeta
            knownCheat = @($script:knownCheatHashes)
            samples = $script:mlSamples
            sessionModelVersion = $script:smModelVersion
            sintercept = [Math]::Round([double]$script:smIntercept, 6)
            sweights = $swobj
            ssamples = $script:smSamples
            updated = (Get-Date).ToString("s")
        }
        ($obj | ConvertTo-Json -Depth 5) | Out-File -FilePath (Get-LearnPath) -Encoding UTF8
    } catch {}
}

function Update-ModelOnline($raw, $label) {
    if ($script:NoLearn) { return }
    try {
        $lr = 0.08; $l2 = 0.02; $clamp = 8.0
        $z = [double]$script:mlIntercept
        foreach ($k in $script:mlFeatureOrder) { $z += [double]$script:mlWeights[$k] * [double]$raw[$k] }
        $p = if ($z -lt -60) { 0.0 } elseif ($z -gt 60) { 1.0 } else { 1.0 / (1.0 + [Math]::Exp(-$z)) }
        $err = $p - $label
        foreach ($k in $script:mlFeatureOrder) {
            $w = [double]$script:mlWeights[$k] - $lr * ($err * [double]$raw[$k] + $l2 * ([double]$script:mlWeights[$k] - [double]$script:mlBaseWeights[$k]))
            if ($w -gt $clamp) { $w = $clamp } elseif ($w -lt (-$clamp)) { $w = -$clamp }
            $script:mlWeights[$k] = $w
        }
        $script:mlIntercept = [double]$script:mlIntercept - $lr * ($err + $l2 * ([double]$script:mlIntercept - [double]$script:mlBaseIntercept))
        $script:mlSamples++
    } catch {}
}


# ---------------------------------------------------------------------------
# Session AI ("overall scan" model) - the SECOND model.
# The mod model scores ONE jar. This one scores the WHOLE scan: the mods plus
# every other stage (system checks, JVM injection, cheat processes, deleted
# executables, stray jars, cheat folders). It answers "does this PC look like
# someone is cheating?", not just "is this one file a cheat?" - and it learns
# from every finished scan, locally and (with team mode) across everyone.
# Source of truth for the weights: ml/session_model.py -> ml/session_model.json
# ---------------------------------------------------------------------------
$script:smModelVersion = 2
$script:smFeatureOrder = @('flagged_ratio','review_ratio','unverified_ratio','random_ratio','cheatsite_dl','hard_confirmed','sys_issues','jvm_inject','bam_deleted','cheat_procs','stray_jars','cheat_folders','deleted_jars','mc_running','mem_client')
$script:smIntercept = -4.0
$script:smWeights = @{
    'flagged_ratio' = 4.0
    'review_ratio' = 1.2
    'unverified_ratio' = 0.8
    'random_ratio' = 1.5
    'cheatsite_dl' = 3.0
    'hard_confirmed' = 4.5
    'sys_issues' = 1.2
    'jvm_inject' = 3.0
    'bam_deleted' = 1.0
    'cheat_procs' = 3.5
    'stray_jars' = 2.0
    'cheat_folders' = 3.0
    'deleted_jars' = 2.5
    'mc_running' = 0.0
    'mem_client' = 5.0
}
$script:smBaseWeights = @{}
foreach ($smk in $script:smWeights.Keys) { $script:smBaseWeights[$smk] = $script:smWeights[$smk] }
$script:smBaseIntercept = $script:smIntercept
$script:smSamples = 0

function Get-Clip01([double]$x) { if ($x -lt 0) { return 0.0 } elseif ($x -gt 1) { return 1.0 } else { return $x } }

function Get-SessionRaw {
    $ev = $script:Evidence
    return @{
        total_mods     = [int]$script:TotalMods
        verified       = [int]$script:Verified
        flagged        = [int]$script:Flagged
        review         = [int]$script:Review
        random_named   = [int]$ev.RandomNamed
        cheatsite_dl   = [int]$ev.CheatSiteDl
        hard_confirmed = [int]$ev.HardConfirmed
        sys_issues     = [int]$script:SystemIssues
        jvm_inject     = [int]$ev.JvmInject
        bam_deleted    = [int](@($script:BamDeleted).Count)
        cheat_procs    = [int]$ev.CheatProcs
        stray_jars     = [int]$ev.StrayJars
        cheat_folders  = [int]$ev.CheatFolders
        deleted_jars   = [int]$ev.DeletedJars
        mc_running     = $(if (@(Get-Process -Name javaw, java -ErrorAction SilentlyContinue).Count -gt 0) { 1 } else { 0 })
        mem_client     = [int]$ev.MemCheatClient
    }
}

function Get-SessionVector($raw) {
    $total = [int]$raw.total_mods
    $den = if ($total -gt 0) { [double]$total } else { 1.0 }
    $unver = if ($total -gt 0) { Get-Clip01 (([double]$total - [double]$raw.verified) / $den) } else { 0.0 }
    return @{
        flagged_ratio    = Get-Clip01 ([double]$raw.flagged / $den)
        review_ratio     = Get-Clip01 ([double]$raw.review / $den)
        unverified_ratio = $unver
        random_ratio     = Get-Clip01 ([double]$raw.random_named / $den)
        cheatsite_dl     = $(if ($raw.cheatsite_dl) { 1.0 } else { 0.0 })
        hard_confirmed   = $(if ($raw.hard_confirmed) { 1.0 } else { 0.0 })
        sys_issues       = Get-Clip01 ([Math]::Min([double]$raw.sys_issues, 10.0) / 10.0)
        jvm_inject       = Get-Clip01 ([Math]::Min([double]$raw.jvm_inject, 5.0) / 5.0)
        bam_deleted      = Get-Clip01 ([Math]::Min([double]$raw.bam_deleted, 10.0) / 10.0)
        cheat_procs      = Get-Clip01 ([Math]::Min([double]$raw.cheat_procs, 5.0) / 5.0)
        stray_jars       = Get-Clip01 ([Math]::Min([double]$raw.stray_jars, 3.0) / 3.0)
        cheat_folders    = Get-Clip01 ([Math]::Min([double]$raw.cheat_folders, 2.0) / 2.0)
        deleted_jars     = Get-Clip01 ([Math]::Min([double]$raw.deleted_jars, 3.0) / 3.0)
        mc_running       = $(if ($raw.mc_running) { 1.0 } else { 0.0 })
        mem_client       = $(if ($raw.mem_client) { 1.0 } else { 0.0 })
    }
}

function Invoke-SessionModel($vec) {
    $z = [double]$script:smIntercept
    foreach ($k in $script:smFeatureOrder) { $z += [double]$script:smWeights[$k] * [double]$vec[$k] }
    if ($z -lt -60) { return 0.0 } elseif ($z -gt 60) { return 1.0 }
    return 1.0 / (1.0 + [Math]::Exp(-$z))
}

function Get-SessionVerdict($raw) {
    $vec = Get-SessionVector $raw
    $p = Invoke-SessionModel $vec
    $score = [int][Math]::Round($p * 100)
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($raw.hard_confirmed) { $score = [Math]::Max($score, 85); [void]$reasons.Add("A mod was confirmed as a cheat by a hard rule (hash / package path / cheat site)") }
    if ($raw.jvm_inject -gt 0)   { $score = [Math]::Max($score, 60); [void]$reasons.Add("Live JVM shows injection traces ($($raw.jvm_inject))") }
    if ($raw.cheat_procs -gt 0)  { $score = [Math]::Max($score, 60); [void]$reasons.Add("Known cheat process running ($($raw.cheat_procs))") }
    if ($raw.cheatsite_dl)       { $score = [Math]::Max($score, 60); [void]$reasons.Add("A mod was downloaded from a known cheat site") }
    if ($raw.stray_jars -gt 0 -or $raw.cheat_folders -gt 0) { $score = [Math]::Max($score, 30); [void]$reasons.Add("Cheat files outside the mods folder: $($raw.stray_jars) jar(s), $($raw.cheat_folders) folder(s)") }
    if ($raw.mem_client -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("A named cheat client was identified inside the RUNNING game's memory $([char]0x2014) it is loaded right now, whatever the mods folder looks like") }
    if ($raw.deleted_jars -gt 0 -and $raw.mc_running) { $score = [Math]::Max($score, 60); [void]$reasons.Add("$($raw.deleted_jars) .jar file(s) ran on this PC and were deleted while Minecraft is still running $([char]0x2014) the classic 'wiped it before the screenshare' pattern") }
    if ($raw.bam_deleted -gt 0)  { [void]$reasons.Add("$($raw.bam_deleted) executable(s) ran on this PC and were deleted afterwards") }
    if ($raw.flagged -gt 0)      { [void]$reasons.Add("$($raw.flagged) flagged mod(s)") }
    if ($raw.review -gt 0)       { [void]$reasons.Add("$($raw.review) mod(s) to review") }
    if ($raw.sys_issues -gt 0)   { [void]$reasons.Add("$($raw.sys_issues) system issue(s)") }
    if ($reasons.Count -eq 0)    { [void]$reasons.Add("Nothing cheat-like across mods, system, processes or history") }

    $band = if ($score -ge 85) { "Confirmed" } elseif ($score -ge 60) { "Likely" } elseif ($score -ge 30) { "Review" } else { "Clean" }
    return @{ Score = $score; Band = $band; Probability = [int][Math]::Round($p * 100); Reasons = $reasons; Vector = $vec }
}

function Get-SessionVerdictCached {
    if ($null -eq $script:SessionVerdict) {
        $script:SessionRaw = Get-SessionRaw
        $script:SessionVerdict = Get-SessionVerdict $script:SessionRaw
    }
    return $script:SessionVerdict
}

function Get-SessionLabel($raw) {
    # Only unambiguous scans teach the model - that is what stops it drifting.
    if ($raw.hard_confirmed -or $raw.jvm_inject -gt 0 -or $raw.cheat_procs -gt 0 -or $raw.mem_client -gt 0) { return 1 }
    if ($raw.total_mods -gt 0 -and $raw.flagged -eq 0 -and $raw.review -eq 0 -and $raw.sys_issues -eq 0 -and
        $raw.bam_deleted -eq 0 -and $raw.stray_jars -eq 0 -and $raw.cheat_folders -eq 0 -and $raw.deleted_jars -eq 0 -and
        [double]$raw.verified -ge (0.6 * [double]$raw.total_mods)) { return 0 }
    return -1
}

function Update-SessionModelOnline($vec, $label) {
    if ($script:NoLearn) { return }
    try {
        $lr = 0.05; $l2 = 0.02; $clamp = 8.0
        $p = Invoke-SessionModel $vec
        $err = $p - $label
        foreach ($k in $script:smFeatureOrder) {
            $w = [double]$script:smWeights[$k] - $lr * ($err * [double]$vec[$k] + $l2 * ([double]$script:smWeights[$k] - [double]$script:smBaseWeights[$k]))
            if ($w -gt $clamp) { $w = $clamp } elseif ($w -lt (-$clamp)) { $w = -$clamp }
            $script:smWeights[$k] = $w
        }
        $si = [double]$script:smIntercept - $lr * ($err + $l2 * ([double]$script:smIntercept - [double]$script:smBaseIntercept))
        if ($si -gt $clamp) { $si = $clamp } elseif ($si -lt (-$clamp)) { $si = -$clamp }
        $script:smIntercept = $si
        $script:smSamples++
    } catch {}
}

function Write-ScanGaps {
    if ($script:ScanGaps.Count -eq 0) { return }
    Write-Host ""
    W "  $([char]0x26A0) What this scan could NOT check:" Yellow
    foreach ($g in $script:ScanGaps) { W "    $([char]0x2022) $g" DarkYellow }
    W "    A clean result only covers what was actually checked." DarkGray
    Write-Host ""
}

function Save-ScanSummary($v) {
    # Nothing waits for a keypress any more, so if the window closes the result has
    # to survive somewhere. Plain text on purpose: readable without a browser.
    try {
        $dir = Join-Path $env:APPDATA "AsyncAnalyzer"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $out = [System.Collections.Generic.List[string]]::new()
        [void]$out.Add("AsyncAnalyzer $($script:Version)  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$out.Add("PC: $env:COMPUTERNAME   User: $env:USERNAME")
        foreach ($t in @($script:ScanTargets)) { [void]$out.Add("Scanned: $t") }
        [void]$out.Add("")
        if ($v) { [void]$out.Add("OVERALL: $($v.Band)  ($($v.Score)/100)") ; foreach ($r in $v.Reasons) { [void]$out.Add("  - $r") } }
        [void]$out.Add("")
        [void]$out.Add("Mods: $($script:TotalMods) total / $($script:Verified) verified / $($script:Review) review / $($script:Flagged) flagged")
        [void]$out.Add("System issues: $($script:SystemIssues)")
        if (@($flaggedMods).Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("FLAGGED:")
            foreach ($m in @($flaggedMods)) {
                [void]$out.Add("  $($m.FileName)  [$($m.Band) $($m.Score)/100]")
                foreach ($r in @($m.Reasons)) { [void]$out.Add("      - $r") }
            }
        }
        if (@($reviewMods).Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("REVIEW:")
            foreach ($m in @($reviewMods)) { [void]$out.Add("  $($m.FileName)  [$($m.Score)/100]") }
        }
        if ($script:ScanGaps.Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("NOT CHECKED:")
            foreach ($g in $script:ScanGaps) { [void]$out.Add("  - $g") }
        }
        $file = Join-Path $dir "last-scan.txt"
        $out -join "`r`n" | Out-File -FilePath $file -Encoding UTF8
        W "  $([char]0x2713) Result saved: $file" DarkGray
    } catch {}
}

function Write-SessionCard($v, $raw) {
    $w = 72
    $col = switch ($v.Band) { "Confirmed" { "Red" } "Likely" { "DarkYellow" } "Review" { "Yellow" } default { "Green" } }
    $label = switch ($v.Band) {
        "Confirmed" { "CHEATING CONFIRMED" }
        "Likely"    { "LIKELY CHEATING" }
        "Review"    { "NEEDS A MANUAL LOOK" }
        default     { "CLEAN $([char]0x2014) NOTHING FOUND" }
    }
    Write-Host ""
    W ("  $([char]0x2554)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x2557)") $col
    W ("  $([char]0x2551)" + "  OVERALL SCAN VERDICT (AI, whole scan)".PadRight($w + 1) + "$([char]0x2551)") Cyan
    W ("  $([char]0x2551)" + "  $label".PadRight($w + 1) + "$([char]0x2551)") $col
    W ("  $([char]0x2551)" + "  Score $($v.Score)/100    AI probability $($v.Probability)%".PadRight($w + 1) + "$([char]0x2551)") White
    W ("  $([char]0x2560)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x2563)") $col
    foreach ($r in $v.Reasons) {
        $line = "    $([char]0x2022) $r"
        if ($line.Length -gt $w) { $line = $line.Substring(0, $w - 3) + "..." }
        W ("  $([char]0x2551)" + $line.PadRight($w + 1) + "$([char]0x2551)") DarkGray
    }
    W ("  $([char]0x255A)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x255D)") $col
    Write-Host ""
}

function Invoke-CloudUpdate {
    if ($script:NoUpdate) { return }
    try {
        $m = Invoke-RestMethod -Uri "$($script:RepoRaw)/model.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($m.version -and ([int]$m.version) -gt $script:mlModelVersion -and $m.weights -and $m.feature_order) {
            $script:mlFeatureOrder = @($m.feature_order)
            foreach ($k in $script:mlFeatureOrder) {
                $wv = $m.weights.$k
                if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv; $script:mlBaseWeights[$k] = [double]$wv }
            }
            $script:mlIntercept = [double]$m.intercept; $script:mlBaseIntercept = [double]$m.intercept
            $script:mlModelVersion = [int]$m.version
            W "  $([char]0x2713) AI model auto-updated to v$($script:mlModelVersion) from GitHub." DarkGray
        }
    } catch {}
    try {
        $sm = Invoke-RestMethod -Uri "$($script:RepoRaw)/session_model.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($sm.version -and ([int]$sm.version) -gt $script:smModelVersion -and $sm.weights -and $sm.feature_order) {
            $script:smFeatureOrder = @($sm.feature_order)
            foreach ($k in $script:smFeatureOrder) {
                $sv = $sm.weights.$k
                if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv; $script:smBaseWeights[$k] = [double]$sv }
            }
            $script:smIntercept = [double]$sm.intercept; $script:smBaseIntercept = [double]$sm.intercept
            $script:smModelVersion = [int]$sm.version
            W "  $([char]0x2713) Overall-scan AI updated to v$($script:smModelVersion) from GitHub." DarkGray
        }
    } catch {}
    try {
        $s = Invoke-RestMethod -Uri "$($script:RepoRaw)/signatures.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($s.knownCheatHashes) { foreach ($h in $s.knownCheatHashes) { [void]$script:knownCheatHashes.Add([string]$h) } }
        if ($s.knownGoodHashes)  { foreach ($h in $s.knownGoodHashes)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        if ($s.packagePaths)     { $script:cheatPackagePaths = @(@($script:cheatPackagePaths) + @($s.packagePaths) | Select-Object -Unique) }
        if ($s.clientTokens)     { foreach ($t in $s.clientTokens) { [void]$script:distinctiveClientTokens.Add([string]$t) } }
        if ($s.downloadDomains)  {
            foreach ($d in $s.downloadDomains) {
                if ($d.match -and $d.name) {
                    $script:cheatDomainMap += [PSCustomObject]@{ match = [string]$d.match; name = [string]$d.name }
                    if ($script:cheatDownloadSources -notcontains [string]$d.name) { $script:cheatDownloadSources += [string]$d.name }
                }
            }
        }
        if ($s.processNames)     { $script:pendingProcessNames = @($s.processNames) }
        if ($s.scanPaths)        { $script:PathsFromConfig = @($s.scanPaths) }
        if ($s.moduleNames) {
            # Cheat MODULE names confirmed in two independent open-source clients. The
            # list is curated for collisions on purpose - names like Timer/Step/Reach are
            # everyday identifiers and VeinMiner/Freecam are mods people actually run.
            $added = $false
            foreach ($mn in $s.moduleNames) {
                if ($mn -and $script:suspiciousPatterns -notcontains [string]$mn) {
                    $script:suspiciousPatterns += [string]$mn; $added = $true
                }
            }
            if ($added) { Build-PatternRegex }
        }
        if ($s.telemetry -and -not $env:ASYNCANALYZER_ENDPOINT) { $script:Telemetry = $s.telemetry }
    } catch {}

    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.pullSignatures -and $script:Telemetry.endpoint) {
        try {
            $ts = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/signatures" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($ts.knownCheatHashes) { foreach ($h in $ts.knownCheatHashes) { [void]$script:knownCheatHashes.Add([string]$h) } }
            if ($ts.knownGoodHashes)  { foreach ($h in $ts.knownGoodHashes)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        } catch {}
    }

    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
        try {
            $tm = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/model" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($tm.weights -and $tm.feature_order) {
                $script:mlFeatureOrder = @($tm.feature_order)
                foreach ($k in $script:mlFeatureOrder) { $wv = $tm.weights.$k; if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv; $script:mlBaseWeights[$k] = [double]$wv } }
                $script:mlIntercept = [double]$tm.intercept; $script:mlBaseIntercept = [double]$tm.intercept
                W "  $([char]0x2713) Using team-trained AI model $([char]0x2014) learned from $($tm.trainedCount) samples across all team scans." DarkGray
            }
        } catch {}
        try {
            $tsm = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/smodel" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($tsm.weights -and $tsm.feature_order) {
                $script:smFeatureOrder = @($tsm.feature_order)
                foreach ($k in $script:smFeatureOrder) { $sv = $tsm.weights.$k; if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv; $script:smBaseWeights[$k] = [double]$sv } }
                $script:smIntercept = [double]$tsm.intercept; $script:smBaseIntercept = [double]$tsm.intercept
                W "  $([char]0x2713) Overall-scan AI is team-trained $([char]0x2014) $($tsm.trainedCount) whole scans learned from." DarkGray
            }
        } catch {}
    }
}

function Get-MinecraftName {
    $roots = [System.Collections.Generic.List[string]]::new()
    [void]$roots.Add((Join-Path $env:APPDATA ".minecraft"))
    if ($ModPath) {
        $dir = Split-Path $ModPath -Parent
        for ($i = 0; $i -lt 3 -and $dir; $i++) {
            [void]$roots.Add($dir)
            $dir = Split-Path $dir -Parent
        }
    }
    foreach ($root in $roots) {
        foreach ($leaf in @("launcher_accounts.json", "launcher_accounts_microsoft_store.json")) {
            try {
                $f = Join-Path $root $leaf
                if (-not (Test-Path $f)) { continue }
                $j = Get-Content -Raw $f -ErrorAction Stop | ConvertFrom-Json
                $active = $j.activeAccountLocalId
                foreach ($acc in $j.accounts.PSObject.Properties.Value) {
                    if ($acc.localId -eq $active -and $acc.minecraftProfile.name) { return [string]$acc.minecraftProfile.name }
                }
                foreach ($acc in $j.accounts.PSObject.Properties.Value) {
                    if ($acc.minecraftProfile.name) { return [string]$acc.minecraftProfile.name }
                }
            } catch {}
        }
    }
    return ""
}

function Send-ScanResult {
    $t = $script:Telemetry
    if (-not $t -or -not $t.enabled -or -not $t.endpoint -or -not $t.key) { return }
    try {
        $verdict = if ($script:Flagged -gt 0) { "flagged" } elseif ($script:Review -gt 0) { "review" } else { "clean" }
        $mkMod = { param($m) @{ name = $m.FileName; score = $m.Score; band = $m.Band; probability = $m.Probability; hash = $m.Hash; reasons = @($m.Reasons) } }
        $payload = @{
            scanner      = $env:USERNAME
            targetUser   = (Get-MinecraftName)
            pcName       = $env:COMPUTERNAME
            modPath      = $ModPath
            verdict      = $verdict
            totals       = @{ total = $script:TotalMods; verified = $script:Verified; unknown = $script:Unknown; review = $script:Review; flagged = $script:Flagged; systemIssues = $script:SystemIssues }
            flagged      = @(@($flaggedMods) | ForEach-Object { & $mkMod $_ })
            review       = @(@($reviewMods)  | ForEach-Object { & $mkMod $_ })
            newCheat     = @($script:sessionCheat | Select-Object -Unique)
            newGood      = @($script:sessionGood  | Select-Object -Unique)
            samples      = @(@($script:sessionSamples) | Select-Object -First 400)
            session      = $(if ($script:SessionVerdict) { @{ score = $script:SessionVerdict.Score; band = $script:SessionVerdict.Band; probability = $script:SessionVerdict.Probability; reasons = @($script:SessionVerdict.Reasons) } } else { $null })
            sessionSample = $script:SessionSample
            sessionModelVersion = $script:smModelVersion
            toolVersion  = $script:Version
            modelVersion = $script:mlModelVersion
            clientTs     = (Get-Date).ToString("s")
        }
        $json = $payload | ConvertTo-Json -Depth 6 -Compress
        $r = Invoke-RestMethod -Uri "$($t.endpoint)/api/scan" -Method Post -Body $json -ContentType "application/json" -Headers @{ "x-key" = [string]$t.key } -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        if ($r.ok) { W "  $([char]0x2713) Result uploaded to the team dashboard (id $($r.id))." DarkGray }
    } catch { W "  $([char]0x26A0) Could not reach the team dashboard $([char]0x2014) result kept locally." DarkGray }
}
$script:mlFactorLabels = @{
    'pkgpath' = "cheat-client package path"
    'cheatsite' = "downloaded from a known cheat site"
    'strong_sig' = "distinctive cheat signatures"
    'weak_sig' = "multiple generic cheat indicators"
    'fullwidth_str' = "fullwidth-disguised cheat strings"
    'fullwidth_cls' = "fullwidth class-name obfuscation"
    'japanese_cls' = "Japanese class-name obfuscation"
    'singlechar_cls' = "single-letter class-name obfuscation"
    'numeric_cls' = "numeric class-name obfuscation"
    'high_entropy' = "encrypted/packed classes (high entropy)"
    'avg_entropy' = "elevated class entropy"
    'runtime_exec' = "runs OS commands (Runtime.exec)"
    'http_download' = "downloads and writes files at runtime"
    'http_exfil' = "sends data to an external server"
    'nested_hollow' = "hollow shell wrapping a hidden jar"
    'fake_identity' = "fake mod identity"
    'filename_client' = "filename of a known cheat client"
}

function Invoke-MlModel($raw) {
    $z = [double]$script:mlIntercept
    foreach ($k in $script:mlFeatureOrder) {
        $v = if ($raw.ContainsKey($k)) { [double]$raw[$k] } else { 0.0 }
        $z += [double]$script:mlWeights[$k] * $v
    }
    if ($z -lt -60) { return 0.0 }
    if ($z -gt 60)  { return 1.0 }
    return 1.0 / (1.0 + [Math]::Exp(-$z))
}

# ---------------------------------------------------------------------------
# Behavioural bytecode analysis - reads what a mod DOES, not what it says.
#
# String scraping loses to any cheat that encrypts its strings. The constant
# pool does not: to call a Minecraft method you must name it there. You can
# obfuscate your own symbols; you cannot obfuscate the API you call.
#
# Only the constant pool is parsed. It sits at the head of every class file, so
# this stays affordable even over a large mods folder.
# ---------------------------------------------------------------------------
$script:bcBehaviour = [ordered]@{
    'movepacket' = 'ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828'
    'rotation'   = '\.setYRot|\.setXRot|\.setYaw|\.setPitch|\.method_36456|\.method_36457'
    # A bare '\.swing' matched javax/swing and any field called swingGui - rhino's
    # debugger UI tripped it. Qualified to the actual Minecraft method, so a Swing
    # application in a mods folder cannot look like combat code.
    'attack'     = 'MultiPlayerGameMode\.attack|ServerboundInteractPacket|PlayerInteractEntityC2SPacket|(?:LocalPlayer|Player|LivingEntity)\.swing\b|\.swingHand\b|\.method_6104\b|class_2824'
    # Both Wurst and Meteor hook the network layer itself, not just the listener.
    # Qualified on purpose - a bare 'Connection' is an everyday identifier.
    'pktlisten'  = 'ClientPacketListener|ClientPlayNetworkHandler|class_634|net/minecraft/network/Connection|class_2535'
    'entityscan' = 'entitiesForRendering|getEntities|method_18112|\.getEntityList'
    'render'     = 'VertexConsumer|RenderSystem|BufferBuilder|MatrixStack|PoseStack|Tessellator|class_4587'
    'input'      = 'KeyMapping|KeyBinding|GLFW\.glfwGetKey|\.isPressed|client/input|class_304|client/KeyboardHandler|client/MouseHandler'
    'reflect'    = 'java/lang/reflect|\.getDeclaredMethod|\.setAccessible|Class\.forName|MethodHandles|\.getDeclaredField'
    'classload'  = '\.defineClass|URLClassLoader|defineAnonymousClass|\.defineHiddenClass'
    'crypto'     = 'javax/crypto|Cipher\.|SecretKeySpec|IvParameterSpec'
    'exec'       = 'Runtime\.getRuntime|ProcessBuilder|Runtime\.exec'
    'net'        = 'java/net/Socket|HttpURLConnection|\.openConnection|java/net/http|URL\.openStream'
    'unsafe'     = 'sun/misc/Unsafe|jdk/internal/misc/Unsafe'
    'instrument' = 'java/lang/instrument|Instrumentation\.'
    # Minecraft-specific API names on purpose. A behaviour category only earns its
    # place if a real Maven library cannot match it by accident - these name packets
    # and interaction-manager methods that exist nowhere outside the game.
    'blockplace' = 'ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885|\.useItemOn|\.interactBlock|\.method_2896'
    'blockbreak' = 'ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|\.startDestroyBlock|\.destroyBlock|\.method_2910'
    'container'  = 'ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|ScreenHandler|class_1703'
    'motion'     = '\.setDeltaMovement|\.getDeltaMovement|\.setVelocity|\.method_18800|\.method_18798'
    # A jar working out where its own file is. Ordinary code has no reason to - it
    # is how something finds itself in order to delete itself.
    'selfpath'   = '\.getProtectionDomain|\.getCodeSource|ProtectionDomain|CodeSource'
    'filedelete' = 'File\.delete|\.deleteOnExit|Files\.delete|Files\.deleteIfExists'
    # Unpacking a bundled native library and cleaning up the copy afterwards. This
    # is the innocent reason a class locates its own jar and then deletes a file,
    # and naming it is what lets the self-wipe signal exclude it.
    'nativetemp' = 'createTempFile|createTempDirectory|System\.load|\.loadLibrary|java\.io\.tmpdir'
}
# Derived per-class signals. Not patterns: combinations that only mean something
# when ONE class does all of it. Jar-level ratios cannot express that - in a large
# library "something locates its own jar" and "something deletes a file" are
# usually unrelated classes, which is exactly how the first version of this signal
# matched sixteen legitimate bytecode libraries.
$script:bcDerived = @('selfwipe')
# Names a dropper reaches REFLECTIVELY, so they land in a string constant rather
# than a Methodref. Deliberately tiny - broad names like setAccessible are
# everyday library code and would drag legitimate jars in.
$script:bcReflectiveNames = @{
    'classload'  = '^(defineClass|defineAnonymousClass|defineHiddenClass)$'
    'instrument' = '^(premain|agentmain|retransformClasses)$'
}

# Cheap pre-filter run over the raw decompressed head of EVERY class.
#
# Fully parsing every constant pool is not affordable here: a 200-mod pack is
# ~44k classes and real jars run to a median of 218 classes each. But sampling is
# worse than slow, it is WRONG - a cheat whose aura module sits at class #150 is
# invisible to a 40-class sample, which measured out as completely undetected.
#
# So every class gets searched cheaply and only matches get parsed precisely.
# Sound because these are API names: the JVM resolves classes and methods BY NAME,
# so they must appear literally in the pool. A cheat can encrypt its own strings;
# it cannot encrypt the Minecraft API it calls.