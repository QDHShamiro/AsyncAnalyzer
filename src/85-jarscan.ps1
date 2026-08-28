# ---------------------------------------------------------------------------
# Everything one jar goes through: hash, provenance lookup, features, bytecode,
# verdict, evidence, and the one-shot online learning step.
#
# It lives in a function because the scan now runs it TWICE. The first pass is
# the mods folders the tool found on disk; the second is folders the running
# game turned out to be reading that nobody knew about - and a jar found by the
# second route has to be judged by exactly the same code as one found by the
# first, or the folder the cheat was actually in gets the weaker analysis.
#
# The four result lists are script-scope, so this appends to the same lists the
# main loop fills. Counters are $script:-qualified for the same reason.
# ---------------------------------------------------------------------------
function Invoke-JarAnalysis($jar) {

    $hash   = Get-FileSHA1 $jar.FullName
    $dlObj  = Get-DownloadSource $jar.FullName
    $dlName = if ($dlObj) { $dlObj.Name } else { $null }
    $dlUrl  = if ($dlObj) { $dlObj.RawUrl } else { $null }

    $verified = $false; $verifiedName = ""; $modUrl = ""; $verifiedVia = ""
    if ($hash -and $script:knownGoodHashes.Contains($hash)) {
        $verified = $true; $verifiedVia = "known-good list"
        $gm = $script:goodMeta[$hash]
        if ($gm) { $gp = $gm -split '\|', 2; $verifiedName = [string]$gp[0]; if ($gp.Count -gt 1) { $modUrl = [string]$gp[1] } }
    }
    if ($hash -and -not $verifiedName) {
        $mr = Get-ModrinthMeta $hash
        if ($mr.Slug) { $verified = $true; $verifiedName = $mr.Name; $modUrl = "https://modrinth.com/mod/$($mr.Slug)"; if (-not $verifiedVia) { $verifiedVia = "Modrinth" } }
        if (-not $verifiedName) {
            $fp = Get-FileMurmur2 $jar.FullName
            if ($null -ne $fp) {
                $cf = Get-CurseForgeMeta $fp
                if ($cf.Slug) { $verified = $true; $verifiedName = $cf.Name; $modUrl = "https://www.curseforge.com/minecraft/mc-mods/$($cf.Slug)"; if (-not $verifiedVia) { $verifiedVia = "CurseForge" } }
            }
        }
        if (-not $verifiedName) {
            $mb = Get-MegabaseMeta $hash
            if ($mb -and $mb.name) { $verified = $true; $verifiedName = $mb.name; $modUrl = if ($mb.modrinth_id) { "https://modrinth.com/mod/$($mb.modrinth_id)" } else { "" }; if (-not $verifiedVia) { $verifiedVia = "Megabase" } }
        }
        if ($verified -and $verifiedName) { $script:goodMeta[$hash] = "$verifiedName|$modUrl" }
    }

    Add-DiskPackages $jar.FullName
    $feat = Get-JarFeatures $jar.FullName
    $bcFeat = $null
    if (-not $verified) { $bcFeat = Get-BytecodeFeatures $jar.FullName $script:BcMaxClasses }

    $checkName = $jar.Name -replace '\.(temp|disabled|bak|old|backup)(\.jar)$','$2'
    $fnMatch   = Get-FilenameSimilarityMatch $checkName
    $filenameClient = $false; $filenameToken = ""
    if ($null -ne $fnMatch -and $script:distinctiveClientTokens.Contains($fnMatch.Token)) { $filenameClient = $true; $filenameToken = $fnMatch.Token }
    $randomName = (-not $filenameClient) -and (Test-RandomFilename $checkName)
    $modIdNorm  = if ($feat.ModId) { ($feat.ModId -replace '[^a-zA-Z0-9]','').ToLower() } else { "" }
    $legitModId = ($modIdNorm -ne "") -and $script:legitModIds.Contains($modIdNorm)
    $hashKnownCheat = ($null -ne $hash) -and $script:knownCheatHashes.Contains($hash)
    $cheatSite  = ($null -ne $dlName) -and ($script:cheatDownloadSources -contains $dlName)

    $ctx = @{
        Features = $feat; Verified = $verified; LegitModId = $legitModId
        HashKnownCheat = $hashKnownCheat; CheatSite = $cheatSite; CheatSiteName = $dlName
        FilenameClient = $filenameClient; FilenameToken = $filenameToken; RandomName = $randomName
        Bytecode = $bcFeat
    }
    $verdict = Get-ModVerdict $ctx
    $mechCheat = $feat.JavaAgent -or ($feat.HiddenPayload -gt 0)

    # A mixin config lists, in plain text, how many places in the game this
    # mod rewrites. If it declares mixins and the bytecode reader saw none of
    # them, the jar was not read - that is a gap in coverage, and a clean
    # result on an unread jar has to say so rather than look like an answer.
    if ($feat.MixinDeclared -gt 0 -and $null -ne $bcFeat -and $bcFeat.mixin -eq 0) {
        Add-ScanGap ("$($jar.Name): declares $($feat.MixinDeclared) mixin(s) in its config but none could be read from the bytecode $([char]0x2014) what it rewrites in the game was NOT checked")
    }

    # What the behaviour rules found, kept separate from the band so the
    # whole-scan model sees it directly. Only counted where the finding
    # actually stands: a verified mod is capped safe, and its behaviour is
    # part of the mod's own function rather than a cheat.
    if ($verdict.BehaviourScore -ge 85 -and $verdict.Band -eq "Confirmed") {
        $script:Evidence.BehaviourCheat++
    } elseif ($verdict.BehaviourScore -ge 60 -and ($verdict.Band -eq "Confirmed" -or $verdict.Band -eq "Likely")) {
        $script:Evidence.BehaviourLikely++
    }
    if ($verdict.HiddenApi -and -not $verified) { $script:Evidence.HiddenApi++ }
    if ($randomName) { $script:Evidence.RandomNamed++ }
    if ($cheatSite)  { $script:Evidence.CheatSiteDl++ }
    if ((-not $verified) -and ($hashKnownCheat -or $feat.PackageHits.Count -gt 0 -or $cheatSite -or $mechCheat)) { $script:Evidence.HardConfirmed++ }

    $rec = [PSCustomObject]@{
        FileName = $jar.Name; FilePath = $jar.FullName; Hash = $hash
        Verified = $verified; VerifiedName = $verifiedName; ModName = $verifiedName; VerifiedVia = $verifiedVia; ModUrl = $modUrl
        DownloadSource = $dlName; DownloadUrl = $dlUrl
        Score = $verdict.Score; Band = $verdict.Band; Probability = $verdict.Probability; Reasons = $verdict.Reasons
    }

    if ($verified) {
        [void]$script:verifiedMods.Add($rec)
    } elseif ($verdict.Band -eq "Confirmed" -or $verdict.Band -eq "Likely") {
        [void]$script:flaggedMods.Add($rec)
        [void]$script:FlaggedModsList.Add($jar.Name)
        $script:Flagged++
    } elseif ($verdict.Band -eq "Review" -or $verdict.Band -eq "ServerRule") {
        # A server-rule finding goes in the same list as Review - it needs a
        # person to look at it either way. It keeps its own band so the report
        # can say WHY: uncertainty in one case, a rule question in the other.
        [void]$script:reviewMods.Add($rec)
        [void]$script:ReviewModsList.Add($jar.Name)
        if ($verdict.Band -eq "ServerRule") { $script:ServerRule++ }
    } else {
        [void]$script:unknownMods.Add($rec)
    }

    # Only ever train on externally grounded labels, and only once per file hash: rescanning
    # the same folder must not re-weight the model toward whatever it already believes.
    if ($hash) {
        $rawv = Get-ModFeatureVector $ctx
        if ($verified) {
            $isNew = $script:knownGoodHashes.Add($hash)
            [void]$script:sessionGood.Add($hash)
            if ($isNew) {
                Update-ModelOnline $rawv 0
                [void]$script:sessionSamples.Add(@{ vec = @($script:mlFeatureOrder | ForEach-Object { [double]$rawv[$_] }); label = 0 })
            }
        } elseif ($verdict.Band -eq "Confirmed" -and ($hashKnownCheat -or $feat.PackageHits.Count -gt 0 -or $cheatSite -or $mechCheat)) {
            $isNew = $script:knownCheatHashes.Add($hash)
            [void]$script:sessionCheat.Add($hash)
            if ($isNew) {
                Update-ModelOnline $rawv 1
                [void]$script:sessionSamples.Add(@{ vec = @($script:mlFeatureOrder | ForEach-Object { [double]$rawv[$_] }); label = 1 })
            }
            if ($script:Share) { [void]$script:shareHashes.Add($hash) }
        }
    }
}

# ---------------------------------------------------------------------------
# The second pass.
#
# The file scan looks where Minecraft installs normally live. The RUNNING game
# knows better: its own memory holds the path of every jar it actually loaded,
# and some of those can sit in a folder nothing on disk pointed at - a second
# instance, a hand-made pack, a directory added to the classpath by hand. That
# is precisely where a jar goes when the obvious folder is the one being
# watched.
#
# Those folders arrive late, because reading them out needs the live process.
# So rather than printing "re-run with -Path <folder>" - advice nobody follows
# while a suspect is on the other end of the call - the tool scans them itself,
# through the same Invoke-JarAnalysis the first pass used. Same code, same
# thresholds, same model: a jar found the second way is judged exactly like a
# jar found the first way.
# ---------------------------------------------------------------------------
function Invoke-LateFolderScan {
    if ($script:LateScanDirs.Count -eq 0) { return }
    $extra = @()
    foreach ($d in $script:LateScanDirs) {
        if (-not (Test-Path $d -PathType Container)) {
            Add-ScanGap "The running game is loading mods from $d, but that folder could not be opened for scanning"
            continue
        }
        $extra += @(Get-ChildItem -Path $d -Filter "*.jar" -ErrorAction SilentlyContinue)
        $extra += @(Get-ChildItem -Path $d -Filter "*.litemod" -ErrorAction SilentlyContinue)
        if (-not $script:ScanTargetDirs.Contains($d)) { [void]$script:ScanTargetDirs.Add($d) }
        if (-not (@($script:ScanTargets) -contains $d)) { $script:ScanTargets = @($script:ScanTargets) + @($d) }
    }
    # A jar already analysed in the first pass must not be analysed again: it
    # would be counted twice in every total, and the report would show a
    # duplicate card for one file.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($lst in @($script:verifiedMods, $script:unknownMods, $script:reviewMods, $script:flaggedMods)) {
        foreach ($m in @($lst)) { if ($m.FilePath) { [void]$seen.Add([string]$m.FilePath) } }
    }
    $extra = @($extra | Where-Object { -not $seen.Contains($_.FullName) })
    if ($extra.Count -eq 0) { return }

    Write-Host ""
    Write-SectionHeader "FOLDERS THE RUNNING GAME REVEALED" $extra.Count Yellow Yellow
    Write-Rule "$([char]0x2500)" 76 DarkGray
    Write-Host ""
    foreach ($d in $script:LateScanDirs) { W "  $([char]0x2022) $d" DarkGray }
    Write-Host ""
    W "  Scanning $($extra.Count) more jar(s) found this way $([char]0x2014) same checks as the first pass..." DarkGray

    # Remember where each list ended, so only the jars this pass adds get a card.
    $nBefore = @{ flagged = $script:flaggedMods.Count; review = $script:reviewMods.Count }
    $before = $script:Flagged + $script:Review
    $i = 0
    foreach ($jar in $extra) {
        $i++
        Spin "[$i/$($extra.Count)] $($jar.Name)"
        Invoke-JarAnalysis $jar
    }
    SpinClear

    # The totals are derived from the lists, so they have to be taken again -
    # they were computed at the end of the first pass and are now stale.
    $script:TotalMods   = $script:verifiedMods.Count + $script:unknownMods.Count + $script:reviewMods.Count + $script:flaggedMods.Count
    $script:Verified    = $script:verifiedMods.Count
    $script:Unknown     = $script:unknownMods.Count
    $script:Review      = $script:reviewMods.Count
    $script:LateScanned = $extra.Count

    $found = ($script:Flagged + $script:Review) - $before
    if ($found -gt 0) {
        W "  $([char]0x26A0) $found of them need looking at $([char]0x2014) in a folder the file scan would never have opened." Red
        Write-Host ""
        # The first pass printed its cards before these jars existed as far as the
        # scan was concerned. Print theirs here, or the console shows a number
        # while the reasons sit only in the HTML.
        for ($k = $nBefore.flagged; $k -lt $script:flaggedMods.Count; $k++) { Write-VerdictCard $script:flaggedMods[$k] }
        for ($k = $nBefore.review;  $k -lt $script:reviewMods.Count;  $k++) { Write-VerdictCard $script:reviewMods[$k] }
    } else {
        W "  $([char]0x2713) Nothing in them, but they are now part of the result rather than a hole in it." DarkGray
    }
    Add-Finding $(if ($found -gt 0) { "FAIL" } else { "INFO" }) "Where this was scanned" `
        "$($extra.Count) extra jar(s) in $($script:LateScanDirs.Count) folder(s) the running game revealed" `
        @($script:LateScanDirs) `
        "The live game's own memory names every folder it loaded a mod from. These were not on the list the file scan built from disk." `
        "A jar parked in a folder no launcher points at is out of sight of any scan that only looks where Minecraft is normally installed." `
        "They were scanned with the same checks as everything else, so their results are in the totals above." `
        $(if ($found -gt 0) { "Look at the flagged jars from these folders first $([char]0x2014) someone put them somewhere deliberately." } else { "Nothing was found in them." }) | Out-Null
}
