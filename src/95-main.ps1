if ($SelfTest) { Invoke-SelfTest; return }
if ($HashOnly) { Invoke-HashOnly $HashOnly; return }

if (Invoke-SelfElevate) { return }   # an elevated window took over; nothing left to do here
[void](Set-AutoDepth)
if (-not (Test-IsAdmin)) {
    Add-ScanGap "Ran without Administrator $([char]0x2014) deleted-program history (BAM), Defender exclusions and scheduled tasks were NOT checked"
}

W "  What this tool does $([char]0x2014) and does not do:" Cyan
W "    $([char]0x2713) Read-only. It never changes, deletes, or quarantines your files." Green
W "    $([char]0x2713) Runs fully on your PC. It never uploads your files or your data." Green
W "    $([char]0x2713) Network use is limited to looking mods up by hash on Modrinth /" DarkGray
W "      CurseForge / Megabase $([char]0x2014) only the file hash is sent, never the file." DarkGray
W "    $([char]0x2713) The cheat verdict is scored by a local AI model (no cloud, no key)." Green
W "    $([char]0x2713) Verified mods are never flagged. Flags come with a reason + score." Green
W "    $([char]0x2139) By default it only scans your mods folder. A deep, whole-PC scan is" DarkGray
W "      optional and asked for separately." DarkGray
W "    $([char]0x2139) The deep scan also reads macro scripts (.ahk .ahk2 .au3 .lua .vbs) in" DarkGray
W "      Downloads, Desktop, Documents, Temp and your mouse driver's script folder," DarkGray
W "      because an autoclicker is never in the mods folder. Read-only, like the rest." DarkGray
if ($script:MemoryAuto) {
    W "    $([char]0x2139) Minecraft is running $([char]0x2014) the live-memory check is ON automatically." Yellow
    W "      That is the only way to catch a ghost client injected into the game." DarkGray
    W "      It only READS the game's memory. Nothing is changed, nothing uploaded." DarkGray
} elseif ($script:DeepMemory) {
    W "    $([char]0x2139) Live-memory check is ON (-DeepMemory) $([char]0x2014) read-only, changes nothing." DarkGray
} else {
    W "    $([char]0x2139) Minecraft is not running, so there is no live game memory to check." DarkGray
}
W "    $([char]0x2713) Self-improving: it learns from every scan (all local) and auto-updates" Green
W "      its model from GitHub, so detection keeps getting better over time." Green
Write-Host ""
W ("$([char]0x2501)" * 76) DarkCyan
Write-Host ""

Load-LearnState
# Self-hosters / testing: point the tool at your own backend without publishing the key.
if ($env:ASYNCANALYZER_ENDPOINT) {
    $script:Telemetry = @{ enabled = $true; endpoint = $env:ASYNCANALYZER_ENDPOINT; key = $env:ASYNCANALYZER_KEY; pullSignatures = $true }
}
Invoke-CloudUpdate
if ($script:mlSamples -gt 0 -or $script:knownGoodHashes.Count -gt 0 -or $script:knownCheatHashes.Count -gt 0) {
    W "  $([char]0x25CF) AI memory: " DarkGray -NoNewline
    W "$($script:knownGoodHashes.Count)" Green -NoNewline; W " known-good  " DarkGray -NoNewline
    W "$($script:knownCheatHashes.Count)" Red -NoNewline; W " known-cheat  " DarkGray -NoNewline
    W "$($script:mlSamples)" Cyan -NoNewline; W " examples learned (model v$($script:mlModelVersion))" DarkGray
    Write-Host ""
}

if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
    W "  $([char]0x25CF) NOTICE $([char]0x2014) team mode is ON: this scan's result (mod list, hashes, verdict," Yellow
    W "    your Windows & Minecraft name, PC name) will be uploaded to the AsyncStudios team" DarkGray
    W "    dashboard so staff can review it. Your personal files are NOT uploaded." DarkGray
    Write-Host ""
}

if ($Dev) {
    W "  [DEV MODE] Quick scan $([char]0x2014) max 10 items per category, heavy checks skipped." DarkYellow
    Write-Host ""
    $ModPath = if ([string]::IsNullOrWhiteSpace($DevPath)) { "$env:APPDATA\.minecraft\mods" } else { $DevPath.Trim('"').Trim("'").Trim() }
    if (-not (Test-Path $ModPath -PathType Container)) {
        W "  $([char]0x2717) Dev path does not exist: $ModPath" Red
        Write-Host ""
        return
    }
    W "  Target : " DarkGray -NoNewline; W $ModPath White
    Write-Host ""
    $SkipSystemCheck  = $true
    $SkipServiceCheck = $true
    $SkipMemoryCheck  = $true
    $SkipModCheck     = $false
    $script:_DevMode  = $true
    $script:_DevLimit = 10
} else {
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $script:ScanTargets = @($Path) }
    elseif ($script:Ask) { $script:ScanTargets = @(Ask-ModPath) }
    else { $script:ScanTargets = @(Get-ScanTargets) }
    $script:ScanTargets = @($script:ScanTargets | ForEach-Object { ([string]$_).Trim('"').Trim("'").Trim() } | Where-Object { $_ })
    $ModPath = if ($script:ScanTargets.Count -gt 0) { $script:ScanTargets[0] } else { "" }

    if (-not (Test-Path $ModPath -PathType Container)) {
        W "" White
        W "  $([char]0x2717) Invalid path $([char]0x2014) directory does not exist:" Red
        W "    $ModPath" DarkGray
        W "" White
        return
    }

    Write-Host ""
    if ($script:ScanTargets.Count -eq 1) {
        W "  Target : " DarkGray -NoNewline; W $ModPath White
    } else {
        W "  Targets: " DarkGray -NoNewline; W "$($script:ScanTargets.Count) folders" White
        foreach ($t in $script:ScanTargets) { W "           $t" DarkGray }
    }
    Write-Host ""

    $mcProcess = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProcess) { $mcProcess = Get-Process java -ErrorAction SilentlyContinue }
    if ($mcProcess) {
        try {
            $uptime = (Get-Date) - $mcProcess.StartTime
            W "  $([char]0x25CF) Minecraft running $([char]0x2014) PID $($mcProcess.Id)  uptime $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" DarkCyan
            Write-Host ""
        } catch {}
    }

    $SkipSystemCheck  = $false
    $SkipServiceCheck = $false
    $SkipMemoryCheck  = $false
    $script:_DevMode  = $false
}

if ($null -eq $SkipSystemCheck)  { $SkipSystemCheck  = $false }
if ($null -eq $SkipServiceCheck) { $SkipServiceCheck = $false }
if ($null -eq $SkipModCheck)     { $SkipModCheck     = $false }
if ($null -eq $SkipMemoryCheck)  { $SkipMemoryCheck  = $false }

if (-not $SkipSystemCheck)  { Run-SystemChecks }
if (-not $SkipServiceCheck) { Run-ServiceCheck }

if (-not $SkipModCheck) {
    # Every target, not just the first: the whole point is that a second open
    # instance cannot hide. Everything downstream works per jar and records
    # FilePath, so nothing else in the loop has to change.
    $jarFiles = @()
    foreach ($t in $script:ScanTargets) {
        if (-not (Test-Path $t -PathType Container)) {
            Add-ScanGap "Folder could not be read: $t"
            continue
        }
        $jarFiles += @(Get-ChildItem -Path $t -Filter "*.jar" -ErrorAction SilentlyContinue)
        $jarFiles += @(Get-ChildItem -Path $t -Filter "*.litemod" -ErrorAction SilentlyContinue)
    }
    $jarFiles = @($jarFiles)
    if ($script:_DevLimit) { $jarFiles = @($jarFiles | Select-Object -First $script:_DevLimit) }
    $script:TotalMods = @($jarFiles).Count

    $exeFiles = @()
    $pyFiles  = @()
    if ($script:_DevMode) {
        $exeFiles = @(Get-ChildItem -Path $ModPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10)
        $pyFiles  = @(Get-ChildItem -Path $ModPath -Filter "*.py"  -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10)
    }

    if ($script:TotalMods -eq 0) {
        Write-Host ""
        W "  $([char]0x26A0)  No JAR files found in: $ModPath" Yellow
    } else {
        Write-Host ""
        W "  $([char]0x25CF) Found $($script:TotalMods) JAR file(s) to analyze" Cyan
        Write-Host ""

        $verifiedMods   = [System.Collections.Generic.List[object]]::new()
        $unknownMods    = [System.Collections.Generic.List[object]]::new()

        $reviewMods  = [System.Collections.Generic.List[object]]::new()
        $flaggedMods = [System.Collections.Generic.List[object]]::new()

        $idx = 0
        W "  Analyzing mods $([char]0x2014) verify hash, extract features, AI score..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"

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
                [void]$verifiedMods.Add($rec)
            } elseif ($verdict.Band -eq "Confirmed" -or $verdict.Band -eq "Likely") {
                [void]$flaggedMods.Add($rec)
                [void]$script:FlaggedModsList.Add($jar.Name)
                $script:Flagged++
            } elseif ($verdict.Band -eq "Review" -or $verdict.Band -eq "ServerRule") {
                # A server-rule finding goes in the same list as Review - it needs a
                # person to look at it either way. It keeps its own band so the report
                # can say WHY: uncertainty in one case, a rule question in the other.
                [void]$reviewMods.Add($rec)
                [void]$script:ReviewModsList.Add($jar.Name)
                if ($verdict.Band -eq "ServerRule") { $script:ServerRule++ }
            } else {
                [void]$unknownMods.Add($rec)
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
        SpinClear

        if ($script:Flagged -gt 0) {
            Request-DeepEscalation "a mod was flagged, so the rest of the system is worth a closer look"
        } elseif ($reviewMods.Count -gt 0 -or $script:Evidence.HardConfirmed -gt 0 -or $script:Evidence.RandomNamed -gt 0) {
            Request-DeepEscalation "something here could not be accounted for"
        }

        $script:Verified = $verifiedMods.Count
        $script:Unknown  = $unknownMods.Count
        $script:Review   = $reviewMods.Count

        if ($verifiedMods.Count -gt 0) {
            Write-SectionHeader "VERIFIED MODS" $verifiedMods.Count Green Green
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            $vw = 70
            foreach ($mod in $verifiedMods) {
                $nameLine  = "$([char]0x2022) $($mod.ModName)"
                $fileLine  = "  $([char]0x2192) $($mod.FileName)"
                $sep = "$([char]0x2550)" * ($vw + 1)
                W ("  $([char]0x2554)$sep$([char]0x2557)") Green
                W ("  $([char]0x2551)  " + $nameLine.PadRight($vw - 1) + "$([char]0x2551)") Green
                W ("  $([char]0x2551)  " + $fileLine.PadRight($vw - 1) + "$([char]0x2551)") DarkGray
                if ($mod.ModUrl) {
                    $urlTxt = "[URL] $($mod.ModUrl)"
                    W ("  $([char]0x2551)  " + $urlTxt.PadRight($vw - 1) + "$([char]0x2551)") Cyan
                }
                W ("  $([char]0x255A)$sep$([char]0x255D)") Green
                Write-Host ""
            }
        }

        if ($unknownMods.Count -gt 0) {
            Write-SectionHeader "UNKNOWN MODS" $unknownMods.Count Yellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $unknownMods) {
                $fname = if ($mod.FileName.Length -gt 50) { $mod.FileName.Substring(0,47) + "..." } else { $mod.FileName }
                $src = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: unknown" }
                $padT = "$([char]0x2500)" * [Math]::Max(0, 65 - $fname.Length)
                W ("  $([char]0x2554)$([char]0x2550) ? " + $fname + " " + $padT + "$([char]0x2557)") Yellow
                if ($mod.DownloadUrl) {
                    $uDisp = if ($mod.DownloadUrl.Length -gt 63) { $mod.DownloadUrl.Substring(0,60) + "..." } else { $mod.DownloadUrl }
                    $uLabel = "[URL] $uDisp"
                    $padU = "$([char]0x2500)" * [Math]::Max(0, 67 - $uLabel.Length)
                    $Host.UI.Write("Yellow", $Host.UI.RawUI.BackgroundColor, "  $([char]0x255A)$([char]0x2550) ")
                    $Host.UI.Write("DarkYellow", $Host.UI.RawUI.BackgroundColor, $uLabel)
                    $Host.UI.WriteLine("Yellow", $Host.UI.RawUI.BackgroundColor, " $padU$([char]0x255D)")
                } else {
                    $padB = "$([char]0x2500)" * [Math]::Max(0, 67 - $src.Length)
                    W ("  $([char]0x255A)$([char]0x2550) " + $src + " " + $padB + "$([char]0x255D)") Yellow
                }
                Write-Host ""
            }
        }

        if ($reviewMods.Count -gt 0) {
            Write-SectionHeader "REVIEW $([char]0x2014) verify these manually" $reviewMods.Count DarkYellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in ($reviewMods | Sort-Object Score -Descending)) { Write-VerdictCard $mod }
        }

        if ($flaggedMods.Count -gt 0) {
            Write-SectionHeader "FLAGGED $([char]0x2014) likely cheats" $flaggedMods.Count Red Red
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in ($flaggedMods | Sort-Object Score -Descending)) { Write-VerdictCard $mod }
        }
    }

    if ($script:_DevMode -and ($exeFiles.Count -gt 0 -or $pyFiles.Count -gt 0)) {
        Write-Host ""
        W "  $([char]0x25CF) Dev mode: scanning $($exeFiles.Count) .exe and $($pyFiles.Count) .py file(s)..." Cyan
        Write-Host ""

        foreach ($exeFile in $exeFiles) {
            $exeFlags = Invoke-ExeScan -FilePath $exeFile.FullName
            if ($exeFlags.Count -gt 0) {
                $hash = Get-FileSHA1 $exeFile.FullName
                $emptySet = [System.Collections.Generic.HashSet[string]]::new()
                $strSet   = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($f in $exeFlags) { [void]$strSet.Add($f) }
                Write-FlaggedCard $exeFile.Name $hash $false "" $null $null $emptySet $strSet $emptySet
                [void]$script:FlaggedModsList.Add($exeFile.Name)
                $script:Flagged++
            } else {
                W "  $([char]0x2713) $($exeFile.Name) $([char]0x2014) clean" Green
            }
        }

        foreach ($pyFile in $pyFiles) {
            $pyFlags = Invoke-PyScan -FilePath $pyFile.FullName
            if ($pyFlags.Count -gt 0) {
                $hash = Get-FileSHA1 $pyFile.FullName
                $emptySet = [System.Collections.Generic.HashSet[string]]::new()
                $strSet   = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($f in $pyFlags) { [void]$strSet.Add($f) }
                Write-FlaggedCard $pyFile.Name $hash $false "" $null $null $emptySet $strSet $emptySet
                [void]$script:FlaggedModsList.Add($pyFile.Name)
                $script:Flagged++
            } else {
                W "  $([char]0x2713) $($pyFile.Name) $([char]0x2014) clean" Green
            }
        }
    }
}
