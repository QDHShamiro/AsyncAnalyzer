if ($SelfTest) { Invoke-SelfTest; Invoke-PackScanSelfTest; return }
if ($HashOnly) { Invoke-HashOnly $HashOnly; return }

if (Invoke-SelfElevate) { return }   # an elevated window took over; nothing left to do here
[void](Set-AutoDepth)
if (-not (Test-IsAdmin)) {
    Add-ScanGap "Ran without Administrator $([char]0x2014) deleted-program history (BAM), Defender exclusions and scheduled tasks were NOT checked"
}

W "  Scan ID: " DarkGray -NoNewline; W "$($script:ScanId)" Cyan -NoNewline
if ($script:ScanCode) {
    W "    Code from staff: " DarkGray -NoNewline; W "$($script:ScanCode)" Yellow
} else {
    W "    (no staff code given $([char]0x2014) run with -Code <word> so this report can be dated)" DarkGray
}
Write-Host ""
W "  What this tool does $([char]0x2014) and does not do:" Cyan
W "    $([char]0x2713) Read-only. It never changes, deletes, or quarantines your files." Green
W "    $([char]0x2713) Runs fully on your PC. It never uploads your files or your data." Green
W "    $([char]0x2713) Network use is limited to looking mods up by hash on Modrinth /" DarkGray
W "      CurseForge / Megabase $([char]0x2014) only the file hash is sent, never the file." DarkGray
W "    $([char]0x2713) The cheat verdict is scored by a local AI model (no cloud, no key)." Green
W "    $([char]0x2713) Verified mods are never flagged. Flags come with a reason + score." Green
W "    $([char]0x2139) Inside Minecraft it reads: the mods folder, the game's own logs and" DarkGray
W "      crash reports, the launcher profiles under versions/, and resource and" DarkGray
W "      shader packs. Nothing outside Minecraft except the folders below." DarkGray
W "    $([char]0x2139) A deep, whole-PC scan (processes, stray jars, autostart) is separate" DarkGray
W "      and turns itself on when Minecraft is running or something turns up." DarkGray
W "    $([char]0x2139) Every scan also reads macro scripts (.ahk .ahk2 .au3 .lua .vbs) in" DarkGray
W "      Downloads, Desktop, Documents, Temp and your mouse driver's script folder," DarkGray
W "      because an autoclicker is never in the mods folder and does not need the" DarkGray
W "      game to be open. Read-only, like everything else here." DarkGray
W "    $([char]0x2139) It also reads what Windows remembers about files that are GONE:" DarkGray
W "      the Recycle Bin's own records (original path and deletion time), the" DarkGray
W "      list of programs you started by double-clicking them, and with" DarkGray
W "      Administrator the NTFS change journal and the compatibility cache." DarkGray
W "      Those are the only places a jar deleted before a screenshare still" DarkGray
W "      exists. All read-only: nothing is mounted, copied or restored." DarkGray
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
    # The jar-finding loop below reads $script:ScanTargets, not $ModPath - Dev
    # mode set $ModPath for the banner and nothing else, so every -Dev -DevPath
    # run found 0 jars regardless of what was actually in the folder. Same story
    # for Run-InstanceScan, which reads $script:ScanTargetDirs (only ever filled
    # by Get-ScanTargets, which Dev mode skips) - it silently checked 0 folders.
    $script:ScanTargets = @($ModPath)
    if (-not $script:ScanTargetDirs.Contains($ModPath)) { [void]$script:ScanTargetDirs.Add($ModPath) }
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
    # Which target each jar came from, so the loop below knows whether it may
    # start on the cheap bytecode budget (an idle profile) or must always use
    # the full one (the instance actually being watched). $script:IdleScanTargets
    # is populated by Get-ScanTargets; empty when -Path/-Ask named a single
    # folder directly, which then behaves like any primary target.
    $script:JarOriginIdle = @{}
    foreach ($t in $script:ScanTargets) {
        if (-not (Test-Path $t -PathType Container)) {
            Add-ScanGap "Folder could not be read: $t"
            continue
        }
        $isIdleTarget = ($null -ne $script:IdleScanTargets) -and $script:IdleScanTargets.Contains($t)
        $tJars = @(Get-ChildItem -Path $t -Filter "*.jar" -ErrorAction SilentlyContinue)
        $tJars += @(Get-ChildItem -Path $t -Filter "*.litemod" -ErrorAction SilentlyContinue)
        foreach ($tj in $tJars) { $script:JarOriginIdle[$tj.FullName] = $isIdleTarget }
        $jarFiles += $tJars
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

        $script:verifiedMods   = [System.Collections.Generic.List[object]]::new()
        $script:unknownMods    = [System.Collections.Generic.List[object]]::new()

        $script:reviewMods  = [System.Collections.Generic.List[object]]::new()
        $script:flaggedMods = [System.Collections.Generic.List[object]]::new()

        # Read every jar first, on as many cores as this PC has. Nothing is decided
        # here - it is the same three functions the loop below would have called,
        # just not one after another. A jar missing from $pre (or an empty $pre,
        # which is what a small folder or a failed pool gives) is read inline in the
        # loop, exactly as before.
        $pre = Invoke-JarPrecompute $jarFiles

        $idx = 0
        # An idle profile's own jars run on a fixed, cheap bytecode budget until
        # something in THIS run earns the deep one - not $script:BcMaxClasses,
        # which Set-AutoDepth may already have raised to 400 for the instance
        # actually running. Once anything scores Review (30) or above, every jar
        # after it - idle profiles included - gets the full budget: the same
        # "widen the search" rule Request-DeepEscalation already applies to the
        # PC-wide checks, reaching backward into the mod pass that finds it.
        $idleQuickBudget = 40
        W "  Analyzing mods $([char]0x2014) verify hash, extract features, AI score..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            $isIdleJar = [bool]$script:JarOriginIdle[$jar.FullName]
            $budget = if ($isIdleJar -and -not $script:Escalated) { $idleQuickBudget } else { 0 }
            $rec = Invoke-JarAnalysis $jar $pre[$jar.FullName] $budget
            if (-not $script:Escalated -and $rec -and [int]$rec.Score -ge 50) {
                SpinClear
                Request-DeepEscalation "$($jar.Name) scored $($rec.Score)/100 during the quick pass"
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
