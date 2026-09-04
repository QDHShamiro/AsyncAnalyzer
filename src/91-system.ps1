# ---------------------------------------------------------------------------
# Windows system checks.
#
# Every check in here used to decide by GUESSING AT NAMES, and every one of them
# fired on an ordinary gaming PC:
#
#   hosts     the line contains "aac"       -> any pi-hole blocklist
#   tasks     the name contains "updater"   -> Discord, OneDrive, Razer, Epic
#   Defender  the path contains "mod"       -> C:\Games\ModernWarfare
#   prefetch  the name contains "LOADER"    -> fabric-loader
#   startup   the value contains "java"     -> every Java application ever
#
# They are replaced by STRUCTURAL tests - what the entry actually does, not what
# it is called. See ml/sysscan.py, where each one has the clean case that used
# to trip it as a test.
#
# The second thing wrong here: none of these checks called Add-Finding. The whole
# section, IFEO hijacking included - javaw.exe replaced by an injector, about as
# conclusive as this tool gets - printed to the console, bumped a counter and
# reached the report, the upload and "Look at these first" not at all. After the
# call there was nothing left of it.
#
# Findings are now split in two, because they answer different questions:
#   Add-SysCheat  bears on cheating. Counts, and can reach the report's first page.
#   Add-SysState  is the state of the PC. Shown in its own block, never counted:
#                 a third-party antivirus turns the Windows firewall off by
#                 itself, and an innocent player must not collect "system issues"
#                 for owning one.
# ---------------------------------------------------------------------------
# Write-SystemFlag already records the finding, under $script:SysArea - calling
# Add-Finding here as well would put every system check in the report twice.
function Add-SysCheat([string]$Level, [string]$Title, [string[]]$Items = @()) {
    $script:SysArea = "System forensics"
    Write-SystemFlag $Level $Title $Items
    $script:SystemIssues++
}

function Add-SysState([string]$Title, [string[]]$Items = @()) {
    $script:SysArea = "PC state"
    Write-SystemFlag "STATE" $Title $Items
}

# PendingFileRenameOperations is a REG_MULTI_SZ of [source, destination] pairs;
# an empty destination means "delete this on reboot" rather than "rename it to
# this". Pulled out as its own pure function - no registry, no live path check
# beyond Test-UserWritablePath - so a self-test can pin it without a Windows
# registry to read.
function Get-PendingRenameJarDllExe($Pairs) {
    $out = @()
    if (-not $Pairs) { return $out }
    for ($pi = 0; $pi -lt $Pairs.Count; $pi += 2) {
        $psrc = ([string]$Pairs[$pi]) -replace '^\\\?\?\\', ''
        if ($psrc -match '(?i)\.(jar|dll|exe)$' -and (Test-UserWritablePath $psrc)) {
            $out += $psrc
        }
    }
    return $out
}

# A hosts line that really sends a name that matters to nowhere.
# Returns "cheatsite", "auth" or "" - see hosts_block() in ml/sysscan.py.
function Test-HostsBlock([string]$Line, [string[]]$CheatDomains) {
    $l = ($Line -split '#', 2)[0].Trim()
    if (-not $l) { return @{ Kind = ""; Host = "" } }
    $parts = @($l -split '\s+' | Where-Object { $_ })
    if ($parts.Count -lt 2) { return @{ Kind = ""; Host = "" } }
    if ($script:sysBlackhole -notcontains $parts[0]) { return @{ Kind = ""; Host = "" } }
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $h = $parts[$i].Trim('.').ToLower()
        foreach ($d in $CheatDomains) {
            $dl = ([string]$d).ToLower()
            if ($dl -and ($h -eq $dl -or $h.EndsWith("." + $dl))) { return @{ Kind = "cheatsite"; Host = $h } }
        }
        foreach ($a in $script:sysAuthHosts) {
            if ($h -eq $a -or $h.EndsWith("." + $a)) { return @{ Kind = "auth"; Host = $h } }
        }
    }
    return @{ Kind = ""; Host = "" }
}

function Test-DefenderExclusion([string]$Path) {
    $p = ([string]$Path).ToLower().Replace('/', '\')
    foreach ($m in $script:sysMcMarkers) { if ($p.Contains($m)) { return $true } }
    if ($p.TrimEnd('\').EndsWith('\mods')) { return $true }
    # A process exclusion on the game's own runtime: nothing inside Minecraft is
    # ever scanned again, which is the point of adding it.
    if ($p -match '(?:^|\\)javaw?\.exe$') { return $true }
    return $false
}

# Why this startup entry or scheduled task is worth reporting, or "".
function Test-AutostartAction([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($Command)) { return "" }
    $hit = Test-CheatName $Command
    if ($hit) { return "names a known cheat client ($hit)" }
    if ($Command.ToLower().Contains('-javaagent:')) { return "attaches a Java agent to the process it starts" }
    # The switch alone would match -Execute; an encoded command is the switch
    # followed by a base64 blob long enough to be a command.
    if ($Command -match '(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{40,}') { return "runs a base64-encoded PowerShell command" }
    if ($Command -match '(?i)\.jar(?:"|\s|$)' -and $Command -match '(?i)(?:^|[\\/"\s])javaw?(?:\.exe)?(?:"|\s|$)') {
        return "starts a .jar with Java at login"
    }
    return ""
}

# FOO.EXE-1A2B3C4D.pf -> foo.exe. The hash suffix is not part of the name, and
# leaving it on is why "PROJECTOR.EXE" once matched a search for "INJECT".
function Get-PrefetchImage([string]$FileName) {
    $m = [regex]::Match($FileName, '(?i)^(.+)-[0-9A-F]{8}\.pf$')
    return $(if ($m.Success) { $m.Groups[1].Value } else { $FileName }).ToLower()
}

function Run-SystemChecks {
    Write-SysSection "SYSTEM FORENSICS"
    $script:SysArea = "System forensics"

    # ---- hosts file --------------------------------------------------------
    # Only lines that point a name at a blackhole address, and only for names
    # that have no business being in a hosts file: a cheat vendor's own domain,
    # or the game's login servers. Blocking Modrinth or CurseForge is a parental
    # filter, not a cheat, and used to be flagged as one.
    $hostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsCheat  = @()
    $hostsAuth   = @()
    $hostDomains = @(@($script:cheatDomainMap | ForEach-Object { $_.match }) | Where-Object { $_ -and ([string]$_).Contains('.') })
    foreach ($line in @(Get-Content $hostsPath -ErrorAction SilentlyContinue)) {
        $hb = Test-HostsBlock $line $hostDomains
        if ($hb.Kind -eq "cheatsite") { $hostsCheat += "$($hb.Host)  <-  $($line.Trim())" }
        elseif ($hb.Kind -eq "auth")  { $hostsAuth  += "$($hb.Host)  <-  $($line.Trim())" }
    }
    if ($hostsCheat.Count -gt 0) {
        Add-SysCheat "FAIL" "A cheat vendor's own domain is redirected in the hosts file:" $hostsCheat
        Write-Detail "The hosts file overrides DNS: these names resolve to nowhere on this PC." `
            "The domain belongs to a cheat client. Nothing puts it in a hosts file except software that talks to it $([char]0x2014) usually a cracked build being kept from phoning home for a licence check." `
            "Added by editing C:\Windows\System32\drivers\etc\hosts, which needs administrator rights." `
            "Open that file and remove the flagged lines."
    } elseif ($hostsAuth.Count -gt 0) {
        Add-SysCheat "WARN" "The game's own login servers are blackholed in the hosts file:" $hostsAuth
        Write-Detail "These are Mojang's session and authentication servers." `
            "Blocking them stops the client talking to Mojang while the game still runs $([char]0x2014) offline-mode and cracked setups do this, and so does anything that does not want its session seen." `
            "Added by editing C:\Windows\System32\drivers\etc\hosts." `
            "Open that file and remove the flagged lines, then check the game still logs in."
    } else { Write-SystemFlag "OK" "Hosts file $([char]0x2014) nothing that matters is redirected" }

    # ---- Defender exclusions -----------------------------------------------
    try {
        $mpExcReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction Stop
        $defExc   = @($mpExcReg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name)
        $javaExc  = @($defExc | Where-Object { Test-DefenderExclusion $_ })
        if ($javaExc.Count -gt 0) {
            Add-SysCheat "WARN" "Windows Defender is told never to scan the Minecraft install:" $javaExc
            Write-Detail "An exclusion tells Windows Security to skip a folder or a process entirely." `
                "Anything inside the excluded path is never scanned again $([char]0x2014) which is exactly what a cheat installer wants, and also what somebody chasing frames might set by hand." `
                "Set in Windows Security, or by a script writing to the Defender registry key." `
                "Windows Security > Virus & threat protection > Manage settings > Exclusions."
        } else { Write-SystemFlag "OK" "Defender exclusions $([char]0x2014) the Minecraft install is not excluded" }
    } catch { Add-ScanGap "Windows Defender exclusions could not be read $([char]0x2014) that needs Administrator, so an exclusion hiding the mods folder would not have been seen" }

    # ---- IFEO -------------------------------------------------------------
    # Replacing an executable with another one. On a game PC this has no
    # innocent version, and when the hijacked image is the game's own runtime it
    # is as close to proof as this tool gets.
    $ifeoFlags = @()
    $ifeoGame  = $false
    $rp = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $rp) {
        foreach ($child in @(Get-ChildItem $rp -ErrorAction SilentlyContinue)) {
            $prop = Get-ItemProperty -Path $child.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($prop -and $prop.Debugger -notmatch 'vsjitdebugger|drwatson|ntsd|windbg') {
                $ifeoFlags += "$($child.PSChildName) -> $($prop.Debugger)"
                if ($child.PSChildName -match '(?i)^(javaw?|minecraft.*|.*launcher)\.exe$') { $ifeoGame = $true }
            }
        }
    }
    if ($ifeoFlags.Count -gt 0) {
        Add-SysCheat $(if ($ifeoGame) { "FAIL" } else { "WARN" }) `
            $(if ($ifeoGame) { "The game's own executable is hijacked (IFEO):" } else { "An executable is hijacked (IFEO):" }) $ifeoFlags
        Write-Detail "Image File Execution Options lets Windows run a different program whenever a named executable is launched." `
            $(if ($ifeoGame) { "The hijacked name is the game's own runtime, so every Minecraft launch runs the listed program FIRST. That is what an injector is." } else { "Whatever launches the name on the left actually runs the program on the right." }) `
            "Set under HKLM\...\Image File Execution Options\<name>\Debugger, which needs administrator rights." `
            "Open regedit, go to the flagged key and delete its 'Debugger' value."
    } else { Write-SystemFlag "OK" "IFEO $([char]0x2014) no executable is hijacked" }

    # ---- execution history: prefetch ---------------------------------------
    # Through the same boundary-anchored client matcher the log and instance
    # readers use, on the image name with its hash suffix removed. The old
    # substring list matched fabric-loader, examiner.exe and projector.exe.
    $prefetchDir = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchDir) {
        $prefFlags = @()
        foreach ($pf in @(Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue)) {
            $img = Get-PrefetchImage $pf.Name
            $hit = Test-CheatName $img
            if ($hit) { $prefFlags += "$img  ($hit, last run $($pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" }
        }
        if ($prefFlags.Count -gt 0) {
            Add-SysCheat "FAIL" "Windows recorded a known cheat client being executed:" $prefFlags
            Write-Detail "Windows writes a .pf file the first time any program runs, to make later starts faster." `
                "The recorded name matches a known cheat client. The record survives deleting the program $([char]0x2014) it is proof that it ran on this PC, with the date it last did." `
                "C:\Windows\Prefetch, one file per executable." `
                "Nothing to fix: this is evidence, and deleting it destroys it."
        } else { Write-SystemFlag "OK" "Prefetch $([char]0x2014) no known client in the execution history" }
    } else { Add-ScanGap "Windows Prefetch could not be read, so programs that ran and were then deleted could not be checked there" }

    # ---- autostart: Run keys ------------------------------------------------
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $runFlags = @()
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk)) { continue }
        $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
        foreach ($pr in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $val = [string]$pr.Value
            $why = Test-AutostartAction $val
            if ($why) { $runFlags += "$($pr.Name) $([char]0x2014) $why$([char]0x0A)      $val" }
        }
    }
    if ($runFlags.Count -gt 0) {
        Add-SysCheat "WARN" "A startup entry does something a launcher does not:" $runFlags
        Write-Detail "Run and RunOnce start programs automatically at every login." `
            "Starting a jar, attaching a Java agent or running an encoded PowerShell command at login is not how any launcher or game installs itself." `
            "Registry, under Software\Microsoft\Windows\CurrentVersion\Run." `
            "Open regedit, go to the flagged key and delete the entry after reading what it points at."
    } else { Write-SystemFlag "OK" "Startup entries $([char]0x2014) nothing starts a jar or an agent at login" }

    # ---- autostart: scheduled tasks ----------------------------------------
    # By ACTION, not by name. The check this replaces flagged any task whose name
    # contained update/sync/helper/service/loader/check/runner/java and was not
    # from one of eight vendors - which is Discord, OneDrive, Epic, Razer,
    # Logitech, Corsair, Spotify and Brave on an ordinary PC.
    try {
        $taskFlags = @()
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($a in @($t.Actions)) {
                $cmd = (("$($a.Execute) $($a.Arguments)").Trim())
                $why = Test-AutostartAction $cmd
                if ($why) { $taskFlags += "$($t.TaskPath)$($t.TaskName) $([char]0x2014) $why$([char]0x0A)      $cmd" }
            }
        }
        if ($taskFlags.Count -gt 0) {
            Add-SysCheat "WARN" "A scheduled task does something a launcher does not:" $taskFlags
            Write-Detail "Scheduled tasks run programs at login, on a timer or on an event." `
                "The task's ACTION starts a jar, attaches a Java agent or runs an encoded command $([char]0x2014) none of which any game or launcher schedules." `
                "Task Scheduler (taskschd.msc)." `
                "Open the flagged task, read its Actions tab, and delete it if you do not recognise what it starts."
        } else { Write-SystemFlag "OK" "Scheduled tasks $([char]0x2014) none starts a jar, an agent or an encoded command" }
    } catch { Add-ScanGap "Scheduled tasks could not be listed $([char]0x2014) a task starting a cheat at login would not have been seen" }

    # ---- pending delete on reboot: PendingFileRenameOperations --------------
    # A file still locked by a running process cannot be deleted outright, so
    # Windows lets the caller queue the delete for the next boot instead -
    # MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT and no new name. A jar or DLL
    # still loaded by the game landing here is how a cheat finishes cleaning
    # up after the game closes. No admin needed to READ this value, only to
    # have written it.
    try {
        $pfro = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction Stop).PendingFileRenameOperations
        $pfroFlags = @(Get-PendingRenameJarDllExe $pfro)
        if ($pfroFlags.Count -gt 0) {
            Add-SysCheat "FAIL" "Files queued to vanish on the next restart, from a user-writable folder:" $pfroFlags
            Write-Detail "Windows lets a program that could not delete a locked file queue the delete for the next boot instead." `
                "A jar, DLL or EXE still loaded by a running process cannot be deleted outright; queuing it for reboot is how a cheat or its loader finishes cleaning up after the game closes." `
                "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations." `
                "Do not restart the PC before this is reviewed $([char]0x2014) restarting is exactly what completes the deletion."
            foreach ($pf in $pfroFlags) { Add-SessionEvent "Disk" "queued to delete on next reboot: $pf" $null }
        } else { Write-SystemFlag "OK" "Pending reboot deletes $([char]0x2014) nothing queued to vanish from a user-writable folder" }
    } catch { Write-SystemFlag "OK" "Pending reboot deletes $([char]0x2014) none queued" }

    # ---- mods folder touched while the game was already running -------------
    if ($script:GameStarted -and $script:ScanTargets) {
        $mtimeFlags = @()
        foreach ($mt in @($script:ScanTargets)) {
            if ([string]::IsNullOrWhiteSpace($mt)) { continue }
            try {
                $mlw = [System.IO.Directory]::GetLastWriteTime($mt)
                if ($mlw -ge $script:GameStarted) {
                    $mtimeFlags += "$mt  (folder itself last changed $($mlw.ToString('yyyy-MM-dd HH:mm:ss')), game started $($script:GameStarted.ToString('yyyy-MM-dd HH:mm:ss')))"
                    Add-SessionEvent "Disk" "mods folder changed while the game was running: $mt" $mlw
                }
            } catch {}
        }
        if ($mtimeFlags.Count -gt 0) {
            Add-SysCheat "WARN" "A mods folder's own contents changed after the game had already started:" $mtimeFlags
            Write-Detail "Every scanned mods folder's own last-modified time (a file being added or removed, not a file's own content changing) was compared against when the running game process started." `
                "A launcher writes mods BEFORE starting the game, not during $([char]0x2014) a folder that changes after launch is either the player managing their own mods live, or something adding or removing a jar mid-session." `
                "NTFS directory metadata, read directly $([char]0x2014) no admin needed." `
                "Check what changed: a jar that used to be there and is not any more, or one that appeared after the screenshare started."
        } else { Write-SystemFlag "OK" "Mods folders $([char]0x2014) none changed after the game started" }
    }

    # ---- Windows Defender: past detections -----------------------------------
    # Get-MpThreatDetection is real detection HISTORY, not a fresh scan: the
    # file existed, Defender recognised and acted on it. An injector's exe
    # caught and quarantined leaves exactly this, even after the file itself
    # is gone - which is why this belongs next to the other gone-file evidence
    # rather than needing its own live scan.
    try {
        $mpCutoff = (Get-Date).AddDays(-30)
        $mpDetections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -and $_.InitialDetectionTime -ge $mpCutoff })
        $mpFail = @()
        $mpWarn = @()
        foreach ($mdet in $mpDetections) {
            $tname = ""
            try { $tname = (Get-MpThreat -ThreatID $mdet.ThreatID -ErrorAction Stop).ThreatName } catch {}
            $mpaths = @($mdet.Resources | ForEach-Object { [string]$_ -replace '^file:_', '' })
            $mrelevant = @($mpaths | Where-Object { $_ -match '(?i)\\(\.minecraft|temp|downloads)\\' })
            $isRelevant = ($mrelevant.Count -gt 0) -or ($mdet.ProcessName -match '(?i)^javaw?\.exe$')
            if (-not $isRelevant) { continue }
            $pathPart = if ($mpaths.Count -gt 0) { "  " + ($mpaths -join '; ') } else { "" }
            $line = "$tname  $([char]0x2014) $($mdet.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm'))$pathPart"
            if ($tname -match '(?i)HackTool|Injector|Trojan') { $mpFail += $line } else { $mpWarn += $line }
            Add-SessionEvent "Defender" "detection: $tname" $mdet.InitialDetectionTime
        }
        if ($mpFail.Count -gt 0) {
            Add-SysCheat "FAIL" "Windows Defender caught a hacking tool near the game or Java itself:" $mpFail
            Write-Detail "Defender's own detection history for the last 30 days (Get-MpThreatDetection), filtered to detections touching .minecraft, Temp, Downloads or the Java process." `
                "HackTool/Injector/Trojan is Defender's own classification, not a name match here $([char]0x2014) Defender inspected the file's actual behaviour before flagging it." `
                "Windows Security's own detection log." `
                "The file is very likely already quarantined or removed by Defender itself; check Protection History in Windows Security for what happened to it."
        }
        if ($mpWarn.Count -gt 0) {
            Add-SysCheat "WARN" "Windows Defender recorded other detections near the game or Java itself:" $mpWarn
            Write-Detail "Same detection history, for anything Defender flagged that was not HackTool/Injector/Trojan." `
                "Adware, PUA and generic detections are not proof of cheating on their own, but a detection this close to the game is worth a look." `
                "Windows Security's own detection log." `
                "Check what it was in Windows Security's Protection History."
        }
        if ($mpFail.Count -eq 0 -and $mpWarn.Count -eq 0) {
            Write-SystemFlag "OK" "Windows Defender detection history $([char]0x2014) nothing near the game or Java in the last 30 days"
        }
    } catch {
        Add-ScanGap "Windows Defender's detection history could not be read (Get-MpThreatDetection) $([char]0x2014) a quarantined injector would not have been seen there"
    }

    # ---- PC state: real, reported, deliberately not counted ----------------
    Write-Host ""
    W "  $([char]0x2502)  PC state $([char]0x2014) not cheat evidence, but a moderator should see it" DarkCyan
    $script:SysArea = "PC state"

    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Enabled -eq $false })
        if ($fw.Count -gt 0) {
            Add-SysState ("Windows Firewall is off on: " + ($fw.Name -join ', '))
            Write-Detail "The firewall blocks connections this PC did not ask for." `
                "Most third-party antivirus suites turn the Windows firewall off and use their own, so this on its own says nothing about cheating." `
                "" "If no other firewall is installed, turn it back on in Windows Security."
        } else { Write-SystemFlag "OK" "Firewall $([char]0x2014) on for every profile" }
    } catch { Add-ScanGap "Firewall status could not be read" }

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($mpStatus -and -not $mpStatus.RealTimeProtectionEnabled) {
            Add-SysState "Windows Defender real-time protection is turned off"
            Write-Detail "RealTimeProtectionEnabled from Get-MpComputerStatus." `
                "Off means nothing new gets scanned as it runs or downloads - including an injector. Plenty of third-party antivirus switches this off too, so it is not counted against anyone by itself." `
                "" "If no other antivirus is installed, turn real-time protection back on in Windows Security."
        } else { Write-SystemFlag "OK" "Windows Defender real-time protection $([char]0x2014) enabled" }
    } catch { Add-ScanGap "Windows Defender's status could not be read (Get-MpComputerStatus)" }

    $psLogKey  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psLogging = if (Test-Path $psLogKey) { (Get-ItemProperty $psLogKey -ErrorAction SilentlyContinue).EnableScriptBlockLogging } else { $null }
    if ($psLogging -eq 0) {
        Add-SysState "PowerShell script logging is switched off by policy"
        Write-Detail "Script Block Logging records PowerShell commands to the event log." `
            "It is off by default on home Windows, so this is only interesting if somebody turned it off deliberately." `
            "" "Set EnableScriptBlockLogging to 1 under HKLM\...\PowerShell\ScriptBlockLogging."
    } else { Write-SystemFlag "OK" "PowerShell script logging $([char]0x2014) enabled or left at the default" }

    try {
        $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1 -ErrorAction Stop)
        if ($ev.Count -gt 0) {
            Add-SysState ("The Security event log was cleared on " + $ev[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'))
            Write-Detail "Windows writes event 1102 whenever somebody clears the Security log." `
                "Clearing it removes the record of what ran and when. Ordinary users have no reason to, so the DATE is the interesting part $([char]0x2014) compare it with when the screenshare was arranged." `
                "" ""
        } else { Write-SystemFlag "OK" "Security event log $([char]0x2014) not cleared in the last 30 days" }
    } catch { Write-SystemFlag "OK" "Security event log $([char]0x2014) no clearing recorded" }

    Write-SysSectionEnd
}

function Run-ServiceCheck {
    Write-SysSection "WINDOWS SERVICE STATUS"
    W "  $([char]0x2502)" DarkCyan
    W "  $([char]0x2502)  Checking services that affect system security and cheat detection..." DarkGray
    W "  $([char]0x2502)" DarkCyan

    $serviceTable = @(
        @{ Name="SysMain";    DisplayName="Superfetch / SysMain";             Expected="Running"; WhatDoes="Prefetches frequently used apps into RAM."; WhySecurity="Disabling slows forensic execution tracking used by AV tools." },
        @{ Name="PcaSvc";     DisplayName="Program Compatibility Assistant";  Expected="Running"; WhatDoes="Monitors programs and logs launched applications."; WhySecurity="Disabling removes execution logging that AV tools rely on." },
        @{ Name="DPS";        DisplayName="Diagnostic Policy Service";        Expected="Running"; WhatDoes="Enables diagnostics for Windows components."; WhySecurity="Malware disables this to prevent crash dumps from being analyzed." },
        @{ Name="EventLog";   DisplayName="Windows Event Log";                Expected="Running"; WhatDoes="Records all system, security, and application events."; WhySecurity="Stopping this makes the system blind to logins and process creation." },
        @{ Name="Schedule";   DisplayName="Task Scheduler";                   Expected="Running"; WhatDoes="Runs scheduled tasks at specified times or triggers."; WhySecurity="Malware uses scheduled tasks for persistence after reboot." },
        @{ Name="bam";        DisplayName="Background Activity Monitor";      Expected="Running"; WhatDoes="Kernel driver tracking EXE execution history in registry."; WhySecurity="BAM data is a key forensic source for executed programs." },
        @{ Name="Dusmsvc";    DisplayName="Delivery Optimization";            Expected="Running"; WhatDoes="Manages Windows Update downloads and data usage."; WhySecurity="Stopping can interfere with Defender definition updates." },
        @{ Name="Appinfo";    DisplayName="Application Information (UAC)";    Expected="Running"; WhatDoes="Handles UAC elevation prompts."; WhySecurity="With AppInfo stopped, UAC prompts fail silently." },
        @{ Name="SSDPSRV";    DisplayName="SSDP Discovery";                   Expected="Stopped"; WhatDoes="Discovers UPnP devices on the local network."; WhySecurity="UPnP exploited by malware to auto-open firewall ports on routers." },
        @{ Name="CDPSvc";     DisplayName="Connected Devices Platform";       Expected="Running"; WhatDoes="Enables device connectivity like phone sync."; WhySecurity="Stopping CDPSvc can suppress diagnostic data used by Microsoft AV." },
        @{ Name="DcomLaunch"; DisplayName="DCOM Server Process Launcher";     Expected="Running"; WhatDoes="Launches COM and DCOM servers."; WhySecurity="Malware hijacking DCOM can escalate privileges or spread laterally." },
        @{ Name="PlugPlay";   DisplayName="Plug and Play";                    Expected="Running"; WhatDoes="Detects and configures hardware devices automatically."; WhySecurity="Stopping can prevent recognition of USB attack devices." },
        @{ Name="WinDefend";  DisplayName="Windows Defender Antivirus";       Expected="Running"; WhatDoes="Real-time protection, malware scanning."; WhySecurity="If stopped, no real-time AV protection is active. Cheats run freely." },
        @{ Name="MpsSvc";     DisplayName="Windows Firewall";                 Expected="Running"; WhatDoes="Enforces the Windows Firewall ruleset."; WhySecurity="A stopped firewall means all traffic is unfiltered. RATs communicate freely." },
        @{ Name="wscsvc";     DisplayName="Security Center";                  Expected="Running"; WhatDoes="Monitors AV, firewall, and Windows Update status."; WhySecurity="Malware disables this to hide that security tools have been turned off." }
    )

    $colW1 = 32; $colW2 = 10; $colW3 = 10
    W ("  $([char]0x2502)  $([char]0x250C)$([char]0x2500)" + ("$([char]0x2500)" * $colW1) + "$([char]0x2500)$([char]0x252C)$([char]0x2500)" + ("$([char]0x2500)" * $colW2) + "$([char]0x2500)$([char]0x252C)$([char]0x2500)" + ("$([char]0x2500)" * $colW3) + "$([char]0x2500)$([char]0x2510)") DarkCyan
    W ("  $([char]0x2502)  $([char]0x2502) " + "Service".PadRight($colW1) + " $([char]0x2502) " + "Status".PadRight($colW2) + " $([char]0x2502) " + "Expected".PadRight($colW3) + " $([char]0x2502)") DarkCyan
    W ("  $([char]0x2502)  $([char]0x251C)$([char]0x2500)" + ("$([char]0x2500)" * $colW1) + "$([char]0x2500)$([char]0x253C)$([char]0x2500)" + ("$([char]0x2500)" * $colW2) + "$([char]0x2500)$([char]0x253C)$([char]0x2500)" + ("$([char]0x2500)" * $colW3) + "$([char]0x2500)$([char]0x2524)") DarkCyan

    $serviceIssues = @()
    $svcNames  = $serviceTable | ForEach-Object { $_.Name }
    # -ErrorAction handles errors the cmdlet raises; it cannot handle the cmdlet
    # not existing, which is a CommandNotFoundException raised before it is called
    # - fatal under $ErrorActionPreference = 'Stop'.
    $allSvcs = @()
    try { $allSvcs = @(Get-Service -Name $svcNames -ErrorAction SilentlyContinue) }
    catch { Add-ScanGap "The Windows services could not be listed, so it was not checked whether Defender or the firewall service had been stopped" }
    $svcLookup = @{}
    foreach ($s in $allSvcs) { $svcLookup[$s.Name] = $s.Status.ToString() }

    foreach ($svc in $serviceTable) {
        $status  = if ($svcLookup.ContainsKey($svc.Name)) { $svcLookup[$svc.Name] } else { "Not Found" }
        $isOK    = ($status -eq $svc.Expected)

        W "  $([char]0x2502)  $([char]0x2502) " DarkCyan -NoNewline
        W $svc.DisplayName.PadRight($colW1) White -NoNewline
        W " $([char]0x2502) " DarkCyan -NoNewline
        if ($isOK) { W $status.PadRight($colW2) Green -NoNewline } else { W $status.PadRight($colW2) Red -NoNewline }
        W " $([char]0x2502) " DarkCyan -NoNewline
        W $svc.Expected.PadRight($colW3) DarkGray -NoNewline
        W " $([char]0x2502)" DarkCyan

        if (-not $isOK) { $serviceIssues += $svc; $script:SystemIssues++ }
    }

    W ("  $([char]0x2502)  $([char]0x2514)$([char]0x2500)" + ("$([char]0x2500)" * $colW1) + "$([char]0x2500)$([char]0x2534)$([char]0x2500)" + ("$([char]0x2500)" * $colW2) + "$([char]0x2500)$([char]0x2534)$([char]0x2500)" + ("$([char]0x2500)" * $colW3) + "$([char]0x2500)$([char]0x2518)") DarkCyan

    if ($serviceIssues.Count -gt 0) {
        W "  $([char]0x2502)" DarkCyan
        W "  $([char]0x2502)  Flagged Services $([char]0x2014) Details:" Yellow
        W "  $([char]0x2502)" DarkCyan
        foreach ($svc in $serviceIssues) {
            $status = if ($svcLookup.ContainsKey($svc.Name)) { $svcLookup[$svc.Name] } else { "Not Found" }
            W "  $([char]0x2502)  $([char]0x25C9) " Red -NoNewline; W "$($svc.DisplayName)  [$status / expected: $($svc.Expected)]" Red
            W "  $([char]0x2502)    WHAT: $($svc.WhatDoes)" White
            W "  $([char]0x2502)    WHY : $($svc.WhySecurity)" DarkGray
            W "  $([char]0x2502)" DarkCyan
            Add-Finding "WARN" "Windows services" "$($svc.DisplayName) is $status, expected $($svc.Expected)" `
                @() $svc.WhatDoes $svc.WhySecurity "" "Open services.msc and set '$($svc.Name)' back to $($svc.Expected)." | Out-Null
        }
    } else {
        W "  $([char]0x2502)" DarkCyan
        Write-SystemFlag "OK" "All security-relevant services are in their expected state"
    }

    Write-SysSectionEnd
}

Show-Banner
