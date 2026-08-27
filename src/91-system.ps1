function Run-SystemChecks {
    Write-SysSection "SYSTEM FORENSICS"

    $hostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $suspHosts    = @("modrinth.com","curseforge.com","minecraft.net","mojang.com","hypixel.net","badlion.net","lunarclient.com","watchdog","anticheat","nocheatplus","aac","vulcan","grim")
    $hostsFlags   = @()
    foreach ($line in $hostsContent) {
        if ($line -match '^\s*[^#]') {
            foreach ($h in $suspHosts) { if ($line -match $h) { $hostsFlags += $line.Trim() } }
        }
    }
    if ($hostsFlags.Count -gt 0) {
        Write-SystemFlag "WARN" "Hosts file is blocking suspicious domains:"
        foreach ($f in $hostsFlags) { W "  $([char]0x2502)         $f" Red }
        Write-Detail "The hosts file overrides DNS and redirects domain names to fake IPs." `
            "Blocking Modrinth/Mojang/anticheat domains prevents ban syncs and cheat detection." `
            "Cheaters add entries like '127.0.0.1 hypixel.net' to break AC connections." `
            "Open C:\Windows\System32\drivers\etc\hosts and remove flagged lines."
        $script:SystemIssues++
    } else { Write-SystemFlag "OK" "Hosts file $([char]0x2014) no suspicious domain blocks" }

    try {
        $mpExcReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction Stop
        $defExc   = $mpExcReg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
        $javaExc  = $defExc | Where-Object { $_ -match 'java|minecraft|jdk|jre|mod|\.minecraft|launcher' }
        if ($javaExc) {
            Write-SystemFlag "WARN" "Windows Defender exclusions cover Java/Minecraft paths:"
            foreach ($e in $javaExc) { W "  $([char]0x2502)         $e" Red }
            Write-Detail "Defender exclusions tell Windows Security to never scan specific folders." `
                "Excluding the Minecraft folder means any malware inside a mod is never detected." `
                "Cheat installers add these via PowerShell or registry to protect themselves." `
                "Windows Security > Virus & threat protection > Manage settings > Remove exclusions."
            $script:SystemIssues++
        } else { Write-SystemFlag "OK" "Defender exclusions $([char]0x2014) no Java/Minecraft paths excluded" }
    } catch { Write-SystemFlag "INFO" "Defender exclusions $([char]0x2014) run as Administrator for full check" }

    $ifeoPaths = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
    $ifeoFlags = @()
    foreach ($rp in $ifeoPaths) {
        if (Test-Path $rp) {
            $children = Get-ChildItem $rp -ErrorAction SilentlyContinue
            foreach ($child in $children) {
                $prop = Get-ItemProperty -Path $child.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($prop -and $prop.Debugger -notmatch 'vsjitdebugger|drwatson|ntsd') {
                    $ifeoFlags += "$($child.PSChildName) -> $($prop.Debugger)"
                }
            }
        }
    }
    if ($ifeoFlags.Count -gt 0) {
        Write-SystemFlag "FAIL" "IFEO hijacking detected:"
        foreach ($f in $ifeoFlags) { W "  $([char]0x2502)         $f" Red }
        Write-Detail "Image File Execution Options (IFEO) allows replacing any EXE with another." `
            "When javaw.exe is hijacked, every Minecraft launch runs a cheat injector first." `
            "Set via Registry Editor at HKLM\...\Image File Execution Options\javaw.exe" `
            "Delete the 'Debugger' value from the flagged key in regedit."
        $script:SystemIssues++
    } else { Write-SystemFlag "OK" "IFEO $([char]0x2014) no process hijacking detected" }

    $psLogKey  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psLogging = if (Test-Path $psLogKey) { (Get-ItemProperty $psLogKey -ErrorAction SilentlyContinue).EnableScriptBlockLogging } else { $null }
    if ($psLogging -eq 0) {
        Write-SystemFlag "WARN" "PowerShell Script Block Logging is DISABLED via policy"
        Write-Detail "Script Block Logging records every PowerShell command to the event log." `
            "Disabling it makes PowerShell-based malware invisible to forensic tools." `
            "" "Set-ItemProperty -Path 'HKLM:\...\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
        $script:SystemIssues++
    } else { Write-SystemFlag "OK" "PowerShell Script Block Logging $([char]0x2014) enabled or default" }

    try {
        $logEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1 -ErrorAction Stop
        if ($logEvents) {
            Write-SystemFlag "WARN" "Security event log was recently cleared"
            Write-Detail "Event ID 1102 is logged whenever the Security event log is manually cleared." `
                "Clearing it destroys evidence of past malware or unauthorized access." `
                "Normal users almost never clear this log. It was cleared deliberately." ""
            $script:SystemIssues++
        } else { Write-SystemFlag "OK" "Security event log $([char]0x2014) not recently cleared" }
    } catch { Write-SystemFlag "OK" "Security event log $([char]0x2014) no clearing events found" }

    $bamKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bamFlags = @()
    if (Test-Path $bamKey) {
        $bamChildren = Get-ChildItem $bamKey -ErrorAction SilentlyContinue
        foreach ($child in $bamChildren) {
            $vals = Get-ItemProperty -Path $child.PSPath -ErrorAction SilentlyContinue
            $vals.PSObject.Properties | Where-Object { $_.Name -match '\\' -and $_.Name -match '\.(exe|jar)$' } | ForEach-Object {
                if ($_.Name -match 'cheat|hack|inject|stealer|miner|payload|exploit|crack|loader|bypass') { $bamFlags += $_.Name }
            }
        }
    }
    if ($bamFlags.Count -gt 0) {
        Write-SystemFlag "FAIL" "BAM registry: suspicious executables recently executed:"
        foreach ($f in $bamFlags) { W "  $([char]0x2502)         $f" Red }
        Write-Detail "BAM (Background Activity Monitor) logs every executable launched, stored in registry." `
            "Logged EXE names match known cheat clients or malware. Proves they were run on this PC." `
            "BAM data persists for 7 days. Check HKLM\SYSTEM\...\bam\State\UserSettings." ""
        $script:SystemIssues++
    } else { Write-SystemFlag "OK" "BAM/DAM registry $([char]0x2014) no suspicious executables recorded" }

    try {
        $stRaw     = schtasks /query /fo CSV /nh 2>$null | ConvertFrom-Csv -Header TaskName,NextRun,Status
        $suspTasks = $stRaw | Where-Object {
            $_.TaskName -notmatch 'Microsoft|Adobe|Google|Mozilla|Steam|NVIDIA|Intel|AMD' -and
            $_.TaskName -match 'update|sync|helper|service|loader|check|runner|updater|java'
        }
        if ($suspTasks) {
            Write-SystemFlag "WARN" ("Suspicious scheduled tasks found: " + @($suspTasks).Count)
            foreach ($t in $suspTasks | Select-Object -First 5) { W "  $([char]0x2502)         $($t.TaskName)" Yellow }
            Write-Detail "Scheduled tasks run programs automatically at login, on a timer, or on events." `
                "These tasks launch Java or scripts with generic names like 'updater'." `
                "Malware uses scheduled tasks to persist across reboots." `
                "Open Task Scheduler (taskschd.msc) and delete suspicious tasks."
            $script:SystemIssues++
        } else { Write-SystemFlag "OK" "Scheduled tasks $([char]0x2014) nothing suspicious" }
    } catch { Write-SystemFlag "INFO" "Scheduled tasks $([char]0x2014) run as Administrator for full check" }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Enabled -eq $false }
        if ($fw) {
            Write-SystemFlag "WARN" ("Windows Firewall DISABLED on profiles: " + ($fw.Name -join ', '))
            Write-Detail "Windows Firewall blocks unauthorized inbound and outbound network connections." `
                "With the firewall off, malware can open server sockets for RATs/reverse shells." `
                "" "Windows Security > Firewall & network protection > Enable all profiles."
            $script:SystemIssues++
        } else { Write-SystemFlag "OK" "Firewall $([char]0x2014) enabled on all profiles" }
    } catch { Write-SystemFlag "INFO" "Firewall status $([char]0x2014) could not read" }

    $prefetchDir = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchDir) {
        $prefFlags = Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match 'CHEAT|HACK|INJECT|STEALER|MINER|PAYLOAD|EXPLOIT|LOADER|LIQUIDBOUNCE|WURST|METEOR|VAPE|RISE|SIGMA|BARITONE' }
        if ($prefFlags) {
            Write-SystemFlag "WARN" "Prefetch shows suspicious programs were recently executed:"
            foreach ($p in $prefFlags) { W "  $([char]0x2502)         $($p.Name)" Yellow }
            Write-Detail "Windows Prefetch (.pf files) records every program launched to speed up restarts." `
                "These filenames match known cheat clients, injectors, or malware tools." `
                "Prefetch data persists even if the original program was deleted." ""
            $script:SystemIssues++
        } else { Write-SystemFlag "OK" "Prefetch $([char]0x2014) no suspicious execution history" }
    } else { Write-SystemFlag "INFO" "Prefetch $([char]0x2014) directory not accessible" }

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $runFlags = @()
    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $val = $_.Value.ToString()
                if ($val -match 'java|\.jar|powershell.*encoded|mshta|wscript|cscript' -and $val -notmatch 'JetBrains|Eclipse|IntelliJ|Visual Studio|Android') {
                    $runFlags += "$($_.Name) = $val"
                }
            }
        }
    }
    if ($runFlags.Count -gt 0) {
        Write-SystemFlag "WARN" "Startup registry entries launching Java/scripts:"
        foreach ($f in $runFlags) { W "  $([char]0x2502)         $f" Yellow }
        Write-Detail "Run/RunOnce registry keys launch programs automatically at every Windows login." `
            "These entries auto-start Java processes or encoded PowerShell scripts." `
            "Malware uses this to reload itself after every reboot." `
            "Open regedit, navigate to the flagged key, and delete the suspicious entry."
        $script:SystemIssues++
    } else { Write-SystemFlag "OK" "Startup registry $([char]0x2014) no suspicious auto-run entries" }

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
    $allSvcs   = Get-Service -Name $svcNames -ErrorAction SilentlyContinue
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
        }
    } else {
        W "  $([char]0x2502)" DarkCyan
        Write-SystemFlag "OK" "All security-relevant services are in their expected state"
    }

    Write-SysSectionEnd
}

Show-Banner
