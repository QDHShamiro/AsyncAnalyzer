function Find-MinecraftModFolders {
    $runningJava = @(Get-Process javaw,java -ErrorAction SilentlyContinue)

    $script:javaProcessInfos = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($runningJava.Count -gt 0) {
        foreach ($proc in $runningJava) {
            try {
                $wp = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                if ($wp) {
                    [void]$script:javaProcessInfos.Add([PSCustomObject]@{
                        CommandLine = if ($wp.CommandLine) { $wp.CommandLine } else { "" }
                        WorkingDir  = if ($wp.ExecutablePath) { [System.IO.Path]::GetDirectoryName($wp.ExecutablePath) } else { "" }
                    })
                }
            } catch {}
        }
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $seen    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function IsJavaRunningIn([string]$dir) {
        $dirNorm = $dir.TrimEnd('\')
        foreach ($info in $script:javaProcessInfos) {
            $cl = $info.CommandLine
            if ($cl) {
                if ($cl.IndexOf($dirNorm, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
            }
            if ($info.WorkingDir -and $info.WorkingDir.StartsWith($dirNorm, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }

    $directMods = @(
        "$env:APPDATA\.minecraft\mods",
        "$env:LOCALAPPDATA\Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe\LocalCache\Local\.minecraft\mods"
    )
    foreach ($d in $directMods) {
        if ([System.IO.Directory]::Exists($d)) {
            if ($seen.Add($d)) {
                $jars  = @([System.IO.Directory]::GetFiles($d, "*.jar"))
                $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($d) }
                $parentDir = [System.IO.Path]::GetDirectoryName($d)
                $isRun = IsJavaRunningIn $parentDir
                [void]$results.Add([PSCustomObject]@{ Path=$d; Launcher="Vanilla"; Instance=""; JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$isRun })
            }
        }
    }
    $launcherRoots = @(
        "$env:APPDATA\PrismLauncher\instances",
        "$env:APPDATA\prismlauncher\instances",
        "$env:LOCALAPPDATA\Programs\Prism Launcher\instances",
        "$env:APPDATA\ATLauncher\instances",
        "$env:APPDATA\MultiMC\instances",
        "$env:LOCALAPPDATA\MultiMC\instances",
        "$env:APPDATA\ftblauncher\instances",
        "$env:LOCALAPPDATA\GDLauncher Carbon\instances",
        "$env:APPDATA\gdlauncher\instances",
        "$env:LOCALAPPDATA\curseforge\minecraft\Instances",
        "$env:USERPROFILE\curseforge\minecraft\Instances",
        "$env:USERPROFILE\Documents\curseforge\minecraft\Instances",
        "$env:APPDATA\.technic\modpacks",
        "$env:APPDATA\PolyMC\instances",
        "$env:APPDATA\Modrinth\profiles",
        "$env:APPDATA\com.modrinth.theseus\profiles",
        "$env:APPDATA\ModrinthApp\profiles"
    )
    foreach ($root in $launcherRoots) {
        if (-not [System.IO.Directory]::Exists($root)) { continue }
        $launcher = Get-LauncherName $root
        foreach ($inst in [System.IO.Directory]::GetDirectories($root)) {
            $instName = [System.IO.Path]::GetFileName($inst)
            $candidates = @(
                [System.IO.Path]::Combine($inst, ".minecraft", "mods"),
                [System.IO.Path]::Combine($inst, "minecraft", "mods"),
                [System.IO.Path]::Combine($inst, "mods")
            )
            foreach ($c in $candidates) {
                if ([System.IO.Directory]::Exists($c)) {
                    if ($seen.Add($c)) {
                        $jars  = @([System.IO.Directory]::GetFiles($c, "*.jar"))
                        $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($c) }
                        $isRun = IsJavaRunningIn $inst
                        [void]$results.Add([PSCustomObject]@{ Path=$c; Launcher=$launcher; Instance=$instName; JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$isRun })
                    }
                    break
                }
            }
        }
    }

    $lunarRunning = @(Get-Process "lunar-launcher","lunarclient","Lunar Client" -ErrorAction SilentlyContinue).Count -gt 0
    $lunarOffline = "$env:USERPROFILE\.lunarclient\offline"
    if ([System.IO.Directory]::Exists($lunarOffline)) {
        foreach ($verDir in [System.IO.Directory]::GetDirectories($lunarOffline)) {
            $modsDir = [System.IO.Path]::Combine($verDir, "mods")
            if ([System.IO.Directory]::Exists($modsDir) -and $seen.Add($modsDir)) {
                $jars  = @([System.IO.Directory]::GetFiles($modsDir, "*.jar"))
                $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($modsDir) }
                [void]$results.Add([PSCustomObject]@{ Path=$modsDir; Launcher="LunarClient"; Instance=[System.IO.Path]::GetFileName($verDir); JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$lunarRunning })
            }
        }
    }

    $badlionRunning = @(Get-Process "BadlionClient","badlionclient" -ErrorAction SilentlyContinue).Count -gt 0
    $badlionDirs = @(
        "$env:APPDATA\Badlion Client\.minecraft\mods",
        "$env:APPDATA\.badlion\.minecraft\mods",
        "$env:APPDATA\.minecraft\mods"
    )
    foreach ($bd in $badlionDirs) {
        if ([System.IO.Directory]::Exists($bd) -and $seen.Add($bd)) {
            $jars  = @([System.IO.Directory]::GetFiles($bd, "*.jar"))
            $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($bd) }
            [void]$results.Add([PSCustomObject]@{ Path=$bd; Launcher="Badlion"; Instance=""; JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$badlionRunning })
            break
        }
    }

    $featherRunning = @(Get-Process "feather-launcher","featherclient","Feather Client" -ErrorAction SilentlyContinue).Count -gt 0
    $featherDirs = @(
        "$env:APPDATA\feather\instances",
        "$env:LOCALAPPDATA\feather\instances",
        "$env:APPDATA\.feather\instances"
    )
    foreach ($fr in $featherDirs) {
        if (-not [System.IO.Directory]::Exists($fr)) { continue }
        foreach ($inst in [System.IO.Directory]::GetDirectories($fr)) {
            $modsDir = [System.IO.Path]::Combine($inst, "mods")
            if ([System.IO.Directory]::Exists($modsDir) -and $seen.Add($modsDir)) {
                $jars  = @([System.IO.Directory]::GetFiles($modsDir, "*.jar"))
                $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($modsDir) }
                [void]$results.Add([PSCustomObject]@{ Path=$modsDir; Launcher="Feather"; Instance=[System.IO.Path]::GetFileName($inst); JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$featherRunning })
            }
        }
    }

    # deep scan: find .minecraft folders anywhere on fixed drives (portable / renamed installs)
    # skipped when a running instance is already found (that is the target anyway)
    if (-not ($results | Where-Object { $_.IsRunning })) {
    try {
        $skipDeep = @('windows','program files','program files (x86)','programdata','$recycle.bin','system volume information','windows.old','node_modules','.git')
        foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
            if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or -not $drive.IsReady) { continue }
            $queue = [System.Collections.Generic.Queue[object]]::new()
            $queue.Enqueue([PSCustomObject]@{ P = $drive.RootDirectory.FullName; D = 0 })
            $checked = 0
            while ($queue.Count -gt 0 -and $checked -lt 6000) {
                $node = $queue.Dequeue(); $checked++
                try {
                    foreach ($sub in [System.IO.Directory]::GetDirectories($node.P)) {
                        $nm = [System.IO.Path]::GetFileName($sub).ToLower()
                        if ($skipDeep -contains $nm) { continue }
                        if ($nm -eq '.minecraft') {
                            $md = [System.IO.Path]::Combine($sub, 'mods')
                            if ([System.IO.Directory]::Exists($md) -and $seen.Add($md)) {
                                $jars = @([System.IO.Directory]::GetFiles($md, '*.jar'))
                                $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($md) }
                                $inst = [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($sub))
                                [void]$results.Add([PSCustomObject]@{ Path=$md; Launcher="Detected"; Instance=$inst; JarCount=$jars.Count; LastWrite=$lastW; IsRunning=(IsJavaRunningIn $sub) })
                            }
                        } elseif ($node.D -lt 4) {
                            $queue.Enqueue([PSCustomObject]@{ P = $sub; D = $node.D + 1 })
                        }
                    }
                } catch {}
            }
        }
    } catch {}
    }

    $sorted = $results | Sort-Object @{e={[int]$_.IsRunning};Descending=$true}, @{e='JarCount';Descending=$true}, @{e='LastWrite';Descending=$true}
    return @($sorted)
}

function Get-ConfiguredPaths {
    # Extra folders to always look at, from two optional sources - neither needs to
    # exist. Same shape as the other community lists so a team can push a path once
    # and everyone picks it up.
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @($script:PathsFromConfig)) { if ($p) { [void]$out.Add([string]$p) } }
    try {
        $local = Join-Path $env:APPDATA "AsyncAnalyzer\paths.txt"
        if (Test-Path $local) {
            foreach ($line in (Get-Content $local -ErrorAction Stop)) {
                $t = ([string]$line).Trim().Trim('"').Trim("'")
                if ($t -and -not $t.StartsWith('#')) { [void]$out.Add($t) }
            }
        }
    } catch {}
    return @($out | Select-Object -Unique)
}

function Get-ScanTargets {
    # During a screenshare the instance that is OPEN is the one that matters: it is
    # the one being played, and it cannot be swapped out while you are watching.
    W "  $([char]0x25CF) Finding what to scan..." DarkGray
    $targets = [System.Collections.Generic.List[string]]::new()
    $found   = @(Find-MinecraftModFolders)
    $running = @($found | Where-Object { $_.IsRunning })

    if ($running.Count -gt 0) {
        foreach ($r in $running) {
            if (-not $targets.Contains($r.Path)) { [void]$targets.Add($r.Path) }
            W "  $([char]0x2713) Open now: " Green -NoNewline
            W "$($r.Launcher)" Cyan -NoNewline
            if ($r.Instance) { W " / $($r.Instance)" White -NoNewline }
            W "  ($($r.JarCount) mods)" DarkGray
        }
        $idle = @($found | Where-Object { -not $_.IsRunning })
        if ($idle.Count -gt 0) {
            Add-ScanGap "$($idle.Count) other Minecraft install(s) exist but were not open, so they were not scanned"
        }
    } elseif ($found.Count -gt 0) {
        [void]$targets.Add($found[0].Path)
        W "  $([char]0x2713) Nothing open $([char]0x2014) checking the most likely install: $($found[0].Launcher)" Yellow
        if ($found.Count -gt 1) {
            Add-ScanGap "$($found.Count) installs found and none was open $([char]0x2014) only the most likely one was scanned"
        }
    }

    foreach ($p in (Get-ConfiguredPaths)) {
        if ((Test-Path $p -PathType Container) -and -not $targets.Contains($p)) {
            [void]$targets.Add($p)
            W "  $([char]0x2713) From your path list: $p" DarkGray
        }
    }

    if ($targets.Count -eq 0) {
        $def = "$env:APPDATA\.minecraft\mods"
        W "  $([char]0x26A0)  No Minecraft found $([char]0x2014) trying the default folder." Yellow
        [void]$targets.Add($def)
    }
    Write-Host ""
    return @($targets)
}

function Ask-ModPath {
    W "  Enter the full path to your mods folder." White
    W "  (press Enter for default: %APPDATA%\.minecraft\mods  |  type " DarkGray -NoNewline
    W "auto" Cyan -NoNewline
    W " to auto-detect)" DarkGray
    Write-Host ""
    $raw = Read-Host "  PATH"
    $p = ([string]$raw).Trim('"').Trim("'").Trim()

    if ($p -ieq "auto") {
        Write-Host ""
        W "  Scanning for Minecraft installations..." DarkGray
        $found = Find-MinecraftModFolders
        if ($found.Count -eq 0) {
            Write-Host ""
            W "  $([char]0x26A0)  No Minecraft mods folders found. Enter path manually." Yellow
            Write-Host ""
            $raw2 = Read-Host "  PATH"
            $p2 = ([string]$raw2).Trim('"').Trim("'").Trim()
            if ([string]::IsNullOrWhiteSpace($p2)) { $p2 = "$env:APPDATA\.minecraft\mods" }
            return $p2
        }
        $runningInstances = @($found | Where-Object { $_.IsRunning })
        if ($runningInstances.Count -eq 1) {
            $e = $runningInstances[0]
            Write-Host ""
            W "  $([char]0x2713) Auto-selected (currently running): " Green -NoNewline
            W "$($e.Launcher)" Cyan -NoNewline
            if ($e.Instance) { W " / $($e.Instance)" White -NoNewline }
            W "  ($($e.JarCount) mods)  $([char]0x25CF) RUNNING" Green
            Write-Host ""
            return $e.Path
        }
        if ($found.Count -eq 1) {
            $e   = $found[0]
            $tag = if ($e.IsRunning) { "  $([char]0x25CF) RUNNING" } else { "" }
            Write-Host ""
            W "  $([char]0x2713) Auto-selected: " Green -NoNewline
            W "$($e.Launcher)" Cyan -NoNewline
            if ($e.Instance) { W " / $($e.Instance)" White -NoNewline }
            W "  ($($e.JarCount) mods)$tag" DarkGray
            Write-Host ""
            return $e.Path
        }
        $displayList = if ($runningInstances.Count -gt 1) { $runningInstances } else { $found }
        $w = 72
        Write-Host ""
        $header = if ($runningInstances.Count -gt 1) { "RUNNING INSTANCES" } else { "FOUND INSTALLATIONS" }
        W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) $header " + "$([char]0x2500)" * (69 - $header.Length) + "$([char]0x2510)") DarkCyan
        W "  $([char]0x2502)   #   Launcher        Instance                   Mods  Last Used    $([char]0x2502)" DarkCyan
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkCyan
        $idx = 1
        foreach ($e in $displayList) {
            $runMark = if ($e.IsRunning) { "$([char]0x25CF) " } else { "  " }
            $inst    = if ($e.Instance) { $e.Instance } else { "-" }
            $inst    = if ($inst.Length -gt 26) { $inst.Substring(0,26) } else { $inst.PadRight(26) }
            $launch  = if ($e.Launcher.Length -gt 13) { $e.Launcher.Substring(0,13) } else { $e.Launcher.PadRight(13) }
            $mods    = "$($e.JarCount)".PadLeft(4)
            $date    = $e.LastWrite.ToString("yyyy-MM-dd")
            $idxStr  = "$idx".PadRight(3)
            $line    = "  $([char]0x2502)   $idxStr $runMark$launch  $inst  $mods  $date  $([char]0x2502)"
            if ($e.IsRunning) { W $line Green } else { W $line White }
            $idx++
        }
        W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkCyan
        Write-Host ""
        $sel = Read-Host "  Select number (Enter = 1)"
        $sel = ([string]$sel).Trim()
        $selIdx = 1
        $parsed = 0
        if (-not [string]::IsNullOrWhiteSpace($sel) -and [int]::TryParse($sel, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $displayList.Count) { $selIdx = $parsed }
        $chosen = $displayList[$selIdx - 1]
        Write-Host ""
        W "  $([char]0x2713) Selected: " Green -NoNewline
        W "$($chosen.Launcher)" Cyan -NoNewline
        if ($chosen.Instance) { W " / $($chosen.Instance)" White -NoNewline }
        W "  ($($chosen.JarCount) mods)" DarkGray
        Write-Host ""
        return $chosen.Path
    }

    if ([string]::IsNullOrWhiteSpace($p)) {
        $p = "$env:APPDATA\.minecraft\mods"
        Write-Host ""
        W "  Continuing with " Gray -NoNewline
        W $p White
    }
    return $p
}

function Run-RecentActivity {
    $w = 72
    Write-Host ""
    W ("$([char]0x2501)" * 76) DarkCyan
    Write-Host ""
    W "  RECENT ACTIVITY CHECK" Cyan
    Write-Host ""
    W ("$([char]0x2501)" * 76) DarkCyan
    Write-Host ""

    $since = (Get-Date).AddHours(-48)
    $anyFound = $false
    $cheatExeNames = @($script:cheatProcessNames) + @("cheat","hack","inject","bypass","aimbot","killaura","autoclicker","nofall","freecam","xray","stealer","grabber")

    W "  $([char]0x25CF) Checking currently running processes for suspicious activity..." DarkGray
    Write-Host ""
    $runningProcs = Get-Process -ErrorAction SilentlyContinue
    $suspRunning  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tempPathRx     = [regex]::new('(?i)(\\Temp\\|\\AppData\\Roaming\\[^\\]+\.exe$|\\AppData\\Local\\Temp\\)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $trustedPathRx  = [regex]::new('(?i)(\\Windows\\|\\WindowsApps\\|\\Program Files\\|\\Program Files \(x86\)\\|\\ProgramData\\|\\AppData\\Local\\Programs\\|\\AppData\\Roaming\\(?:Avira|Razer|NVIDIA|Intel|Microsoft|Discord|Slack|Spotify|Steam|Epic Games|CefSharp|crashpad|Medal|Claude|cowork)|\\NVIDIA Corporation\\|\\Razer\\|FrameViewSDK|PresentMon|\\JetBrains\\|\\IntelliJ|\\WebStorm|\\PyCharm|\\CLion|\\GoLand|\\Rider|\\DataGrip|\\RubyMine|\\AppCode|\\PhpStorm|\\jbr\\bin\\|\\lib\\pty4j\\)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    foreach ($proc in $runningProcs) {
        $name      = $proc.Name
        $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($name)
        if ($script:processWhitelist.Contains($name) -or $script:processWhitelist.Contains($nameNoExt)) { continue }
        $reasons   = [System.Collections.Generic.List[string]]::new()
        $nameLower = $nameNoExt.ToLower()
        foreach ($kw in $cheatExeNames) {
            $kwl = $kw.ToLower()
            if ($kwl.Length -le 4) {
                if ($nameLower -eq $kwl) { $reasons.Add("keyword match [$kw]"); break }
            } else {
                if ($nameLower.Contains($kwl)) { $reasons.Add("keyword match [$kw]"); break }
            }
        }
        $procPath = ""
        try { $procPath = $proc.MainModule.FileName } catch {}
        if ($procPath -and $tempPathRx.IsMatch($procPath)) {
            $isInstaller = $procPath -match '(?i)(CodeSetup|is-[A-Z0-9]{5}\.tmp|Squirrel|SquirrelSetup|nsis|setup\.exe|installer\.exe|unins\d+|Update\.exe|bootstrapper|vcredist|dotnet|ndp|wix)'
            if (-not $isInstaller) { $reasons.Add("running from temp/roaming path") }
        }
        $windowTitle = ""; $companyName = ""
        try { $windowTitle = $proc.MainWindowTitle } catch {}
        try { $companyName = $proc.MainModule.FileVersionInfo.CompanyName } catch {}
        if ([string]::IsNullOrWhiteSpace($windowTitle) -and [string]::IsNullOrWhiteSpace($companyName) -and $procPath -ne "") {
            if (-not $trustedPathRx.IsMatch($procPath)) {
                $reasons.Add("no window + no company name (hidden/unsigned)")
            }
        }
        if ($nameNoExt.Length -ge 6 -and $nameNoExt.Length -le 12 -and $nameNoExt -cmatch '^[a-z]+$') {
            $vowels = ($nameNoExt.ToCharArray() | Where-Object { $_ -in @('a','e','i','o','u') }).Count
            $ratio  = $vowels / $nameNoExt.Length
            if ($ratio -lt 0.20) { $reasons.Add("random-looking name (vowel ratio: $([Math]::Round($ratio,2)))") }
        }
        if ($reasons.Count -eq 0) { continue }
        $dp = if ($procPath.Length -gt 55) { "..." + $procPath.Substring($procPath.Length - 52) } else { $procPath }
        [void]$suspRunning.Add([PSCustomObject]@{ Name=$name; PID=$proc.Id; DisplayPath=$dp; ReasonStr=($reasons -join " + ") })
    }
    if ($suspRunning.Count -gt 0) {
        $anyFound = $true
        W ("  $([char]0x250C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2510)") DarkRed
        W ("  $([char]0x2502)  $([char]0x26A0)  Suspicious running processes detected:" + " " * [Math]::Max(0,$w - 39) + "$([char]0x2502)") DarkRed
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed
        $shown = $suspRunning | Select-Object -First 20
        $last  = $shown | Select-Object -Last 1
        foreach ($p in $shown) {
            $l1 = "    $([char]0x25C9) $($p.Name)  [PID $($p.PID)]"
            $t1 = if ($l1.Length -gt $w) { $l1.Substring(0,$w-3)+"..." } else { $l1 }
            W ("  $([char]0x2502)" + $t1.PadRight($w+1) + "$([char]0x2502)") Red
            $l2 = "      WHY  : $($p.ReasonStr)"
            $t2 = if ($l2.Length -gt $w) { $l2.Substring(0,$w-3)+"..." } else { $l2 }
            W ("  $([char]0x2502)" + $t2.PadRight($w+1) + "$([char]0x2502)") DarkRed
            if ($p.DisplayPath) {
                $l3 = "      PATH : $($p.DisplayPath)"
                $t3 = if ($l3.Length -gt $w) { $l3.Substring(0,$w-3)+"..." } else { $l3 }
                W ("  $([char]0x2502)" + $t3.PadRight($w+1) + "$([char]0x2502)") DarkGray
            }
            if ($p -ne $last) { W ("  $([char]0x2502)" + "$([char]0x2500)" * ($w+1) + "$([char]0x2502)") DarkGray }
        }
        if ($suspRunning.Count -gt 20) {
            $rem = $suspRunning.Count - 20
            $moreMsg = "    ... and $rem more suspicious process$(if($rem -ne 1){'es'})"
            W ("  $([char]0x2502)" + $moreMsg.PadRight($w+1) + "$([char]0x2502)") DarkGray
        }
        W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkRed
    } else {
        W "  $([char]0x2713) No suspicious running processes found." Green
    }
    Write-Host ""

    W "  $([char]0x25CF) Checking recently deleted files (Recycle Bin)..." DarkGray
    Write-Host ""
    try {
        $shell   = New-Object -ComObject Shell.Application
        $recycle = $shell.Namespace(0xA)
        $deleted = @($recycle.Items() | Where-Object {
            try { $_.ExtendedProperty("System.Recycle.DateDeleted") -ge $since } catch { $false }
        })
        $jarDel = @($deleted | Where-Object { $_.Name -match '\.jar$|\.zip$|\.exe$' })
        if ($jarDel.Count -gt 0) {
            $anyFound = $true
            W ("  $([char]0x250C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2510)") DarkYellow
            W ("  $([char]0x2502)  $([char]0x26A0)  Recently deleted files (last 48h):" + " " * [Math]::Max(0,$w - 38) + "$([char]0x2502)") DarkYellow
            W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkYellow
            foreach ($item in $jarDel) {
                $delDate = ""
                try { $delDate = $item.ExtendedProperty("System.Recycle.DateDeleted").ToString("yyyy-MM-dd HH:mm") } catch {}
                $origPath = ""
                try { $origPath = $item.ExtendedProperty("System.Recycle.DeletedFrom") } catch {}
                $line = "    $([char]0x25BA) $($item.Name)  [$delDate]"
                if ($origPath) { $line += "  from: $origPath" }
                $trimmed = if ($line.Length -gt $w) { $line.Substring(0, $w - 3) + "..." } else { $line }
                W ("  $([char]0x2502)" + $trimmed.PadRight($w + 1) + "$([char]0x2502)") Yellow
            }
            W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkYellow
        } else {
            W "  $([char]0x2713) No suspicious files deleted in the last 48 hours." Green
        }
    } catch {
        W "  $([char]0x2014) Recycle Bin check failed (access denied or COM error)." DarkGray
    }
    Write-Host ""

    W "  $([char]0x25CF) Checking recently added / modified JARs (last 48h)..." DarkGray
    Write-Host ""
    $newJarRoots = @(
        "$env:APPDATA\.minecraft\mods",
        "$env:LOCALAPPDATA\Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe\LocalCache\Local\.minecraft\mods"
    )
    foreach ($root in $script:mcInstanceRoots) {
        if ([System.IO.Directory]::Exists($root)) { $newJarRoots += $root }
    }
    $recentJars = [System.Collections.Generic.List[object]]::new()
    foreach ($root in ($newJarRoots | Select-Object -Unique)) {
        if (-not [System.IO.Directory]::Exists($root)) { continue }
        try {
            Get-ChildItem -Path $root -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since } | ForEach-Object {
                $recentJars.Add([PSCustomObject]@{ Name = $_.Name; Path = $_.FullName; Modified = $_.LastWriteTime; Size = $_.Length })
            }
        } catch {}
    }
    if ($recentJars.Count -gt 0) {
        $anyFound = $true
        $recentJarsCapped = if ($script:_DevMode) { $recentJars | Select-Object -First 10 } else { $recentJars }
        $capNote = if ($script:_DevMode -and $recentJars.Count -gt 10) { " (showing 10 of $($recentJars.Count))" } else { "" }
        W ("  $([char]0x250C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2510)") DarkYellow
        W ("  $([char]0x2502)  $([char]0x26A0)  New / modified JARs in the last 48h$capNote" + (" " * [Math]::Max(0,$w - 37 - $capNote.Length)) + "$([char]0x2502)") DarkYellow
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkYellow
        foreach ($jar in ($recentJarsCapped | Sort-Object Modified -Descending)) {
            $ts   = $jar.Modified.ToString("yyyy-MM-dd HH:mm")
            $kb   = [Math]::Round($jar.Size / 1KB, 0)
            $line = "    $([char]0x25BA) $($jar.Name)  [$ts]  ${kb} KB"
            $trimmed = if ($line.Length -gt $w) { $line.Substring(0, $w - 3) + "..." } else { $line }
            W ("  $([char]0x2502)" + $trimmed.PadRight($w + 1) + "$([char]0x2502)") Yellow
        }
        W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkYellow
    } else {
        W "  $([char]0x2713) No new or modified JARs found in the last 48 hours." Green
    }
    Write-Host ""

    W "  $([char]0x25CF) Checking recently closed processes..." DarkGray
    Write-Host ""
    $closedProcs = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Source 1: Security log event 4689 (needs Audit Process Termination policy)
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4689; StartTime = $since } -MaxEvents 300 -ErrorAction SilentlyContinue
        foreach ($ev in $secEvents) {
            $msg = $ev.Message
            $procName = if ($msg -match '(?m)Process Name:\s+(.+)') { [System.IO.Path]::GetFileName($matches[1].Trim()) } else { $null }
            if (-not $procName) { continue }
            $procNameLower = $procName.ToLower()
            $isSusp = $false
            foreach ($n in $cheatExeNames) { if ($procNameLower.Contains($n.ToLower())) { $isSusp = $true; break } }
            if ($isSusp) { $closedProcs.Add([PSCustomObject]@{ Name = $procName; Time = $ev.TimeCreated; Source = "Security" }) }
        }
    } catch {}

    # Source 2: Application log — app crashes (event 1000) and WER (event 1001)
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = @(1000,1001); StartTime = $since } -MaxEvents 300 -ErrorAction SilentlyContinue
        foreach ($ev in $appEvents) {
            $msg = $ev.Message
            $procName = if ($msg -match '(?m)Faulting application name:\s*([^\r\n,]+)') { $matches[1].Trim() }
                        elseif ($msg -match '(?m)Application Name:\s*([^\r\n,]+)') { $matches[1].Trim() }
                        else { $null }
            if (-not $procName) { continue }
            $procNameLower = $procName.ToLower()
            $isSusp = $false
            foreach ($n in $cheatExeNames) { if ($procNameLower.Contains($n.ToLower())) { $isSusp = $true; break } }
            if ($isSusp) { $closedProcs.Add([PSCustomObject]@{ Name = $procName; Time = $ev.TimeCreated; Source = "Crash" }) }
        }
    } catch {}

    # Source 3: UserAssist registry — recently run executables (last-run timestamps)
    try {
        $uaKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        $uaGuids = Get-ChildItem -Path $uaKey -ErrorAction SilentlyContinue
        foreach ($guid in $uaGuids) {
            $countKey = Join-Path $guid.PSPath "Count"
            if (-not (Test-Path $countKey)) { continue }
            $vals = Get-ItemProperty -Path $countKey -ErrorAction SilentlyContinue
            if (-not $vals) { continue }
            foreach ($prop in $vals.PSObject.Properties) {
                $name = $prop.Name
                if ($name -in @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive')) { continue }
                $decoded = -join ($name.ToCharArray() | ForEach-Object {
                    $c = [int]$_
                    if    ($c -ge 65 -and $c -le 90)  { [char](($c - 65 + 13) % 26 + 65) }
                    elseif($c -ge 97 -and $c -le 122) { [char](($c - 97 + 13) % 26 + 97) }
                    else  { $_ }
                })
                $exeName = [System.IO.Path]::GetFileName($decoded).ToLower()
                if (-not $exeName.EndsWith('.exe')) { continue }
                $isSusp = $false
                foreach ($n in $cheatExeNames) { if ($exeName.Contains($n.ToLower())) { $isSusp = $true; break } }
                if (-not $isSusp) { continue }
                $raw = $prop.Value
                if ($raw -isnot [byte[]] -or $raw.Length -lt 72) { continue }
                $ft = [System.BitConverter]::ToInt64($raw, 60)
                if ($ft -le 0) { continue }
                $lastRun = [System.DateTime]::FromFileTime($ft)
                if ($lastRun -ge $since) {
                    $closedProcs.Add([PSCustomObject]@{ Name = [System.IO.Path]::GetFileName($decoded); Time = $lastRun; Source = "UserAssist" })
                }
            }
        }
    } catch {}

    $closedProcs = @($closedProcs | Sort-Object Time -Descending | Group-Object Name | ForEach-Object { $_.Group[0] })
    if ($closedProcs.Count -gt 0) {
        $anyFound = $true
        W ("  $([char]0x250C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2510)") DarkRed
        W ("  $([char]0x2502)  $([char]0x26A0)  Suspicious processes closed recently:" + " " * [Math]::Max(0,$w - 38) + "$([char]0x2502)") DarkRed
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed
        foreach ($p in ($closedProcs | Select-Object -First 15)) {
            $ts  = $p.Time.ToString("yyyy-MM-dd HH:mm")
            $src = "[$($p.Source)]"
            $line = "    $([char]0x25C9) $($p.Name)  $ts  $src"
            $trimmed = if ($line.Length -gt $w) { $line.Substring(0, $w - 3) + "..." } else { $line }
            W ("  $([char]0x2502)" + $trimmed.PadRight($w + 1) + "$([char]0x2502)") Red
        }
        W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkRed
    } else {
        W "  $([char]0x2713) No suspicious recently closed processes found." Green
    }
    Write-Host ""

    if (-not $anyFound) {
        W "  $([char]0x2713) Recent activity check clean $([char]0x2014) nothing suspicious found." Green
        Write-Host ""
    }
}

function Write-FlaggedCard([string]$FileName, [string]$Hash, [bool]$Verified, [string]$VerifiedName, [string]$DlSource, [string]$DlUrl, [object]$Patterns, [object]$Strings, [object]$Fullwidth) {
    $w = 72
    $titleText = " FLAGGED  $FileName"
    $pad = [Math]::Max(0, $w - $titleText.Length - 2)
    W ("  $([char]0x250C)$([char]0x2500)" + $titleText + "$([char]0x2500)" * $pad + "$([char]0x2510)") DarkRed
    W "  $([char]0x2502)" DarkRed -NoNewline; W (" FLAGGED " ) White -NoNewline; W (" " * ([Math]::Max(0,$w - 9))) DarkRed -NoNewline; W "$([char]0x2502)" DarkRed

    $hashLine = if ($Hash) { "  SHA1: $Hash" } else { "  SHA1: unknown" }
    W ("  $([char]0x2502)  " + $hashLine.PadRight($w - 2) + "$([char]0x2502)") DarkGray

    $srcLine = if ($DlSource) { "  Source: $DlSource" } else { "  Source: unverified" }
    if ($Verified) {
        W ("  $([char]0x2502)  $([char]0x2713) Verified: $VerifiedName".PadRight($w + 2) + "$([char]0x2502)") Green
    } else {
        W ("  $([char]0x2502)  $([char]0x2717) Not found on Modrinth, CurseForge or Megabase".PadRight($w + 2) + "$([char]0x2502)") Yellow
    }
    W ("  $([char]0x2502)  " + $srcLine.Substring(2).PadRight($w - 2) + "$([char]0x2502)") DarkGray
    if ($DlUrl) {
        $urlDisplay = if ($DlUrl.Length -gt ($w - 10)) { $DlUrl.Substring(0, $w - 13) + "..." } else { $DlUrl }
        $urlLabel = "[URL] $urlDisplay"
        $Host.UI.Write("DarkGray", $Host.UI.RawUI.BackgroundColor, "  $([char]0x2502)  ")
        $Host.UI.Write("DarkYellow", $Host.UI.RawUI.BackgroundColor, $urlLabel)
        $Host.UI.WriteLine("DarkGray", $Host.UI.RawUI.BackgroundColor, (" " * ($w - 2 - $urlLabel.Length)) + "$([char]0x2502)")
    }
    W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed

    if ($Patterns -and $Patterns.Count -gt 0) {
        W ("  $([char]0x2502)  PATTERNS".PadRight($w + 2) + "$([char]0x2502)") DarkGray
        foreach ($p in ($Patterns | Sort-Object)) {
            $line = "    $([char]0x25C9) $p"
            W ("  $([char]0x2502)" + $line.PadRight($w + 1) + "$([char]0x2502)") Red
        }
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed
    }

    $uniqueStrings = @($Strings | Where-Object { $Patterns -notcontains $_ } | Sort-Object)
    if ($uniqueStrings.Count -gt 0) {
        W ("  $([char]0x2502)  STRINGS".PadRight($w + 2) + "$([char]0x2502)") DarkGray
        $shown = 0
        foreach ($s in $uniqueStrings) {
            if ($shown -ge 12) {
                $rem = $uniqueStrings.Count - $shown
                W ("  $([char]0x2502)    ... and $rem more".PadRight($w + 2) + "$([char]0x2502)") DarkGray
                break
            }
            $line = "    $([char]0x25BA) $s"
            W ("  $([char]0x2502)" + $line.PadRight($w + 1) + "$([char]0x2502)") DarkYellow
            $shown++
        }
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed
    }

    if ($Fullwidth -and $Fullwidth.Count -gt 0) {
        W ("  $([char]0x2502)  FULLWIDTH UNICODE".PadRight($w + 2) + "$([char]0x2502)") DarkGray
        foreach ($fw in ($Fullwidth | Sort-Object)) {
            $line = "    $([char]0x25B6) $fw"
            W ("  $([char]0x2502)" + $line.PadRight($w + 1) + "$([char]0x2502)") Cyan
        }
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkRed
    }

    W ("  $([char]0x2502)  $([char]0x26A0)  Remove this mod immediately. Run a full AV scan.".PadRight($w + 2) + "$([char]0x2502)") Red
    W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkRed
    Write-Host ""
}

function Write-InjectionCard([string]$FileName, [object]$Flags) {
    $w = 72
    W ("  $([char]0x250C)$([char]0x2500) INJECTION  $FileName " + "$([char]0x2500)" * [Math]::Max(0, $w - 14 - $FileName.Length) + "$([char]0x2510)") DarkMagenta
    W "  $([char]0x2502)" DarkMagenta -NoNewline; W " INJECTION " White -NoNewline; W (" " * [Math]::Max(0,$w - 11)) DarkMagenta -NoNewline; W "$([char]0x2502)" DarkMagenta
    W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkMagenta

    foreach ($flag in $Flags) {
        $ft = $flag; $fd = ""
        if ($flag -match "^(.+?) $([char]0x2014) (.+)$") { $ft = $matches[1]; $fd = $matches[2] }
        W "  $([char]0x2502)" DarkMagenta
        W ("  $([char]0x2502)  ") DarkMagenta -NoNewline; W "$([char]0x25C9) " Magenta -NoNewline; W $ft White
        if ($fd) { W ("  $([char]0x2502)    " + $fd.PadRight($w - 4)) Gray }
    }

    W "  $([char]0x2502)" DarkMagenta
    W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkMagenta
    Write-Host ""
}

# The console scrolls past and the staff member reading the report was not sitting
# in front of it. Every check records what it looked at and what it concluded, so
# the report can print the reasoning instead of a bare "3 system issues".
function Add-Finding {
    param(
        [string]$Level, [string]$Area, [string]$Title,
        [string[]]$Items = @(),
        [string]$What = "", [string]$Why = "", [string]$How = "", [string]$Fix = ""
    )
    $f = [PSCustomObject]@{
        Level = $Level; Area = $Area; Title = $Title; Items = @($Items)
        What  = $What;  Why   = $Why;  How   = $How;  Fix   = $Fix
    }
    [void]$script:Findings.Add($f)
    $script:LastFinding = $f
    return $f
}

function Write-SystemFlag([string]$Level, [string]$Msg, [string[]]$Items = @()) {
    switch ($Level) {
        "FAIL" { W "  $([char]0x2502) " DarkRed -NoNewline; W " FAIL " White -NoNewline; W "  $Msg" Red }
        "WARN" { W "  $([char]0x2502) " DarkYellow -NoNewline; W " WARN " Black -NoNewline; W "  $Msg" Yellow }
        "OK"   { W "  $([char]0x2502) " DarkGreen -NoNewline; W "  OK  " White -NoNewline; W "  $Msg" Green }
        "INFO" { W "  $([char]0x2502) " DarkGray -NoNewline; W "  ??  " White -NoNewline; W "  $Msg" DarkGray }
    }
    $items = @($Items)
    if ($items.Count -gt 0) {
        $itemColor = if ($Level -eq "FAIL") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "DarkGray" }
        # The console gets a readable excerpt; the report keeps every single one,
        # because on a screenshare the full list is the evidence.
        foreach ($i in ($items | Select-Object -First 8)) { W "  $([char]0x2502)         $i" $itemColor }
        if ($items.Count -gt 8) { W "  $([char]0x2502)         ... and $($items.Count - 8) more (all of them are in the report)" DarkGray }
    }
    Add-Finding $Level $script:SysArea $Msg $items | Out-Null
    # INFO from a check means it could not run - no admin, key unreadable, directory
    # missing. That is a gap in coverage, not a result, and the whole point of the
    # coverage box is that nothing like this goes unlisted.
    if ($Level -eq "INFO") { Add-ScanGap $Msg }
}

function Write-Detail([string]$what, [string]$why, [string]$how, [string]$fix) {
    if ($what) { W ("  $([char]0x2502)    WHAT : " + $what) White }
    if ($why)  { W ("  $([char]0x2502)    WHY  : " + $why) DarkGray }
    if ($how)  { W ("  $([char]0x2502)    HOW  : " + $how) DarkGray }
    if ($fix)  { W ("  $([char]0x2502)    FIX  : " + $fix) DarkCyan }
    # Attaches to the flag that was just printed - every call site prints the flag
    # first and the reasoning right after, so the pairing is the existing order.
    if ($script:LastFinding) {
        $script:LastFinding.What = $what; $script:LastFinding.Why = $why
        $script:LastFinding.How  = $how;  $script:LastFinding.Fix = $fix
    }
}

function Write-SysSection([string]$Title) {
    $script:SysArea = $Title
    Write-Host ""
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) " + $Title + " " + ("$([char]0x2500)" * [Math]::Max(0, 65 - $Title.Length)) + "$([char]0x2510)") DarkCyan
}
function Write-SysSectionEnd { W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan }

function Get-FileSHA1([string]$path) {
    try {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        $fs  = [System.IO.File]::OpenRead($path)
        $bytes = $sha.ComputeHash($fs)
        $fs.Close()
        return ([BitConverter]::ToString($bytes) -replace '-','').ToLower()
    } catch { return $null }
}

function Get-FileMurmur2([string]$path) {
    try {
        $allBytes = [System.IO.File]::ReadAllBytes($path)
        $filtered = [System.Collections.Generic.List[byte]]::new($allBytes.Length)
        foreach ($b in $allBytes) {
            if ($b -ne 9 -and $b -ne 10 -and $b -ne 13 -and $b -ne 32) { $filtered.Add($b) }
        }
        $data = $filtered.ToArray()
        $len  = $data.Length
        $seed = [uint32]1
        $m    = [uint32]0xc6a4a793
        $r    = 24
        $h    = $seed -bxor ([uint32]$len * $m)
        $i    = 0
        while ($i + 4 -le $len) {
            $k = [uint32]([uint32]$data[$i] -bor ([uint32]$data[$i+1] -shl 8) -bor ([uint32]$data[$i+2] -shl 16) -bor ([uint32]$data[$i+3] -shl 24))
            $k = [uint32]($k * $m)
            $k = [uint32]($k -bxor ($k -shr $r))
            $k = [uint32]($k * $m)
            $h = [uint32]($h * $m)
            $h = [uint32]($h -bxor $k)
            $i += 4
        }
        $rem = $len - $i
        if ($rem -ge 3) { $h = [uint32]($h -bxor ([uint32]$data[$i+2] -shl 16)) }
        if ($rem -ge 2) { $h = [uint32]($h -bxor ([uint32]$data[$i+1] -shl 8)) }
        if ($rem -ge 1) { $h = [uint32]($h -bxor [uint32]$data[$i]); $h = [uint32]($h * $m) }
        $h = [uint32]($h -bxor ($h -shr 13))
        $h = [uint32]($h * $m)
        $h = [uint32]($h -bxor ($h -shr 15))
        return [long]$h
    } catch { return $null }
}

function Get-CurseForgeMeta([long]$fingerprint) {
    if ([string]::IsNullOrWhiteSpace($script:CurseForgeApiKey)) { return @{ Name = ""; Slug = "" } }
    try {
        $body = "{`"fingerprints`":[" + $fingerprint + "]}"
        $r = Invoke-RestMethod -Uri "https://api.curseforge.com/v1/fingerprints/432" -Method Post -Body $body -ContentType "application/json" -Headers @{ "x-api-key" = $script:CurseForgeApiKey } -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        $match = $r.data.exactMatches | Where-Object { $_.file.fileFingerprint -eq $fingerprint } | Select-Object -First 1
        if ($match) { return @{ Name = $match.file.displayName; Slug = [string]$match.id } }
    } catch {}
    return @{ Name = ""; Slug = "" }
}

function Get-ModrinthMeta([string]$hash) {
    try {
        $v = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$hash" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($v.project_id) {
            $p = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($v.project_id)" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            return @{ Name = $p.title; Slug = $p.slug }
        }
    } catch {}
    return @{ Name = ""; Slug = "" }
}

function Get-MegabaseMeta([string]$hash) {
    try {
        $r = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$hash" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if (-not $r.error -and $r.data) { return $r.data }
    } catch {}
    return $null
}

function Get-DownloadSource([string]$path) {
    try {
        $zoneData = Get-Content -Raw -Stream Zone.Identifier $path -ErrorAction SilentlyContinue
        if ($zoneData -match "HostUrl=(.+)") {
            $url = $matches[1].Trim()
            $name = $null
            if ($url -match "mediafire\.com")                                        { $name = "MediaFire" }
            elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { $name = "Discord" }
            elseif ($url -match "dropbox\.com")                                      { $name = "Dropbox" }
            elseif ($url -match "drive\.google\.com")                                { $name = "Google Drive" }
            elseif ($url -match "mega\.nz|mega\.co\.nz")                             { $name = "MEGA" }
            elseif ($url -match "github\.com")                                       { $name = "GitHub" }
            elseif ($url -match "modrinth\.com")                                     { $name = "Modrinth" }
            elseif ($url -match "curseforge\.com")                                   { $name = "CurseForge" }
            elseif ($url -match "anydesk\.com")                                      { $name = "AnyDesk" }
            elseif ($url -match "doomsdayclient\.com")                               { $name = "DoomsdayClient" }
            elseif ($url -match "prestigeclient\.vip")                               { $name = "PrestigeClient" }
            elseif ($url -match "198macros\.com")                                    { $name = "198Macros" }
            elseif ($url -match "dqrkis\.xyz")                                       { $name = "Dqrkis" }
            else {
                $cm = $null
                if ($script:cheatDomainMap) { $cm = @($script:cheatDomainMap | Where-Object { $url -match [regex]::Escape($_.match) }) | Select-Object -First 1 }
                if ($cm) { $name = $cm.name }
                elseif ($url -match "https?://(?:www\.)?([^/]+)") { $name = $matches[1] }
                else { $name = $url }
            }
            return [PSCustomObject]@{ Name = $name; RawUrl = $url }
        }
    } catch {}
    return $null
}

function Invoke-ObfuscationScan([string]$FilePath) {
    $flags = [System.Collections.Generic.List[string]]::new()

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $totalClass = 0; $numericCount = 0; $unicodeCount = 0; $fullwidthCount = 0
        $japaneseCount = 0; $singleLetterCount = 0; $twoLetterCount = 0
        $gibberishCount = 0; $noVowelCount = 0; $confusionCount = 0; $singleCharPkg = 0
        $contentSample = [System.Text.StringBuilder]::new()
        $sampleSize = 0

        $cheatObfuscators = @{
            "Skidfuscator"   = @("dev/skidfuscator","Skidfuscator","skidfuscator.dev")
            "Paramorphism"   = @("Paramorphism","paramorphism-","dev/paramorphism")
            "Radon"          = @("ItzSomebody/Radon","me/itzsomebody/radon","Radon Obfuscator")
            "Caesium"        = @("sim0n/Caesium","Caesium Obfuscator","dev/sim0n/caesium")
            "Bozar"          = @("vimasig/Bozar","Bozar Obfuscator","com/bozar")
            "Branchlock"     = @("Branchlock","branchlock.dev")
            "Binscure"       = @("Binscure","com/binscure")
            "SuperBlaubeere" = @("superblaubeere","superblaubeere27")
            "Qprotect"       = @("Qprotect","QProtect","mdma.dev/qprotect")
            "Zelix"          = @("ZKMFLOW","ZKM","ZelixKlassMaster","com/zelix")
            "Stringer"       = @("StringerJavaObfuscator","com/licel/stringer")
            "JNIC"           = @("JNIC","jnic.obf","jnic-obfuscator")
            "Scuti"          = @("ScutiObf","scuti.obf")
            "Smoke"          = @("SmokeObf","smoke.obf","com/icqm/smoke")
            "Allatori"       = @("allatori/annotations")
            "DashO"          = @("com/preemptive/dasho")
            "ByteBuddy"      = @("net/bytebuddy","bytebuddy/asm")
            "Javassist"      = @("javassist/","org/javassist")
        }

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if ($name -match "\.class$") {
                $totalClass++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                if ($className -match "^\d+$")                                                          { $numericCount++ }
                if ($className -match "[^\x00-\x7F]")                                                   { $unicodeCount++ }
                if ($className -match "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]")                     { $fullwidthCount++ }
                if ($className -match "[$([char]0x3040)-$([char]0x309F)$([char]0x30A0)-$([char]0x30FF)$([char]0x3400)-$([char]0x4DBF)$([char]0x4E00)-$([char]0x9FFF)]")       { $japaneseCount++ }
                if ($className -match "^[a-zA-Z]$")                                                    { $singleLetterCount++ }
                if ($className -match "^[a-zA-Z]{2}$")                                                 { $twoLetterCount++ }
                if ($className -match "^[Il1O0]+$" -or $className -match "^[_]+$")                    { $confusionCount++ }

                if ($className.Length -ge 3 -and $className.Length -le 8 -and $className -match "^[a-zA-Z]+$") {
                    $vowels = ($className.ToCharArray() | Where-Object { $_ -match "[aeiouAEIOU]" }).Count
                    if ($vowels -eq 0) { $noVowelCount++ }
                    if ($className -match "[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}" -and ($vowels / $className.Length) -lt 0.3) { $gibberishCount++ }
                }

                $segs = ($name -replace "\.class$","") -split "/"
                foreach ($seg in $segs[0..([Math]::Max(0,$segs.Count - 2))]) {
                    if ($seg.Length -eq 1) { $singleCharPkg++ }
                }

                if ($sampleSize -lt 150000 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                    try {
                        $st = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $st.CopyTo($ms); $st.Close()
                        $ascii = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                        $ms.Dispose()
                        [void]$contentSample.Append($ascii)
                        $sampleSize += $ascii.Length
                    } catch {}
                }
            }
        }
        $archive.Dispose()

        if ($totalClass -lt 5) { return $flags }

        $numPct  = [math]::Round(($numericCount  / $totalClass) * 100)
        $uniPct  = [math]::Round(($unicodeCount  / $totalClass) * 100)
        $fwPct   = [math]::Round(($fullwidthCount / $totalClass) * 100)
        $jpPct   = [math]::Round(($japaneseCount  / $totalClass) * 100)
        $s1Pct   = [math]::Round(($singleLetterCount / $totalClass) * 100)
        $s2Pct   = [math]::Round(($twoLetterCount / $totalClass) * 100)
        $gibPct  = [math]::Round(($gibberishCount / $totalClass) * 100)
        $novPct  = [math]::Round(($noVowelCount   / $totalClass) * 100)
        $confPct = [math]::Round(($confusionCount / $totalClass) * 100)

        if ($numPct  -ge 20) { $flags.Add("Numeric class names $([char]0x2014) $numPct% of classes have numeric-only names") }
        if ($uniPct  -ge 10) { $flags.Add("Unicode class names $([char]0x2014) $uniPct% of classes use non-ASCII characters") }
        if ($fwPct   -gt  0) { $flags.Add("Fullwidth Unicode class names $([char]0x2014) $fwPct% use $([char]0xFF41)$([char]0xFF42)$([char]0xFF43)/$([char]0xFF21)$([char]0xFF22)$([char]0xFF23) chars ($fullwidthCount classes)") }
        if ($jpPct   -gt  0) { $flags.Add("Japanese obfuscation $([char]0x2014) $jpPct% use hiragana/katakana names ($japaneseCount classes)") }
        if ($s1Pct   -ge 15) { $flags.Add("Single-letter class names $([char]0x2014) $s1Pct% ($singleLetterCount classes)") }
        if ($s2Pct   -ge 20) { $flags.Add("Two-letter class names $([char]0x2014) $s2Pct% ($twoLetterCount classes)") }
        if ($gibPct  -ge  5) { $flags.Add("Gibberish class names $([char]0x2014) $gibPct% have no vowels/consonant clusters ($gibberishCount classes)") }
        if ($novPct  -ge  8) { $flags.Add("No-vowel class names $([char]0x2014) $novPct% ($noVowelCount classes)") }
        if ($confPct -ge  3) { $flags.Add("Confusion-char names (Il1O0/_) $([char]0x2014) $confPct% ($confusionCount classes)") }
        if ($singleCharPkg -ge 6) { $flags.Add("Single-char package paths $([char]0x2014) $singleCharPkg path segments like a/b/c") }

        $fwMatches = [regex]::Matches($contentSample.ToString(), "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]{2,}")
        if ($fwMatches.Count -gt 0) {
            $ex = ($fwMatches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join ", "
            $flags.Add("Fullwidth strings in class content $([char]0x2014) $($fwMatches.Count) occurrences (e.g. $ex)")
        }

        $sampleStr = $contentSample.ToString()
        foreach ($obfName in $cheatObfuscators.Keys) {
            foreach ($pat in $cheatObfuscators[$obfName]) {
                if ($sampleStr.Contains($pat)) {
                    $flags.Add("Known cheat obfuscator detected $([char]0x2014) $obfName (matched: $pat)")
                    break
                }
            }
        }
    } catch {}
    return $flags
}

function Get-ShannonEntropy([byte[]]$data) {
    $len = $data.Length
    if ($len -eq 0) { return 0.0 }
    $freq = New-Object 'int[]' 256
    foreach ($b in $data) { $freq[$b]++ }
    $entropy = 0.0
    foreach ($c in $freq) {
        if ($c -gt 0) { $p = $c / $len; $entropy -= $p * [Math]::Log($p, 2) }
    }
    return [Math]::Round($entropy, 4)
}

function Invoke-ExeScan([string]$FilePath) {
    $flags = [System.Collections.Generic.List[string]]::new()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes) -replace '[^\x20-\x7E]', ' '
        $tokens = $ascii -split '\s+' | Where-Object { $_.Length -ge 5 }

        foreach ($tok in $tokens) {
            if ($script:cheatStringSet.Contains($tok)) {
                [void]$flags.Add("Cheat string match: '$tok'")
            }
        }
        foreach ($tok in $tokens) {
            $pm = $script:patternRegex.Match($tok)
            if ($pm.Success) { [void]$flags.Add("Cheat pattern ($($pm.Value)): '$tok'") }
        }

        $injectApis = @("CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","NtWriteVirtualMemory","RtlCreateUserThread","SetWindowsHookEx","OpenProcess")
        foreach ($api in $injectApis) {
            if ($ascii -match [regex]::Escape($api)) { [void]$flags.Add("PE injection API: $api") }
        }
        $netApis = @("WinHttpOpen","InternetOpenA","InternetOpenW","socket","WSAStartup","HttpSendRequest","URLDownloadToFile")
        foreach ($api in $netApis) {
            if ($ascii -match [regex]::Escape($api)) { [void]$flags.Add("Network API: $api") }
        }

        if ($bytes.Count -ge 256) {
            $freq = @{}
            foreach ($b in $bytes) { $freq[$b] = ($freq[$b] -as [int]) + 1 }
            $entropy = 0.0
            foreach ($kv in $freq.GetEnumerator()) {
                $p = $kv.Value / $bytes.Count
                if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
            }
            if ($entropy -gt 7.2) { [void]$flags.Add("High entropy ($([Math]::Round($entropy,2))) $([char]0x2014) likely packed/encrypted payload") }
        }
    } catch {}
    return $flags
}

function Invoke-PyScan([string]$FilePath) {
    $flags = [System.Collections.Generic.List[string]]::new()
    try {
        $src = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)

        foreach ($entry in $script:cheatStringSet) {
            if ($src -match [regex]::Escape($entry)) { [void]$flags.Add("Cheat string match: '$entry'") }
        }
        foreach ($pm in $script:patternRegex.Matches($src)) { [void]$flags.Add("Cheat pattern ($($pm.Value))") }

        $suspImports = @("pyautogui","pynput","ctypes","win32api","win32con","keyboard","mouse","mss","pyscreeze","subprocess","socket","requests","urllib","paramiko","ftplib","smtplib")
        foreach ($imp in $suspImports) {
            if ($src -match "(?:import|from)\s+$([regex]::Escape($imp))") { [void]$flags.Add("Suspicious import: $imp") }
        }

        $dash = [char]0x2014
        $obfPatterns = @(
            @{ R = 'exec\s*\(';        D = "exec() call $dash dynamic code execution" },
            @{ R = 'eval\s*\(';        D = "eval() call $dash dynamic expression evaluation" },
            @{ R = '__import__\s*\(';  D = "__import__() $dash hidden dynamic import" },
            @{ R = 'base64\.b64decode'; D = "base64 decode $dash encoded payload" },
            @{ R = 'compile\s*\(';     D = "compile() $dash runtime bytecode construction" },
            @{ R = 'marshal\.loads';   D = "marshal.loads $dash raw bytecode deserialization" }
        )
        foreach ($op in $obfPatterns) {
            if ($src -match $op.R) { [void]$flags.Add($op.D) }
        }
    } catch {}
    return $flags
}
