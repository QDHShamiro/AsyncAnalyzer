# ---------------------------------------------------------------------------
# Two things Windows remembers that deleting a file does not erase.
#
# The mods folder can be emptied in three seconds. What takes longer to think of:
#
#   The Recycle Bin keeps a $I file per deleted item holding the ORIGINAL PATH,
#   the size and the exact deletion time. Emptying the bin removes it; pressing
#   Delete does not.
#
#   UserAssist keeps, per user, the path of every program started from Explorer -
#   a double-click, a Start-menu entry, a desktop shortcut - with how many times
#   it ran and when it last did. It is ROT13-encoded, which is obfuscation and
#   not encryption, and it outlives the program itself.
#
# Both are readable WITHOUT administrator rights, which matters: the tool offers
# to elevate and the answer can be no.
#
# Neither is an accusation by itself. A deleted jar can be a mod somebody
# uninstalled last month, so the date is carried into the report, and only a
# deletion inside the current session may reach the rule that says jars were
# wiped with the game running. See ml/histscan.py, where each layout is tested
# against bytes assembled to the documented format.
# ---------------------------------------------------------------------------

# 100-nanosecond intervals since 1601-01-01 UTC.
function ConvertFrom-FileTime([long]$Value) {
    if ($Value -le 0 -or $Value -ge 0x7FFFFFFFFFFFFFFF) { return $null }
    try { return [DateTime]::FromFileTimeUtc($Value).ToLocalTime() } catch { return $null }
}

# One $I file. Two layouts exist and both are still found on a live PC: version 1
# (Vista..8.1) has a fixed 260-character path at offset 24, version 2 (Windows 10)
# has a character count there and then the path. Reading a v2 file with the v1
# layout yields a path with a length field glued to the front - which is exactly
# the kind of thing that turns into a wrong accusation.
function Read-RecycleEntry([string]$Path) {
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        if ($b.Length -lt 24) { return $null }
        $version = [BitConverter]::ToInt64($b, 0)
        $size    = [BitConverter]::ToInt64($b, 8)
        $deleted = [BitConverter]::ToInt64($b, 16)
        $raw = $null
        if ($version -eq 1) {
            if ($b.Length -lt 544) { return $null }
            $raw = New-Object byte[] 520
            [Array]::Copy($b, 24, $raw, 0, 520)
        } elseif ($version -eq 2) {
            if ($b.Length -lt 28) { return $null }
            $nchars = [BitConverter]::ToUInt32($b, 24)
            if ($nchars -le 0 -or $nchars -gt 32768) { return $null }
            $take = [int][Math]::Min([int64]($nchars * 2), [int64]($b.Length - 28))
            if ($take -le 0) { return $null }
            $raw = New-Object byte[] $take
            [Array]::Copy($b, 28, $raw, 0, $take)
        } else { return $null }
        $p = [System.Text.Encoding]::Unicode.GetString($raw)
        $z = $p.IndexOf([char]0)
        if ($z -ge 0) { $p = $p.Substring(0, $z) }
        if (-not $p) { return $null }
        return @{ Path = $p; Size = $size; Deleted = (ConvertFrom-FileTime $deleted) }
    } catch { return $null }
}

# UserAssist value names are ROT13. Letters rotate, everything else is untouched -
# a path keeps its backslashes, its colon and its digits.
function Convert-Rot13([string]$Text) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int][char]$ch
        if ($c -ge 65 -and $c -le 90)      { [void]$sb.Append([char](((($c - 65) + 13) % 26) + 65)) }
        elseif ($c -ge 97 -and $c -le 122) { [void]$sb.Append([char](((($c - 97) + 13) % 26) + 97)) }
        else                               { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

# May this deletion reach the rule that says jars were wiped mid-session?
#
# The Recycle Bin holds months of history. Feeding all of it to a rule whose text
# is "deleted while Minecraft is still running" would accuse somebody for tidying
# up a modpack in May. The window is the running game if there is one, and
# otherwise the scan itself - short enough that the claim stays true.
function Test-DeletedDuringSession($Deleted) {
    if ($null -eq $Deleted) { return $false }
    $start = $script:GameStarted
    if ($null -eq $start) { $start = $script:ScanStart }
    return ([DateTime]$Deleted -ge [DateTime]$start)
}

function Run-RecycleScan {
    $res = @{
        Fresh   = [System.Collections.Generic.List[string]]::new()
        Old     = [System.Collections.Generic.List[string]]::new()
        Named   = [System.Collections.Generic.List[string]]::new()
        Read    = 0
    }
    $roots = @()
    foreach ($d in @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq 'Fixed' })) {
        $roots += (Join-Path $d.RootDirectory.FullName '$Recycle.Bin')
    }
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        # One folder per user SID. Another user's folder is unreadable, which is
        # a limit worth saying out loud rather than reporting as "nothing found".
        $sidDirs = @()
        try { $sidDirs = @(Get-ChildItem $root -Directory -Force -ErrorAction Stop) } catch {
            Add-ScanGap "The Recycle Bin on $root could not be listed, so files deleted from it were not checked"
            continue
        }
        foreach ($sd in $sidDirs) {
            $files = @()
            try { $files = @(Get-ChildItem $sd.FullName -Filter '$I*' -Force -ErrorAction Stop | Select-Object -First 4000) } catch { continue }
            foreach ($f in $files) {
                $e = Read-RecycleEntry $f.FullName
                if ($null -eq $e) { continue }
                $res.Read++
                $leaf = ($e.Path -split '\\')[-1]
                $when = if ($e.Deleted) { ([DateTime]$e.Deleted).ToString('yyyy-MM-dd HH:mm') } else { "date unreadable" }
                $isJar = $e.Path -match '(?i)\.(jar|litemod)$'
                $inMods = $e.Path.ToLower().Contains('\mods\')
                $hit = Test-CheatName $leaf
                if ($hit) {
                    $res.Named.Add("$($e.Path)  ($hit, deleted $when, $([Math]::Round($e.Size / 1KB)) KB)")
                } elseif ($isJar -and $inMods) {
                    $line = "$($e.Path)  (deleted $when, $([Math]::Round($e.Size / 1KB)) KB)"
                    if (Test-DeletedDuringSession $e.Deleted) {
                        $res.Fresh.Add($line)
                        [void]$script:DeletedJarPaths.Add([string]$e.Path)
                    } else { $res.Old.Add($line) }
                }
            }
        }
    }
    $script:Evidence.DeletedJars = $script:DeletedJarPaths.Count
    return $res
}

function Run-UserAssistScan {
    $res = @{ Hits = [System.Collections.Generic.List[string]]::new(); Read = 0 }
    $base = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (-not (Test-Path $base)) {
        Add-ScanGap "UserAssist is not present, so which programs were started by double-clicking could not be checked"
        return $res
    }
    foreach ($guid in @(Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $count = Join-Path $guid.PSPath "Count"
        if (-not (Test-Path $count)) { continue }
        $props = $null
        try { $props = Get-ItemProperty $count -ErrorAction Stop } catch { continue }
        foreach ($pr in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $path = Convert-Rot13 $pr.Name
            # Explorer keeps its own two counters under the same key. They are
            # not programs and must not be read as one.
            if ($path.ToUpper().StartsWith("UEME_")) { continue }
            $res.Read++
            $hit = Test-CheatName $path
            if (-not $hit) { continue }
            $runs = 0; $last = $null
            $d = $pr.Value
            if ($d -is [byte[]] -and $d.Length -ge 68) {
                $runs = [BitConverter]::ToUInt32($d, 4)
                $last = ConvertFrom-FileTime ([BitConverter]::ToInt64($d, 60))
            }
            $when = if ($last) { ([DateTime]$last).ToString('yyyy-MM-dd HH:mm') } else { "date unreadable" }
            $res.Hits.Add("$path  ($hit, started $runs time(s), last $when)")
        }
    }
    return $res
}

function Show-HistoryScan {
    Write-SysSection "WHAT WINDOWS STILL REMEMBERS"
    $script:SysArea = "Deleted & started"

    $rec = Run-RecycleScan
    $ua  = Run-UserAssistScan
    W "  $([char]0x2502)  Read $($rec.Read) recycle-bin record(s) and $($ua.Read) Explorer start record(s)" DarkGray

    if ($rec.Named.Count -gt 0) {
        Write-SystemFlag "FAIL" "A known cheat client is sitting in the Recycle Bin:" @($rec.Named)
        Write-Detail "Windows keeps the original path, the size and the exact deletion time of every file put in the Recycle Bin." `
            "The deleted file's name matches a known cheat client. Deleting it did not remove the record $([char]0x2014) it created one." `
            "One `$I file per deleted item under `$Recycle.Bin, readable without administrator rights." `
            "Nothing to fix: this is evidence. Emptying the bin destroys it."
        $script:SystemIssues += $rec.Named.Count
    }
    if ($rec.Fresh.Count -gt 0) {
        Write-SystemFlag "FAIL" "Mods were deleted during this session:" @($rec.Fresh)
        Write-Detail "These jars were in a mods folder and were moved to the Recycle Bin after $(if ($script:GameStarted) { 'the game started' } else { 'this scan began' })." `
            "The timing is the finding, not the deletion: a mod removed months ago is housekeeping, one removed while the screenshare was being arranged is not." `
            "The deletion time comes from the Recycle Bin's own record." `
            "Restore them from the Recycle Bin and scan again before drawing a conclusion."
        $script:SystemIssues += $rec.Fresh.Count
    }
    if ($rec.Old.Count -gt 0) {
        # Deliberately not counted. Everyone uninstalls mods.
        Write-SystemFlag "STATE" "Mods deleted earlier, kept for the dates:" @($rec.Old)
        Write-Detail "Jars that were in a mods folder and are now in the Recycle Bin, deleted before this session." `
            "Uninstalling a mod is normal, so this is not counted against anyone. It is here because the dates can matter if a ban appeal argues about when something was removed." `
            "" ""
    }
    if ($ua.Hits.Count -gt 0) {
        Write-SystemFlag "FAIL" "A known cheat client was started by double-clicking it:" @($ua.Hits)
        Write-Detail "UserAssist records every program launched from Explorer, per user, with a run count and the time it last ran." `
            "This is not a file that happens to exist on the disk $([char]0x2014) it is a record that somebody opened it, how often, and when. It survives deleting the program." `
            "HKCU\...\Explorer\UserAssist, ROT13-encoded, readable without administrator rights." `
            "Nothing to fix: this is evidence."
        $script:SystemIssues += $ua.Hits.Count
    }
    if ($rec.Named.Count -eq 0 -and $rec.Fresh.Count -eq 0 -and $ua.Hits.Count -eq 0) {
        Write-SystemFlag "OK" "Deleted files and Explorer start history $([char]0x2014) no cheat client, no mod deleted during this session"
    }
    Write-SysSectionEnd
}

# ---------------------------------------------------------------------------
# "It was opened here once" - three more places Explorer and the shell leave a
# record of a file that no longer needs to exist for the record to still be
# there: RecentDocs (every file opened by double-click, per extension),
# MuiCache (every executable Explorer has ever shown a friendly name for) and
# the .lnk shortcuts under Recent (the actual target a jump-list entry points
# at). None of these need Administrator.
# ---------------------------------------------------------------------------

function Get-RecentDocFileName([byte[]]$Bytes) {
    # A RecentDocs value is a UTF-16LE file name, null-terminated (two zero
    # bytes back to back), followed by a binary shell item ID list this tool
    # has no use for. Stop at the terminator; do not try to parse the rest.
    if ($null -eq $Bytes -or $Bytes.Length -lt 4) { return "" }
    $end = -1
    for ($gi = 0; $gi -lt ($Bytes.Length - 1); $gi += 2) {
        if ($Bytes[$gi] -eq 0 -and $Bytes[$gi + 1] -eq 0) { $end = $gi; break }
    }
    if ($end -le 0) { return "" }
    try { return [System.Text.Encoding]::Unicode.GetString($Bytes, 0, $end) } catch { return "" }
}

function Get-MuiCachePath([string]$ValueName) {
    # MuiCache stores the PATH in the value's NAME, not its data - the data is
    # just the friendly name Explorer shows for it ("Vape Client", "Notepad").
    if ([string]::IsNullOrEmpty($ValueName)) { return "" }
    if ($ValueName -notmatch '(?i)\.FriendlyAppName$') { return "" }
    return ($ValueName -replace '(?i)\.FriendlyAppName$', '')
}

function Run-ExecTraceScan {
    $res  = @{ Fail = [System.Collections.Generic.List[string]]::new(); Warn = [System.Collections.Generic.List[string]]::new(); Read = 0 }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # One rule for all three sources: only a .jar/.exe/.dll matters here, and
    # only one that is GONE - a trace pointing at a file still on disk is what
    # the file scan itself already judges, on its own evidence, not a leftover
    # shortcut's say-so. A cheat name is the finding by itself; a plain name is
    # only worth a look if it sat somewhere a launcher does not put mods.
    function Add-ExecTraceHit([string]$Path, [string]$Source) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        if ($Path -notmatch '(?i)\.(jar|exe|dll)$') { return }
        if (-not $seen.Add("$Source|$Path")) { return }
        $res.Read++
        $hit = Test-CheatName ([System.IO.Path]::GetFileName($Path))
        $exists = $true
        try { $exists = [System.IO.File]::Exists($Path) } catch {}
        if ($exists) { return }
        $inModsOrTemp = ($Path -match '(?i)\\mods\\') -or (Test-UserWritablePath $Path)
        if ($hit) {
            $res.Fail.Add("$Path  ($hit, from $Source, no longer on disk)")
            Add-SessionEvent "ExecTrace" "$Source remembers $Path ($hit), now gone" $null
        } elseif ($inModsOrTemp) {
            $res.Warn.Add("$Path  (from $Source, no longer on disk)")
            Add-SessionEvent "ExecTrace" "$Source remembers $Path, now gone" $null
        }
    }

    try {
        $rdRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        if (Test-Path $rdRoot) {
            $rdKeys = @($rdRoot) + @(Get-ChildItem $rdRoot -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSPath)
            foreach ($rk in $rdKeys) {
                $rdItem = Get-Item -LiteralPath $rk -ErrorAction SilentlyContinue
                if (-not $rdItem) { continue }
                foreach ($vn in @($rdItem.Property)) {
                    # Only the numbered slots are file entries; MRUListEx is the
                    # ordering index, not a file.
                    if ($vn -notmatch '^\d+$') { continue }
                    $raw = $null
                    try { $raw = (Get-ItemProperty -LiteralPath $rk -Name $vn -ErrorAction Stop).$vn } catch {}
                    if ($null -eq $raw) { continue }
                    $rdName = Get-RecentDocFileName ([byte[]]$raw)
                    if ($rdName) { Add-ExecTraceHit $rdName "RecentDocs" }
                }
            }
        }
    } catch { Add-ScanGap "RecentDocs could not be read $([char]0x2014) a deleted jar/exe opened recently would not have been seen there" }

    try {
        $muiKey = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        if (Test-Path $muiKey) {
            $muiItem = Get-Item -LiteralPath $muiKey -ErrorAction SilentlyContinue
            foreach ($vn in @($muiItem.Property)) {
                $muiPath = Get-MuiCachePath $vn
                if ($muiPath) { Add-ExecTraceHit $muiPath "MuiCache" }
            }
        }
    } catch { Add-ScanGap "MuiCache could not be read $([char]0x2014) an executable that ran and was then deleted would not have been seen there" }

    try {
        $recentDir = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Recent")
        if ([System.IO.Directory]::Exists($recentDir)) {
            $lnkShell = New-Object -ComObject WScript.Shell
            foreach ($lnk in @([System.IO.Directory]::GetFiles($recentDir, "*.lnk"))) {
                try {
                    $lnkTarget = $lnkShell.CreateShortcut($lnk).TargetPath
                    if ($lnkTarget) { Add-ExecTraceHit $lnkTarget "Recent (.lnk)" }
                } catch {}
            }
        }
    } catch {
        Add-ScanGap "Recent .lnk shortcuts could not be read $([char]0x2014) a shortcut to a deleted jar/exe would not have been seen there"
    }

    return $res
}

function Show-ExecTraceScan {
    $et = Run-ExecTraceScan
    if ($et.Read -eq 0 -and $et.Fail.Count -eq 0 -and $et.Warn.Count -eq 0) { return }
    Write-SysSection "SHORTCUTS AND RECENT-FILE RECORDS TO SOMETHING GONE"
    $script:SysArea = "Deleted & started"
    W "  $([char]0x2502)  Checked $($et.Read) recent-file/shortcut record(s) for a .jar/.exe/.dll no longer on disk" DarkGray

    if ($et.Fail.Count -gt 0) {
        Write-SystemFlag "FAIL" "A known cheat client was opened and is now gone:" @($et.Fail)
        Write-Detail "RecentDocs, MuiCache and Recent\*.lnk each record a file Explorer opened or ran, independently of the Recycle Bin, UserAssist or BAM." `
            "The recorded name matches a known cheat client, and the file it points at no longer exists." `
            "HKCU\...\Explorer\RecentDocs, HKCU\...\Shell\MuiCache, and the .lnk shortcuts under %APPDATA%\Microsoft\Windows\Recent $([char]0x2014) none need Administrator." `
            "Nothing to fix: this is evidence."
        $script:SystemIssues += $et.Fail.Count
        $script:Evidence.ExecTrace += $et.Fail.Count
    }
    if ($et.Warn.Count -gt 0) {
        Write-SystemFlag "WARN" "Something was opened from mods\ or a Temp/AppData folder and is now gone:" @($et.Warn)
        Write-Detail "Same three sources, for a jar/exe/DLL that is not named after a known client but sat in mods\ or a folder the user can write to." `
            "Not proof by itself - files get moved and renamed for ordinary reasons - but it is exactly where an injector's own loader lives, and it is gone now." `
            "HKCU\...\Explorer\RecentDocs, HKCU\...\Shell\MuiCache, and Recent\*.lnk." `
            "Ask what it was before drawing a conclusion."
        # Not added to Evidence.ExecTrace: that field feeds a hard rule, and a
        # plain jar/exe/dll from a user-writable folder is not certain enough
        # for one, the same reason dllReview and Defender's WARN tier stay out
        # of their own hard-rule fields. It still counts toward sys_issues.
        $script:SystemIssues += $et.Warn.Count
    }
    if ($et.Fail.Count -eq 0 -and $et.Warn.Count -eq 0) {
        Write-SystemFlag "OK" "Recent-file and shortcut records $([char]0x2014) nothing pointing at a missing jar/exe/DLL"
    }
    Write-SysSectionEnd
}
