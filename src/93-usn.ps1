# ---------------------------------------------------------------------------
# Two records of files that are gone, for the case the Recycle Bin cannot cover.
#
# Shift+Delete leaves no $I file. Two things still see it:
#
#   The NTFS change journal (USN) records every create, rename and delete on the
#   volume with a timestamp. A rename matters as much as a delete: moving a jar
#   out of the mods folder is the quiet version of removing it.
#
#   ShimCache (AppCompatCache) holds up to about a thousand executable PATHS with
#   the file's last-modified time. It lives in the SYSTEM hive, which Windows
#   already has mounted, so it is read as an ordinary registry value.
#
# Both need administrator rights, and both are read-only. Nothing here mounts a
# registry hive or copies a locked system file - the transparency notice says
# this tool only reads, and that has to stay true even where it costs coverage.
# Amcache, which would add the SHA1 of executables that no longer exist, is
# NOT read for exactly that reason: its hive is locked while Windows runs, and
# getting at it means copying it out and mounting it.
#
# The ShimCache parser is deliberately distrustful of its own input. A binary
# blob mis-parsed by one field yields plausible-looking garbage, and garbage here
# is a filename presented to a moderator as a deleted cheat. Every entry is
# validated and the first one that fails ENDS the parse and reports why: a short
# honest answer beats a long invented one. See ml/test_usnscan.py, where eight
# corrupt shapes each have to stop it.
# ---------------------------------------------------------------------------

function Read-ShimCache([byte[]]$Blob, [int]$MaxEntries = 1024) {
    $out = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Blob -or $Blob.Length -lt 8) {
        return @{ Entries = $out; Reason = "the AppCompatCache value is too short to be one" }
    }
    $header = [BitConverter]::ToUInt32($Blob, 0)
    if (@(0x30, 0x34, 0x80) -notcontains [int]$header) {
        return @{ Entries = $out; Reason = ("an AppCompatCache layout this tool does not know (header 0x{0:X})" -f $header) }
    }
    $off = [int]$header
    while (($off + 12) -le $Blob.Length -and $out.Count -lt $MaxEntries) {
        # Windows 8.1 / 10 / 11 all use the "10ts" entry signature.
        if (-not ($Blob[$off] -eq 0x31 -and $Blob[$off+1] -eq 0x30 -and $Blob[$off+2] -eq 0x74 -and $Blob[$off+3] -eq 0x73)) {
            return @{ Entries = $out; Reason = $(if ($out.Count -eq 0) { "stopped at an unrecognised entry signature" } else { "" }) }
        }
        $pathLen = [int][BitConverter]::ToUInt16($Blob, $off + 12)
        if ($pathLen -eq 0 -or ($pathLen % 2) -ne 0 -or ($off + 14 + $pathLen + 12) -gt $Blob.Length) {
            return @{ Entries = $out; Reason = "stopped at an entry whose path length does not fit" }
        }
        $path = [System.Text.Encoding]::Unicode.GetString($Blob, $off + 14, $pathLen)
        if ($path -notmatch '^(?:\\\?\?\\)?[A-Za-z]:\\|^\\\\') {
            return @{ Entries = $out; Reason = "stopped at an entry that does not look like a path" }
        }
        $p = $off + 14 + $pathLen
        $when = ConvertFrom-FileTime ([BitConverter]::ToInt64($Blob, $p))
        # Nothing on a Windows PC was modified in 1604. An impossible date means
        # the offsets have drifted, and everything after it would be invented.
        if ($null -eq $when -or $when.Year -lt 2000 -or $when.Year -gt 2100) {
            return @{ Entries = $out; Reason = "stopped at an entry with an impossible timestamp" }
        }
        $dataLen = [int][BitConverter]::ToUInt32($Blob, $p + 8)
        if ($dataLen -lt 0 -or $dataLen -gt $Blob.Length) {
            return @{ Entries = $out; Reason = "stopped at an entry with an impossible data length" }
        }
        [void]$out.Add(@{ Path = ($path -replace '^\\\?\?\\', ''); Modified = $when })
        $off = $p + 12 + $dataLen
    }
    return @{ Entries = $out; Reason = "" }
}

function Run-ShimCacheScan {
    $res = @{ Hits = [System.Collections.Generic.List[string]]::new(); Read = 0 }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    $blob = $null
    try { $blob = (Get-ItemProperty -Path $key -Name AppCompatCache -ErrorAction Stop).AppCompatCache } catch {}
    if ($null -eq $blob) {
        Add-ScanGap "The Windows application-compatibility cache could not be read $([char]0x2014) that needs Administrator, so executables that ran and were then deleted were not checked there"
        return $res
    }
    $sc = Read-ShimCache ([byte[]]$blob)
    $res.Read = $sc.Entries.Count
    if ($sc.Reason) {
        Add-ScanGap "The application-compatibility cache was only partly readable ($($sc.Reason)) $([char]0x2014) $($sc.Entries.Count) entr(y/ies) were checked and the rest was not"
    }
    foreach ($e in $sc.Entries) {
        $leaf = ($e.Path -split '\\')[-1]
        $hit = Test-CheatName $leaf
        if (-not $hit) { continue }
        $gone = $false
        try { $gone = -not [System.IO.File]::Exists($e.Path) } catch {}
        $res.Hits.Add("$($e.Path)  ($hit, last modified $($e.Modified.ToString('yyyy-MM-dd HH:mm'))$(if ($gone) { ', NOT on disk any more' } else { '' }))")
    }
    return $res
}

# One fsutil record block. The two reasons that matter are a file being deleted
# and the OLD name of a rename.
function Test-UsnDelete([string]$Block) {
    $m = [regex]::Match($Block, '(?im)^\s*File name\s*:\s*(.+?)\s*$')
    $r = [regex]::Match($Block, '(?im)^\s*Reason\s*:\s*(.+?)\s*$')
    if (-not $m.Success -or -not $r.Success) { return $null }
    $reason = $r.Groups[1].Value
    if ($reason -notmatch '(?i)File Delete|Rename Old Name') { return $null }
    $t = [regex]::Match($Block, '(?im)^\s*Time ?stamp\s*:\s*(.+?)\s*$')
    return @{ Name = $m.Groups[1].Value; Reason = $reason; When = $(if ($t.Success) { $t.Groups[1].Value } else { "" }) }
}

# Folder names, not paths - the journal only ever gives a bare file name, never
# its parent. A directory-delete record for one of these names is as close as
# this reader can get to "a mods-adjacent folder was removed while the game
# was running", without inventing a path the journal never supplied.
$script:usnConfigDirNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('config', 'shaderpacks', 'resourcepacks', 'texturepacks', 'saves') | ForEach-Object { [void]$script:usnConfigDirNames.Add($_) }

# A bare file/folder name -> what kind of delete/rename record this is, for
# everything that is not a cheat-named file (Test-CheatName is checked first,
# separately, in Run-UsnScan). Pulled out as its own pure function so the
# classification can be pinned by a self-test without needing fsutil, a real
# journal or Administrator.
function Get-UsnDeleteCategory([string]$Name) {
    if ([string]::IsNullOrEmpty($Name)) { return "None" }
    if ($Name -match '(?i)\.(jar|litemod)$') { return "Jar" }
    if ($Name -match '(?i)\.pf$') { return "Prefetch" }
    if ($Name -ieq 'latest.log') { return "Log" }
    if ($script:usnConfigDirNames.Contains($Name)) { return "ConfigDir" }
    return "None"
}

function Run-UsnScan {
    $res = @{ Hits = [System.Collections.Generic.List[string]]::new(); Warn = [System.Collections.Generic.List[string]]::new(); Read = 0 }
    if (-not (Test-IsAdmin)) {
        Add-ScanGap "The NTFS change journal needs Administrator $([char]0x2014) files removed with Shift+Delete, which leave no Recycle Bin record, were not checked"
        return $res
    }
    $drive = ($env:SystemDrive)
    if (-not $drive) { $drive = "C:" }
    try {
        $q = & fsutil usn queryjournal $drive 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $q) {
            Add-ScanGap "The NTFS change journal is not enabled on $drive, so deletions could not be read from it"
            return $res
        }
        $nm = [regex]::Match(($q -join "`n"), '(?im)Next\s+Usn\s*:\s*(?:0x)?([0-9A-Fa-f]+)')
        if (-not $nm.Success) {
            Add-ScanGap "The NTFS change journal did not report its position, so deletions could not be read from it"
            return $res
        }
        $next = [Convert]::ToInt64($nm.Groups[1].Value, $(if (($q -join '') -match '0x') { 16 } else { 10 }))
        # The journal is a ring buffer and records are appended in order, so the
        # newest sit at the END. Reading from the start and stopping early - the
        # obvious way to bound the cost - returns the OLDEST records, which is
        # the opposite of what a screenshare needs.
        $window = 64MB
        $start = $next - $window
        if ($start -lt 0) { $start = 0 }
        $raw = & fsutil usn readjournal $drive startusn=$start 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            Add-ScanGap "The NTFS change journal could not be read on $drive"
            return $res
        }
        $text = ($raw -join "`n")
        foreach ($block in ($text -split '(?m)^\s*Usn\s*:')) {
            if (-not $block.Trim()) { continue }
            $res.Read++
            $d = Test-UsnDelete $block
            if ($null -eq $d) { continue }
            $hit    = Test-CheatName $d.Name
            $usnCat = Get-UsnDeleteCategory $d.Name
            $isJar  = $usnCat -eq "Jar"
            $isPf   = $usnCat -eq "Prefetch"
            $isLog  = $usnCat -eq "Log"
            $isCfgD = $usnCat -eq "ConfigDir"
            # Built before the string, not inside it. A $( ) subexpression that
            # contains a double quote cannot sit inside a double-quoted string:
            # the inner quote closes the outer one and the whole file stops
            # parsing. That is what broke the first Windows run of this tool.
            $whenPart = ""
            if ($d.When) { $whenPart = ", " + $d.When }
            $whenDt = $null
            if ($d.When) { $whenDt = [DateTime]::MinValue; if (-not [DateTime]::TryParse($d.When, [ref]$whenDt)) { $whenDt = $null } }
            $duringSession = ($null -ne $whenDt) -and (Test-DeletedDuringSession $whenDt)
            if ($hit) {
                $res.Hits.Add("$($d.Name)  ($hit, $($d.Reason.Trim())$whenPart)")
                Add-SessionEvent "USN" "$($d.Name) ($hit) $($d.Reason.Trim())" $whenDt
            } elseif ($isJar) {
                # Every jar now, not only one this scan already flagged or one
                # named after a known client - a client renamed to look like a
                # library still shows up here, because the journal does not
                # care what a file is called. The journal has no parent
                # folder, so this cannot say "from mods\"; it says what it
                # actually knows.
                $already = if ($script:FlaggedModsList.Contains($d.Name)) { " (a jar this scan flagged)" } else { "" }
                $res.Hits.Add("$($d.Name)$already  ($($d.Reason.Trim())$whenPart)")
                [void]$script:DeletedJarPaths.Add([string]$d.Name)
                $script:Evidence.DeletedJars = $script:DeletedJarPaths.Count
                Add-SessionEvent "USN" "$($d.Name) removed from disk$already" $whenDt
            } elseif ($isPf) {
                # Nothing legitimate deletes its own Prefetch entry - Windows
                # writes and ages these out itself. A .pf gone before its own
                # ageing cycle is someone clearing the record of a program
                # that ran, which is exactly the record this scan also reads
                # from Prefetch directly.
                $res.Hits.Add("$($d.Name)  (Prefetch entry removed, not by Windows' own ageing $([char]0x2014) $($d.Reason.Trim())$whenPart)")
                Add-SessionEvent "USN" "Prefetch record wiped: $($d.Name)" $whenDt
            } elseif ($isLog -and $duringSession) {
                $res.Warn.Add("latest.log  (removed while the game was running, $($d.Reason.Trim())$whenPart)")
                Add-SessionEvent "USN" "latest.log deleted during this session" $whenDt
            } elseif ($isCfgD -and $duringSession) {
                $res.Warn.Add("$($d.Name)\  (folder removed while the game was running, $($d.Reason.Trim())$whenPart)")
                Add-SessionEvent "USN" "$($d.Name)\ folder removed during this session" $whenDt
            }
        }
    } catch {
        Add-ScanGap "The NTFS change journal could not be read $([char]0x2014) files removed with Shift+Delete were not checked"
    }
    return $res
}

function Show-UsnScan {
    if (-not (Test-IsAdmin)) {
        # Both sources need admin. Saying so once, here, beats two gaps that
        # read like separate failures.
        Add-ScanGap "Ran without Administrator, so neither the NTFS change journal nor the application-compatibility cache was read $([char]0x2014) a cheat removed with Shift+Delete would leave no trace this scan could see"
        return
    }
    Write-SysSection "FILES THAT ARE ALREADY GONE"
    $script:SysArea = "Deleted & started"

    $shim = Run-ShimCacheScan
    $usn  = Run-UsnScan
    W "  $([char]0x2502)  Read $($shim.Read) compatibility-cache entr(y/ies) and $($usn.Read) change-journal record(s)" DarkGray

    if ($shim.Hits.Count -gt 0) {
        Write-SystemFlag "FAIL" "Windows recorded a known cheat client on this PC:" @($shim.Hits)
        Write-Detail "The application-compatibility cache keeps the path and date of executables Windows has seen, whether or not they are still there." `
            "The recorded path names a known cheat client. An entry whose file is gone is the stronger one: the program was here, and now only the record is." `
            "HKLM\SYSTEM\...\AppCompatCache, read as a registry value $([char]0x2014) nothing was mounted or copied." `
            "Nothing to fix: this is evidence."
        $script:SystemIssues += $shim.Hits.Count
    }
    if ($usn.Hits.Count -gt 0) {
        Write-SystemFlag "FAIL" "The filesystem journal recorded these being deleted or renamed:" @($usn.Hits)
        Write-Detail "NTFS logs every create, rename and delete on the volume, with a timestamp." `
            "This is the record Shift+Delete does not avoid $([char]0x2014) it leaves no Recycle Bin entry, but it leaves this. A rename counts too: moving a jar out of the mods folder is the quiet version of deleting it." `
            "fsutil usn readjournal, read from the end of the journal so the recent past is what gets looked at." `
            "Do not let the PC be restarted before this is reviewed $([char]0x2014) the journal is a ring buffer and old records fall out of it."
        $script:SystemIssues += $usn.Hits.Count
    }
    if ($usn.Warn.Count -gt 0) {
        Write-SystemFlag "WARN" "The filesystem journal recorded these being removed while the game was running:" @($usn.Warn)
        Write-Detail "The same NTFS journal, matched against the log file and the folders a modpack keeps its settings in." `
            "latest.log or a config/shaderpacks/resourcepacks folder disappearing mid-session is not proof by itself - a player can clean up their own settings - but it is also how a resource-pack x-ray or a config-based cheat hides what it changed." `
            "fsutil usn readjournal, same record, matched against known file and folder names instead of a cheat name." `
            "Ask what was in it before it was removed."
        $script:SystemIssues += $usn.Warn.Count
    }
    if ($shim.Hits.Count -eq 0 -and $usn.Hits.Count -eq 0 -and $usn.Warn.Count -eq 0) {
        Write-SystemFlag "OK" "Deleted-file history $([char]0x2014) no cheat client in the compatibility cache or the change journal"
    }
    Write-SysSectionEnd
}
