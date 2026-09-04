    # Before the memory scan, learn what is actually ON the disk: the version jar
    # and the whole libraries tree, not just the mods folder. The injected-code
    # rule says "this package belongs to no jar here", and that claim is only as
    # good as this set - without it every launcher library reads as injected.
    $instJars = 0
    foreach ($t in @($script:ScanTargetDirs)) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        try { $instJars += Add-InstallPackages ([System.IO.Path]::GetDirectoryName(([string]$t).TrimEnd('\'))) } catch {}
    }
    if ($instJars -gt 0) {
        W "  $([char]0x25CF) Read $instJars library/version jar(s) so injected code can be told from a library" DarkGray
    }

    $jvm = Run-JVMScan
    # ONLY the findings count. A note has an innocent explanation and a gap is
    # something the scan could not look at - neither is proof of an injection,
    # and jvm_inject is a hard rule that forces the whole scan to "Likely".
    $script:Evidence.JvmInject = $jvm.Findings.Count
    foreach ($g in $jvm.Gaps) { Add-ScanGap $g }
    if ($jvm.Findings.Count -gt 0) {
        Write-SectionHeader "JVM / RUNTIME INJECTION" $jvm.Findings.Count Yellow Yellow
        Write-Rule "$([char]0x2500)" 76 DarkGray
        Write-Host ""
        Write-InjectionCard "javaw / java process" $jvm.Findings
        $script:SystemIssues += $jvm.Findings.Count
        Add-Finding "FAIL" "Live game process" "$($jvm.Findings.Count) injection trace(s) in the running Java process" `
            @($jvm.Findings) `
            "The scan attached to the running javaw/java process and read its loaded agents, its open localhost ports and its heap." `
            "This is what the mods folder cannot show: code that is live in the game right now, whether or not any file on disk still contains it." `
            "Deleting a jar does not remove what is already loaded, so these traces survive a last-second cleanup." `
            "Do not let the player close the game before this is reviewed $([char]0x2014) closing it destroys this evidence." | Out-Null
    } else {
        Write-Host ""
        W "  $([char]0x2713) JVM $([char]0x2014) no agents, no remote debugger, no loaded cheat code in the heap" DarkGray
        Add-Finding "OK" "Live game process" "Running Java process $([char]0x2014) no injected agent, no remote debugger, no cheat code loaded in the heap" | Out-Null
    }
    # The live game named folders nothing on disk pointed at. Scan them now,
    # with the same code the first pass used, before anything reads the totals.
    Invoke-LateFolderScan

    # Notes are printed whether or not there were findings: they are real
    # observations, they move the model score through sys_issues, and they are
    # exactly the kind of thing a moderator should look at with their own eyes.
    # What they must never do is decide the verdict by themselves.
    if ($jvm.Notes.Count -gt 0) {
        Write-Host ""
        W "  $([char]0x2139) Worth a look in the live process (each of these also has an innocent explanation):" DarkYellow
        foreach ($n in $jvm.Notes) { W "    $([char]0x2022) $n" DarkGray }
        $script:SystemIssues += $jvm.Notes.Count
        Add-Finding "WARN" "Live game process" "$($jvm.Notes.Count) observation(s) in the running Java process that need a human" `
            @($jvm.Notes) `
            "The scan read the running javaw/java process and found things that are unusual but not proof." `
            "Each of these has a legitimate cause as well as a suspicious one $([char]0x2014) a launcher agent, a dev tool on a local port, a cheat word typed in chat." `
            "Calling any of them an injection on its own would flag innocent players, so they are reported and left to a person." `
            "Look at the path or the port named above and decide from what is actually there." | Out-Null
    }
}

Write-Host ""
W ("$([char]0x2501)" * 76) Blue
Write-Host ""
W "  SCAN SUMMARY" Cyan
Write-Host ""
$reviewColor = if ($script:Review -gt 0) { [ConsoleColor]::DarkYellow } else { [ConsoleColor]::Green }
W "  Total mods scanned   : " DarkGray -NoNewline; W "$($script:TotalMods)" White
W "  Verified (safe)      : " DarkGray -NoNewline; W "$($script:Verified)" Green
W "  Unknown (looks clean): " DarkGray -NoNewline; W "$($script:Unknown)" Yellow
W "  Review (check these) : " DarkGray -NoNewline; W "$($script:Review)" $reviewColor
W "  Flagged (likely cheat): " DarkGray -NoNewline; W "$($script:Flagged)" Red
$issueColor = if ($script:SystemIssues -gt 0) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
W "  System issues        : " DarkGray -NoNewline; W "$($script:SystemIssues)" $issueColor
W "  AI self-learning     : " DarkGray -NoNewline; W "$($script:mlSamples)" Cyan -NoNewline; W " examples learned  $([char]0x2014)  memory $($script:knownGoodHashes.Count) good / $($script:knownCheatHashes.Count) cheat  (model v$($script:mlModelVersion))" DarkGray
Write-Host ""
W ("$([char]0x2501)" * 76) Blue
Write-Host ""

Write-FinalVerdict $flaggedMods $reviewMods

if ($script:SystemIssues -gt 0) {
    W "  $([char]0x26A0) $($script:SystemIssues) system issue(s) found outside the mods folder $([char]0x2014) see the sections above." Red
    Write-Host ""
}

Write-Host ""
W "  Analysis complete!" Cyan
Write-Host ""
W "  Created by  : " White -NoNewline; W $script:Author Cyan
W "  GitHub      : " DarkGray -NoNewline; W "https://github.com/QDHShamiro" DarkGray
W "  Discord     : " Blue -NoNewline; W "discord.gg/asyncstudios" Blue
Write-Host ""
W ("$([char]0x2501)" * 76) Blue
Write-Host ""
W "  Run anywhere:" DarkGray
$runCmd = '  powershell -ExecutionPolicy Bypass -Command "iex (irm ''https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1'')"'
W $runCmd DarkGray
Write-Host ""
Write-Host ""
Write-Host ""
# No question here any more - the tool decided this itself in Set-AutoDepth, and
# escalated on its own if the mod pass turned anything up.
# Neither of these is gated on the deep scan.
#
# An autoclicker is not in the mods folder and does not need the game to be open,
# so closing Minecraft before the screenshare used to hide it completely - which is
# the opposite of the point.
#
# And the game's own logs are the only evidence that survives deleting the jar: a
# log line says the cheat LOADED, and says when.
Show-MacroScan
Show-LogScan
Show-InstanceScan
Show-ClientJarScan

$doDeep = $script:DeepScan -or $script:AssumeYes
if (-not $doDeep -and -not $script:_DevMode) {
    Add-ScanGap "Deep system scan was not run $([char]0x2014) nothing suspicious came up and Minecraft was not running. Running processes, stray jars and autostart entries were therefore not checked (click macros WERE checked $([char]0x2014) that scan runs every time)"
}
if ($doDeep -or $script:_DevMode) {
    Run-RecentActivity
    Run-PCscan
}
if (-not $script:_DevMode) {
    Run-BamScan
}
# What Windows still remembers about files that are already gone. Runs last, so
# the deletion window can use the game's start time and the mod scan's results.
Show-HistoryScan
# Needs Administrator, so it is announced separately when it cannot run.
Show-UsnScan

# Every stage has now run (mods, system, JVM, PC, BAM) - so the session AI can
# finally judge the scan AS A WHOLE, learn from it, and upload it to the team.
$script:SessionRaw = Get-SessionRaw
$script:SessionVerdict = Get-SessionVerdict $script:SessionRaw
Write-SessionCard $script:SessionVerdict $script:SessionRaw
Write-ScanGaps
Save-ScanSummary $script:SessionVerdict
$slabel = Get-SessionLabel $script:SessionRaw
if ($slabel -ge 0) {
    Update-SessionModelOnline $script:SessionVerdict.Vector $slabel
    $script:SessionSample = @{ vec = @($script:smFeatureOrder | ForEach-Object { [double]$script:SessionVerdict.Vector[$_] }); label = $slabel }
    W "  $([char]0x2713) Overall-scan AI learned from this scan ($($script:smSamples) whole scans learned so far)." DarkGray
} else {
    W "  $([char]0x2139) Overall-scan AI did not learn from this scan $([char]0x2014) the result was not clear-cut enough." DarkGray
}
Write-Host ""

Send-ScanResult

Save-LearnState
if ($script:Share -and $script:shareHashes.Count -gt 0) {
    try {
        $shareFile = Join-Path (Split-Path (Get-LearnPath)) "contribute_hashes.txt"
        (@($script:shareHashes) | Select-Object -Unique) | Out-File -FilePath $shareFile -Encoding UTF8
        Write-Host ""
        W "  $([char]0x2191) Share $([char]0x2014) $($script:shareHashes.Count) confirmed cheat hash(es) saved to:" Cyan
        W "    $shareFile" DarkGray
        W "    Submit them at github.com/QDHShamiro/AsyncAnalyzer/issues to help everyone." DarkGray
        Write-Host ""
    } catch {}
}

if ($script:_DevMode) {
    New-HtmlReport
    return
}

Write-Host ""
if ($script:ScanClock) { W ("  Finished in " + ("{0:N1}" -f $script:ScanClock.Elapsed.TotalSeconds) + " s.") DarkGray }
W "  Done." Green
Write-Host ""
# Nothing waits for a keypress any more, so the result must survive the window
# closing: it is written to the HTML report and to last-scan.txt (see Save-ScanSummary).
