    $jvmFlags = Run-JVMScan
    $script:Evidence.JvmInject = $jvmFlags.Count
    if ($jvmFlags.Count -gt 0) {
        Write-SectionHeader "JVM / RUNTIME INJECTION" $jvmFlags.Count Yellow Yellow
        Write-Rule "$([char]0x2500)" 76 DarkGray
        Write-Host ""
        Write-InjectionCard "javaw / java process" $jvmFlags
        $script:SystemIssues += $jvmFlags.Count
        Add-Finding "FAIL" "Live game process" "$($jvmFlags.Count) injection trace(s) in the running Java process" `
            @($jvmFlags) `
            "The scan attached to the running javaw/java process and read its loaded agents, its open localhost ports and its heap." `
            "This is what the mods folder cannot show: code that is live in the game right now, whether or not any file on disk still contains it." `
            "Deleting a jar does not remove what is already loaded, so these traces survive a last-second cleanup." `
            "Do not let the player close the game before this is reviewed $([char]0x2014) closing it destroys this evidence." | Out-Null
    } else {
        Write-Host ""
        W "  $([char]0x2713) JVM $([char]0x2014) no agents, no localhost listeners, no heap signatures" DarkGray
        Add-Finding "OK" "Live game process" "Running Java process $([char]0x2014) no agents, no localhost listeners, no cheat signatures in the heap" | Out-Null
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
$doDeep = $script:DeepScan -or $script:AssumeYes
if (-not $doDeep -and -not $script:_DevMode) {
    Add-ScanGap "Deep system scan was not run $([char]0x2014) nothing suspicious came up and Minecraft was not running"
}
if ($doDeep -or $script:_DevMode) {
    Run-RecentActivity
    Run-PCscan
}
if (-not $script:_DevMode) {
    Run-BamScan
}

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
W "  Done." Green
Write-Host ""
# Nothing waits for a keypress any more, so the result must survive the window
# closing: it is written to the HTML report and to last-scan.txt (see Save-ScanSummary).
