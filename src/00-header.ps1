[CmdletBinding()]
param(
    [switch]$Dev,
    [string]$DevPath = "",
    [switch]$DeepScan,
    [switch]$DeepMemory,
    [switch]$Yes,
    [switch]$SelfTest,
    [switch]$NoUpdate,
    [switch]$NoLearn,
    [switch]$Reset,
    [switch]$Share,
    [switch]$Ask,
    [switch]$Deep,
    [switch]$NoElevate,
    [string]$Path = "",
    [string]$HashOnly = "",
    # A code the staff member says out loud before the scan starts. It appears in
    # the console, in the report and in the summary file, so a report produced
    # BEFORE that code was given cannot carry it. It proves freshness, not honesty:
    # somebody who controls the PC can always fake a local file, and the report says
    # so in as many words.
    [string]$Code = ""
)

if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "  [!] AsyncAnalyzer requires PowerShell 5.1 or newer." -ForegroundColor Red
    Write-Host "      Your version: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    return
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# chcp is a Windows program, and this tool only ever runs on Windows - but it is
# also PARSED and SELF-TESTED elsewhere, and a missing external command becomes a
# TERMINATING error under $ErrorActionPreference = 'Stop', which is what GitHub
# Actions sets for pwsh by default. The script then died here, on line 33, before
# one check had run - and the CI self-test could never have passed.
if (Get-Command chcp -ErrorAction SilentlyContinue) { $null = chcp 65001 }
$script:ScanClock = [System.Diagnostics.Stopwatch]::StartNew()
$ModPath = ""

# The elevated window runs a temp copy of this file (see Invoke-SelfElevate). By
# the time this line runs the copy has been read and parsed in full, so it can
# go - and it goes NOW, before one check has run, so that nothing of the tool is
# left on the PC even if the scan dies halfway. Only the copy: a clone that is
# run with -NoElevate lives somewhere else and is not named after a scan id.
if ($NoElevate -and $PSCommandPath) {
    try {
        $elevTmpDir = [System.IO.Path]::GetTempPath().TrimEnd('\')
        if ((Split-Path -Parent $PSCommandPath).TrimEnd('\') -ieq $elevTmpDir -and
            (Split-Path -Leaf $PSCommandPath) -match '^AsyncAnalyzer_[0-9A-F]{12}\.ps1$') {
            Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction Stop
        }
    } catch {}
}

$script:Version      = "4.0.0"
$script:Author       = "QDHShamiro"
$script:ToolName     = "AsyncAnalyzer"
$script:TotalMods    = 0
$script:Verified     = 0
$script:Unknown      = 0
$script:Review       = 0
# Recognised for certain, but whether it is allowed is the server's rule. Counted
# separately from Review so a moderator can tell a rule question from uncertainty.
$script:ServerRule   = 0
$script:Flagged      = 0
$script:SystemIssues = 0
$script:DeepMemory   = [bool]$DeepMemory
# Behavioural bytecode analysis reads every class's constant pool, so it is the
# expensive part of a scan. Default reads a sample per jar (fast enough to sit
# through during a screenshare); -Deep reads far more, for when you are actually
# investigating someone.
$script:Deep         = [bool]$Deep
$script:BcMaxClasses = if ($Deep) { 400 } else { 40 }
# A ghost client (Doomsday and friends) is usually INJECTED into the running game
# instead of sitting in the mods folder, so no file scan can ever see it. When
# Minecraft is actually running, switch the live-memory check on by itself - it is
# the only thing that catches an injected client. Read-only, and announced openly
# in the transparency notice so the scanned person knows it happened.
$script:MemoryAuto = $false
if (-not $script:DeepMemory) {
    try {
        if (@(Get-Process -Name javaw, java -ErrorAction SilentlyContinue).Count -gt 0) {
            $script:DeepMemory = $true
            $script:MemoryAuto = $true
        }
    } catch {}
}
$script:DeepScan     = [bool]$DeepScan
$script:AssumeYes    = [bool]$Yes
$script:NoUpdate     = [bool]$NoUpdate
$script:SelfTestMode = [bool]$SelfTest
$script:NoLearn      = [bool]$NoLearn
$script:Reset        = [bool]$Reset
$script:Share        = [bool]$Share
$script:Ask          = [bool]$Ask
$script:shareHashes  = [System.Collections.Generic.List[string]]::new()
$script:sessionGood  = [System.Collections.Generic.List[string]]::new()
$script:sessionCheat = [System.Collections.Generic.List[string]]::new()
$script:sessionSamples = [System.Collections.Generic.List[object]]::new()
# Evidence collected across the WHOLE scan (not just the mods folder). Feeds the
# session AI at the end so it can judge the scan as a whole, and learn from it.
$script:Evidence = @{ RandomNamed = 0; CheatSiteDl = 0; HardConfirmed = 0; JvmInject = 0; CheatProcs = 0; StrayJars = 0; CheatFolders = 0; MemCheatClient = 0; MemModule = 0; MemInjectedOnly = 0; DeletedJars = 0; MacroCheat = 0; MacroNamed = 0; BehaviourCheat = 0; BehaviourLikely = 0; HiddenApi = 0; AttachAgent = 0; ManualMap = 0; DllGoneMissing = 0; DefenderDetect = 0; ExecTrace = 0 }
# A chronological trail across every evidence source (BAM, USN, Prefetch,
# Defender, the JVM memory sweep, exec traces), all keyed to the same clock -
# GameStarted. One line here does not prove anything by itself; "an .exe ran
# 2 minutes after the game started, then vanished 3 seconds later" is a
# pattern no single source shows, because no single source has both halves.
$script:SessionEvents = [System.Collections.Generic.List[object]]::new()
$script:AltClients = [System.Collections.Generic.List[string]]::new()
# The folders that were actually scanned, so the log reader knows which
# instances' logs/ and crash-reports/ to read.
$script:ScanTargetDirs = [System.Collections.Generic.List[string]]::new()
$script:LogHits = 0
$script:InstanceHits = 0
$script:InstanceAgents = 0
$script:SessionRaw = $null
$script:SessionVerdict = $null
$script:SessionSample = $null
$script:Telemetry    = $null
$script:CurseForgeApiKey = if ($env:CURSEFORGE_API_KEY) { $env:CURSEFORGE_API_KEY } else { "" }
# Qualified as $script: on purpose. Invoke-JarAnalysis adds to these from inside
# a function, as $script:verifiedMods, and an UNQUALIFIED assignment here only
# happens to land in the same scope when the file is run with -File. The way this
# tool is actually delivered is iex (irm ...), where it does not - and the scan
# died with "Es ist nicht moeglich, eine Methode fuer einen Ausdruck aufzurufen,
# der den NULL hat" on the fourth jar. Assign and read the same way, always.
$script:verifiedMods = [System.Collections.Generic.List[object]]::new()
$script:unknownMods  = [System.Collections.Generic.List[object]]::new()
$script:reviewMods   = [System.Collections.Generic.List[object]]::new()
$script:flaggedMods  = [System.Collections.Generic.List[object]]::new()
$script:BamDeleted = @()
# Every check appends here (see Add-Finding): level, area, what was found, and the
# WHAT/WHY/HOW/FIX reasoning. The HTML report is built from this list.
$script:Findings   = [System.Collections.Generic.List[object]]::new()
$script:LastFinding = $null
$script:SysArea    = "System"
# Identity of this one scan. The ID is random per run and is uploaded with the
# result when team mode is on, so a moderator can open the ID in the dashboard and
# compare it against what they were shown. The challenge code is whatever the staff
# member said before the scan started.
$script:ScanId = ([guid]::NewGuid().ToString('N').Substring(0, 12).ToUpper())
$script:ScanCode = ($Code -replace '[^A-Za-z0-9 _-]', '').Trim()
$script:ScanStart = Get-Date
# When the running game was started, if one is running. Set in
# Find-MinecraftModFolders; used as the window for "deleted during this session".
$script:GameStarted = $null
$script:FlaggedModsList = [System.Collections.Generic.List[string]]::new()
$script:ReviewModsList  = [System.Collections.Generic.List[string]]::new()
$script:SpinFrames   = @("$([char]0x28FE)","$([char]0x28FD)","$([char]0x28FB)","$([char]0x28BF)","$([char]0x287F)","$([char]0x28DF)","$([char]0x28EF)","$([char]0x28F7)")
$script:SpinIdx      = 0
