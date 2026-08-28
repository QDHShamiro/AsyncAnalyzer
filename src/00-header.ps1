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
    [string]$HashOnly = ""
)

if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "  [!] AsyncAnalyzer requires PowerShell 5.1 or newer." -ForegroundColor Red
    Write-Host "      Your version: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    return
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$null = chcp 65001
$ModPath = ""

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
$script:Evidence = @{ RandomNamed = 0; CheatSiteDl = 0; HardConfirmed = 0; JvmInject = 0; CheatProcs = 0; StrayJars = 0; CheatFolders = 0; MemCheatClient = 0; MemModule = 0; MemInjectedOnly = 0; DeletedJars = 0; MacroCheat = 0; MacroNamed = 0 }
$script:SessionRaw = $null
$script:SessionVerdict = $null
$script:SessionSample = $null
$script:Telemetry    = $null
$script:CurseForgeApiKey = if ($env:CURSEFORGE_API_KEY) { $env:CURSEFORGE_API_KEY } else { "" }
$verifiedMods = [System.Collections.Generic.List[object]]::new()
$unknownMods  = [System.Collections.Generic.List[object]]::new()
$reviewMods   = [System.Collections.Generic.List[object]]::new()
$flaggedMods  = [System.Collections.Generic.List[object]]::new()
$script:BamDeleted = @()
# Every check appends here (see Add-Finding): level, area, what was found, and the
# WHAT/WHY/HOW/FIX reasoning. The HTML report is built from this list.
$script:Findings   = [System.Collections.Generic.List[object]]::new()
$script:LastFinding = $null
$script:SysArea    = "System"
$script:FlaggedModsList = [System.Collections.Generic.List[string]]::new()
$script:ReviewModsList  = [System.Collections.Generic.List[string]]::new()
$script:SpinFrames   = @("$([char]0x28FE)","$([char]0x28FD)","$([char]0x28FB)","$([char]0x28BF)","$([char]0x287F)","$([char]0x28DF)","$([char]0x28EF)","$([char]0x28F7)")
$script:SpinIdx      = 0
