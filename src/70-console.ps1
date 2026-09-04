function W([string]$text, [ConsoleColor]$color, [switch]$NoNewline) {
    $old = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $color
    if ($NoNewline) { Write-Host $text -NoNewline } else { Write-Host $text }
    $Host.UI.RawUI.ForegroundColor = $old
}

function Spin([string]$msg) {
    $f = $script:SpinFrames[$script:SpinIdx % 8]
    $script:SpinIdx++
    Write-Host "`r[$f] $msg    " -ForegroundColor Yellow -NoNewline
}

function SpinClear { Write-Host "`r$(' ' * 100)`r" -NoNewline }

function Write-Rule([string]$Char = "$([char]0x2500)", [int]$Width = 76, [ConsoleColor]$Color = "DarkGray") {
    W ($Char * $Width) $Color
}

function Write-SectionHeader([string]$Title, [int]$Count, [ConsoleColor]$DotColor, [ConsoleColor]$CountColor) {
    Write-Host ""
    W "  " White -NoNewline
    W "$([char]0x25CF)" $DotColor -NoNewline
    W "  $Title  " White -NoNewline
    W "($Count)" $CountColor
    Write-Host ""
}

function Show-Banner {
    $banner = @"

  $([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)
  $([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)
  $([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)
  $([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)
  $([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)
  $([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)

  $([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)
  $([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)
  $([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x255D)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)
  $([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2554)$([char]0x2550)$([char]0x2550)$([char]0x2588)$([char]0x2588)$([char]0x2557)
  $([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x255A)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2588)$([char]0x2557)$([char]0x2588)$([char]0x2588)$([char]0x2551)$([char]0x2591)$([char]0x2591)$([char]0x2588)$([char]0x2588)$([char]0x2551)
  $([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x2550)$([char]0x255D)$([char]0x255A)$([char]0x2550)$([char]0x255D)$([char]0x2591)$([char]0x2591)$([char]0x255A)$([char]0x2550)$([char]0x255D)
"@

    W $banner Cyan
    Write-Host ""
    W "                Minecraft Mod Forensics + Cheat Detection Suite" DarkGray
    Write-Host ""
    W "                " Gray -NoNewline
    W $script:Author Cyan -NoNewline
    W "  |  AsyncAnalyzer  v$($script:Version)" DarkGray
    Write-Host ""
    W ("$([char]0x2501)" * 76) DarkCyan
    Write-Host ""
}

$script:mcInstanceRoots = @(
    "$env:APPDATA\.minecraft\mods",
    "$env:APPDATA\.minecraft\shaderpacks",
    "$env:APPDATA\.minecraft\resourcepacks",
    "$env:LOCALAPPDATA\Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe\LocalCache\Local\.minecraft\mods",
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
    "$env:APPDATA\com.modrinth.theseus\profiles"
)

function Get-LauncherName([string]$path) {
    if ($path -match '\\\.minecraft\\mods') { return "Vanilla" }
    if ($path -match 'PrismLauncher|prismlauncher') { return "PrismLauncher" }
    if ($path -match 'ATLauncher') { return "ATLauncher" }
    if ($path -match 'MultiMC') { return "MultiMC" }
    if ($path -match 'ftblauncher') { return "FTB" }
    if ($path -match 'GDLauncher|gdlauncher') { return "GDLauncher" }
    if ($path -match 'curseforge') { return "CurseForge" }
    if ($path -match '\.technic') { return "Technic" }
    if ($path -match 'PolyMC') { return "PolyMC" }
    if ($path -match 'modrinth|theseus|ModrinthApp') { return "Modrinth" }
    return "Unknown"
}

function Show-SessionTimeline {
    # One line here proves nothing by itself. The pattern that matters -
    # "an .exe ran 2 minutes after the game started, then the BAM record for
    # it vanished 3 seconds later, and a jar with the same timestamp is gone
    # from mods\" - only shows up once every source is on the SAME clock. No
    # single source (BAM, USN, Defender, the JVM sweep, RecentDocs) has both
    # halves of that story; only reading them side by side does.
    if ($script:SessionEvents.Count -eq 0) { return }
    Write-SysSection "SESSION TIMELINE"
    $anchorLabel = if ($script:GameStarted) { "game start" } else { "scan start" }
    $anchorTime  = if ($script:GameStarted) { $script:GameStarted } else { $script:ScanStart }
    W "  $([char]0x2502)  Zero point: $anchorLabel at $($anchorTime.ToString('yyyy-MM-dd HH:mm:ss'))" DarkGray
    W "  $([char]0x2502)" DarkGray
    $ordered = @($script:SessionEvents | Sort-Object -Property @{ Expression = { if ($_.Time) { $_.Time } else { [DateTime]::MaxValue } } })
    foreach ($ev in $ordered) {
        $stamp = if ($ev.Offset) { $ev.Offset } else { "time unknown" }
        $stampPadded = $stamp.PadLeft(11)
        W "  $([char]0x2502)  $stampPadded  [$($ev.Source.PadRight(9))]  $($ev.Text)" DarkYellow
    }
    Write-SysSectionEnd
}
