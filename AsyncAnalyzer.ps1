if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "  [!] AsyncAnalyzer requires PowerShell 5.1 or newer." -ForegroundColor Red
    Write-Host "      Your version: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    return
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$null = chcp 65001
$ModPath = ""

$script:Version      = "3.0.0"
$script:Author       = "QDHShamiro"
$script:ToolName     = "AsyncAnalyzer"
$script:TotalMods    = 0
$script:Verified     = 0
$script:Unknown      = 0
$script:Flagged      = 0
$script:SystemIssues = 0
$script:FlaggedModsList = [System.Collections.Generic.List[string]]::new()
$script:SpinFrames   = @("$([char]0x28FE)","$([char]0x28FD)","$([char]0x28FB)","$([char]0x28BF)","$([char]0x287F)","$([char]0x28DF)","$([char]0x28EF)","$([char]0x28F7)")
$script:SpinIdx      = 0

$script:cheatStrings = @(
    "AutoCrystal","autocrystal","auto crystal","cw crystal"
    "dontPlaceCrystal","dontBreakCrystal"
    "AutoHitCrystal","autohitcrystal","canPlaceCrystalServer","healPotSlot"
    "AutoAnchor","autoanchor","auto anchor","DoubleAnchor"
    "hasGlowstone","HasAnchor","anchortweaks","anchor macro","safe anchor","safeanchor"
    "SafeAnchor","AirAnchor"
,"anchorMacro"
    "AutoTotem","autototem","auto totem","InventoryTotem"
    "inventorytotem","HoverTotem","hover totem","legittotem"
    "AutoPot","autopot","auto pot","speedPotSlot","strengthPotSlot"
    "AutoArmor","autoarmor","auto armor"
,"AutoPotRefill"
    "preventSwordBlockBreaking","preventSwordBlockAttack"
    "ShieldDisabler","ShieldBreaker"
    "Breaking shield with axe..."
    "AutoDoubleHand","autodoublehand","auto double hand"
    "Failed to switch to mace after axe!"
    "AutoMace","MaceSwap","SpearSwap"
,"StunSlam"
    "JumpReset","axespam","axe spam"
    "EndCrystalItemMixin","findKnockbackSword","attackRegisteredThisClick"
    "AimAssist","aimassist","aim assist","triggerbot","trigger bot"
    "Silent Rotations","SilentRotations"
    "FakeInv","swapBackToOriginalSlot"
    "FakeLag"
,"fakePunch","Fake Punch"
    "webmacro","web macro","AntiWeb","AutoWeb"
    "lvstrng","dqrkis"
    "WalksyCrystalOptimizerMod","WalksyOptimizer","WalskyOptimizer"
,"autoCrystalPlaceClock"
    "AutoFirework","ElytraSwap","FastXP","FastExp","NoJumpDelay"
    "PackSpoof","Antiknockback","catlean"
    "AuthBypass","obfuscatedAuth","LicenseCheckMixin"
    "BaseFinder","ItemExploit"
    "FreezePlayer"
    "LWFH Crystal"
    "KeyPearl","LootYeeter"
    "FastPlace"
    "AutoBreach"
    "setBlockBreakingCooldown","getBlockBreakingCooldown","blockBreakingCooldown"
    "onBlockBreaking","setItemUseCooldown"
    "setSelectedSlot","invokeDoAttack","invokeDoItemUse","invokeOnMouseButton"
    "onPushOutOfBlocks","onIsGlowing"
    "Automatically switches to sword when hitting with totem"
    "arrayOfString","POT_CHEATS","Dqrkis Client","Entity.isGlowing"
    "Activate Key"
    "Click Simulation"
    "On RMB"
    "No Count Glitch"
    "No Bounce","NoBounce"
    "Place Delay","Break Delay"
    "Fast Mode","Place Chance"
    "Break Chance","Stop On Kill"
,"damagetick"
    "Anti Weakness"
    "Particle Chance"
    "Trigger Key"
    "Switch Delay"
    "Totem Slot"
    "Smooth Rotations"
    "Use Easing","Easing Strength"
    "While Use","Stop on Kill"
    "Glowstone Delay","Glowstone Chance"
    "Explode Delay","Explode Chance"
    "Explode Slot","Only Charge"
    "Anchor Macro"
    "Reach Distance"
    "Min Height","Min Fall Speed"
    "Attack Delay","Breach Delay"
    "Require Elytra"
    "Auto Switch Back"
    "Check Line of Sight"
    "Only When Falling"
    "Require Crit"
    "Show Status Display"
    "Stop On Crystal"
    "Check Shield","On Pop"
    "Check Players","Predict Crystals"
    "Check Aim","Check Items"
    "Activates Above","Blatant"
    "Force Totem","Stay Open For"
    "Auto Inventory Totem"
    "Only On Pop","Vertical Speed"
    "Hover Totem","Swap Speed"
    "Strict One-Tick","Mace Priority"
    "Min Totems","Min Pearls"
    "Totem First","Drop Interval"
    "Random Pattern","Loot Yeeter"
    "Horizontal Aim Speed"
    "Vertical Aim Speed"
    "Include Head"
    "Web Delay","Holding Web"
    "Not When Affects Player"
    "Hit Delay"
    "Require Hold Axe"
    "Fake Punch"
    "placeInterval","breakInterval","stopOnKill"
    "activateOnRightClick","holdCrystal"
    "Macro Key"
    "KillAura","ClickAura","MultiAura","ForceField","LegitAura"
    "AimBot","AutoAim","SilentAim","AimLock","HeadSnap"
    "CrystalAura","AnchorAura","AnchorFill","AnchorPlace"
    "BedAura","AutoBed","BedBomb","BedPlace"
    "BowAimbot","BowSpam","AutoBow"
    "AutoCrit","CritBypass","AlwaysCrit","CriticalHit"
    "ReachHack","ExtendReach","LongReach","HitboxExpand"
    "AntiKB","NoKnockback","GrimVelocity","GrimDisabler","VelocitySpoof","KBReduce"
    "OffhandTotem","TotemSwitch"
    "AutoWeapon","AutoSword","AutoCity","Burrow","SelfTrap"
    "HoleFiller","AntiSurround","AntiBurrow"
    "WTap","TargetStrafe","AutoGap","AutoPearl"
    "FlyHack","CreativeFlight","BoatFly","PacketFly","AirJump"
    "SpeedHack","BHop","BunnyHop"
    "AntiFall","NoFallDamage"
    "StepHack","FastClimb","AutoStep","HighStep"
    "WaterWalk","LiquidWalk","LavaWalk"
    "NoSlow","NoSlowdown","NoWeb","NoSoulSand"
    "WallHack","ElytraSpeed","InstantElytra"
    "ScaffoldWalk","FastBridge","AutoBridge"
    "Nuker","NukerLegit","InstantBreak"
    "GhostHand","NoSwing"
    "PlaceAssist","AirPlace","AutoPlace","InstantPlace"
    "PlayerESP","MobESP","ItemESP","StorageESP","ChestESP"
    "Tracers","NameTagsHack"
    "XRayHack","OreFinder","CaveFinder","OreESP"
    "NewChunks","TunnelFinder"
    "TargetHUD","ReachDisplay"
    "DoubleClicker","JitterClick","ButterflyClick","CPSBoost"
    "ChestStealer","InvManager","InvMovebypass"
    "AutoSprint","AntiAFK"
    "FakeLatency","FakePing","SpoofRotation","PositionSpoof"
    "GameSpeed","SpeedTimer"
    "GrimBypass","VulcanBypass","MatrixBypass"
    "AACBypass","VerusDisabler","IntaveBypass","WatchdogBypass"
    "PacketMine","PacketWalk","PacketSneak","PacketCancel","PacketDupe","PacketSpam"
    "SelfDestruct","HideClient"
    "SessionStealer","TokenLogger","TokenGrabber","DiscordToken"
    "ReverseShell","C2Server","KeyLogger"
    "StashFinder","TrailFinder"
    "imgui.binding","imgui.gl3","imgui.glfw"
    "JNativeHook","GlobalScreen","NativeKeyListener"
    "client-refmap.json","cheat-refmap.json","phantom-refmap.json"
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA=="
    "meteordevelopment","cc/novoline"
    "com/alan/clients","club/maxstats","wtf/moonlight"
    "me/zeroeightsix/kami","net/ccbluex","today/opai"
    "net/minecraft/injection","org/chainlibs/module/impl/modules"
    "xyz/greaj","com/cheatbreaker"
    "doomsdayclient","DoomsdayClient","doomsday.jar"
    "novaclient","api.novaclient.lol"
    "WalksyOptimizer","LWFH Crystal"
    "vape.gg","vapeclient","VapeClient","VapeLite"
    "intent.store","IntentClient"
    "rise.today","riseclient.com"
    "meteor-client","meteorclient","meteordevelopment.meteorclient"
    "liquidbounce","fdp-client","net.ccbluex"
    "novoware","novoclient"
    "aristois","impactclient","azura"
    "pandaware","moonClient","astolfo"
    "futureClient","konas","rusherhack","inertia","exhibition"
    "sessionstealer","tokengrabber","webhookstealer","cookiethief"
    "discordstealer","keylogger","iplogger","cryptominer"
    "reverseShell","backdoormod","exploitmod","ratmod","ransomware"
    "sendWebhook","exfiltrate","connectBack","callHome"
    "grabToken","stealSession","accountstealer"
    "discord/token","grabber/cookie","grab_cookies","stealerutils"
    "sendToWebhook","postDiscord","webhookurl","discordwebhook"
    "Runtime.exec","cmd.exe","powershell.exe"
    "crasher","lagmachine","booksploit","signcrasher","entityspammer"
    "nukermod","worldnuker","tntmod","bedexplode","anchorexplode"
    "injectClass","modifyBytecode","hookMethod"
    "attachAgent","VirtualMachine.attach"
    "FLOW_OBFUSCATION","STRING_ENCRYPTION","RESOURCE_ENCRYPTION"
    "skidfuscator","me/itzsomebody","radon/transform","bozar/"
    "paramorphism","zelix/klassmaster","allatori","dasho","com/icqm/smoke"
    "org.chainlibs.module.impl.modules.Crystal.Y"
    "org.chainlibs.module.impl.modules.Crystal.bF"
    "org.chainlibs.module.impl.modules.Crystal.bM"
    "org.chainlibs.module.impl.modules.Crystal.bY"
    "org.chainlibs.module.impl.modules.Crystal.bq"
    "org.chainlibs.module.impl.modules.Crystal.cv"
    "org.chainlibs.module.impl.modules.Crystal.o"
    "org.chainlibs.module.impl.modules.Blatant.I"
    "org.chainlibs.module.impl.modules.Blatant.bR"
    "org.chainlibs.module.impl.modules.Blatant.bx"
    "org.chainlibs.module.impl.modules.Blatant.cj"
    "org.chainlibs.module.impl.modules.Blatant.dk"
    "dev.krypton","dev.gambleclient"
    "xyz.greaj","com.cheatbreaker"
)

$script:knownCheatFileTokens = @(
    "doomsday","doomsdayclient","doomsday-client","doomsday_client",
    "darik","dariks","dqrkis","dqrk",
    "vape","vapeclient","vape-client","vape_client","vapelite","vape-lite",
    "meteor","meteorclient","meteor-client","meteor_client",
    "liquidbounce","liquid-bounce","liquid_bounce","liquidb",
    "wurst","wurst-client","wurst_client",
    "sigma","sigmaclient","sigma-client",
    "rise","riseclient","rise-client",
    "future","futureclient","future-client",
    "konas","konasclient","konas-client",
    "inertia","inertiaclient","inertia-client",
    "exhibition","exhibitionclient",
    "pandaware","panda-ware","panda_ware",
    "astolfo","astolfoclient","astolfo-client",
    "rusherhack","rusher-hack","rusher_hack",
    "novaclient","nova-client","nova_client","novaware",
    "impact","impactclient","impact-client",
    "aristois","aristois-client",
    "azura","azuraclient","azura-client",
    "moonlight","moonlightclient","moon-client",
    "intent","intentclient","intent-client","intentstore",
    "prestige","prestigeclient","prestige-client",
    "cheatbreaker","cheat-breaker",
    "kami","kamiclient","kami-client",
    "meteor-dev","meteordev",
    "fdp","fdpclient","fdp-client",
    "xray","xrayclient","xray-mod",
    "baritone","baritoneclient",
    "skidfuscator","skid-client","skidclient",
    "noob","nooby","cheat","hack","hacked","hacker",
    "inject","injector","loader","payload","bypass","cracked","crack",
    "stealer","grabber","logger","keylog","token","exploit","malware","rat"
)

function Get-BigramSimilarity([string]$a, [string]$b) {
    if ($a.Length -lt 2 -or $b.Length -lt 2) {
        if ($a -eq $b) { return 1.0 } else { return 0.0 }
    }
    $bigramsA = [System.Collections.Generic.HashSet[string]]::new()
    for ($i = 0; $i -lt $a.Length - 1; $i++) { [void]$bigramsA.Add($a.Substring($i,2)) }
    $bigramsB = [System.Collections.Generic.HashSet[string]]::new()
    for ($i = 0; $i -lt $b.Length - 1; $i++) { [void]$bigramsB.Add($b.Substring($i,2)) }
    $intersection = 0
    foreach ($bg in $bigramsA) { if ($bigramsB.Contains($bg)) { $intersection++ } }
    return (2.0 * $intersection) / ($bigramsA.Count + $bigramsB.Count)
}

function Get-FilenameSimilarityMatch([string]$JarName) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName).ToLower()
    $base = $base -replace '[-_\.\s\d]+', ''
    if ($base.Length -lt 3) { return $null }
    $bestToken = $null
    $bestScore = 0.0
    foreach ($token in $script:knownCheatFileTokens) {
        $t = $token -replace '[-_\.\s]+', ''
        if ($base.Contains($t) -or $t.Contains($base)) {
            $score = [Math]::Max($base.Length, $t.Length) / [Math]::Max($base.Length, $t.Length)
            if ($base.Contains($t)) { $score = [double]$t.Length / [double]$base.Length }
            elseif ($t.Contains($base)) { $score = [double]$base.Length / [double]$t.Length }
            if ($score -gt $bestScore) { $bestScore = $score; $bestToken = $token }
        }
        $sim = Get-BigramSimilarity $base $t
        if ($sim -gt $bestScore) { $bestScore = $sim; $bestToken = $token }
    }
    if ($bestScore -ge 0.25 -and $null -ne $bestToken) {
        return [PSCustomObject]@{ Token = $bestToken; Score = [Math]::Round($bestScore * 100) }
    }
    return $null
}

$script:suspiciousPatterns = @(
    "AimAssist","AnchorTweaks","AutoAnchor","AutoCrystal","AutoDoubleHand",
    "AutoHitCrystal","AutoPot","AutoTotem","AutoArmor","InventoryTotem",
    "JumpReset","LegitTotem",
    "ShieldBreaker","TriggerBot","AxeSpam","WebMacro",
    "FastPlace","WalskyOptimizer","WalksyOptimizer","walsky.optimizer",
    "WalksyCrystalOptimizerMod","Replace Mod",
    "ShieldDisabler","SilentAim","Wtap","FakeLag",
    "BlockESP","dev.krypton","Virgin","AntiMissClick",
    "LagReach","PopSwitch","SprintReset","ChestSteal","AntiBot",
    "ElytraSwap","FastXP","FastExp","AirAnchor",
    "jnativehook","FakeInv","HoverTotem","AutoFirework",
    "PackSpoof","Antiknockback","catlean","Argon",
    "AuthBypass","Asteria","Prestige","AutoEat","AutoMine",
    "MaceSwap","DoubleAnchor","AutoTPA","BaseFinder","Xenon","gypsy",
    "Grim","grim",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui.gl3","imgui.glfw",
    "BowAim","Criticals","Fakenick","FakeItem",
    "ItemExploit","Hellion","hellion",
    "LicenseCheckMixin","ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim","dev.gambleclient","obfuscatedAuth",
    "phantom-refmap.json","xyz.greaj",
    "$([char]0x3058).class","$([char]0x3075).class","$([char]0x3076).class","$([char]0x3077).class","$([char]0x305F).class",
    "$([char]0x306D).class","$([char]0x305D).class","$([char]0x306A).class","$([char]0x3069).class","$([char]0x3050).class",
    "$([char]0x305A).class","$([char]0x3067).class","$([char]0x3064).class","$([char]0x3079).class","$([char]0x305B).class",
    "$([char]0x3068).class","$([char]0x307F).class","$([char]0x3073).class","$([char]0x3059).class","$([char]0x306E).class"
)

Add-Type -Assembly "System.IO.Compression.FileSystem" -ErrorAction SilentlyContinue

$script:patternRegex = [regex]::new(
    '(?<![A-Za-z])(' + ($script:suspiciousPatterns | ForEach-Object { [regex]::Escape($_) } | Select-Object -Unique) + ')(?![A-Za-z])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($s in $script:cheatStrings) { [void]$script:cheatStringSet.Add($s) }

$script:fullwidthRegex = [regex]::new(
    "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]{2,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

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
    if ($path -match 'modrinth|theseus') { return "Modrinth" }
    return "Unknown"
}

function Find-MinecraftModFolders {
    $runningJava = @(Get-Process javaw,java -ErrorAction SilentlyContinue)
    $runningPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($proc in $runningJava) {
        try { $rp = $proc.MainModule.FileName; if ($rp) { [void]$runningPaths.Add($rp) } } catch {}
    }
    $results = [System.Collections.Generic.List[object]]::new()
    $seen    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function IsJavaRunningIn([string]$dir) {
        foreach ($rp in $runningPaths) {
            if ($rp -and $rp.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
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
        "$env:APPDATA\com.modrinth.theseus\profiles"
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
    $sorted = $results | Sort-Object @{e={[int]$_.IsRunning};Descending=$true}, @{e='JarCount';Descending=$true}, @{e='LastWrite';Descending=$true}
    return @($sorted)
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
        $w = 72
        Write-Host ""
        W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) FOUND INSTALLATIONS " + "$([char]0x2500)" * 51 + "$([char]0x2510)") DarkCyan
        W "  $([char]0x2502)   #   Launcher        Instance                   Mods  Last Used    $([char]0x2502)" DarkCyan
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkCyan
        $idx = 1
        foreach ($e in $found) {
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
        if (-not [string]::IsNullOrWhiteSpace($sel) -and [int]::TryParse($sel, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $found.Count) { $selIdx = $parsed }
        $chosen = $found[$selIdx - 1]
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

function Ask-YesNo([string]$Prompt) {
    $ans = Read-Host "  $Prompt (Y/N)"
    return ([string]$ans).Trim().ToUpper() -eq "Y"
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
        W ("  $([char]0x250C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2510)") DarkYellow
        W ("  $([char]0x2502)  $([char]0x26A0)  New / modified JARs in the last 48h:" + " " * [Math]::Max(0,$w - 37) + "$([char]0x2502)") DarkYellow
        W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkYellow
        foreach ($jar in ($recentJars | Sort-Object Modified -Descending)) {
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

function Write-FlaggedCard([string]$FileName, [string]$Hash, [bool]$Verified, [string]$VerifiedName, [string]$DlSource, [object]$Patterns, [object]$Strings, [object]$Fullwidth) {
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

function Write-ObfuscationCard([string]$FileName, [object]$Flags) {
    $w = 72
    W ("  $([char]0x250C)$([char]0x2500) OBFUSCATED  $FileName " + "$([char]0x2500)" * [Math]::Max(0, $w - 15 - $FileName.Length) + "$([char]0x2510)") DarkYellow
    W "  $([char]0x2502)" DarkYellow -NoNewline; W " OBFUSCATED " Black -NoNewline; W (" " * [Math]::Max(0,$w - 12)) DarkYellow -NoNewline; W "$([char]0x2502)" DarkYellow
    W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") DarkYellow

    foreach ($flag in $Flags) {
        $ft = $flag; $fd = ""
        if ($flag -match "^(.+?) $([char]0x2014) (.+)$") { $ft = $matches[1]; $fd = $matches[2] }
        W "  $([char]0x2502)" DarkYellow
        W ("  $([char]0x2502)  ") DarkYellow -NoNewline; W "$([char]0x2691) " Yellow -NoNewline; W $ft White
        if ($fd) { W ("  $([char]0x2502)    " + $fd) Gray }
    }

    W "  $([char]0x2502)" DarkYellow
    W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") DarkYellow
    Write-Host ""
}

function Write-SystemFlag([string]$Level, [string]$Msg) {
    switch ($Level) {
        "FAIL" { W "  $([char]0x2502) " DarkRed -NoNewline; W " FAIL " White -NoNewline; W "  $Msg" Red }
        "WARN" { W "  $([char]0x2502) " DarkYellow -NoNewline; W " WARN " Black -NoNewline; W "  $Msg" Yellow }
        "OK"   { W "  $([char]0x2502) " DarkGreen -NoNewline; W "  OK  " White -NoNewline; W "  $Msg" Green }
        "INFO" { W "  $([char]0x2502) " DarkGray -NoNewline; W "  ??  " White -NoNewline; W "  $Msg" DarkGray }
    }
}

function Write-Detail([string]$what, [string]$why, [string]$how, [string]$fix) {
    if ($what) { W ("  $([char]0x2502)    WHAT : " + $what) White }
    if ($why)  { W ("  $([char]0x2502)    WHY  : " + $why) DarkGray }
    if ($how)  { W ("  $([char]0x2502)    HOW  : " + $how) DarkGray }
    if ($fix)  { W ("  $([char]0x2502)    FIX  : " + $fix) DarkCyan }
}

function Write-SysSection([string]$Title) {
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
    try {
        $body = "{`"fingerprints`":[" + $fingerprint + "]}"
        $r = Invoke-RestMethod -Uri "https://api.curseforge.com/v1/fingerprints/432" -Method Post -Body $body -ContentType "application/json" -Headers @{ "x-api-key" = "$2a$10`$bL4bIL5pUWqfcO7KQtnMReakwtfHepBUuxe3G//STEeE0iNHyjPe6" } -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
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
            if ($url -match "mediafire\.com")                                        { return "MediaFire" }
            elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return "Discord" }
            elseif ($url -match "dropbox\.com")                                      { return "Dropbox" }
            elseif ($url -match "drive\.google\.com")                                { return "Google Drive" }
            elseif ($url -match "mega\.nz|mega\.co\.nz")                             { return "MEGA" }
            elseif ($url -match "github\.com")                                       { return "GitHub" }
            elseif ($url -match "modrinth\.com")                                     { return "Modrinth" }
            elseif ($url -match "curseforge\.com")                                   { return "CurseForge" }
            elseif ($url -match "anydesk\.com")                                      { return "AnyDesk" }
            elseif ($url -match "doomsdayclient\.com")                               { return "DoomsdayClient" }
            elseif ($url -match "prestigeclient\.vip")                               { return "PrestigeClient" }
            elseif ($url -match "198macros\.com")                                    { return "198Macros" }
            elseif ($url -match "dqrkis\.xyz")                                       { return "Dqrkis" }
            else {
                if ($url -match "https?://(?:www\.)?([^/]+)") { return $matches[1] }
                return $url
            }
        }
    } catch {}
    return $null
}

function Invoke-ModScan([string]$FilePath) {
    $foundPatterns  = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings   = [System.Collections.Generic.HashSet[string]]::new()
    $foundFullwidth = [System.Collections.Generic.HashSet[string]]::new()

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        foreach ($entry in $archive.Entries) {
            foreach ($m in $script:patternRegex.Matches($entry.FullName)) {
                [void]$foundPatterns.Add($m.Value)
            }
        }

        $allEntries    = [System.Collections.Generic.List[object]]::new()
        $innerArchives = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $archive.Entries) { $allEntries.Add($e) }

        foreach ($nj in ($archive.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerArchives.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch {}
        }

        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            if ($name -match '\.(class|json|txt|cfg|properties|toml|mf|xml)$' -or $name -match 'MANIFEST\.MF') {
                try {
                    $st  = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2); $st.Close()
                    $bytes = $ms2.ToArray(); $ms2.Dispose()

                    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $utf8  = [System.Text.Encoding]::UTF8.GetString($bytes)

                    foreach ($m in $script:patternRegex.Matches($ascii)) { [void]$foundPatterns.Add($m.Value) }

                    foreach ($s in $script:cheatStringSet) {
                        if ($ascii.Contains($s)) { [void]$foundStrings.Add($s); continue }
                        if ($utf8.Contains($s))  { [void]$foundStrings.Add($s) }
                    }

                    foreach ($m in $script:fullwidthRegex.Matches($utf8)) {
                        [void]$foundFullwidth.Add($m.Value)
                    }
                } catch {}
            }
        }

        foreach ($ia in $innerArchives) { try { $ia.Dispose() } catch {} }
        $archive.Dispose()
    } catch {}

    $fwCheatPool = @($script:cheatStrings | Where-Object { $_ -cmatch "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]" })
    $resolvedFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in @($foundFullwidth)) {
        if ($fw.Length -lt 3) { continue }
        $bestMatch = $null
        foreach ($cs in $fwCheatPool) {
            if ($cs.Contains($fw)) {
                if ($null -eq $bestMatch -or $cs.Length -lt $bestMatch.Length) { $bestMatch = $cs }
            }
        }
        if ($null -ne $bestMatch) { [void]$resolvedFullwidth.Add($bestMatch) }
        elseif ($fw.Length -ge 6)  { [void]$resolvedFullwidth.Add($fw) }
    }

    $resolved = @($resolvedFullwidth)
    $finalFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in $resolved) {
        $isRedundant = $false
        foreach ($other in $resolved) {
            if ($fw.Length -lt $other.Length -and $other.Contains($fw)) { $isRedundant = $true; break }
        }
        if (-not $isRedundant) { [void]$finalFullwidth.Add($fw) }
    }

    return @{ Patterns = $foundPatterns; Strings = $foundStrings; Fullwidth = $finalFullwidth }
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

function Invoke-BypassScan([string]$FilePath) {
    $flags = [System.Collections.Generic.List[string]]::new()

    $mavenPrefixes = @("com_","org_","net_","io_","dev_","gs_","xyz_","app_","me_","tv_","uk_","be_","fr_","de_")

    function Test-SuspiciousJarName([string]$JarName) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d') { return $false }
        foreach ($pfx in $mavenPrefixes) { if ($base.ToLower().StartsWith($pfx)) { return $false } }
        if ($base.Length -gt 20) { return $false }
        return $true
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $nestedJars   = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })

        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) {
                $flags.Add("Suspicious nested JAR $([char]0x2014) no version, unknown dependency: $njBase")
            }
        }

        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell $([char]0x2014) only $($outerClasses.Count) own class(es), wraps: $njName")
        }

        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open(); $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch {}
        }

        $allEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }
        $innerZips  = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open(); $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close(); $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch {}
        }

        $runtimeExecFound = $false; $httpDownloadFound = $false; $httpExfilFound = $false
        $obfuscatedCount = 0; $numericClassCount = 0; $unicodeClassCount = 0; $totalClassCount = 0

        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            if ($name -match "\.class$") {
                $totalClassCount++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])
                if ($className -match "^\d+$") { $numericClassCount++ }
                if ($className -match "[^\x00-\x7F]") { $unicodeClassCount++ }

                $segs = ($name -replace "\.class$","") -split "/"
                $consecutive = 0; $maxConsec = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) { $consecutive++; if ($consecutive -gt $maxConsec) { $maxConsec = $consecutive } }
                    else { $consecutive = 0 }
                }
                if ($maxConsec -ge 3) { $obfuscatedCount++ }

                try {
                    $st = $entry.Open(); $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2); $st.Close()
                    $ct = [System.Text.Encoding]::ASCII.GetString($ms2.ToArray()); $ms2.Dispose()

                    if ($ct -match "java/lang/Runtime" -and $ct -match "getRuntime" -and $ct -match "exec") { $runtimeExecFound = $true }
                    if ($ct -match "openConnection" -and $ct -match "HttpURLConnection" -and $ct -match "FileOutputStream") { $httpDownloadFound = $true }
                    if ($ct -match "openConnection" -and $ct -match "setDoOutput" -and $ct -match "getOutputStream" -and $ct -match "getProperty") { $httpExfilFound = $true }
                } catch {}
            }
        }

        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch {} }
        $zip.Dispose()

        $obfPct = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount   / $totalClassCount) * 100) } else { 0 }
        $numPct = if ($totalClassCount -ge 5)  { [math]::Round(($numericClassCount / $totalClassCount) * 100) } else { 0 }
        $uniPct = if ($totalClassCount -ge 5)  { [math]::Round(($unicodeClassCount / $totalClassCount) * 100) } else { 0 }

        if ($runtimeExecFound -and $obfPct -ge 25) { $flags.Add("Runtime.exec() in obfuscated code $([char]0x2014) can run arbitrary OS commands") }
        if ($httpDownloadFound) { $flags.Add("HTTP file download $([char]0x2014) fetches and writes files from a remote server at runtime") }
        if ($httpExfilFound)    { $flags.Add("HTTP POST exfiltration $([char]0x2014) sends system data to an external server") }
        if ($totalClassCount -ge 10 -and $obfPct -ge 25) { $flags.Add("Heavy obfuscation $([char]0x2014) $obfPct% of classes use single-letter path segments (a/b/c style)") }
        if ($numPct -ge 20) { $flags.Add("Numeric class names $([char]0x2014) $numPct% of classes have numeric-only names (e.g. 1234.class)") }
        if ($uniPct -ge 10) { $flags.Add("Unicode class names $([char]0x2014) $uniPct% of classes use non-ASCII characters") }

        $knownLegitModIds = @("vmp-fabric","vmp","lithium","sodium","iris","fabric-api","modmenu",
            "ferrite-core","lazydfu","starlight","entityculling","memoryleakfix","krypton",
            "c2me-fabric","smoothboot-fabric","immediatelyfast","noisium","threadtweak")
        $dangerCount = ($flags | Where-Object { $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested JAR" }).Count
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("Fake mod identity $([char]0x2014) claims to be '$outerModId' but contains dangerous code")
        }
    } catch {}
    return $flags
}

function Run-JVMScan {
    $jvmFlags = [System.Collections.Generic.List[string]]::new()

    $javaProcs = Get-WmiObject Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue
    if (-not $javaProcs) { return $jvmFlags }

    foreach ($proc in $javaProcs) {
        $cmdLine = $proc.CommandLine

        $agentMatches = [regex]::Matches($cmdLine, '-javaagent:([^\s"]+)')
        foreach ($m in $agentMatches) {
            $agentPath = $m.Groups[1].Value.Trim('"').Trim("'")
            $agentName = [System.IO.Path]::GetFileName($agentPath)
            $legitAgents = @("jmxremote","yjp","jrebel","newrelic","jacoco","theseus")
            $isLegit = $false
            foreach ($la in $legitAgents) { if ($agentName -match $la) { $isLegit = $true; break } }
            if (-not $isLegit) { $jvmFlags.Add("JVM Agent $([char]0x2014) -javaagent:$agentName (path: $agentPath)") }
        }

        $suspJvmFlags = @(
            @{ Flag = "-Xbootclasspath/p:"; Desc = "prepends to bootstrap classpath, overrides core Java classes" },
            @{ Flag = "-Xbootclasspath/a:"; Desc = "appends to bootstrap classpath, injects below classloader" },
            @{ Flag = "-agentlib:jdwp";     Desc = "JDWP debug agent, remote debugging enabled" },
            @{ Flag = "-agentpath:";         Desc = "native agent loaded, bypasses Java sandbox" }
        )
        foreach ($sf in $suspJvmFlags) {
            if ($cmdLine -match [regex]::Escape($sf.Flag)) {
                $jvmFlags.Add("Suspicious JVM flag $([char]0x2014) $($sf.Flag) $([char]0x2014) $($sf.Desc)")
            }
        }

        try {
            $netConn = Get-NetTCPConnection -OwningProcess $proc.ProcessId -ErrorAction Stop |
                       Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.State -eq 'Listen' }
            if ($netConn) {
                $ports = $netConn.LocalPort -join ', '
                $jvmFlags.Add("Localhost listener $([char]0x2014) Java opened server socket(s) on port(s): $ports $([char]0x2014) vanilla Minecraft never opens listen sockets")
            }
        } catch {}

        try {
            $sig = @"
[DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr addr,byte[] buf,int sz,out int read);
[DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int acc,bool inh,int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr h,IntPtr addr,out MEMORY_BASIC_INFORMATION mbi,uint len);
[StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress,AllocationBase; public uint AllocationProtect,__alignment1,RegionSize,State,Protect,Type,__alignment2;
}
"@
            Add-Type -MemberDefinition $sig -Name MemAPI -Namespace Win32 -ErrorAction SilentlyContinue

            $handle = [Win32.MemAPI]::OpenProcess(0x10 -bor 0x400, $false, $proc.ProcessId)
            if ($handle -ne [IntPtr]::Zero) {
                $addr      = [IntPtr]::Zero
                $mbi       = New-Object Win32.MemAPI+MEMORY_BASIC_INFORMATION
                $mbiSize   = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
                $memTerms  = @(
                    "liquidbounce","meteorclient","wurst-client","killaura","silentaura",
                    "autocrystal","crystalaura","baritone","rise-client","vape-client",
                    "aimassist","triggerbot","scaffoldhack","bunnyhop","freecam",
                    "webhookstealer","tokengrabber","reverseShell","connectBack",
                    "WalksyOptimizer","dqrkis","LWFH Crystal","AutoCrystal","AutoAnchor"
                )
                $scanLimit = 0

                while ([Win32.MemAPI]::VirtualQueryEx($handle, $addr, [ref]$mbi, [uint32]$mbiSize) -and $scanLimit -lt 512) {
                    $scanLimit++
                    if ($mbi.State -eq 0x1000 -and ($mbi.Protect -band 0x04) -ne 0 -and $mbi.RegionSize -lt 10MB) {
                        $buf  = New-Object byte[] ([int][Math]::Min($mbi.RegionSize, 65536))
                        $read = 0
                        if ([Win32.MemAPI]::ReadProcessMemory($handle, $mbi.BaseAddress, $buf, $buf.Length, [ref]$read) -and $read -gt 0) {
                            $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
                            foreach ($term in $memTerms) {
                                if ($str.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                    $jvmFlags.Add("Memory signature $([char]0x2014) '$term' found live in JVM heap $([char]0x2014) cheat is currently loaded and running")
                                }
                            }
                        }
                    }
                    try { $addr = [IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize) } catch { break }
                }
                [Win32.MemAPI]::CloseHandle($handle) | Out-Null
            }
        } catch {}
    }

    return $jvmFlags
}

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

$ModPath = Ask-ModPath
$ModPath = $ModPath.Trim('"').Trim("'").Trim()

if (-not (Test-Path $ModPath -PathType Container)) {
    W "" White
    W "  $([char]0x2717) Invalid path $([char]0x2014) directory does not exist:" Red
    W "    $ModPath" DarkGray
    W "" White
    return
}

Write-Host ""
W "  Target : " DarkGray -NoNewline; W $ModPath White
Write-Host ""

$mcProcess = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $mcProcess) { $mcProcess = Get-Process java -ErrorAction SilentlyContinue }
if ($mcProcess) {
    try {
        $uptime = (Get-Date) - $mcProcess.StartTime
        W "  $([char]0x25CF) Minecraft running $([char]0x2014) PID $($mcProcess.Id)  uptime $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" DarkCyan
        Write-Host ""
    } catch {}
}

if ($null -eq $SkipSystemCheck)  { $SkipSystemCheck  = $false }
if ($null -eq $SkipServiceCheck) { $SkipServiceCheck = $false }
if ($null -eq $SkipModCheck)     { $SkipModCheck     = $false }

if (-not $SkipSystemCheck)  { Run-SystemChecks }
if (-not $SkipServiceCheck) { Run-ServiceCheck }

if (-not $SkipModCheck) {
    $jarFiles = Get-ChildItem -Path $ModPath -Filter "*.jar" -ErrorAction SilentlyContinue
    $script:TotalMods = @($jarFiles).Count

    if ($script:TotalMods -eq 0) {
        Write-Host ""
        W "  $([char]0x26A0)  No JAR files found in: $ModPath" Yellow
    } else {
        Write-Host ""
        W "  $([char]0x25CF) Found $($script:TotalMods) JAR file(s) to analyze" Cyan
        Write-Host ""

        $verifiedMods   = [System.Collections.Generic.List[object]]::new()
        $unknownMods    = [System.Collections.Generic.List[object]]::new()
        $suspiciousMods = [System.Collections.Generic.List[object]]::new()
        $bypassMods     = [System.Collections.Generic.List[object]]::new()
        $obfuscatedMods = [System.Collections.Generic.List[object]]::new()
        $filenameFlaggedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        W "  Checking filenames for cheat client patterns..." DarkGray
        foreach ($jar in $jarFiles) {
            $fnMatch = Get-FilenameSimilarityMatch $jar.Name
            if ($null -ne $fnMatch) {
                $hash = Get-FileSHA1 $jar.FullName
                $dl   = Get-DownloadSource $jar.FullName
                $fnStrings = [System.Collections.Generic.HashSet[string]]::new()
                [void]$fnStrings.Add("Filename resembles known cheat client: '$($fnMatch.Token)' ($($fnMatch.Score)% match)")
                [void]$suspiciousMods.Add([PSCustomObject]@{
                    FileName = $jar.Name; Hash = $hash; Verified = $false; VerifiedName = ""
                    DownloadSource = $dl
                    Patterns  = [System.Collections.Generic.HashSet[string]]::new()
                    Strings   = $fnStrings
                    Fullwidth = [System.Collections.Generic.HashSet[string]]::new()
                })
                [void]$filenameFlaggedSet.Add($jar.Name)
                [void]$script:FlaggedModsList.Add($jar.Name)
                $script:Flagged++
            }
        }
        SpinClear

        $idx = 0
        W "  Verifying hashes (Modrinth + CurseForge + Megabase)..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            $hash     = Get-FileSHA1 $jar.FullName
            $dlSource = Get-DownloadSource $jar.FullName
            $verified = $false; $verifiedName = ""

            if ($hash) {
                $mr = Get-ModrinthMeta $hash
                if ($mr.Slug) { $verified = $true; $verifiedName = $mr.Name }
                if (-not $verified) {
                    $fp = Get-FileMurmur2 $jar.FullName
                    if ($null -ne $fp) {
                        $cf = Get-CurseForgeMeta $fp
                        if ($cf.Slug) { $verified = $true; $verifiedName = $cf.Name }
                    }
                }
                if (-not $verified) {
                    $mb = Get-MegabaseMeta $hash
                    if ($mb -and $mb.name) { $verified = $true; $verifiedName = $mb.name }
                }
            }

            if ($verified) {
                [void]$verifiedMods.Add([PSCustomObject]@{ ModName = $verifiedName; FileName = $jar.Name; FilePath = $jar.FullName; Hash = $hash })
            } else {
                [void]$unknownMods.Add([PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName; Hash = $hash; DownloadSource = $dlSource })
            }
        }
        SpinClear

        $idx = 0
        W "  Deep-scanning cheat signatures..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            $result = Invoke-ModScan -FilePath $jar.FullName

            if ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0 -or $result.Fullwidth.Count -gt 0) {
                if ($filenameFlaggedSet.Contains($jar.Name)) {
                    $existing = $suspiciousMods | Where-Object { $_.FileName -eq $jar.Name } | Select-Object -First 1
                    if ($null -ne $existing) {
                        foreach ($p in $result.Patterns) { [void]$existing.Patterns.Add($p) }
                        foreach ($s in $result.Strings)  { [void]$existing.Strings.Add($s) }
                        foreach ($f in $result.Fullwidth) { [void]$existing.Fullwidth.Add($f) }
                    }
                } else {
                    $isVer = ($verifiedMods | Where-Object { $_.FileName -eq $jar.Name } | Measure-Object).Count -gt 0
                    $verName = ($verifiedMods | Where-Object { $_.FileName -eq $jar.Name } | Select-Object -First 1).ModName
                    $hash    = ($jarFiles | Where-Object { $_.Name -eq $jar.Name } | ForEach-Object { Get-FileSHA1 $_.FullName } | Select-Object -First 1)
                    $dl      = Get-DownloadSource $jar.FullName

                    [void]$suspiciousMods.Add([PSCustomObject]@{
                        FileName = $jar.Name; Hash = $hash; Verified = $isVer; VerifiedName = $verName
                        DownloadSource = $dl
                        Patterns = $result.Patterns; Strings = $result.Strings; Fullwidth = $result.Fullwidth
                    })
                    $verifiedMods = [System.Collections.Generic.List[object]]($verifiedMods | Where-Object { $_.FileName -ne $jar.Name })
                    [void]$script:FlaggedModsList.Add($jar.Name)
                    $script:Flagged++
                }
            }
        }
        SpinClear

        $idx = 0
        W "  Running bypass / injection scan..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            $bFlags = Invoke-BypassScan -FilePath $jar.FullName

            if ($bFlags.Count -gt 0) {
                $alreadySusp = ($suspiciousMods | Where-Object { $_.FileName -eq $jar.Name } | Measure-Object).Count -gt 0
                if (-not $alreadySusp) {
                    [void]$bypassMods.Add([PSCustomObject]@{ FileName = $jar.Name; Flags = $bFlags })
                    $verifiedMods = [System.Collections.Generic.List[object]]($verifiedMods | Where-Object { $_.FileName -ne $jar.Name })
                    $unknownMods  = [System.Collections.Generic.List[object]]($unknownMods  | Where-Object { $_.FileName -ne $jar.Name })
                    if (-not $filenameFlaggedSet.Contains($jar.Name)) {
                        [void]$script:FlaggedModsList.Add($jar.Name)
                        $script:Flagged++
                    }
                }
            }
        }
        SpinClear

        $idx = 0
        W "  Running obfuscation analysis..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            $oFlags = Invoke-ObfuscationScan -FilePath $jar.FullName

            if ($oFlags.Count -gt 0) {
                $alreadyFlagged = (($suspiciousMods + $bypassMods) | Where-Object { $_.FileName -eq $jar.Name } | Measure-Object).Count -gt 0
                if (-not $alreadyFlagged) {
                    [void]$obfuscatedMods.Add([PSCustomObject]@{ FileName = $jar.Name; Flags = $oFlags })
                    $verifiedMods = [System.Collections.Generic.List[object]]($verifiedMods | Where-Object { $_.FileName -ne $jar.Name })
                    if (-not $filenameFlaggedSet.Contains($jar.Name)) {
                        [void]$script:FlaggedModsList.Add($jar.Name)
                        $script:Flagged++
                    }
                }
            }
        }
        SpinClear

        $script:Verified = $verifiedMods.Count
        $script:Unknown  = $unknownMods.Count

        if ($verifiedMods.Count -gt 0) {
            Write-SectionHeader "VERIFIED MODS" $verifiedMods.Count Green Green
            Write-Rule "$([char]0x2500)" 76 DarkGray
            foreach ($mod in $verifiedMods) {
                W "  $([char]0x2713) " Green -NoNewline
                W $mod.ModName White -NoNewline
                W " $([char]0x2192) " DarkGray -NoNewline
                W $mod.FileName DarkGray
            }
            Write-Host ""
        }

        if ($unknownMods.Count -gt 0) {
            Write-SectionHeader "UNKNOWN MODS" $unknownMods.Count Yellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $unknownMods) {
                $fname = if ($mod.FileName.Length -gt 50) { $mod.FileName.Substring(0,47) + "..." } else { $mod.FileName }
                $src = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: unknown" }
                $padT = "$([char]0x2500)" * [Math]::Max(0, 65 - $fname.Length)
                $padB = "$([char]0x2500)" * [Math]::Max(0, 67 - $src.Length)
                W ("  $([char]0x2554)$([char]0x2550) ? " + $fname + " " + $padT + "$([char]0x2557)") Yellow
                W ("  $([char]0x255A)$([char]0x2550) " + $src + " " + $padB + "$([char]0x255D)") Yellow
                Write-Host ""
            }
        }

        if ($suspiciousMods.Count -gt 0) {
            Write-SectionHeader "SUSPICIOUS MODS" $suspiciousMods.Count Red Red
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $suspiciousMods) {
                Write-FlaggedCard $mod.FileName $mod.Hash $mod.Verified $mod.VerifiedName $mod.DownloadSource $mod.Patterns $mod.Strings $mod.Fullwidth
            }
        }

        if ($bypassMods.Count -gt 0) {
            Write-SectionHeader "BYPASS / INJECTION DETECTED" $bypassMods.Count Magenta Magenta
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $bypassMods) { Write-InjectionCard $mod.FileName $mod.Flags }
        }

        if ($obfuscatedMods.Count -gt 0) {
            Write-SectionHeader "OBFUSCATED MODS" $obfuscatedMods.Count DarkYellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $obfuscatedMods) { Write-ObfuscationCard $mod.FileName $mod.Flags }
        }
    }
}

$script:processWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "System","Idle","smss","csrss","wininit","winlogon","services","lsass","svchost","dwm",
    "explorer","taskmgr","taskhostw","sihost","ctfmon","RuntimeBroker","ShellExperienceHost",
    "StartMenuExperienceHost","SearchApp","SearchIndexer","SearchHost","SearchUI",
    "ApplicationFrameHost","SystemSettingsBroker","SettingsSyncHost","WmiPrvSE","WmiApSrv",
    "spoolsv","msdtc","TrustedInstaller","TiWorker","wuauclt","wuaueng","MpCmdRun",
    "MsMpEng","NisSrv","SecurityHealthService","SecurityHealthHost","SecurityHealthSystray",
    "smartscreen","msmpeng","msseces",
    "fontdrvhost","conhost","conhostv2","dllhost","rundll32","regsvr32","msiexec",
    "userinit","LogonUI","consent","credentialuibroker","backgroundTaskHost",
    "audiodg","WUDFHost","WUDFRd","ibmpmsvc","InputPersonalization","TextInputHost",
    "LockApp","PeopleExperienceHost","YourPhone","YourPhoneServer",
    "MicrosoftEdge","msedge","MicrosoftEdgeUpdate","MicrosoftEdgeSH",
    "chrome","firefox","opera","opera_gx","brave","vivaldi","iexplore","iexplorer",
    "Discord","DiscordPTB","DiscordCanary","Update",
    "Spotify","spotify_helper","EpicGamesLauncher","EpicWebHelper","EpicOnlineServices",
    "Steam","steamwebhelper","steamservice","GameOverlayUI","steam_osx","GameBar","GameBarFTServer",
    "Origin","OriginWebHelperService","EADesktop","EABackgroundService","EALauncher",
    "Minecraft","javaw","java","MinecraftLauncher","LauncherPatcher","MultiMCLauncher",
    "prismlauncher","polymc","atlauncher","ftblauncher","technicplatform","curseforge",
    "CurseForge","overwolf","OverwolfBrowser","OverwolfHelper",
    "code","Code","vscodium","idea64","idea","eclipse","netbeans","rider","rider64",
    "devenv","msbuild","dotnet","node","npm","git","git-cmd","git-bash","bash","sh",
    "powershell","pwsh","cmd","WindowsTerminal","wt","ssh","sshd","sftp-server",
    "python","python3","pythonw","pip",
    "OneDrive","OneDriveSetup","FileCoAuth","FileSyncHelper",
    "Teams","ms-teams","Update","Squirrel",
    "Slack","slack",
    "zoom","Zoom","zoomshare",
    "obs64","obs32","obs","OBSVirtualCam","CrashpadHandler",
    "7zFM","7zG","7z","WinRAR","winrar","peazip",
    "notepad","notepad++","notepad3",
    "mspaint","SnippingTool","ScreenSketch",
    "VirtualBox","VBoxSVC","VBoxHeadless","vmware","vmplayer","vmnat","vmnetdhcp",
    "virtualboxvm","VBoxNetAdp",
    "Razer","RazerCentralService","RazerIngameEngine","rzsd","RzDeviceQuery",
    "SteelSeriesEngine","SteelSeriesGG","LGHub","lghub","CORSAIR","CorsairService",
    "iCUE","iCUEUpdate","Logitech","logitechg_discord","LGHUB","LCore",
    "NVDisplay.Container","nvcontainer","nvtelemetry","nvvsvc","nvxdsync","NvStreamNetworkService",
    "NvStreamUserAgent","NvStreamingService","NvidiaShareHelper","NVSMI","NvBackend",
    "AMDRSServ","RadeonSoftware","CNext","cnext","RtkUWP","RtkNGUI64","RtkAudioService64",
    "igfxEM","igfxHK","igfxTray",
    "MSIAfterburner","RTSS","RTSSHooksLoader64","EncoderServer64",
    "Malwarebytes","mbam","mbamservice","mbamtray","HitmanPro","HitmanPro.Alert",
    "avast","AvastUI","AvastSvc","avg","avgui","avgsvc","avguix",
    "bdredline","bdagent","bdwtxag","vsserv","wsctrl",
    "mcshield","mcsplashtool","mcuicnt","McAfee",
    "eset","ekrn","egui","nod32kui",
    "mbae64","farflt","nldrv","wdswfsafe",
    "DropboxUpdate","Dropbox","dbxsvc",
    "GoogleUpdate","GoogleCrashHandler","GoogleDriveFS","googledrivesync",
    "skype","Skype","SkypeApp","SkypeBackgroundHost",
    "iTunes","AppleMobileDeviceService","bonjour","mDNSResponder","iTunesHelper",
    "AdobeUpdateService","AdobeARMservice","AdobeCollabSync","acrotray","AcroRd32",
    "Acrobat","acrobat",
    "winword","excel","powerpnt","onenote","outlook","msaccess","mspub","visio","winproj",
    "OfficeClickToRun","OfficeC2RClient",
    "SystemExplorer","ProcessHacker","procexp","procexp64","procmon","procmon64",
    "autoruns","autorunsc","Wireshark","dumpcap","rawshark",
    "EasyAntiCheat","EasyAntiCheat_EOS","EACLauncher","BEService","BattlEye",
    "FaceIT","faceit","vgc","vgtray","VALORANT","VALORANT-Win64-Shipping","RiotClientServices",
    "FortniteLauncher","FortniteClient-Win64-Shipping","EpicGamesLauncher",
    "MonsterHunterWorld","RDR2","GTA5","GTAV","Cyberpunk2077","witcher3",
    "LeagueClient","LeagueClientUx","LeagueClientUxRender","LeagueofLegends",
    "dota2","csgo","cs2","hl2","tf_win64","RocketLeague",
    "Minecraft","PrismLauncher",
    "svchost","NVDisplay","nvcontainer","WinStore.App","WinStoreUI",
    "PhoneExperienceHost","UserOOBEBroker","GameInputSvc","GameInput",
    "sppsvc","SgrmBroker","SgrmHost","lsm","ntoskrnl","System Interrupts",
    "MoUsoCoreWorker","UsoClient","usocoreworker",
    "Taskmgr","CompatTelRunner","SRUDB","DiagsCaptureService","DiagnosticsHub",
    "MusNotificationUx","MusNotification","AggregatorHost",
    "WerFaultSecure","WerFault","wermgr","ReportingServicesService",
    "ehRecvr","ehSched","ehtray","WMPNetworkSvc",
    "CCleanerBrowser","CCleaner","CCleanerUpdate","CCleanerHealth",
    "Nahimic","NahimicSvc","NahimicSvc32","NahimicSvc64","AudioWizard",
    "MSASCuiL","MSASCui","MpDlpService","mpssvc",
    "TabTip","TabTip32","wisptis","InputHost",
    "vmcompute","vmwp","vmsp","vmms",
    "docker","dockerd","Docker Desktop","com.docker.backend","com.docker.proxy",
    "wslhost","wsl","wslg","wslservice",
    "jhi_service","LMS","DAProxy","IntelMeFWService",
    "igfxCUIService","igfxCUIServiceN","HDDScan","CrystalDiskInfo",
    "Greenshot","ShareX","ShareXUpdater","gyroflow_toolbox",
    "lively","rainmeter","Rainmeter",
    "NZXT CAM","NZXTCamService","SignalRgb","OpenRGB","openrgb",
    "parsec","parsecd","Parsec",
    "AnyDesk","anydesk","TeamViewer","TeamViewer_Service","tv_w32","tv_x64",
    "Hamachi","hamachi","LogMeIn Hamachi","hamachi-2","hamachi-2-ui",
    "nvsphelper64","NvProfileUpdater64","NvTelemetryContainer",
    "SystemInformer","SystemInformer64","Sysinternals",
    "DbxSvc","DropboxUpdate",
    "explorer","iexplore","mobsync","msiexec",
    "WlanSvc","WwanSvc","p2pimsvc","iphlpsvc",
    "claude","CortexLauncherService","CrossDeviceResume","CrossDeviceService",
    "DataExchangeHost","DiscordSystemHelper","endpointprotection","GameBarPresenceWriter",
    "GameInputRedistService","GameManagerService3","gamingservicesnet","RtkAudUService64",
    "SearchFilterHost","SearchProtocolHost","SystemSettings","WifiAutoInstallSrv",
    "XboxGameBarSpotify",
    "Avira.OptimizerHost","Avira.VpnService","Avira.ServiceHost","Avira.Spotlight","AviraOptimizerHost","AviraVpnService",
    "CefSharp.BrowserSubprocess","CefSharp","cef","cefsharp",
    "chrome-native-host","ChromeNativeHost",
    "cowork-svc","cowork",
    "crashpad_handler","CrashpadHandler","crashpad",
    "dasHost","DeviceAssociationService",
    "DCIService",
    "EdgeGameAssist","MicrosoftEdgeGameAssist",
    "FvContainer","FvContainer.System","FrameViewSDK",
    "FortniteLauncher","EpicGamesLauncher","EpicWebHelper",
    "gamingservices","gamingservicesnet","GamingServices",
    "LsaIso",
    "Memory Compression","MemoryCompression",
    "MoUsoCoreWorker","musNotification","MusNotification","MusNotificationUx",
    "NVDisplay.Container.exe","nvcontainer",
    "PhoneExperienceHost","YourPhone","YourPhoneServer",
    "RtkAudUService64","RtkAudioService64","RtkNGUI64","RtkUWP",
    "SearchFilterHost","SearchProtocolHost",
    "SgrmBroker","SgrmHost",
    "sppsvc","SppExtComObj",
    "TiWorker","TrustedInstaller",
    "UserOOBEBroker",
    "WifiAutoInstallSrv",
    "WerFault","WerFaultSecure","wermgr",
    "ClaudeDesktop","claude-desktop","Claude",
    "nvfvsdksvc_x64","nvfvsdksvc","NvFVSDKSvc","FrameViewSDK","FvContainer","FvContainer.System","PresentMon_x64","PresentMon",
    "razer_elevation_service","RazerElevationService","RazerCentralService","RazerIngameEngine","rzsd","RzDeviceQuery","Razer",
    "Registry","Secure System","SecureSystem",
    "SentryEye","sentryeye",
    "servicehost","ServiceHost",
    "VSSrv","VSS","vssvc","vss"
) | ForEach-Object { [void]$script:processWhitelist.Add($_) }

$script:cheatProcessNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "liquidbounce","meteor-client","meteorplus","wurst","vape","vapelite","vapenp",
    "sigmaclient","sigma","riseplus","rise","baritone","aristois","huzuni",
    "inertia","impact","salhack","killaura","aimbot","xray","freecam",
    "ghostclient","ghost","nofall","nofalldmg","antibot","killaura",
    "autoclicker","jitterclick","butterfly","triggerbot","scaffold",
    "cheatclient","hackmod","hackmodmenu","blamedmod","skidmod",
    "cheat-engine","cheatengine","ce","x64dbg","x32dbg","ollydbg","idaq","idaq64",
    "dnspy","ilspy","dotpeek","jadx","cfr","procyon",
    "injector","dllinjector","dllinjectorapp","extreme-injector","processhollowing",
    "winservicehost","svchost32","svchost64","spoolsv32",
    "javaupdater","javainstaller","javalauncher",
    "msupdater","windowsupdater","windowsupdate32","wuupdate",
    "discord-stealer","tokenstealer","grabber","cookiegrabber","passwordgrabber",
    "rat","asyncrat","quasarrat","dcrat","nanocore","njrat","remcos","xworm",
    "cryptominer","miner","xmrig","xmrigdaemon","xmrig-cpu","nbminer","phoenixminer",
    "bypass","antianticheat","anticheats","eacbypass","bebypass","vacebypass",
    "prestige","prestigeclient","prestige-client","prestige_client",
    "flux","fluxclient","remix","pandora","hypnotic","reflex","phantom",
    "ares","atomclient","zephyr","xeclient","vertex","velocityclient",
    "rusher","rusherhack","novoline","azuraclient","fdp","fdpclient",
    "pyroclient","drip","drippy","entropy","nightx","blaze","blazemod"
) | ForEach-Object { [void]$script:cheatProcessNames.Add($_) }

$script:suspiciousProcessPatterns = @(
    '^[a-z]{1,4}\d{3,}$',
    '^[a-zA-Z0-9]{32}$',
    '^[a-zA-Z0-9]{16,}$',
    '^tmp[a-zA-Z0-9]+$',
    '^svc[a-zA-Z0-9]{4,}$',
    '^win[a-zA-Z0-9]{5,}$',
    '^sys[a-zA-Z0-9]{5,}$',
    '^upd[a-zA-Z0-9]{4,}$',
    '^[a-z]{2}\d{4,}$'
)

$script:suspiciousStartupPatterns = @(
    'AppData\\Roaming\\[^\\]+\.exe',
    'AppData\\Local\\Temp\\',
    'AppData\\Local\\(?!Discord|DiscordPTB|DiscordCanary|Spotify|Medal|Programs|Microsoft|Packages|GitHubDesktop|Slack|Notion|Figma|Logi|Steam|EpicGamesLauncher|cursor|Claude)[^\\]+\\[^\\]+\.exe',
    'Users\\[^\\]+\\AppData\\Local\\[^\\]+\.jar',
    '\\Temp\\.*\.exe',
    '\\Temp\\.*\.bat',
    '\\Temp\\.*\.ps1',
    'powershell.*-enc',
    'powershell.*hidden',
    'cmd.*\/c.*start',
    'wscript.*\.vbs',
    'mshta.*\.hta',
    'regsvr32.*/s.*/u',
    'rundll32.*javascript'
)

$script:knownCheatFolders = @(
    "$env:APPDATA\LiquidBounce",
    "$env:APPDATA\Meteor Client",
    "$env:APPDATA\Wurst",
    "$env:APPDATA\Vape",
    "$env:APPDATA\.vape",
    "$env:APPDATA\Sigma",
    "$env:APPDATA\Rise",
    "$env:APPDATA\Aristois",
    "$env:APPDATA\Huzuni",
    "$env:APPDATA\Inertia",
    "$env:APPDATA\Impact",
    "$env:APPDATA\SalHack",
    "$env:APPDATA\Baritone",
    "$env:APPDATA\GhostClient",
    "$env:APPDATA\AsyncRAT",
    "$env:APPDATA\QuasarRAT",
    "$env:APPDATA\DCRat",
    "$env:APPDATA\xmrig",
    "$env:LOCALAPPDATA\LiquidBounce",
    "$env:LOCALAPPDATA\Meteor",
    "$env:LOCALAPPDATA\Wurst",
    "$env:LOCALAPPDATA\Vape",
    "$env:TEMP\liquidbounce",
    "$env:TEMP\meteor",
    "$env:TEMP\vape",
    "$env:APPDATA\PrestigeClient",
    "$env:APPDATA\Prestige",
    "$env:APPDATA\ArgonClient",
    "$env:APPDATA\Argon",
    "$env:APPDATA\NightX",
    "$env:APPDATA\BlazeMod",
    "$env:APPDATA\RusherHack",
    "$env:APPDATA\rusherhack",
    "$env:APPDATA\Novoline",
    "$env:APPDATA\Azura",
    "$env:APPDATA\FDPClient",
    "$env:APPDATA\fdpclient",
    "$env:APPDATA\EzCheat",
    "$env:APPDATA\Future",
    "$env:APPDATA\.future",
    "$env:APPDATA\Raven",
    "$env:APPDATA\Drip",
    "$env:APPDATA\Pyro",
    "$env:APPDATA\Pyro Client",
    "$env:APPDATA\Entropy",
    "$env:LOCALAPPDATA\PrestigeClient",
    "$env:LOCALAPPDATA\Prestige",
    "$env:LOCALAPPDATA\ArgonClient",
    "$env:LOCALAPPDATA\Argon",
    "$env:LOCALAPPDATA\NightX",
    "$env:LOCALAPPDATA\RusherHack",
    "$env:LOCALAPPDATA\Future",
    "$env:APPDATA\.prestigeclient",
    "$env:APPDATA\prestige-client",
    "$env:APPDATA\Killaura",
    "$env:APPDATA\Aimbot",
    "$env:APPDATA\Flux",
    "$env:APPDATA\Remix",
    "$env:APPDATA\Pandora",
    "$env:APPDATA\Hypnotic",
    "$env:APPDATA\Velocity",
    "$env:APPDATA\Reflex",
    "$env:APPDATA\Azura",
    "$env:APPDATA\Phantom",
    "$env:APPDATA\Ares",
    "$env:APPDATA\AtomClient",
    "$env:APPDATA\Zephyr",
    "$env:APPDATA\XeClient",
    "$env:APPDATA\Vertex",
    "$env:LOCALAPPDATA\PrestigeClient\app-data",
    "$env:TEMP\prestige",
    "$env:TEMP\prestigeclient"
)

function Run-PCscan {
    Write-Host ""
    W ("$([char]0x2501)" * 76) Blue
    Write-Host ""
    W "  FULL PC SCAN" Cyan
    Write-Host ""
    W ("$([char]0x2501)" * 76) Blue
    Write-Host ""

    $pcIssues = 0

    Write-Host ""
    W "  Scanning running processes..." DarkGray
    Write-Host ""

    $allProcs = Get-Process -ErrorAction SilentlyContinue
    $flaggedProcs  = [System.Collections.Generic.List[object]]::new()
    $unknownProcs  = [System.Collections.Generic.List[object]]::new()

    foreach ($proc in $allProcs) {
        $name = $proc.Name
        if ($script:processWhitelist.Contains($name)) { continue }

        $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($name)
        $path = ""
        try { $path = $proc.MainModule.FileName } catch {}

        if ($script:cheatProcessNames.Contains($nameNoExt) -or $script:cheatProcessNames.Contains($name)) {
            $flaggedProcs.Add([PSCustomObject]@{ Name = $name; PID = $proc.Id; Path = $path; Reason = "Known cheat / malware process name" })
            continue
        }

        $isSuspiciousName = $false
        foreach ($pat in $script:suspiciousProcessPatterns) {
            if ($nameNoExt -match $pat) { $isSuspiciousName = $true; break }
        }

        $isSuspiciousPath = $false
        $pathReason = ""
        if ($path) {
            if ($path -match '\\Temp\\') {
                $isInstaller = $path -match '(?i)(CodeSetup|WindowsInstaller|is-[A-Z0-9]{5}\.tmp|Squirrel|SquirrelSetup|nsis|setup\.exe|installer\.exe|unins\d+|Update\.exe|bootstrapper|vcredist|dotnet|ndp|wix)'
                if (-not $isInstaller) { $isSuspiciousPath = $true; $pathReason = "Running from Temp folder" }
            }
            elseif ($path -match 'AppData\\Roaming\\(?!\.minecraft|Minecraft|Discord|Spotify|Code|cursor|npm|JetBrains)') {
                $isSuspiciousPath = $true; $pathReason = "Running from AppData\Roaming"
            }
        }

        if ($isSuspiciousName -and $isSuspiciousPath) {
            $flaggedProcs.Add([PSCustomObject]@{ Name = $name; PID = $proc.Id; Path = $path; Reason = "Suspicious name + suspicious path ($pathReason)" })
        } elseif ($isSuspiciousName) {
            $unknownProcs.Add([PSCustomObject]@{ Name = $name; PID = $proc.Id; Path = $path; Reason = "Unrecognized process name pattern" })
        } elseif ($isSuspiciousPath) {
            $flaggedProcs.Add([PSCustomObject]@{ Name = $name; PID = $proc.Id; Path = $path; Reason = $pathReason })
        }
    }

    $colP = 28; $colI = 7; $colR = 34
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) PROCESS SCAN " + "$([char]0x2500)" * 57 + "$([char]0x2510)") DarkCyan
    W ("  $([char]0x2502)  $([char]0x250C)$([char]0x2500)" + ("$([char]0x2500)" * $colP) + "$([char]0x2500)$([char]0x252C)$([char]0x2500)" + ("$([char]0x2500)" * $colI) + "$([char]0x2500)$([char]0x252C)$([char]0x2500)" + ("$([char]0x2500)" * $colR) + "$([char]0x2500)$([char]0x2510)") DarkCyan
    W ("  $([char]0x2502)  $([char]0x2502) " + "Process".PadRight($colP) + " $([char]0x2502) " + "PID".PadRight($colI) + " $([char]0x2502) " + "Status".PadRight($colR) + " $([char]0x2502)") DarkCyan
    W ("  $([char]0x2502)  $([char]0x251C)$([char]0x2500)" + ("$([char]0x2500)" * $colP) + "$([char]0x2500)$([char]0x253C)$([char]0x2500)" + ("$([char]0x2500)" * $colI) + "$([char]0x2500)$([char]0x253C)$([char]0x2500)" + ("$([char]0x2500)" * $colR) + "$([char]0x2500)$([char]0x2524)") DarkCyan

    if ($flaggedProcs.Count -eq 0 -and $unknownProcs.Count -eq 0) {
        W ("  $([char]0x2502)  $([char]0x2502) " + "All processes recognized".PadRight($colP) + " $([char]0x2502) " + "".PadRight($colI) + " $([char]0x2502) " + "OK".PadRight($colR) + " $([char]0x2502)") Green
    }
    foreach ($p in $flaggedProcs) {
        $pn = $p.Name.PadRight($colP); $pi = "$($p.PID)".PadRight($colI); $pr = "FLAGGED".PadRight($colR)
        W "  $([char]0x2502)  $([char]0x2502) " DarkCyan -NoNewline; W $pn Red -NoNewline; W " $([char]0x2502) " DarkCyan -NoNewline
        W $pi DarkGray -NoNewline; W " $([char]0x2502) " DarkCyan -NoNewline; W $pr Red -NoNewline; W " $([char]0x2502)" DarkCyan
    }
    foreach ($p in $unknownProcs) {
        $pn = $p.Name.PadRight($colP); $pi = "$($p.PID)".PadRight($colI); $pr = "UNKNOWN".PadRight($colR)
        W "  $([char]0x2502)  $([char]0x2502) " DarkCyan -NoNewline; W $pn Yellow -NoNewline; W " $([char]0x2502) " DarkCyan -NoNewline
        W $pi DarkGray -NoNewline; W " $([char]0x2502) " DarkCyan -NoNewline; W $pr Yellow -NoNewline; W " $([char]0x2502)" DarkCyan
    }

    W ("  $([char]0x2502)  $([char]0x2514)$([char]0x2500)" + ("$([char]0x2500)" * $colP) + "$([char]0x2500)$([char]0x2534)$([char]0x2500)" + ("$([char]0x2500)" * $colI) + "$([char]0x2500)$([char]0x2534)$([char]0x2500)" + ("$([char]0x2500)" * $colR) + "$([char]0x2500)$([char]0x2518)") DarkCyan

    if ($flaggedProcs.Count -gt 0) {
        Write-Host ""
        W "  Flagged Process Details:" Red
        foreach ($p in $flaggedProcs) {
            Write-Host ""
            W "  $([char]0x25C9) $($p.Name)  [PID $($p.PID)]" Red
            W "    REASON : $($p.Reason)" DarkGray
            if ($p.Path) { W "    PATH   : $($p.Path)" DarkGray }
        }
        $pcIssues += $flaggedProcs.Count
    }
    if ($unknownProcs.Count -gt 0) {
        Write-Host ""
        W "  Unknown Processes (not in whitelist, no suspicious pattern match):" Yellow
        foreach ($p in $unknownProcs) {
            W "    ? $($p.Name)  [PID $($p.PID)]$(if($p.Path){ '  $([char]0x2014)  ' + $p.Path })" DarkGray
        }
    }

    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W "  Scanning startup entries..." DarkGray

    $startupFlags = [System.Collections.Generic.List[object]]::new()
    $runKeys = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk)) { continue }
        $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $val = $_.Value.ToString()
            foreach ($pat in $script:suspiciousStartupPatterns) {
                if ($val -match $pat) {
                    $startupFlags.Add([PSCustomObject]@{ Key = $rk; Name = $_.Name; Value = $val; Pattern = $pat })
                    break
                }
            }
        }
    }

    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupFolder) {
        Get-ChildItem $startupFolder -ErrorAction SilentlyContinue | ForEach-Object {
            $ext = $_.Extension.ToLower()
            if ($ext -in @(".exe",".bat",".ps1",".vbs",".js",".jar",".hta")) {
                $startupFlags.Add([PSCustomObject]@{ Key = "Startup Folder"; Name = $_.Name; Value = $_.FullName; Pattern = "Executable in startup folder" })
            }
        }
    }

    Write-Host ""
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) STARTUP ENTRIES " + "$([char]0x2500)" * 54 + "$([char]0x2510)") DarkCyan
    if ($startupFlags.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) no suspicious startup entries found" + (" " * 28) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($f in $startupFlags) {
            W "  $([char]0x2502)  FLAGGED  $($f.Name)" Red
            W "  $([char]0x2502)    Key   : $($f.Key)" DarkGray
            W "  $([char]0x2502)    Value : $($f.Value)" DarkGray
            W "  $([char]0x2502)    Match : $($f.Pattern)" DarkGray
        }
        $pcIssues += $startupFlags.Count
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W "  Scanning for known cheat/malware folders..." DarkGray
    Write-Host ""

    $foundFolders = [System.Collections.Generic.List[string]]::new()
    $cheatFolderIdx = 0
    foreach ($folder in $script:knownCheatFolders) {
        $cheatFolderIdx++
        $folderShort = [System.IO.Path]::GetFileName($folder)
        Write-Host "`r  Checking folders: $($folderShort.PadRight(38))  $cheatFolderIdx/$($script:knownCheatFolders.Count)  found: $($foundFolders.Count)" -NoNewline -ForegroundColor DarkGray
        if (Test-Path $folder) { $foundFolders.Add($folder) }
    }
    Write-Host "`r$(' ' * 80)`r" -NoNewline

    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) CHEAT FOLDER SCAN " + "$([char]0x2500)" * 52 + "$([char]0x2510)") DarkCyan
    if ($foundFolders.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no known cheat or malware folders found                      $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $foundFolders) {
            $line = "  $([char]0x2502)  FOUND   $f"
            W ($line.PadRight(74) + "$([char]0x2502)") Red
        }
        $pcIssues += $foundFolders.Count
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W "  Scanning filesystem for cheat JARs..." DarkGray
    Write-Host ""

    $scanRoots = [System.Collections.Generic.List[string]]::new()
    $mcRoots = @(
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
        "$env:USERPROFILE\Documents\curseforge\minecraft\Instances"
    )
    foreach ($r in $mcRoots) { if ([System.IO.Directory]::Exists($r)) { [void]$scanRoots.Add($r) } }
    foreach ($r in @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
        $env:TEMP
    )) { if ($r -and [System.IO.Directory]::Exists($r)) { [void]$scanRoots.Add($r) } }
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        if ($drive.DriveType -in @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable) -and $drive.IsReady) {
            $dr = $drive.RootDirectory.FullName
            if (-not ($scanRoots | Where-Object { $_.StartsWith($dr, [System.StringComparison]::OrdinalIgnoreCase) })) {
                [void]$scanRoots.Add($dr)
            }
        }
    }

    $skipDirsList = @(
        "C:\Windows","C:\Program Files","C:\Program Files (x86)",
        [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft"),
        [System.IO.Path]::Combine($env:APPDATA, "Microsoft"),
        [System.IO.Path]::Combine($env:LOCALAPPDATA, "Google"),
        [System.IO.Path]::Combine($env:APPDATA, "discord"),
        [System.IO.Path]::Combine($env:APPDATA, "Spotify"),
        [System.IO.Path]::Combine($env:LOCALAPPDATA, "Programs"),
        [System.IO.Path]::Combine($env:USERPROFILE, ".gradle"),
        [System.IO.Path]::Combine($env:USERPROFILE, ".m2"),
        [System.IO.Path]::Combine($env:USERPROFILE, ".vscode"),
        [System.IO.Path]::Combine($env:LOCALAPPDATA, ".gradle"),
        [System.IO.Path]::Combine($env:LOCALAPPDATA, ".m2"),
        [System.IO.Path]::Combine($env:APPDATA, ".gradle"),
        [System.IO.Path]::Combine($env:LOCALAPPDATA, "lunarclient"),
        [System.IO.Path]::Combine($env:APPDATA, "lunarclient")
    )
    $skipSegments = @(".paper-remapped", "unknown-origin", "\cache\patches\", "\libraries\net\minecraft",
        "\.gradle\", "\.m2\repository\", "\.vscode\extensions\", "\.lunarclient\offline\",
        "\.lunarclient\launcher\", "\lunarclient\offline\", "\lunarclient\launcher\")

    $allJars  = [System.Collections.Generic.List[string]]::new()
    $seenJars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $jarCollectCount = 0
    foreach ($root in $scanRoots) {
        if (-not [System.IO.Directory]::Exists($root)) { continue }
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($root)
        while ($queue.Count -gt 0) {
            $dir = $queue.Dequeue()
            $dirShort = if ($dir.Length -gt 60) { "..." + $dir.Substring($dir.Length - 57) } else { $dir }
            Write-Host "`r  Indexing: $($dirShort.PadRight(62))  JARs: $jarCollectCount  " -NoNewline
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, '*.jar')) {
                    $skip = $false
                    foreach ($sd in $skipDirsList) { if ($f.StartsWith($sd, [System.StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break } }
                    if (-not $skip) { foreach ($seg in $skipSegments) { if ($f.IndexOf($seg, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break } } }
                    if (-not $skip -and $seenJars.Add($f)) { $allJars.Add($f); $jarCollectCount++ }
                }
            } catch {}
            try {
                foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    $isJunction = ([System.IO.File]::GetAttributes($sub) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                    if (-not $isJunction) { $queue.Enqueue($sub) }
                }
            } catch {}
        }
    }
    Write-Host "`r  Index complete $([char]0x2014) $($allJars.Count) JAR files found.                                                    "

    $fsFlags        = [System.Collections.Generic.List[object]]::new()
    $fsScanned      = 0
    $threadCount    = [Math]::Min([System.Environment]::ProcessorCount, 8)
    $pool           = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threadCount)
    $pool.Open()

    $safeJarPrefixes = @(
        "EssentialsX","Geyser","Floodgate","ViaVersion","ViaBackwards","ViaRewind",
        "ProtocolLib","PlaceholderAPI","Vault","LuckPerms","DiscordSRV","Citizens",
        "WorldGuard","WorldEdit","FastAsyncWorldEdit","CoreProtect","AntiCheatReloaded",
        "Vulcan","TAB","CMI","MythicMobs","ModelEngine","HolographicDisplays","DecentHolograms",
        "SkinsRestorer","AuthMe","LibsDisguises","ProtocolSupport","PacketEvents",
        "spark","BlueMap","Dynmap","Chunky","ChunkMaster","LightCleaner",
        "TotemGuard","Matrix","NoCheatPlus","GrimAC","Themis","Intave",
        "BungeeCoord","Waterfall","Velocity","VelocityPowered",
        "Multiverse","AdvancedPortals","Shopkeepers","AuctionHouse","CMILib",
        "InteractionVisualizer","SlimefunAddon","Slimefun","ItemsAdder","Oraxen",
        "SkQuery","skript","Skript","SkriptBee","MundoSK","Skellett",
        "SuperiorSkyblock","IridiumSkyblock","AscendancySkyblock",
        "EcoEnchants","ExcellentEnchants","AdvancedEnchantments",
        "MobArena","BattleArena","Minigames","SkyWars","BedWars",
        "NamelessPlugin","GalaxyCore","PowerRanks","GroupManager",
        "HikariCP","log4j","slf4j","kotlin-stdlib","kotlin-reflect",
        "adventure-api","adventure-platform","net.kyori","bytebuddy","asm-",
        "skidfuscator-runtime","minecraft_server","paper","purpur","spigot","craftbukkit",
        "patched.","libraries-loader","bundler",
        "fabric-loader","ImmediatelyFast",
        "Axiom","axiom",
        "nb-javac","nb-","groovy-","groovy","kotlin-compiler-embeddable","kotlin-stdlib",
        "gradle-api","gradle-core","gradle-dependency-management","gradle-wrapper",
        "gradle-","instrumented-gradle-",
        "maven-shared-incremental","maven-","org-netbeans","netbeans-",
        "autoclicker-fabric","auto-clicker-fabric","autoclicker",
        "ViaBedrock","viabedrock"
    )

    $scanBlock = {
        param($jarPath, $cheatStrings, $patternRegexStr, $safeJarPrefixes)
        $result = $null
        try {
            $fn = [System.IO.Path]::GetFileName($jarPath)
            if ($fn.EndsWith('.temp.jar', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
            foreach ($pfx in $safeJarPrefixes) {
                if ($fn.StartsWith($pfx, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
            }
            $rx   = [regex]::new($patternRegexStr, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $zip  = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
            $isPlugin = $false
            $hits = [System.Collections.Generic.List[string]]::new()
            $serverDescriptors = @('plugin.yml','paper-plugin.yml','bungee.yml','velocity-plugin.json')
            foreach ($entry in $zip.Entries) {
                if ($serverDescriptors -contains $entry.FullName) { $isPlugin = $true; break }
            }
            if (-not $isPlugin) {
                foreach ($entry in $zip.Entries) {
                    $en = $entry.FullName
                    $matched = $false
                    foreach ($cs in $cheatStrings) {
                        if ($en.Contains($cs)) { [void]$hits.Add($cs); $matched = $true; break }
                    }
                    if (-not $matched -and $rx.IsMatch($en)) {
                        $m = $rx.Match($en)
                        if ($m.Success) { [void]$hits.Add($m.Value) }
                    }
                }
            }
            $zip.Dispose()
            if ($hits.Count -gt 0) {
                $result = [PSCustomObject]@{ Path = $jarPath; Hits = ($hits | Select-Object -Unique | Select-Object -First 5) -join ", " }
            }
        } catch {}
        return $result
    }

    $jobs = foreach ($jar in $allJars) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($scanBlock).AddArgument($jar).AddArgument($script:cheatStrings).AddArgument($script:patternRegex.ToString()).AddArgument($safeJarPrefixes)
        [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Path = $jar }
    }

    $printedFlags = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($job in $jobs) {
        $curName = [System.IO.Path]::GetFileName($job.Path)
        $curShort = if ($curName.Length -gt 38) { $curName.Substring(0,35) + "..." } else { $curName }
        Write-Host "`r  Scanning: $($curShort.PadRight(40))  $fsScanned/$($allJars.Count)  Flagged: $($fsFlags.Count)  " -NoNewline
        $res = $job.PS.EndInvoke($job.Handle)
        $job.PS.Dispose()
        $fsScanned++
        if ($res -and $res.Path) {
            $fsFlags.Add($res)
            if ($printedFlags.Add($res.Path)) {
                Write-Host "`r  " -NoNewline
                Write-Host "FOUND " -ForegroundColor Red -NoNewline
                Write-Host "$([System.IO.Path]::GetFileName($res.Path))" -ForegroundColor Yellow -NoNewline
                Write-Host "  ($($res.Hits))" -ForegroundColor DarkYellow
            }
        }
    }
    Write-Host "`r  Done $([char]0x2014) scanned $fsScanned JARs, flagged $($fsFlags.Count).                                              "
    $pool.Close()
    $pool.Dispose()
    $pcIssues += $fsFlags.Count

    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) FILE SYSTEM JAR SCAN " + "$([char]0x2500)" * 49 + "$([char]0x2510)") DarkCyan
    $scannedLine = "  $([char]0x2502)  Scanned $fsScanned JAR files    Found: $($fsFlags.Count) flagged"
    W ($scannedLine + (" " * [Math]::Max(0, 72 - $scannedLine.Length)) + "$([char]0x2502)") DarkGray
    if ($fsFlags.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no cheat signatures found in JARs                            $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $fsFlags) {
            Write-Host ""
            $pathLine = "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)"
            W $pathLine Red
            $hitsLine = "  $([char]0x2502)    Hits : $($f.Hits)"
            W $hitsLine DarkYellow
        }
        Write-Host ""
        W ("  $([char]0x2502)  " + "$([char]0x2014)" * 68 + "  $([char]0x2502)") DarkGray
        $summLine = "  $([char]0x2502)  $($fsFlags.Count) suspicious JAR(s) detected $([char]0x2014) review immediately"
        W ($summLine + (" " * [Math]::Max(0, 72 - $summLine.Length)) + "$([char]0x2502)") Red
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    $pyCheatKeywordsHigh = @(
        "autoclicker","autoclick","auto_clicker",
        "aimbot","aim_bot","aimassist","aim_assist",
        "triggerbot","trigger_bot",
        "cheatclient","cheat_client","ghosthack","ghost_hack",
        "autototem","auto_totem","autocrystal","auto_crystal",
        "killaura","kill_aura","forcefield","force_field",
        "antiknockback","anti_knockback","velocity_hack",
        "wallhack","wall_hack","flyhack","fly_hack",
        "esp_hack","player_esp","nofall","no_fall",
        "bunnyhop","speed_hack","speedhack","xray","x_ray",
        "critaura","crit_aura","reach_hack","reachhack",
        "dll_inject","dll_injector","process_inject","processinjector",
        "keyboard.hook","pynput","pywin32","win32api",
        "GetAsyncKeyState","GetForegroundWindow","SetForegroundWindow",
        "pymem","ReadProcessMemory","WriteProcessMemory",
        "VirtualAllocEx","CreateRemoteThread","OpenProcess",
        "bhop","bunny_hop","scaffold_walk","scaffoldwalk",
        "crystal_pvp","crystalpvp","surroundaura","surround_aura"
    )
    $pyCheatKeywordsCritical = @(
        "pymem","ReadProcessMemory","WriteProcessMemory",
        "VirtualAllocEx","CreateRemoteThread","OpenProcess",
        "keyboard.hook","GetAsyncKeyState"
    )
    $pyCheatFileNames = @(
        "cheat","hack","inject","aimbot","killaura","autoclicker",
        "triggerbot","bhop","esp","xray","wallhack","stealer","grabber",
        "autocrystal","autototem","ghostclient","cheatclient"
    )
    Write-Host ""
    W "  Scanning Python scripts for cheat indicators..." DarkGray
    $pyFlags = [System.Collections.Generic.List[object]]::new()
    $pyRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        $env:TEMP
    )) {
        [void]$pyRoots.Add($base)
        try {
            foreach ($sub in [System.IO.Directory]::GetDirectories($base)) {
                [void]$pyRoots.Add($sub)
            }
        } catch {}
    }
    $pyScanned = 0
    $pySeenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pyRoot in $pyRoots) {
        if (-not [System.IO.Directory]::Exists($pyRoot)) { continue }
        try {
            foreach ($pyFile in [System.IO.Directory]::EnumerateFiles($pyRoot, '*.py', [System.IO.SearchOption]::TopDirectoryOnly)) {
                if (-not $pySeenPaths.Add($pyFile)) { continue }
                $pyName     = [System.IO.Path]::GetFileName($pyFile)
                $pyNameStem = [System.IO.Path]::GetFileNameWithoutExtension($pyFile).ToLower()
                $pyScanned++
                Spin "Scanning .py: $pyName"
                $reasons = [System.Collections.Generic.List[string]]::new()
                foreach ($fn in $pyCheatFileNames) {
                    if ($pyNameStem.Contains($fn)) { $reasons.Add("[FILENAME] name contains '$fn'"); break }
                }
                try {
                    $content = [System.IO.File]::ReadAllText($pyFile).ToLower()
                    $critHits = [System.Collections.Generic.List[string]]::new()
                    foreach ($kw in $pyCheatKeywordsCritical) {
                        if ($content.Contains($kw.ToLower())) { [void]$critHits.Add($kw) }
                    }
                    if ($critHits.Count -gt 0) {
                        $reasons.Add("[CRITICAL] $($critHits -join ', ')")
                    }
                    $highHits = [System.Collections.Generic.List[string]]::new()
                    foreach ($kw in $pyCheatKeywordsHigh) {
                        if ($content.Contains($kw.ToLower())) { [void]$highHits.Add($kw) }
                    }
                    if ($highHits.Count -ge 2) {
                        $reasons.Add("[CONTENT] $( ($highHits | Select-Object -First 6) -join ', ' )")
                    }
                    $fi = [System.IO.FileInfo]::new($pyFile)
                    $meta = "size: $([math]::Round($fi.Length/1KB,1)) KB  modified: $($fi.LastWriteTime.ToString('yyyy-MM-dd'))"
                } catch { $meta = "" }
                if ($reasons.Count -gt 0) {
                    [void]$pyFlags.Add([PSCustomObject]@{ Path = $pyFile; Reasons = $reasons; Meta = $meta })
                }
            }
        } catch {}
    }
    SpinClear
    $pcIssues += $pyFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) PYTHON SCRIPT SCAN " + "$([char]0x2500)" * 51 + "$([char]0x2510)") DarkCyan
    if ($pyFlags.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no suspicious Python scripts found                           $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $pyFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W "  Scanning EXE files for cheat indicators..." DarkGray
    $exeCheatTokens = @(
        "autoclicker","autoclick","killaura","aimbot","triggerbot","bhop",
        "cheatengine","artmoney","cheatclient","ghostclient","ghosthack",
        "dllinjector","dll_injector","xenos","extremeinjector","xenosinjector",
        "ollydbg","x64dbg","x32dbg","processhacker","dnspy","reshacker",
        "keylogger","ratclient","ratlauncher","ratserver","dcrat","asyncrat",
        "quasar","remcos","njrat","darkcomet","nanocore","netwire","orcus",
        "stealer","grabber","tokenstealer","discordstealer","cookiestealer",
        "crystalaura","autocrystal","autototem","scaffoldhack","nofallhack",
        "speedhack","flyhack","wallhack","xrayhack","reachhack"
    )
    $exeCheatStrings = @(
        "autoclicker","killaura","aimbot","triggerbot","cheat client","ghost client",
        "dll inject","process inject","ReadProcessMemory","WriteProcessMemory",
        "VirtualAllocEx","CreateRemoteThread","GetAsyncKeyState",
        "discord token","webhook url","grab passwords","steal cookies",
        "autocrystal","auto crystal","auto totem","crystal pvp",
        "minhook","easyhook","detours","polyhook","subhook",
        "xenos injector","extreme injector","process hacker"
    )
    $exeSuspiciousDirs = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @(
        $env:TEMP,
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        [System.IO.Path]::Combine($env:APPDATA, ".minecraft")
    )) {
        [void]$exeSuspiciousDirs.Add($base)
        try {
            foreach ($sub in [System.IO.Directory]::GetDirectories($base)) {
                [void]$exeSuspiciousDirs.Add($sub)
            }
        } catch {}
    }
    $exeInstallerPattern = '(?i)(setup|install|uninstall|update|bootstrapper|vcredist|dotnet|ndp|wix|squirrel|CodeSetup|windowsinstaller|msiexec)'
    $exeFlags   = [System.Collections.Generic.List[object]]::new()
    $exeScanned = 0
    $exeSeenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($exeRoot in $exeSuspiciousDirs) {
        if (-not [System.IO.Directory]::Exists($exeRoot)) { continue }
        try {
            foreach ($exeFile in [System.IO.Directory]::EnumerateFiles($exeRoot, '*.exe', [System.IO.SearchOption]::TopDirectoryOnly)) {
                if (-not $exeSeenPaths.Add($exeFile)) { continue }
                $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exeFile).ToLower()
                $exeScanned++
                Spin "Scanning EXE: $([System.IO.Path]::GetFileName($exeFile))"
                if ($exeName -match $exeInstallerPattern) { continue }
                $reasons = [System.Collections.Generic.List[string]]::new()
                foreach ($token in $exeCheatTokens) {
                    if ($exeName.Contains($token)) { $reasons.Add("[FILENAME] name contains '$token'"); break }
                }
                if ($reasons.Count -eq 0) {
                    $fuzzyHit = Get-FilenameSimilarityMatch -JarName $exeFile
                    if ($null -ne $fuzzyHit) { $reasons.Add("[FILENAME~] '$($fuzzyHit.Token)' ($($fuzzyHit.Score)% match)") }
                }
                try {
                    $bytes   = [System.IO.File]::ReadAllBytes($exeFile)
                    $maxRead = [Math]::Min($bytes.Length, 2MB)
                    $sb      = [System.Text.StringBuilder]::new()
                    $run     = 0
                    for ($bi = 0; $bi -lt $maxRead; $bi++) {
                        $b = $bytes[$bi]
                        if ($b -ge 32 -and $b -le 126) {
                            [void]$sb.Append([char]$b); $run++
                        } else {
                            if ($run -ge 5) {
                                [void]$sb.Append(' ')
                            } else {
                                $sb.Length = [Math]::Max(0, $sb.Length - $run)
                            }
                            $run = 0
                        }
                    }
                    $exeText = $sb.ToString().ToLower()
                    $strHits = [System.Collections.Generic.List[string]]::new()
                    foreach ($s in $exeCheatStrings) {
                        if ($exeText.Contains($s.ToLower())) { [void]$strHits.Add($s) }
                    }
                    if ($strHits.Count -gt 0) {
                        $reasons.Add("[STRINGS] $( ($strHits | Select-Object -First 5) -join ', ' )")
                    }
                    $fi   = [System.IO.FileInfo]::new($exeFile)
                    $sig  = Get-AuthenticodeSignature -FilePath $exeFile -ErrorAction SilentlyContinue
                    $signed = if ($sig -and $sig.Status -eq 'Valid') { "signed:YES" } else { "signed:NO" }
                    $meta = "size: $([math]::Round($fi.Length/1KB,1)) KB  $signed  modified: $($fi.LastWriteTime.ToString('yyyy-MM-dd'))"
                } catch { $meta = "" }
                if ($reasons.Count -gt 0) {
                    [void]$exeFlags.Add([PSCustomObject]@{ Path = $exeFile; Reasons = $reasons; Meta = $meta })
                }
            }
        } catch {}
    }
    SpinClear
    $pcIssues += $exeFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) EXE SCAN " + "$([char]0x2500)" * 59 + "$([char]0x2510)") DarkCyan
    if ($exeFlags.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no suspicious EXE files found                               $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $exeFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W "  Scanning loaded DLLs in javaw.exe for injection indicators..." DarkGray
    $dllSuspiciousPatterns = @(
        '(?i)(cheat|hack|inject|hook|bypass|spoof|aimbot|triggerbot|autoclicker|killaura|esp|xray|wallhack|flyhack|speedhack)',
        '(?i)(minhook|easyhook|detours|subhook|polyhook|xenos|extreme_injector)',
        '(?i)(keylog|ratclient|backdoor|stealer|grabber|webhook|tokengrab)',
        '(?i)(reshacker|dnspy|x64dbg|ollydbg|cheatengine|processhacker|artmoney)'
    )
    $dllSafePrefixes = @(
        'C:\Windows\','C:\Program Files\Java\','C:\Program Files\Eclipse Adoptium\',
        'C:\Program Files\Microsoft\','C:\Program Files (x86)\Java\',
        'C:\Program Files\Amazon Corretto\','C:\Program Files\BellSoft\',
        "$($env:LOCALAPPDATA)\Medal\",
        "$($env:LOCALAPPDATA)\Discord\",
        "$($env:APPDATA)\Discord\",
        "$($env:LOCALAPPDATA)\Programs\medal\",
        "$($env:LOCALAPPDATA)\GeForce Experience\"
    )
    $dllFlags = [System.Collections.Generic.List[object]]::new()
    $dllScanned = 0
    $javaProcs = Get-Process -Name @("javaw","java") -ErrorAction SilentlyContinue
    foreach ($jp in $javaProcs) {
        try {
            $modules = $jp.Modules | Select-Object -ExpandProperty FileName -ErrorAction SilentlyContinue
            foreach ($dll in $modules) {
                $dllScanned++
                $dllShort = [System.IO.Path]::GetFileName($dll)
                Write-Host "`r  Scanning DLL: $($dllShort.Substring(0,[Math]::Min($dllShort.Length,38)).PadRight(38))  checked: $dllScanned  flagged: $($dllFlags.Count)" -NoNewline -ForegroundColor DarkGray
                $isSafe = $false
                foreach ($sp in $dllSafePrefixes) {
                    if ($dll.StartsWith($sp, [System.StringComparison]::OrdinalIgnoreCase)) { $isSafe = $true; break }
                }
                if ($isSafe) { continue }
                foreach ($pat in $dllSuspiciousPatterns) {
                    if ($dll -match $pat) {
                        $dllFlags.Add([PSCustomObject]@{ PID = $jp.Id; Process = $jp.Name; DLL = $dll; Pattern = $pat })
                        break
                    }
                }
            }
        } catch {}
    }
    if ($dllScanned -gt 0) { Write-Host "`r  DLL scan done $([char]0x2014) $dllScanned module(s) checked in Java process.                              " }
    else { Write-Host "`r$(' ' * 80)`r" -NoNewline }
    $pcIssues += $dllFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) INJECTABLE DLL SCAN (javaw) " + "$([char]0x2500)" * 42 + "$([char]0x2510)") DarkCyan
    if ($dllFlags.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no suspicious DLLs loaded in Java process                  $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $dllFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  PID $($f.PID) ($($f.Process))" Red
            W "  $([char]0x2502)    DLL    : $($f.DLL)" DarkYellow
        }
    }
    W "  $([char]0x2514)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2518)" DarkCyan

    Write-Host ""
    W ("$([char]0x2501)" * 76) Blue
    Write-Host ""
    W "  PC SCAN SUMMARY" Cyan
    Write-Host ""
    W "  Flagged processes   : " DarkGray -NoNewline; W "$($flaggedProcs.Count)" $(if($flaggedProcs.Count -gt 0){"Red"}else{"Green"})
    W "  Unknown processes   : " DarkGray -NoNewline; W "$($unknownProcs.Count)" $(if($unknownProcs.Count -gt 0){"Yellow"}else{"Green"})
    W "  Startup flags       : " DarkGray -NoNewline; W "$($startupFlags.Count)" $(if($startupFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Cheat folders found : " DarkGray -NoNewline; W "$($foundFolders.Count)" $(if($foundFolders.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged JARs        : " DarkGray -NoNewline; W "$($fsFlags.Count)" $(if($fsFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged .py scripts : " DarkGray -NoNewline; W "$($pyFlags.Count)" $(if($pyFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged EXE files   : " DarkGray -NoNewline; W "$($exeFlags.Count)" $(if($exeFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Injected DLLs       : " DarkGray -NoNewline; W "$($dllFlags.Count)" $(if($dllFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged mods (scan) : " DarkGray -NoNewline; W "$($script:FlaggedModsList.Count)" $(if($script:FlaggedModsList.Count -gt 0){"Red"}else{"Green"})
    if ($script:FlaggedModsList.Count -gt 0) {
        foreach ($m in $script:FlaggedModsList) {
            W "    $([char]0x26A0) $m" Red
        }
    }
    Write-Host ""
    if ($pcIssues -gt 0 -or $script:FlaggedModsList.Count -gt 0) {
        W "  ACTION REQUIRED $([char]0x2014) review all flagged items above." Red
    } else {
        W "  PC scan passed $([char]0x2014) no known threats detected." Green
    }
    W ("$([char]0x2501)" * 76) Blue
}

if (-not $SkipMemoryCheck) {
    $jvmFlags = Run-JVMScan
    if ($jvmFlags.Count -gt 0) {
        Write-SectionHeader "JVM / RUNTIME INJECTION" $jvmFlags.Count Yellow Yellow
        Write-Rule "$([char]0x2500)" 76 DarkGray
        Write-Host ""
        Write-InjectionCard "javaw / java process" $jvmFlags
        $script:SystemIssues += $jvmFlags.Count
    } else {
        Write-Host ""
        W "  $([char]0x2713) JVM $([char]0x2014) no agents, no localhost listeners, no heap signatures" DarkGray
    }
}

Write-Host ""
W ("$([char]0x2501)" * 76) Blue
Write-Host ""
W "  SCAN SUMMARY" Cyan
Write-Host ""
W "  Total files scanned  : " DarkGray -NoNewline; W "$($script:TotalMods)" White
W "  Verified mods        : " DarkGray -NoNewline; W "$($script:Verified)" Green
W "  Unknown mods         : " DarkGray -NoNewline; W "$($script:Unknown)" Yellow
W "  Flagged / suspicious : " DarkGray -NoNewline; W "$($script:Flagged)" Red
$issueColor = if ($script:SystemIssues -gt 0) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
W "  System issues        : " DarkGray -NoNewline; W "$($script:SystemIssues)" $issueColor
Write-Host ""
W ("$([char]0x2501)" * 76) Blue
Write-Host ""

if ($script:Flagged -gt 0 -or $script:SystemIssues -gt 0) {
    W "  ACTION REQUIRED $([char]0x2014) review all flagged items above." Red
} else {
    W "  All checks passed. Installation appears clean." Green
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
if (Ask-YesNo "Check recently deleted files, new JARs and terminated processes?") { Run-RecentActivity }
Write-Host ""
if (Ask-YesNo "Run full PC scan (processes, registry, DLLs, filesystem)?") { Run-PCscan }
