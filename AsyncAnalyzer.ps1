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
$script:Evidence = @{ RandomNamed = 0; CheatSiteDl = 0; HardConfirmed = 0; JvmInject = 0; CheatProcs = 0; StrayJars = 0; CheatFolders = 0; MemCheatClient = 0; MemModule = 0; MemInjectedOnly = 0; DeletedJars = 0; MacroCheat = 0; MacroNamed = 0; BehaviourCheat = 0; BehaviourLikely = 0; HiddenApi = 0 }
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
    "vape","vapeclient","vape-client","vape_client","vapelite","vape-lite","vapepro",
    "meteor","meteorclient","meteor-client","meteor_client","meteordev","meteor-dev",
    "liquidbounce","liquid-bounce","liquid_bounce","liquidb","liquidbounceclient",
    "wurst","wurst-client","wurst_client","wurstclient","wurst7",
    "sigma","sigmaclient","sigma-client","sigmahack","sigmamod",
    "rise","riseclient","rise-client","risehack",
    "future","futureclient","future-client","futurehack",
    "konas","konasclient","konas-client","konashack",
    "inertia","inertiaclient","inertia-client","inertiahack",
    "exhibition","exhibitionclient","exhibitionhack",
    "pandaware","panda-ware","panda_ware","pandaclient",
    "astolfo","astolfoclient","astolfo-client","astolfohack",
    "rusherhack","rusher-hack","rusher_hack","rushermod",
    "novaclient","nova-client","nova_client","novaware","novahack",
    "impact","impactclient","impact-client","impacthack",
    "aristois","aristois-client","aristoisclient",
    "azura","azuraclient","azura-client","azurahack",
    "moonlight","moonlightclient","moon-client","moonhack",
    "intent","intentclient","intent-client","intentstore","intenthack",
    "prestige","prestigeclient","prestige-client","prestigehack",
    "cheatbreaker","cheat-breaker","cheatbreakerclient",
    "kami","kamiclient","kami-client","kamiblue","kami-blue",
    "fdp","fdpclient","fdp-client","fdphack",
    "xray","xrayclient","xray-mod","xrayhack","xraymod",
    "baritone","baritoneclient","baritonehack",
    "skidfuscator","skid-client","skidclient","skidware",
    "noob","nooby","cheat","hack","hacked","hacker","hackme",
    "inject","injector","loader","payload","bypass","cracked","crack",
    "stealer","grabber","logger","keylog","token","exploit","malware","rat",
    "sabotage","sabotageclient","omega","omegaclient","omega-client",
    "flex","flexclient","flex-client","flexhack",
    "swift","swiftclient","swift-client","swifthack",
    "vertex","vertexclient","vertex-client","vertexhack",
    "vapor","vaporclient","vapor-client","vaporhack",
    "blaze","blazeclient","blaze-client","blazehack",
    "noble","nobleclient","noble-client","noblehack",
    "royal","royalclient","royal-client","royalhack",
    "spirit","spiritclient","spirit-client","spirithack",
    "phantom","phantomclient","phantom-client","phantomhack",
    "ghost","ghostclient","ghost-client","ghosthack","ghostware",
    "shadow","shadowclient","shadow-client","shadowhack",
    "crystal","crystalclient","crystal-client","crystalware",
    "drip","dripclient","drip-client","driphack","dripware",
    "tenacity","tenacityclient","tenacity-client",
    "thunder","thunderclient","thunder-client","thunderhack",
    "storm","stormclient","storm-client","stormhack",
    "abyss","abyssclient","abyss-client","abysshack",
    "raven","ravenclient","raven-client","ravenhack","ravenb",
    "themis","themisclient","themishack",
    "saber","saberclient","saber-client","saberhack",
    "blade","bladeclient","blade-client","bladehack",
    "toxic","toxicclient","toxic-client","toxichack",
    "breach","breachclient","breach-client","breachhack",
    "clarity","clarityclient","clarity-client",
    "motion","motionclient","motion-client","motionhack",
    "flux","fluxclient","flux-client","fluxhack","fluxbe",
    "strafe","strafeclient","strafe-client","strafehack",
    "aura","auraclient","aura-client","aurahack",
    "nemesis","nemesisclient","nemesis-client","nemesishack",
    "nexus","nexusclient","nexus-client","nexushack",
    "crypt","cryptclient","crypt-client","crypthack","cryptware",
    "nodus","nodusclient","nodus-client","nodushack",
    "hyperium","hyperiumclient","hyperiumhack",
    "salwyrr","salwyrrclient","salwyrrhack",
    "bleach","bleachclient","bleachhack","bleach-hack",
    "erosion","erosionclient","erosionhack",
    "entropy","entropyclient","entropyhack","entropy-client",
    "ares","aresclient","ares-client","areshack","areswarez",
    "wolfram","wolframclient","wolfram-client","wolframhack",
    "pyro","pyroclient","pyro-client","pyrohack",
    "kira","kiraclient","kira-client","kirahack",
    "solace","solaceclient","solace-client","solacehack",
    "serenity","serenityclient","serenityhack",
    "polaris","polarisclient","polaris-client",
    "lucid","lucidclient","lucid-client","lucidhack",
    "comet","cometclient","comet-client","comethack",
    "aurora","auroraclient","aurora-client","aurorahack",
    "twilight","twilightclient","twilight-hack",
    "quantum","quantumclient","quantum-client","quantumhack",
    "pulsar","pulsarclient","pulsar-client","pulsarhack",
    "radium","radiumclient","radium-client","radiumhack",
    "prism","prismclient","prism-client","prismhack",
    "zenith","zenithclient","zenith-client","zenithhack",
    "apex","apexclient","apex-client","apexhack",
    "orion","orionclient","orion-client","orionhack",
    "inferno","infernoclient","inferno-client","infernohack",
    "eclipse","eclipseclient","eclipse-client","eclipsehack",
    "rage","rageclient","rage-client","ragehack","ragebot",
    "autoclicker","auto-clicker","auto_clicker","clickbot","clicker",
    "killaura","kill-aura","kill_aura","aurabot",
    "aimbot","aim-bot","aim_bot","aimassist","triggerbot",
    "wallhack","wall-hack","nofallhack",
    "bhop","bunny-hop","speedhack","speed-hack","flyhack","fly-hack",
    "scaffold","scaffoldhack","scaffold-hack",
    "dllinjector","dll-injector","dll_injector","injectorpro",
    "bypassed","bypassclient","bypass-client","bypasshack",
    "cracked","crackedclient","cracked-client","crackedhack",
    "nulled","nulledclient","nulled-client","nulledhack",
    "leaked","leakedclient","leaked-client","leakedhack",
    "skid","skidclient","skid-client","skidhack"
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

function Test-RandomFilename([string]$JarName) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName).ToLower()
    $base = $base -replace '\.(temp|disabled|bak|old|backup)$',''
    $stripped = $base -replace '\+.*$',''
    $prev = ''
    while ($stripped -ne $prev) {
        $prev = $stripped
        $stripped = $stripped -replace '[-_](?:v?\d[\d\.\-]*|mc\d[\d\.]*|fabric|forge|neoforge|neo|quilt|rift|liteloader|spigot|paper|bukkit|release|snapshot|alpha|beta|rc\d*|pre\d*|build\d*|final|stable|dev|test)$',''
    }
    $analyze = if ($stripped.Length -ge 3) { $stripped } else { $base }
    if ($analyze.Length -lt 4) { return $false }
    $knownPrefixes = @(
        "fabric","forge","optifine","sodium","lithium","iris","indium","ferrite","starlight","phosphor",
        "lazydfu","ksyxis","smoothboot","entityculling","memoryleakfix","badoptimizations",
        "c2me","moonrise","noisium","raknetify","immediatelyfast","dynamic","continuity",
        "viaversion","viafabric","viafabricplus","essential","replay","journeymap","xaeros","xaero",
        "jei","rei","emi","waystones","ftb","create","mekanism","thermal","botania",
        "appleskin","inventory","item","chunk","render","better","fast","simple","easy",
        "quark","charm","supplementaries","farmers","autumnity","upgrade","twigs",
        "bobby","krypton","modmenu","worldedit","spark","collective","carpet",
        "tweakeroo","minihud","litematica","malilib","modernfix","optifabric",
        "no","void","cloth","player","chat","tab","skin","sound","music","biome",
        "structure","terrain","world","server","client","api","lib","core","compat",
        "config","data","resource","texture","shader","particle","block","entity",
        "fluid","tool","armor","weapon","mouse","key","hud","map","mini","zoom",
        "distance","view","fps","performance","memory","cache","network","ping",
        "recipe","crafting","storage","chest","container","slot","damage","health",
        "potion","effect","enchant","anvil","repair","dye","color","palette",
        "ambient","ambience","atmosphere","weather","season","time","clock","compass","level",
        "xp","experience","hunger","saturation","breath","death","respawn","spawn",
        "animatica","capes","cicada","autoreconnect","cicadalib","ambiencesounds",
        "voice","voicechat","free","freelook","anchor","zoom","cam","look","hold","toggle",
        "auto","custom","enhanced","advanced","tweaked","improved","extra","plus","smooth",
        "real","true","ultra","super","hyper","mega","max","pro","anti","counter",
        "border","full","screen","window","frame","display","mouse","cursor","cross",
        "ping","latency","motion","speed","fly","sprint","jump","sneak","crawl",
        "cape","cloak","cosmetic","emote","gesture","trail","wing","hat","head",
        "night","light","dark","glow","bright","dim","fog","blur","bloom",
        "reach","range","distance","angle","fov","sens","sensitivity","aim",
        "sleep","wake","idle","afk","presence","status","activity","rich",
        "discord","twitch","optim","perf","boost","improve","fix","patch","compat",
        "voxel","height","depth","layer","level","floor","ceil","bound","limit",
        "border","region","area","zone","claim","protect","safe","guard","shield",
        "horse","mount","ride","tame","pet","animal","mob","creature","entity",
        "chest","barrel","hopper","dropper","dispenser","shulker","ender","crafting",
        "furnace","blast","smoker","campfire","anvil","beacon","enchant","brew",
        "book","sign","banner","painting","frame","armor","stand","boat","cart",
        "portal","gate","door","trap","pressure","button","lever","redstone",
        "piston","sticky","observer","comparator","repeater","note","jukebox",
        "ladder","scaffold","slab","stair","fence","wall","glass","pane","iron",
        "oak","spruce","birch","jungle","acacia","dark","warped","crimson","cherry",
        "copper","gold","diamond","netherite","emerald","lapis","quartz","amethyst"
    )
    $firstWord = ($analyze -split '[-_]')[0]
    foreach ($pfx in $knownPrefixes) {
        if ($analyze.StartsWith($pfx) -or $firstWord -eq $pfx) { return $false }
    }
    $allAlpha = $analyze -replace '[^a-z]',''
    if ($allAlpha.Length -lt 4) { return $false }
    # .Contains, not -contains. PowerShell's -contains treats the LEFT side as a
    # collection, and a string is a collection of ONE element - itself - so
    # 'aeiou' -contains 'i' is False. The vowel count was therefore always 0, the
    # ratio always 0, and "looks random" quietly meant nothing more than "has
    # five letters and is not on the prefix list below". Every legitimate mod not
    # in that hand-written list was floored to Review 35 with the reason
    # "Unrecognized random / hash-style filename". Found by running the tool for
    # real: HikariCP-5.1.0.jar and Java-WebSocket-1.5.6.jar were both called
    # random-named.
    $vowels = ($allAlpha.ToCharArray() | Where-Object { 'aeiou'.Contains($_) }).Count
    $ratio  = $vowels / $allAlpha.Length
    $looksRandom = ($ratio -lt 0.12 -and $allAlpha.Length -ge 5)
    return $looksRandom
}

function Get-FilenameSimilarityMatch([string]$JarName) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName).ToLower()
    $base = $base -replace '[-_\.\s\d]+', ''
    if ($base.Length -lt 4) { return $null }
    $bestToken = $null
    $bestScore = 0.0
    foreach ($token in $script:knownCheatFileTokens) {
        $t = $token -replace '[-_\.\s]+', ''
        if ($t.Length -ge 8 -and ($base -eq $t -or $base.StartsWith($t) -or $base.EndsWith($t))) {
            $score = [double]$t.Length / [double]$base.Length
            if ($score -gt $bestScore) { $bestScore = $score; $bestToken = $token }
        } elseif ($base -eq $t) {
            if (1.0 -gt $bestScore) { $bestScore = 1.0; $bestToken = $token }
        }
        $sim = Get-BigramSimilarity $base $t
        if ($sim -gt $bestScore) { $bestScore = $sim; $bestToken = $token }
    }
    if ($bestScore -ge 0.80 -and $null -ne $bestToken) {
        return [PSCustomObject]@{ Token = $bestToken; Score = [Math]::Round($bestScore * 100) }
    }
    return $null
}

$script:suspiciousPatterns = @(
    "AimAssist","AnchorTweaks","AutoAnchor","AutoCrystal","AutoDoubleHand",
    "AutoHitCrystal","AutoHitTotem","AutoTotem","InventoryTotem",
    "HoleFill","AutoHoleFill",
    "JumpReset","LegitTotem",
    "ShieldBreaker","TriggerBot","AxeSpam","WebMacro",
    "WalskyOptimizer","WalksyOptimizer","walsky.optimizer",
    "WalksyCrystalOptimizerMod",
    "ShieldDisabler","SilentAim","FakeLag",
    "BlockESP","dev.krypton",
    "LagReach","PopSwitch","ChestStealer",
    "AirAnchor",
    "FakeInv","HoverTotem",
    "PackSpoof","Antiknockback","catlean",
    "AuthBypass","Asteria",
    "MaceSwap","DoubleAnchor","BaseFinder",
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
    "BowAimbot","Fakenick",
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

function Build-PatternRegex {
    $script:patternRegex = [regex]::new(
        '(?<![A-Za-z])(' + (($script:suspiciousPatterns | ForEach-Object { [regex]::Escape($_) } | Select-Object -Unique) -join '|') + ')(?![A-Za-z])',
        [System.Text.RegularExpressions.RegexOptions]::Compiled
    )
}
Build-PatternRegex

# The shortest client name worth matching. It was 5, which silently excluded
# "vape" - one of the most-used clients there is - from the log reader, the
# instance reader and the pre-filter, while the filename and memory scans still saw
# it. ml/audit.py now fails the build if any token in the signature lists falls
# below this, so it cannot happen again quietly. Mirrored as TOKEN_FLOOR in
# ml/logscan.py.
$script:tokenFloor = 4

function Build-LogPreFilter {
    # One compiled alternation of every cheat package path and client name, run ONCE
    # over a whole log file before any line is looked at individually.
    #
    # This is not an optimisation, it is what makes the log scan usable at all.
    # Test-LogLine checks ~15 package paths in two spellings plus ~60 client tokens
    # per line; over 25 log files of up to 4 MB that is on the order of a million
    # lines and tens of millions of string operations, which in PowerShell is
    # minutes. A clean player's logs contain none of these names, so one search over
    # the whole file answers the question and the per-line pass never runs.
    #
    # Same reasoning as $script:bcPreFilter: search cheaply everywhere, look
    # precisely only where something matched. Rebuilt after a signature update,
    # because the lists it is built from can grow at runtime.
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $script:cheatPackagePaths) {
        [void]$parts.Add([regex]::Escape($p))
        [void]$parts.Add([regex]::Escape(($p -replace '/', '.')))
    }
    foreach ($t in $script:distinctiveClientTokens) {
        if ($t.Length -ge $script:tokenFloor) { [void]$parts.Add([regex]::Escape($t)) }
    }
    $script:logPreFilter = [regex]::new(
        (($parts | Select-Object -Unique) -join '|'),
        ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor
         [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
}

$script:cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($s in $script:cheatStrings) { [void]$script:cheatStringSet.Add($s) }

$script:fullwidthRegex = [regex]::new(
    "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]{2,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:weakStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
@(
    "arrayOfString","setSelectedSlot","invokeDoAttack","invokeDoItemUse","invokeOnMouseButton",
    "onBlockBreaking","setItemUseCooldown","getBlockBreakingCooldown","blockBreakingCooldown",
    "setBlockBreakingCooldown","onPushOutOfBlocks","onIsGlowing","Entity.isGlowing",
    "NoBounce","No Bounce","damagetick","Runtime.exec","cmd.exe","powershell.exe","FastPlace",
    "Blatant","Fast Mode","Reach Distance","Min Height","Min Fall Speed","Attack Delay","Hit Delay",
    "Include Head","Check Players","Stop On Kill","Stop on Kill","Only Charge","Vertical Speed",
    "Swap Speed","Random Pattern","Particle Chance","Place Delay","Break Delay","Place Chance",
    "Break Chance","Switch Delay","Trigger Key","Activate Key","On RMB","Anti Weakness",
    "Smooth Rotations","Use Easing","Easing Strength","While Use","Glowstone Delay","Glowstone Chance",
    "Explode Delay","Explode Chance","Explode Slot","Require Elytra","Auto Switch Back",
    "Check Line of Sight","Only When Falling","Require Crit","Show Status Display","Stop On Crystal",
    "Check Shield","On Pop","Predict Crystals","Check Aim","Check Items","Activates Above","Force Totem",
    "Stay Open For","Only On Pop","Strict One-Tick","Mace Priority","Min Totems","Min Pearls",
    "Totem First","Drop Interval","Horizontal Aim Speed","Vertical Aim Speed","Web Delay","Holding Web",
    "Not When Affects Player","Require Hold Axe","Anchor Macro","Breach Delay","Click Simulation",
    "No Count Glitch","ClassLoader","defineClass"
) | ForEach-Object { [void]$script:weakStringSet.Add($_) }

$script:strongPhraseSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
@(
    "Breaking shield with axe...","Failed to switch to mace after axe!",
    "Automatically switches to sword when hitting with totem","Dqrkis Client","LWFH Crystal",
    "auto crystal","auto totem","auto anchor","aim assist","trigger bot","silent rotations",
    "web macro","axe spam","safe anchor","cw crystal","POT_CHEATS"
) | ForEach-Object { [void]$script:strongPhraseSet.Add($_) }

$script:cheatPackagePaths = @(
    "net/ccbluex","meteordevelopment","org/chainlibs","wtf/moonlight","today/opai","cc/novoline",
    "com/alan/clients","club/maxstats","me/zeroeightsix/kami","net/minecraft/injection","xyz/greaj",
    "com/cheatbreaker","dev/krypton","dev/gambleclient","doomsdayclient",
    # Baritone. A jar that SHIPS baritone/ classes ships Baritone - it is the
    # pathfinding engine every walk/mine bot is built on, and Impact and Meteor
    # bundle it. Shamiro's call was that it counts as a cheat rather than a
    # server-rule question, so it belongs here rather than in the grey band.
    "baritone/"
)

$script:distinctiveClientTokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "doomsday","doomsdayclient","doomsday-client","doomsday_client","liquidbounce","liquidbounceclient",
    "meteorclient","wurst","wurstclient","wurst7","sigmaclient","sigmahack","sigmamod","riseclient",
    "futureclient","konasclient","inertiaclient","exhibitionclient","exhibitionhack","pandaware",
    "astolfo","astolfoclient","rusherhack","novaclient","novoline","impactclient","aristois",
    "aristoisclient","moonlightclient","intentclient","prestigeclient","cheatbreaker","kamiblue",
    "fdpclient","vape","vapeclient","vapelite","vapepro","salwyrrclient","nodusclient","wolframclient",
    "huzuni",
    # Baritone was in the filename list but not in this one, so a jar called
    # baritone-standalone-1.10.1.jar got no identity floor at all. It still came out
    # Likely - but through the FREECAM rule, because Baritone aims the player and
    # draws its path, which is rotation plus rendering without a forged packet. The
    # verdict was right and the reason was wrong, which in a document a moderator
    # shows to somebody is its own kind of wrong.
    "baritone"
) | ForEach-Object { [void]$script:distinctiveClientTokens.Add($_) }

$script:legitModIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "grimac","grim","vulcan","nocheatplus","ncp","matrix","themis","intave","spartan",
    "anticheatreloaded","aac","negativity","exploitfixer","polar","karhu","sodium","iris","lithium",
    "ferritecore","lazydfu","starlight","krypton","c2me","immediatelyfast","modernfix","entityculling",
    "memoryleakfix","noisium","create","jei","emi","roughlyenoughitems","rei","journeymap",
    "xaerominimap","xaeroworldmap","tweakeroo","litematica","minihud","malilib","carpet","fabric",
    "fabricloader","fabricapi","quilt","modmenu","clothconfig","appleskin","jade","waystones",
    "twilightforest","farmersdelight","supplementaries","cloth","yacl","yetanotherconfiglib"
) | ForEach-Object { [void]$script:legitModIds.Add($_) }

$script:cheatDownloadSources = @("DoomsdayClient","PrestigeClient","198Macros","Dqrkis")
# Extra cheat-download domains merged from signatures.json (community-extendable, no script edit needed).
# Each entry: @{ match = 'domain-or-substring'; name = 'DisplayName' }.
$script:cheatDomainMap = @()
$script:pendingProcessNames = @()
# Every Java package that exists in a jar on disk. If a cheat's classes are live in
# the game's memory but NO jar on disk contains them, it was injected rather than
# loaded from the mods folder - which is the whole point of a ghost client, and the
# strongest thing a screenshare check can show.
$script:DiskPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# Everything this run could NOT check. An autonomous tool must never report "clean"
# for a check it silently skipped, so every limitation is collected and shown with
# the verdict instead of being swallowed.
# ---------------------------------------------------------------------------
# Windows system checks - the tables. Mirrors ml/sysscan.py.
#
# An address that sends a name nowhere. A hosts line pointing at a REAL ip is a
# redirect, not a block: LAN setups, mirrors and split-horizon DNS all do it.
$script:sysBlackhole = @('0.0.0.0', '0:0:0:0:0:0:0:0', '127.0.0.1', '255.255.255.255', '::', '::1')
# The game's own login servers. Blackholing these while playing is not a
# preference; it is the client being kept from talking to Mojang.
$script:sysAuthHosts = @('sessionserver.mojang.com', 'authserver.mojang.com', 'api.mojang.com', 'api.minecraftservices.com')
# Folders a launcher actually keeps a Minecraft install in. Used to decide
# whether a Defender exclusion is about Minecraft AT ALL - the check this
# replaced matched the substring 'mod', which covers ModernWarfare and \Models\.
$script:sysMcMarkers = @('\.minecraft', '\.lunarclient', '\badlion', '\feather', '\labymod', '\prismlauncher', '\multimc', '\polymc', '\atlauncher', '\modrinthapp', '\curseforge\minecraft', '\.technic', '\.tlauncher', '\gdlauncher')

$script:ScanGaps    = [System.Collections.Generic.List[string]]::new()
# Jars that ran on this PC and are gone now, from BOTH sources: the BAM registry
# (needs admin, sees executables) and the live JVM's own record of what it loaded
# (needs no admin, sees mods). One set rather than two counters, because the two
# sources overlap and because whichever ran last used to overwrite the other.
$script:DeletedJarPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# Mods folders the RUNNING game turned out to be reading that the file scan never
# opened. Found from the live process, so they arrive after the main pass - the
# tool scans them in a second pass rather than telling a moderator to re-run it.
$script:LateScanDirs = [System.Collections.Generic.List[string]]::new()
$script:LateScanned  = 0
$script:ScanTargets = @()
$script:NoElevate   = [bool]$NoElevate
$script:Escalated   = $false
$script:PathsFromConfig = @()
$script:knownGoodHashes  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:goodMeta         = @{}
$script:knownCheatHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# ---------------------------------------------------------------------------
# Macro / autoclicker files - the half of an autoclicker that is not a mod
#
# An autoclicker is not in the mods folder. It is an AutoHotkey script on the
# desktop, an AutoIt binary, or - the case people assume cannot be seen - a Lua
# script running inside the mouse driver, where the clicks are produced below the
# game entirely.
#
# The line held here is the same one the mod rules hold: clicking the mouse is not
# a cheat. Millions of AutoHotkey scripts expand text and remap keys, and a G HUB
# profile with a recoil script belongs to a shooter. So there are two levels, and
# the difference is evidence rather than confidence:
#   CHEAT  clicks IN A LOOP and names Minecraft - the window, javaw, a known
#          client - or the file is named after the technique. No innocent reading.
#   MACRO  clicks in a loop and nothing ties it to the game. Reported as exactly
#          that, with the limitation stated, and never as an accusation.
#
# Mirrored in ml/macro.py, which is the source of these patterns; parity is
# machine-checked by ml/test_macro.py.
# ---------------------------------------------------------------------------
$script:macroLangs = [ordered]@{
    # Mouse-specific on purpose: a text expander or a window-tiling script uses
    # Send with text and never names a mouse button, which is what keeps it out.
    # 'repeat' is a real loop construct, not Sleep - one Click then Sleep is a hotkey.
    '.ahk' = @{
        'click' = '\bClick\b|\bMouseClick\b|\bLButton\b|\bRButton\b|\bMouseClickDrag\b'
        'repeat' = '(?im)^\s*Loop\b|\bLoop\s*,|\bSetTimer\b|\bWhile\b|\bLoop\s*\{'
        'mc' = 'ahk_exe\s+javaw?\.exe|ahk_class\s+LWJGL|ahk_class\s+GLFW|\bMinecraft\b|lunarclient|badlion|feather\s*client|labymod|prismlauncher'
        'human' = '\bRandom\b|RandomSleep|jitter|humaniz'
    }
    '.ahk2' = @{
        'click' = '\bClick\b|\bMouseClick\b|\bLButton\b|\bRButton\b|\bMouseClickDrag\b'
        'repeat' = '(?im)^\s*Loop\b|\bLoop\s*,|\bSetTimer\b|\bWhile\b|\bLoop\s*\{'
        'mc' = 'ahk_exe\s+javaw?\.exe|ahk_class\s+LWJGL|ahk_class\s+GLFW|\bMinecraft\b|lunarclient|badlion|feather\s*client|labymod|prismlauncher'
        'human' = '\bRandom\b|RandomSleep|jitter|humaniz'
    }
    '.au3' = @{
        'click' = '\bMouseClick\b|\bMouseDown\b|\bMouseUp\b|\{LBUTTON|\{RBUTTON'
        'repeat' = '(?im)^\s*While\b|^\s*For\b|\bAdlibRegister\b|\bDo\b'
        'mc' = 'WinActivate.*Minecraft|WinActive.*Minecraft|javaw?\.exe|LWJGL|\bMinecraft\b|lunarclient|badlion'
        'human' = '\bRandom\b|jitter|humaniz'
    }
    # These names exist ONLY in the Logitech G HUB / G-series and Razer scripting
    # APIs, and that is what makes .lua safe to scan at all: Minecraft's own Lua
    # (ComputerCraft), Garry's Mod and Roblox share none of this vocabulary. A
    # driver script that never touches a mouse button is a lighting or remap
    # profile, of which there are a great many - hence the 'driver' gate.
    '.lua' = @{
        'click' = '\bPressMouseButton\b|\bReleaseMouseButton\b|\bPressAndReleaseMouseButton\b|\bMouseClick\b|\bIsMouseButtonPressed\b'
        'repeat' = '(?im)^\s*while\b|^\s*repeat\b|^\s*for\b|\bSetTimer\b'
        'mc' = '\bMinecraft\b|javaw|lunarclient|badlion|labymod'
        'human' = '\bmath\.random\b|\brandom\b|jitter|humaniz'
        'driver' = '\bOnEvent\b|\bGetMKeyState\b|\bOutputLogMessage\b|\bPlayMacro\b|\bEnablePrimaryMouseButtonEvents\b|\bMoveMouseRelative\b'
    }
    # Narrow on purpose: VBScript cannot click a mouse without an external object,
    # so the only shape worth reading is SendKeys in a loop against the game.
    '.vbs' = @{
        'click' = '\bSendKeys\b|\bAppActivate\b'
        'repeat' = '(?im)^\s*Do\b|^\s*While\b|^\s*For\b'
        'mc' = '\bMinecraft\b|javaw?\.exe|lunarclient|badlion'
        'human' = '\bRnd\b|\bRandomize\b'
    }
}
# Filenames that name the TECHNIQUE. 'macro' on its own is deliberately absent -
# it is what people call any automation, including the harmless kind.
$script:macroCheatNames = @(
    'autoclick', 'autoclicker', 'auto_click', 'auto-click',
    'clicker', 'dragclick', 'drag_click', 'butterflyclick',
    'butterfly_click', 'jitterclick', 'jitter_click', 'blockhit',
    'block_hit', 'autotool', 'aimassist', 'aim_assist',
    'triggerbot', 'autocrystal', 'auto_crystal', 'killaura',
    'autoaim', 'auto_aim', 'autobridge', 'auto_bridge',
    'bhop', 'autosprint', 'autototem', 'auto_totem',
    'reachmacro', 'anchormacro', 'anchorbot', 'autoanchor',
    'cpsmacro', 'clickermacro'
)
# Where a mouse or keyboard driver keeps the macros it runs. Presence is NOT a
# finding - this hardware is owned by millions. What is worth recording is that a
# macro profile exists and when it last changed, plus the scripts themselves where
# the driver stores them as plain files.
$script:macroDriverPaths = @(
    @('Logitech G HUB', '%LOCALAPPDATA%\LGHUB\scripts', 'Lua macro scripts, one per profile')
    @('Logitech G HUB', '%LOCALAPPDATA%\LGHUB\settings.db', 'profile database - can hold macros')
    @('Logitech LGS', '%LOCALAPPDATA%\Logitech\Logitech Gaming Software\profiles', 'profile XML with macros')
    @('Razer Synapse 3', '%PROGRAMDATA%\Razer\Synapse3\Accounts', 'device profiles with macros')
    @('Razer Synapse 2', '%APPDATA%\Razer\Synapse\Accounts', 'device profiles with macros')
    @('Corsair iCUE', '%APPDATA%\Corsair\CUE4', 'profile database - can hold macros')
    @('SteelSeries GG', '%APPDATA%\SteelSeries\SteelSeries Engine 3', 'device profiles with macros')
    @('Bloody / A4Tech', '%PROGRAMDATA%\A4TECH', 'onboard macro profiles')
    @('Bloody / A4Tech', '%PROGRAMDATA%\Bloody7', 'onboard macro profiles')
    @('Glorious Core', '%APPDATA%\GloriousCore', 'device profiles with macros')
)
$script:macroExtList = @('.ahk', '.ahk2', '.au3', '.lua', '.vbs')

Build-LogPreFilter
# ---------------------------------------------------------------------------
# Reading Minecraft's own logs as evidence
#
# A log line survives the jar. Deleting a cheat before a screenshare removes the
# file, not the record that it loaded - and a log line is DATED, so it says the
# cheat was running at 20:14, which a file on disk never says.
#
# The whole difficulty is one thing: latest.log contains the chat. Somebody typing
# "killaura" into chat writes the word killaura into the log, and a scanner that
# matches module names there accuses people for what they SAID. That is the worst
# false flag this tool could produce, because it looks like hard evidence and comes
# with a timestamp on it.
#
# So: module names are never matched at all, chat lines are dropped before anything
# is tested, and a client name only counts inside a stack frame, a classloader
# line, a mixin config or a jar name. Mirrored from ml/logscan.py; parity is
# machine-checked by ml/test_logscan.py.
# ---------------------------------------------------------------------------
# A line the game logged as chat, or as a message from another player. Anything in
# here is something a HUMAN typed and is never evidence of anything.
$script:logChatLine = '\[CHAT\]|/INFO\]: <[^>]{1,32}>|\[Server thread/INFO\]: <|issued server command|\[Async Chat Thread|commands\.message|\bwhispers to you\b|\bwhispers:\b'
# A stack frame, a classloader line, a mixin config, a jar filename - the places a
# class name legitimately appears in a log.
$script:logCodeContext = '^\s*at\s+[\w$.]+\(|\bClassNotFoundException\b|\bNoClassDefFoundError\b|\bLoading\b.*\bmods?\b|\bmixin\b|\bMixin\b|\.jar\b|\bClassLoader\b|\bTransformer\b|\bCaused by:|\bjava\.lang\.|\bcom\.|\bnet\.|\borg\.|\bme\.|\bdev\.'
# "Loading 42 mods:" then "- modid 1.2.3" - Fabric and Forge both print this.
$script:logModListHeader = 'Loading \d+ mods?:|Mod List:|Loading Minecraft .* with'
$script:logModListItem = '^\s*[-│|]\s*([a-z0-9_-]{2,64})\s+([\w.+-]{1,32})\s*$'

# ---------------------------------------------------------------------------
# The parts of a Minecraft install that are NOT the mods folder
#
# Four things, all structural rather than fuzzy, because this directory is full of
# files every normal player has and none of them may be accused:
#   version profile   versions/<v>/<v>.json says which mainClass the launcher
#                     starts and which --tweakClass it passes. An injected client
#                     installs itself as a custom version profile and writes its
#                     own class name in there in plain text.
#   launcher profile  launcher_profiles.json can carry JVM arguments, and
#                     -javaagent: is how a ghost client gets attached to the game.
#   resource pack     a .zip in resourcepacks/ or shaderpacks/ containing .class or
#                     .jar entries. A pack is textures, sounds, json and shader
#                     source; Java classes in one are not a thing.
#   config folder     config/<name> named after a known client. A config folder
#                     outlives the jar - it is what is left when somebody deletes
#                     the mod and not its settings.
#
# Mirrored from ml/instscan.py; parity is machine-checked by ml/test_instscan.py.
# ---------------------------------------------------------------------------
# What a normal version profile starts. The list is not the test - the test is
# whether a CHEAT's own name is in there - but anything outside it is worth a look.
$script:instKnownMain = @(
    'cpw.mods.bootstraplauncher.BootstrapLauncher'
    'cpw.mods.modlauncher.Launcher'
    'io.github.zekerzhayard.forgewrapper.installer.Main'
    'net.fabricmc.loader.impl.launch.knot.KnotClient'
    'net.minecraft.client.main.Main'
    'net.minecraft.launchwrapper.Launch'
    'org.quiltmc.loader.impl.launch.knot.KnotClient'
)
$script:instJavaAgent  = '-javaagent:\s*([^\"'',\s\]]+)'
$script:instMainClass  = '"mainClass"\s*:\s*"([^"]+)"'
$script:instTweakClass = '--tweakClass["\s,:]+([\w.$]+)'
# Entries a resource pack has no business containing. .jar is in there because a
# pack that ships one is a jar in a costume.
$script:instPackExec   = '\.(class|jar|dll|so|dylib|exe)$'

$script:mlModelVersion = 2
$script:mlIntercept = -3.595535
$script:mlFeatureOrder = @('pkgpath','cheatsite','strong_sig','weak_sig','fullwidth_str','fullwidth_cls','japanese_cls','singlechar_cls','numeric_cls','novowel_cls','avg_entropy','high_entropy','reflection','runtime_exec','http_download','http_exfil','nested_hollow','fake_identity','filename_client','random_name','verified','legit_modid')
$script:mlWeights = @{
    'pkgpath' = 1.411735
    'cheatsite' = 1.414517
    'strong_sig' = 3.507748
    'weak_sig' = 2.269847
    'fullwidth_str' = 1.131481
    'fullwidth_cls' = 0.546677
    'japanese_cls' = 0.202722
    'singlechar_cls' = 1.922687
    'numeric_cls' = 0.605933
    'novowel_cls' = -0.66706
    'avg_entropy' = 0.781555
    'high_entropy' = 2.899511
    'reflection' = -1.485873
    'runtime_exec' = 1.274711
    'http_download' = 1.479519
    'http_exfil' = -0.239139
    'nested_hollow' = 2.615867
    'fake_identity' = 1.961105
    'filename_client' = 2.371303
    'random_name' = 0.0
    'verified' = -2.507493
    'legit_modid' = -2.338688
}
$script:mlBaseIntercept = $script:mlIntercept
$script:mlBaseWeights = @{}
foreach ($mlk in $script:mlWeights.Keys) { $script:mlBaseWeights[$mlk] = $script:mlWeights[$mlk] }
$script:mlSamples = 0
$script:RepoRaw = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml"

# Magic bytes for resource types a dropper likes to disguise its payload as. A file that claims one
# of these extensions but does not start with the right header is almost certainly a hidden blob.
$script:magicExt = @{
    'png'  = @(0x89, 0x50, 0x4E, 0x47)
    'gif'  = @(0x47, 0x49, 0x46, 0x38)
    'jpg'  = @(0xFF, 0xD8, 0xFF)
    'jpeg' = @(0xFF, 0xD8, 0xFF)
    'ogg'  = @(0x4F, 0x67, 0x67, 0x53)
    'wav'  = @(0x52, 0x49, 0x46, 0x46)
}
# Text resources should read as text (entropy well under 6). Ciphertext hidden in one spikes to ~8.
$script:textExt = @('json', 'txt', 'properties', 'cfg', 'toml', 'lang', 'mcmeta', 'md', 'yml', 'yaml', 'csv')

function Add-ScanGap([string]$What) {
    if (-not $script:ScanGaps.Contains($What)) { [void]$script:ScanGaps.Add($What) }
}

function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-SelfElevate {
    # Without admin the BAM history (which executables ran and were then deleted),
    # the Defender exclusion list and scheduled tasks cannot be read - and those are
    # exactly what a screenshare check needs. So ask Windows for elevation once.
    if ($script:NoElevate -or $script:_DevMode -or $script:SelfTestMode) { return $false }
    if (Test-IsAdmin) { return $false }

    W "  $([char]0x2139) Some checks need Administrator: which programs ran and were deleted" DarkGray
    W "    (BAM), Defender exclusions and scheduled tasks. Asking Windows for it now." DarkGray
    W "    Windows will show a UAC prompt. Decline and the scan simply continues" DarkGray
    W "    without those checks $([char]0x2014) it is not required. Use -NoElevate to skip asking." DarkGray
    Write-Host ""
    try {
        # The one-liner has no file on disk, so the elevated process re-fetches the
        # script. Say so plainly rather than doing it quietly.
        $flags = @()
        if ($script:DeepScan)   { $flags += '-DeepScan' }
        if ($script:Deep)       { $flags += '-Deep' }
        if ($script:DeepMemory) { $flags += '-DeepMemory' }
        if ($script:NoUpdate)   { $flags += '-NoUpdate' }
        if ($script:NoLearn)    { $flags += '-NoLearn' }
        if ($script:Share)      { $flags += '-Share' }
        $flags += '-NoElevate'          # the elevated run must never try to elevate again
        $url = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1"
        $inner = "& ([scriptblock]::Create((irm '$url'))) " + ($flags -join ' ')
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $inner) -ErrorAction Stop
        W "  $([char]0x2713) Continuing in the elevated window." Green
        return $true
    } catch {
        Add-ScanGap "Ran without Administrator $([char]0x2014) deleted-program history (BAM), Defender exclusions and scheduled tasks were NOT checked"
        W "  $([char]0x2139) Continuing without Administrator." DarkGray
        Write-Host ""
        return $false
    }
}

function Request-DeepEscalation([string]$Reason) {
    # Something turned up, so look harder for the rest of the run. This widens the
    # SEARCH only - it never lowers a scoring threshold, because that is how a
    # detector starts inventing false flags.
    if ($script:Deep -and $script:DeepScan) { return }
    $script:Deep         = $true
    $script:DeepScan     = $true
    $script:BcMaxClasses = 400
    if (-not $script:Escalated) {
        $script:Escalated = $true
        Write-Host ""
        W "  $([char]0x25B2) Going deeper by itself $([char]0x2014) $Reason" Yellow
        W "    (searching harder from here on; the scoring rules are unchanged)" DarkGray
        Write-Host ""
    }
}

function Set-AutoDepth {
    # Minecraft running means someone is being checked right now, so be thorough.
    # Nothing running means this is a self-check, so stay quick.
    $running = @(Get-Process -Name javaw, java -ErrorAction SilentlyContinue).Count -gt 0
    if ($running) {
        $script:Deep         = $true
        $script:DeepScan     = $true
        $script:BcMaxClasses = 400
        W "  $([char]0x25CF) Minecraft is running $([char]0x2014) running the full check by itself." Cyan
    } else {
        Add-ScanGap "Minecraft was not running $([char]0x2014) an injected client leaves nothing to find once the game is closed"
        W "  $([char]0x25CF) Minecraft is not running $([char]0x2014) quick check. It goes deeper on its own if anything turns up." DarkGray
    }
    Write-Host ""
    return $running
}

function Get-LearnPath {
    $dir = Join-Path $env:APPDATA "AsyncAnalyzer"
    if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch {} }
    return (Join-Path $dir "learned.json")
}

function Load-LearnState {
    if ($script:Reset) {
        try { $rp = Get-LearnPath; if (Test-Path $rp) { Remove-Item $rp -Force } } catch {}
        return
    }
    try {
        $lp = Get-LearnPath
        if (-not (Test-Path $lp)) { return }
        $st = Get-Content -Raw $lp -ErrorAction Stop | ConvertFrom-Json
        if ($st.knownGood)  { foreach ($h in $st.knownGood)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        if ($st.goodMeta)   { foreach ($gp in $st.goodMeta.PSObject.Properties) { $script:goodMeta[$gp.Name] = [string]$gp.Value } }
        if ($st.knownCheat) { foreach ($h in $st.knownCheat) { [void]$script:knownCheatHashes.Add([string]$h) } }
        if ($st.weights -and $st.modelVersion -ge $script:mlModelVersion) {
            foreach ($k in $script:mlFeatureOrder) {
                $wv = $st.weights.$k
                if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv }
            }
            if ($null -ne $st.intercept) { $script:mlIntercept = [double]$st.intercept }
            if ($null -ne $st.samples)   { $script:mlSamples = [int]$st.samples }
        }
        if ($st.sweights -and $st.sessionModelVersion -ge $script:smModelVersion) {
            foreach ($k in $script:smFeatureOrder) {
                $sv = $st.sweights.$k
                if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv }
            }
            if ($null -ne $st.sintercept) { $script:smIntercept = [double]$st.sintercept }
            if ($null -ne $st.ssamples)   { $script:smSamples = [int]$st.ssamples }
        }
    } catch {}
}

function Save-LearnState {
    try {
        $wobj = @{}
        foreach ($k in $script:mlFeatureOrder) { $wobj[$k] = [Math]::Round([double]$script:mlWeights[$k], 6) }
        $swobj = @{}
        foreach ($k in $script:smFeatureOrder) { $swobj[$k] = [Math]::Round([double]$script:smWeights[$k], 6) }
        $obj = [ordered]@{
            v = 1
            modelVersion = $script:mlModelVersion
            intercept = [Math]::Round([double]$script:mlIntercept, 6)
            weights = $wobj
            knownGood = @($script:knownGoodHashes)
            goodMeta = $script:goodMeta
            knownCheat = @($script:knownCheatHashes)
            samples = $script:mlSamples
            sessionModelVersion = $script:smModelVersion
            sintercept = [Math]::Round([double]$script:smIntercept, 6)
            sweights = $swobj
            ssamples = $script:smSamples
            updated = (Get-Date).ToString("s")
        }
        ($obj | ConvertTo-Json -Depth 5) | Out-File -FilePath (Get-LearnPath) -Encoding UTF8
    } catch {}
}

function Update-ModelOnline($raw, $label) {
    if ($script:NoLearn) { return }
    try {
        $lr = 0.08; $l2 = 0.02; $clamp = 8.0
        $z = [double]$script:mlIntercept
        foreach ($k in $script:mlFeatureOrder) { $z += [double]$script:mlWeights[$k] * [double]$raw[$k] }
        $p = if ($z -lt -60) { 0.0 } elseif ($z -gt 60) { 1.0 } else { 1.0 / (1.0 + [Math]::Exp(-$z)) }
        $err = $p - $label
        foreach ($k in $script:mlFeatureOrder) {
            $w = [double]$script:mlWeights[$k] - $lr * ($err * [double]$raw[$k] + $l2 * ([double]$script:mlWeights[$k] - [double]$script:mlBaseWeights[$k]))
            if ($w -gt $clamp) { $w = $clamp } elseif ($w -lt (-$clamp)) { $w = -$clamp }
            $script:mlWeights[$k] = $w
        }
        $script:mlIntercept = [double]$script:mlIntercept - $lr * ($err + $l2 * ([double]$script:mlIntercept - [double]$script:mlBaseIntercept))
        $script:mlSamples++
    } catch {}
}


# ---------------------------------------------------------------------------
# Session AI ("overall scan" model) - the SECOND model.
# The mod model scores ONE jar. This one scores the WHOLE scan: the mods plus
# every other stage (system checks, JVM injection, cheat processes, deleted
# executables, stray jars, cheat folders). It answers "does this PC look like
# someone is cheating?", not just "is this one file a cheat?" - and it learns
# from every finished scan, locally and (with team mode) across everyone.
# Source of truth for the weights: ml/session_model.py -> ml/session_model.json
# ---------------------------------------------------------------------------
$script:smModelVersion = 5
$script:smFeatureOrder = @('flagged_ratio','review_ratio','unverified_ratio','random_ratio','cheatsite_dl','hard_confirmed','sys_issues','jvm_inject','bam_deleted','cheat_procs','stray_jars','cheat_folders','deleted_jars','mc_running','mem_client','behaviour_cheat','behaviour_likely','server_rule','hidden_api','macro_cheat','log_cheat','instance_cheat')
$script:smIntercept = -4.0
$script:smWeights = @{
    'flagged_ratio' = 4
    'review_ratio' = 1.2
    'unverified_ratio' = 0.8
    'random_ratio' = 1.5
    'cheatsite_dl' = 3
    'hard_confirmed' = 4.5
    'sys_issues' = 1.2
    'jvm_inject' = 3
    'bam_deleted' = 1
    'cheat_procs' = 3.5
    'stray_jars' = 2
    'cheat_folders' = 3
    'deleted_jars' = 2.5
    'mc_running' = 0
    'mem_client' = 5
    'behaviour_cheat' = 4.5
    'behaviour_likely' = 2
    'server_rule' = 0.8
    'hidden_api' = 0.8
    'macro_cheat' = 4.5
    'log_cheat' = 5
    'instance_cheat' = 5
}
$script:smBaseWeights = @{}
foreach ($smk in $script:smWeights.Keys) { $script:smBaseWeights[$smk] = $script:smWeights[$smk] }
$script:smBaseIntercept = $script:smIntercept
$script:smSamples = 0

function Get-Clip01([double]$x) { if ($x -lt 0) { return 0.0 } elseif ($x -gt 1) { return 1.0 } else { return $x } }

function Get-SessionRaw {
    $ev = $script:Evidence
    return @{
        total_mods     = [int]$script:TotalMods
        verified       = [int]$script:Verified
        flagged        = [int]$script:Flagged
        review         = [int]$script:Review
        random_named   = [int]$ev.RandomNamed
        cheatsite_dl   = [int]$ev.CheatSiteDl
        hard_confirmed = [int]$ev.HardConfirmed
        sys_issues     = [int]$script:SystemIssues
        jvm_inject     = [int]$ev.JvmInject
        bam_deleted    = [int](@($script:BamDeleted).Count)
        cheat_procs    = [int]$ev.CheatProcs
        stray_jars     = [int]$ev.StrayJars
        cheat_folders  = [int]$ev.CheatFolders
        deleted_jars   = [int]$ev.DeletedJars
        mc_running     = $(if (@(Get-Process -Name javaw, java -ErrorAction SilentlyContinue).Count -gt 0) { 1 } else { 0 })
        mem_client     = [int]$ev.MemCheatClient
        # A click macro is not a mod, so it reaches the whole-scan verdict through
        # a hard rule rather than through the model - the model's 15 features are
        # trained and versioned, and one cannot be bolted on without retraining.
        macro_cheat    = [int]$ev.MacroCheat
        macro_named    = [int]$ev.MacroNamed
        # What the BEHAVIOUR rules found. These used to reach this model through
        # nothing but flagged_ratio, which a big modpack divides away: measured, a
        # 100-mod pack with ONE behaviour-confirmed aimbot in it scored 3/100 and
        # read Clean, while the same jar recognised by hash scored 85.
        behaviour_cheat  = [int]$ev.BehaviourCheat
        behaviour_likely = [int]$ev.BehaviourLikely
        server_rule      = [int]$script:ServerRule
        hidden_api       = [int]$ev.HiddenApi
        # The game's own logs. This is the evidence that survives deleting the jar:
        # a log line says the cheat LOADED, and says when.
        log_cheat        = [int]$script:LogHits
        # The rest of the .minecraft folder: a launcher profile that starts a
        # cheat's own class, a pack carrying bytecode, a config folder named after a
        # client. None of it is in the mods folder, all of it outlives the jar.
        instance_cheat   = [int]$script:InstanceHits
        instance_agent   = [int]$script:InstanceAgents
    }
}

function Get-SessionVector($raw) {
    $total = [int]$raw.total_mods
    $den = if ($total -gt 0) { [double]$total } else { 1.0 }
    $unver = if ($total -gt 0) { Get-Clip01 (([double]$total - [double]$raw.verified) / $den) } else { 0.0 }
    return @{
        flagged_ratio    = Get-Clip01 ([double]$raw.flagged / $den)
        review_ratio     = Get-Clip01 ([double]$raw.review / $den)
        unverified_ratio = $unver
        random_ratio     = Get-Clip01 ([double]$raw.random_named / $den)
        cheatsite_dl     = $(if ($raw.cheatsite_dl) { 1.0 } else { 0.0 })
        hard_confirmed   = $(if ($raw.hard_confirmed) { 1.0 } else { 0.0 })
        sys_issues       = Get-Clip01 ([Math]::Min([double]$raw.sys_issues, 10.0) / 10.0)
        jvm_inject       = Get-Clip01 ([Math]::Min([double]$raw.jvm_inject, 5.0) / 5.0)
        bam_deleted      = Get-Clip01 ([Math]::Min([double]$raw.bam_deleted, 10.0) / 10.0)
        cheat_procs      = Get-Clip01 ([Math]::Min([double]$raw.cheat_procs, 5.0) / 5.0)
        stray_jars       = Get-Clip01 ([Math]::Min([double]$raw.stray_jars, 3.0) / 3.0)
        cheat_folders    = Get-Clip01 ([Math]::Min([double]$raw.cheat_folders, 2.0) / 2.0)
        deleted_jars     = Get-Clip01 ([Math]::Min([double]$raw.deleted_jars, 3.0) / 3.0)
        mc_running       = $(if ($raw.mc_running) { 1.0 } else { 0.0 })
        mem_client       = $(if ($raw.mem_client) { 1.0 } else { 0.0 })
        behaviour_cheat  = $(if ($raw.behaviour_cheat) { 1.0 } else { 0.0 })
        behaviour_likely = $(if ($raw.behaviour_likely) { 1.0 } else { 0.0 })
        server_rule      = Get-Clip01 ([Math]::Min([double]$raw.server_rule, 2.0) / 2.0)
        hidden_api       = Get-Clip01 ([Math]::Min([double]$raw.hidden_api, 2.0) / 2.0)
        macro_cheat      = $(if ($raw.macro_cheat) { 1.0 } else { 0.0 })
        log_cheat        = $(if ($raw.log_cheat) { 1.0 } else { 0.0 })
        instance_cheat   = $(if ($raw.instance_cheat) { 1.0 } else { 0.0 })
    }
}

function Invoke-SessionModel($vec) {
    $z = [double]$script:smIntercept
    foreach ($k in $script:smFeatureOrder) { $z += [double]$script:smWeights[$k] * [double]$vec[$k] }
    if ($z -lt -60) { return 0.0 } elseif ($z -gt 60) { return 1.0 }
    return 1.0 / (1.0 + [Math]::Exp(-$z))
}

function Get-SessionVerdict($raw) {
    $vec = Get-SessionVector $raw
    $p = Invoke-SessionModel $vec
    $score = [int][Math]::Round($p * 100)
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($raw.hard_confirmed) { $score = [Math]::Max($score, 85); [void]$reasons.Add("A mod was confirmed as a cheat by a hard rule (hash / package path / cheat site)") }
    if ($raw.jvm_inject -gt 0)   { $score = [Math]::Max($score, 60); [void]$reasons.Add("Live JVM shows injection traces ($($raw.jvm_inject))") }
    if ($raw.cheat_procs -gt 0)  { $score = [Math]::Max($score, 60); [void]$reasons.Add("Known cheat process running ($($raw.cheat_procs))") }
    if ($raw.cheatsite_dl)       { $score = [Math]::Max($score, 60); [void]$reasons.Add("A mod was downloaded from a known cheat site") }
    if ($raw.stray_jars -gt 0 -or $raw.cheat_folders -gt 0) { $score = [Math]::Max($score, 30); [void]$reasons.Add("Cheat files outside the mods folder: $($raw.stray_jars) jar(s), $($raw.cheat_folders) folder(s)") }
    if ($raw.mem_client -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("A named cheat client was identified inside the RUNNING game's memory $([char]0x2014) it is loaded right now, whatever the mods folder looks like") }
    # A mod confirmed by its BEHAVIOUR is proof of the same order as a hash match,
    # and stronger in one way: it survives renaming and string encryption, a hash
    # does not. Before this rule, one behaviour-confirmed aimbot in a 100-mod pack
    # left the whole scan reading Clean at 3/100.
    if ($raw.behaviour_cheat -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("$($raw.behaviour_cheat) mod(s) confirmed as a cheat by what the code DOES $([char]0x2014) forged movement packets, a computed rotation, decrypt-then-load. That reading survives renaming and string encryption") }
    if ($raw.behaviour_likely -gt 0) { $score = [Math]::Max($score, 60); [void]$reasons.Add("$($raw.behaviour_likely) mod(s) whose behaviour matches a cheat pattern without being conclusive on its own") }
    # A server-rule finding is not an accusation, and this floor is not one either:
    # it puts the scan in front of a person, which is the whole purpose of the band.
    if ($raw.server_rule -gt 0) { $score = [Math]::Max($score, 30); [void]$reasons.Add("$($raw.server_rule) mod(s) recognised for certain whose legality is YOUR server's rule, not a technical question (ESP-shaped rendering, schematic printer) $([char]0x2014) not an accusation") }
    # Minecraft's own log naming a cheat package or client, in a code context. The
    # jar can be gone; the record that it loaded is not, and it is dated. Chat is
    # excluded before anything is matched, so this cannot be someone typing a cheat
    # name at another player.
    if ($raw.log_cheat -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("$($raw.log_cheat) cheat name(s) found in Minecraft's OWN logs $([char]0x2014) proof it was loaded, with a timestamp, whatever is in the mods folder now") }
    # The launcher profile that starts the cheat, the pack with bytecode in it, the
    # config folder named after a client. Written down before the game starts, and
    # left behind after the jar is gone.
    if ($raw.instance_cheat -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("$($raw.instance_cheat) thing(s) in the Minecraft folder outside mods name a cheat $([char]0x2014) a launcher profile that starts it, a pack carrying code, or its config folder") }
    # A -javaagent in a launcher profile is how a ghost client gets attached at
    # launch. One step below the rest, because a profiler or a dev setup can carry
    # one too - so it flags for a person and teaches the model nothing.
    if ($raw.instance_agent -gt 0) { $score = [Math]::Max($score, 60); [void]$reasons.Add("$($raw.instance_agent) launcher profile(s) attach a Java agent at startup $([char]0x2014) that is how an injected client is loaded, and the path is in the report") }
    # An autoclicker is not a mod and never shows up in the mods folder. A script
    # that repeats mouse input in a loop AND names the Minecraft window, the
    # launcher or javaw has no second reading.
    if ($raw.macro_cheat -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("$($raw.macro_cheat) click macro(s) that repeat mouse input in a loop and name Minecraft $([char]0x2014) an autoclicker, aimed at this game") }
    # Butterfly-click, blockhit, autocrystal and the rest are Minecraft terms. A file
    # with one of those names containing a click loop IS an autoclicker; what the file
    # alone does not prove is which game it was used in - which is a question for the
    # person reading the report, not a reason to score it lower.
    if ($raw.macro_named -gt 0) { $score = [Math]::Max($score, 85); [void]$reasons.Add("$($raw.macro_named) click macro(s) named after a cheat technique (autoclicker, blockhit, butterfly-click $([char]0x2026)) $([char]0x2014) the file says what it is; it does not say which game it was used in") }
    if ($raw.deleted_jars -gt 0 -and $raw.mc_running) { $score = [Math]::Max($score, 60); [void]$reasons.Add("$($raw.deleted_jars) .jar file(s) ran on this PC and were deleted while Minecraft is still running $([char]0x2014) the classic 'wiped it before the screenshare' pattern") }
    if ($raw.bam_deleted -gt 0)  { [void]$reasons.Add("$($raw.bam_deleted) executable(s) ran on this PC and were deleted afterwards") }
    if ($raw.flagged -gt 0)      { [void]$reasons.Add("$($raw.flagged) flagged mod(s)") }
    if ($raw.review -gt 0)       { [void]$reasons.Add("$($raw.review) mod(s) to review") }
    if ($raw.sys_issues -gt 0)   { [void]$reasons.Add("$($raw.sys_issues) system issue(s)") }
    if ($reasons.Count -eq 0)    { [void]$reasons.Add("Nothing cheat-like across mods, system, processes or history") }

    $band = if ($score -ge 85) { "Confirmed" } elseif ($score -ge 60) { "Likely" } elseif ($score -ge 30) { "Review" } else { "Clean" }
    return @{ Score = $score; Band = $band; Probability = [int][Math]::Round($p * 100); Reasons = $reasons; Vector = $vec }
}

function Get-SessionVerdictCached {
    if ($null -eq $script:SessionVerdict) {
        $script:SessionRaw = Get-SessionRaw
        $script:SessionVerdict = Get-SessionVerdict $script:SessionRaw
    }
    return $script:SessionVerdict
}

function Get-SessionLabel($raw) {
    # Only unambiguous scans teach the model - that is what stops it drifting.
    if ($raw.hard_confirmed -or $raw.jvm_inject -gt 0 -or $raw.cheat_procs -gt 0 -or $raw.mem_client -gt 0 -or
        $raw.macro_cheat -gt 0 -or $raw.behaviour_cheat -gt 0 -or $raw.log_cheat -gt 0 -or
        $raw.instance_cheat -gt 0) { return 1 }
    if ($raw.total_mods -gt 0 -and $raw.flagged -eq 0 -and $raw.review -eq 0 -and $raw.sys_issues -eq 0 -and
        $raw.bam_deleted -eq 0 -and $raw.stray_jars -eq 0 -and $raw.cheat_folders -eq 0 -and $raw.deleted_jars -eq 0 -and
        $raw.macro_cheat -eq 0 -and $raw.macro_named -eq 0 -and
        $raw.behaviour_cheat -eq 0 -and $raw.behaviour_likely -eq 0 -and $raw.server_rule -eq 0 -and
        $raw.log_cheat -eq 0 -and $raw.instance_cheat -eq 0 -and $raw.instance_agent -eq 0 -and
        [double]$raw.verified -ge (0.6 * [double]$raw.total_mods)) { return 0 }
    return -1
}

function Update-SessionModelOnline($vec, $label) {
    if ($script:NoLearn) { return }
    try {
        $lr = 0.05; $l2 = 0.02; $clamp = 8.0
        $p = Invoke-SessionModel $vec
        $err = $p - $label
        foreach ($k in $script:smFeatureOrder) {
            $w = [double]$script:smWeights[$k] - $lr * ($err * [double]$vec[$k] + $l2 * ([double]$script:smWeights[$k] - [double]$script:smBaseWeights[$k]))
            if ($w -gt $clamp) { $w = $clamp } elseif ($w -lt (-$clamp)) { $w = -$clamp }
            $script:smWeights[$k] = $w
        }
        $si = [double]$script:smIntercept - $lr * ($err + $l2 * ([double]$script:smIntercept - [double]$script:smBaseIntercept))
        if ($si -gt $clamp) { $si = $clamp } elseif ($si -lt (-$clamp)) { $si = -$clamp }
        $script:smIntercept = $si
        $script:smSamples++
    } catch {}
}

function Write-ScanGaps {
    if ($script:ScanGaps.Count -eq 0) { return }
    Write-Host ""
    W "  $([char]0x26A0) What this scan could NOT check:" Yellow
    foreach ($g in $script:ScanGaps) { W "    $([char]0x2022) $g" DarkYellow }
    W "    A clean result only covers what was actually checked." DarkGray
    Write-Host ""
}

function Save-ScanSummary($v) {
    # Nothing waits for a keypress any more, so if the window closes the result has
    # to survive somewhere. Plain text on purpose: readable without a browser.
    try {
        $dir = Join-Path $env:APPDATA "AsyncAnalyzer"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $out = [System.Collections.Generic.List[string]]::new()
        [void]$out.Add("AsyncAnalyzer $($script:Version)  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$out.Add("PC: $env:COMPUTERNAME   User: $env:USERNAME")
        [void]$out.Add("Scan ID: $($script:ScanId)" + $(if ($script:ScanCode) { "   Staff code: $($script:ScanCode)" } else { "   (no staff code was given)" }))
        foreach ($t in @($script:ScanTargets)) { [void]$out.Add("Scanned: $t") }
        [void]$out.Add("")
        if ($v) { [void]$out.Add("OVERALL: $($v.Band)  ($($v.Score)/100)") ; foreach ($r in $v.Reasons) { [void]$out.Add("  - $r") } }
        [void]$out.Add("")
        [void]$out.Add("Mods: $($script:TotalMods) total / $($script:Verified) verified / $($script:Review) review / $($script:Flagged) flagged")
        [void]$out.Add("System issues: $($script:SystemIssues)")
        if (@($flaggedMods).Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("FLAGGED:")
            foreach ($m in @($flaggedMods)) {
                [void]$out.Add("  $($m.FileName)  [$($m.Band) $($m.Score)/100]")
                foreach ($r in @($m.Reasons)) { [void]$out.Add("      - $r") }
            }
        }
        if (@($reviewMods).Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("REVIEW:")
            foreach ($m in @($reviewMods)) { [void]$out.Add("  $($m.FileName)  [$($m.Score)/100]") }
        }
        if ($script:ScanGaps.Count -gt 0) {
            [void]$out.Add(""); [void]$out.Add("NOT CHECKED:")
            foreach ($g in $script:ScanGaps) { [void]$out.Add("  - $g") }
        }
        $file = Join-Path $dir "last-scan.txt"
        $out -join "`r`n" | Out-File -FilePath $file -Encoding UTF8
        W "  $([char]0x2713) Result saved: $file" DarkGray
    } catch {}
}

function Write-SessionCard($v, $raw) {
    $w = 72
    $col = switch ($v.Band) { "Confirmed" { "Red" } "Likely" { "DarkYellow" } "Review" { "Yellow" } default { "Green" } }
    $label = switch ($v.Band) {
        "Confirmed" { "CHEATING CONFIRMED" }
        "Likely"    { "LIKELY CHEATING" }
        "Review"    { "NEEDS A MANUAL LOOK" }
        default     { "CLEAN $([char]0x2014) NOTHING FOUND" }
    }
    Write-Host ""
    W ("  $([char]0x2554)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x2557)") $col
    W ("  $([char]0x2551)" + "  OVERALL SCAN VERDICT (AI, whole scan)".PadRight($w + 1) + "$([char]0x2551)") Cyan
    W ("  $([char]0x2551)" + "  $label".PadRight($w + 1) + "$([char]0x2551)") $col
    W ("  $([char]0x2551)" + "  Score $($v.Score)/100    AI probability $($v.Probability)%".PadRight($w + 1) + "$([char]0x2551)") White
    W ("  $([char]0x2560)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x2563)") $col
    foreach ($r in $v.Reasons) {
        $line = "    $([char]0x2022) $r"
        if ($line.Length -gt $w) { $line = $line.Substring(0, $w - 3) + "..." }
        W ("  $([char]0x2551)" + $line.PadRight($w + 1) + "$([char]0x2551)") DarkGray
    }
    W ("  $([char]0x255A)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x255D)") $col
    Write-Host ""
}

function Invoke-CloudUpdate {
    if ($script:NoUpdate) { return }
    try {
        $m = Invoke-RestMethod -Uri "$($script:RepoRaw)/model.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($m.version -and ([int]$m.version) -gt $script:mlModelVersion -and $m.weights -and $m.feature_order) {
            $script:mlFeatureOrder = @($m.feature_order)
            foreach ($k in $script:mlFeatureOrder) {
                $wv = $m.weights.$k
                if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv; $script:mlBaseWeights[$k] = [double]$wv }
            }
            $script:mlIntercept = [double]$m.intercept; $script:mlBaseIntercept = [double]$m.intercept
            $script:mlModelVersion = [int]$m.version
            W "  $([char]0x2713) AI model auto-updated to v$($script:mlModelVersion) from GitHub." DarkGray
        }
    } catch {}
    try {
        $sm = Invoke-RestMethod -Uri "$($script:RepoRaw)/session_model.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($sm.version -and ([int]$sm.version) -gt $script:smModelVersion -and $sm.weights -and $sm.feature_order) {
            $script:smFeatureOrder = @($sm.feature_order)
            foreach ($k in $script:smFeatureOrder) {
                $sv = $sm.weights.$k
                if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv; $script:smBaseWeights[$k] = [double]$sv }
            }
            $script:smIntercept = [double]$sm.intercept; $script:smBaseIntercept = [double]$sm.intercept
            $script:smModelVersion = [int]$sm.version
            W "  $([char]0x2713) Overall-scan AI updated to v$($script:smModelVersion) from GitHub." DarkGray
        }
    } catch {}
    try {
        $s = Invoke-RestMethod -Uri "$($script:RepoRaw)/signatures.json" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($s.knownCheatHashes) { foreach ($h in $s.knownCheatHashes) { [void]$script:knownCheatHashes.Add([string]$h) } }
        if ($s.knownGoodHashes)  { foreach ($h in $s.knownGoodHashes)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        $sigGrew = $false
        if ($s.packagePaths)     { $script:cheatPackagePaths = @(@($script:cheatPackagePaths) + @($s.packagePaths) | Select-Object -Unique); $sigGrew = $true }
        if ($s.clientTokens)     { foreach ($t in $s.clientTokens) { [void]$script:distinctiveClientTokens.Add([string]$t) }; $sigGrew = $true }
        # The log pre-filter is built FROM those two lists, so a signature update
        # that adds a client without rebuilding it would leave the new name
        # unsearchable in logs - silently, because a pre-filter miss looks exactly
        # like a clean file.
        if ($sigGrew) { Build-LogPreFilter }
        if ($s.downloadDomains)  {
            foreach ($d in $s.downloadDomains) {
                if ($d.match -and $d.name) {
                    $script:cheatDomainMap += [PSCustomObject]@{ match = [string]$d.match; name = [string]$d.name }
                    if ($script:cheatDownloadSources -notcontains [string]$d.name) { $script:cheatDownloadSources += [string]$d.name }
                }
            }
        }
        if ($s.processNames)     { $script:pendingProcessNames = @($s.processNames) }
        if ($s.scanPaths)        { $script:PathsFromConfig = @($s.scanPaths) }
        if ($s.moduleNames) {
            # Cheat MODULE names confirmed in two independent open-source clients. The
            # list is curated for collisions on purpose - names like Timer/Step/Reach are
            # everyday identifiers and VeinMiner/Freecam are mods people actually run.
            $added = $false
            foreach ($mn in $s.moduleNames) {
                if ($mn -and $script:suspiciousPatterns -notcontains [string]$mn) {
                    $script:suspiciousPatterns += [string]$mn; $added = $true
                }
            }
            if ($added) { Build-PatternRegex }
        }
        if ($s.telemetry -and -not $env:ASYNCANALYZER_ENDPOINT) { $script:Telemetry = $s.telemetry }
    } catch {}

    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.pullSignatures -and $script:Telemetry.endpoint) {
        try {
            $ts = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/signatures" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($ts.knownCheatHashes) { foreach ($h in $ts.knownCheatHashes) { [void]$script:knownCheatHashes.Add([string]$h) } }
            if ($ts.knownGoodHashes)  { foreach ($h in $ts.knownGoodHashes)  { [void]$script:knownGoodHashes.Add([string]$h) } }
        } catch {}
    }

    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
        try {
            $tm = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/model" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($tm.weights -and $tm.feature_order) {
                $script:mlFeatureOrder = @($tm.feature_order)
                foreach ($k in $script:mlFeatureOrder) { $wv = $tm.weights.$k; if ($null -ne $wv) { $script:mlWeights[$k] = [double]$wv; $script:mlBaseWeights[$k] = [double]$wv } }
                $script:mlIntercept = [double]$tm.intercept; $script:mlBaseIntercept = [double]$tm.intercept
                W "  $([char]0x2713) Using team-trained AI model $([char]0x2014) learned from $($tm.trainedCount) samples across all team scans." DarkGray
            }
        } catch {}
        try {
            $tsm = Invoke-RestMethod -Uri "$($script:Telemetry.endpoint)/api/smodel" -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($tsm.weights -and $tsm.feature_order) {
                $script:smFeatureOrder = @($tsm.feature_order)
                foreach ($k in $script:smFeatureOrder) { $sv = $tsm.weights.$k; if ($null -ne $sv) { $script:smWeights[$k] = [double]$sv; $script:smBaseWeights[$k] = [double]$sv } }
                $script:smIntercept = [double]$tsm.intercept; $script:smBaseIntercept = [double]$tsm.intercept
                W "  $([char]0x2713) Overall-scan AI is team-trained $([char]0x2014) $($tsm.trainedCount) whole scans learned from." DarkGray
            }
        } catch {}
    }
}

function Get-MinecraftName {
    $roots = [System.Collections.Generic.List[string]]::new()
    [void]$roots.Add((Join-Path $env:APPDATA ".minecraft"))
    if ($ModPath) {
        $dir = Split-Path $ModPath -Parent
        for ($i = 0; $i -lt 3 -and $dir; $i++) {
            [void]$roots.Add($dir)
            $dir = Split-Path $dir -Parent
        }
    }
    foreach ($root in $roots) {
        foreach ($leaf in @("launcher_accounts.json", "launcher_accounts_microsoft_store.json")) {
            try {
                $f = Join-Path $root $leaf
                if (-not (Test-Path $f)) { continue }
                $j = Get-Content -Raw $f -ErrorAction Stop | ConvertFrom-Json
                $active = $j.activeAccountLocalId
                foreach ($acc in $j.accounts.PSObject.Properties.Value) {
                    if ($acc.localId -eq $active -and $acc.minecraftProfile.name) { return [string]$acc.minecraftProfile.name }
                }
                foreach ($acc in $j.accounts.PSObject.Properties.Value) {
                    if ($acc.minecraftProfile.name) { return [string]$acc.minecraftProfile.name }
                }
            } catch {}
        }
    }
    return ""
}

function Send-ScanResult {
    $t = $script:Telemetry
    if (-not $t -or -not $t.enabled -or -not $t.endpoint -or -not $t.key) { return }
    try {
        $verdict = if ($script:Flagged -gt 0) { "flagged" } elseif ($script:Review -gt 0) { "review" } else { "clean" }
        $mkMod = { param($m) @{ name = $m.FileName; score = $m.Score; band = $m.Band; probability = $m.Probability; hash = $m.Hash; reasons = @($m.Reasons) } }
        $payload = @{
            scanner      = $env:USERNAME
            targetUser   = (Get-MinecraftName)
            pcName       = $env:COMPUTERNAME
            modPath      = $ModPath
            verdict      = $verdict
            totals       = @{ total = $script:TotalMods; verified = $script:Verified; unknown = $script:Unknown; review = $script:Review; flagged = $script:Flagged; systemIssues = $script:SystemIssues }
            flagged      = @(@($flaggedMods) | ForEach-Object { & $mkMod $_ })
            review       = @(@($reviewMods)  | ForEach-Object { & $mkMod $_ })
            newCheat     = @($script:sessionCheat | Select-Object -Unique)
            newGood      = @($script:sessionGood  | Select-Object -Unique)
            samples      = @(@($script:sessionSamples) | Select-Object -First 400)
            session      = $(if ($script:SessionVerdict) { @{ score = $script:SessionVerdict.Score; band = $script:SessionVerdict.Band; probability = $script:SessionVerdict.Probability; reasons = @($script:SessionVerdict.Reasons) } } else { $null })
            sessionSample = $script:SessionSample
            sessionModelVersion = $script:smModelVersion
            scanId       = $script:ScanId
            scanCode      = $script:ScanCode
            toolVersion  = $script:Version
            modelVersion = $script:mlModelVersion
            clientTs     = (Get-Date).ToString("s")
        }
        $json = $payload | ConvertTo-Json -Depth 6 -Compress
        $r = Invoke-RestMethod -Uri "$($t.endpoint)/api/scan" -Method Post -Body $json -ContentType "application/json" -Headers @{ "x-key" = [string]$t.key } -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        if ($r.ok) { W "  $([char]0x2713) Result uploaded to the team dashboard (id $($r.id))." DarkGray }
    } catch { W "  $([char]0x26A0) Could not reach the team dashboard $([char]0x2014) result kept locally." DarkGray }
}
$script:mlFactorLabels = @{
    'pkgpath' = "cheat-client package path"
    'cheatsite' = "downloaded from a known cheat site"
    'strong_sig' = "distinctive cheat signatures"
    'weak_sig' = "multiple generic cheat indicators"
    'fullwidth_str' = "fullwidth-disguised cheat strings"
    'fullwidth_cls' = "fullwidth class-name obfuscation"
    'japanese_cls' = "Japanese class-name obfuscation"
    'singlechar_cls' = "single-letter class-name obfuscation"
    'numeric_cls' = "numeric class-name obfuscation"
    'high_entropy' = "encrypted/packed classes (high entropy)"
    'avg_entropy' = "elevated class entropy"
    'runtime_exec' = "runs OS commands (Runtime.exec)"
    'http_download' = "downloads and writes files at runtime"
    'http_exfil' = "sends data to an external server"
    'nested_hollow' = "hollow shell wrapping a hidden jar"
    'fake_identity' = "fake mod identity"
    'filename_client' = "filename of a known cheat client"
}

function Invoke-MlModel($raw) {
    $z = [double]$script:mlIntercept
    foreach ($k in $script:mlFeatureOrder) {
        $v = if ($raw.ContainsKey($k)) { [double]$raw[$k] } else { 0.0 }
        $z += [double]$script:mlWeights[$k] * $v
    }
    if ($z -lt -60) { return 0.0 }
    if ($z -gt 60)  { return 1.0 }
    return 1.0 / (1.0 + [Math]::Exp(-$z))
}

# ---------------------------------------------------------------------------
# Behavioural bytecode analysis - reads what a mod DOES, not what it says.
#
# String scraping loses to any cheat that encrypts its strings. The constant
# pool does not: to call a Minecraft method you must name it there. You can
# obfuscate your own symbols; you cannot obfuscate the API you call.
#
# Only the constant pool is parsed. It sits at the head of every class file, so
# this stays affordable even over a large mods folder.
# ---------------------------------------------------------------------------
$script:bcBehaviour = [ordered]@{
    'movepacket' = 'ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828|C03PacketPlayer|CPacketPlayer'
    'rotation'   = '\.setYRot|\.setXRot|\.setYaw|\.setPitch|\.method_36456|\.method_36457|\.rotationYaw\b|\.rotationPitch\b|\.rotationYawHead\b'
    # A bare '\.swing' matched javax/swing and any field called swingGui - rhino's
    # debugger UI tripped it. Qualified to the actual Minecraft method, so a Swing
    # application in a mods folder cannot look like combat code.
    'attack'     = 'MultiPlayerGameMode\.attack|ServerboundInteractPacket|PlayerInteractEntityC2SPacket|class_2824|(?:LocalPlayer|Player|LivingEntity)\.swing\b|\.swingHand\b|\.method_6104\b|C02PacketUseEntity|CPacketUseEntity|PlayerControllerMP|\.swingItem\b|\.attackEntity\b'
    # Both Wurst and Meteor hook the network layer itself, not just the listener.
    # Qualified on purpose - a bare 'Connection' is an everyday identifier.
    'pktlisten'  = 'ClientPacketListener|ClientPlayNetworkHandler|class_634|net/minecraft/network/Connection|class_2535|NetHandlerPlayClient|net/minecraft/network/NetworkManager'
    'entityscan' = 'entitiesForRendering|getEntities|method_18112|\.getEntityList|\.loadedEntityList\b|\.getLoadedEntityList\b|\.playerEntities\b'
    'render'     = 'VertexConsumer|RenderSystem|BufferBuilder|MatrixStack|PoseStack|Tessellator|class_4587|GlStateManager|WorldRenderer'
    'input'      = 'KeyMapping|KeyBinding|GLFW\.glfwGetKey|\.isPressed|client/input|class_304|client/KeyboardHandler|client/MouseHandler|Keyboard\.isKeyDown|GameSettings\.'
    'reflect'    = 'java/lang/reflect|\.getDeclaredMethod|\.setAccessible|Class\.forName|MethodHandles|\.getDeclaredField'
    'classload'  = '\.defineClass|URLClassLoader|defineAnonymousClass|\.defineHiddenClass'
    'crypto'     = 'javax/crypto|Cipher\.|SecretKeySpec|IvParameterSpec'
    'exec'       = 'Runtime\.getRuntime|ProcessBuilder|Runtime\.exec'
    'net'        = 'java/net/Socket|HttpURLConnection|\.openConnection|java/net/http|URL\.openStream'
    'unsafe'     = 'sun/misc/Unsafe|jdk/internal/misc/Unsafe'
    'instrument' = 'java/lang/instrument|Instrumentation\.'
    # Minecraft-specific API names on purpose. A behaviour category only earns its
    # place if a real Maven library cannot match it by accident - these name packets
    # and interaction-manager methods that exist nowhere outside the game.
    'blockplace' = 'ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885|\.useItemOn|\.interactBlock|\.method_2896|C08PacketPlayerBlockPlacement|CPacketPlayerTryUseItemOnBlock|\.onPlayerRightClick\b'
    'blockbreak' = 'ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|\.startDestroyBlock|\.destroyBlock|\.method_2910|C07PacketPlayerDigging|CPacketPlayerDigging|\.onPlayerDamageBlock\b|\.clickBlock\b'
    'container'  = 'ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|ScreenHandler|class_1703|C0EPacketClickWindow|CPacketClickWindow|\.windowClick\b|InventoryPlayer'
    'motion'     = '\.setDeltaMovement|\.getDeltaMovement|\.setVelocity|\.method_18800|\.method_18798|\.motionX\b|\.motionY\b|\.motionZ\b'
    # A jar working out where its own file is. Ordinary code has no reason to - it
    # is how something finds itself in order to delete itself.
    'selfpath'   = '\.getProtectionDomain|\.getCodeSource|ProtectionDomain|CodeSource'
    'filedelete' = 'File\.delete|\.deleteOnExit|Files\.delete|Files\.deleteIfExists'
    # Unpacking a bundled native library and cleaning up the copy afterwards. This
    # is the innocent reason a class locates its own jar and then deletes a file,
    # and naming it is what lets the self-wipe signal exclude it.
    'nativetemp' = 'createTempFile|createTempDirectory|System\.load|\.loadLibrary|java\.io\.tmpdir'
    # Opening or writing an archive. A mod loader, a remapper or a shader cache
    # legitimately locates its own jar and deletes files - it is tooling that
    # processes archives for a living. A client deleting itself never opens one.
    'archive'    = 'java/util/jar|java/util/zip|JarFile|ZipFile|JarOutputStream|ZipOutputStream|JarInputStream|ZipInputStream|JarEntry|ZipEntry'
    # This class is a Mixin - it does not call the game, it is COMPILED INTO it.
    # Neutral on its own: Sodium, Lithium and the Fabric API itself are nothing but
    # mixins. It matters for what it does to the evidence, below.
    'mixin'      = 'org/spongepowered/asm/mixin'
    # The third way into the game's code, next to Mixin and a Java agent: a Forge
    # coremod or a LaunchWrapper tweaker installs a CLASS TRANSFORMER that runs
    # before the game and can rewrite any class on the way in. Neutral on its own -
    # OptiFine is a tweaker - and, like a mixin, it names its targets as strings.
    'transformer' = 'IClassTransformer|IFMLLoadingPlugin|ITransformer|net/minecraftforge/coremod|cpw/mods/modlauncher|net/minecraft/launchwrapper|LaunchClassLoader'
}
# Derived per-class signals. Not patterns: combinations that only mean something
# when ONE class does all of it. Jar-level ratios cannot express that - in a large
# library "something locates its own jar" and "something deletes a file" are
# usually unrelated classes, which is exactly how the first version of this signal
# matched sixteen legitimate bytecode libraries.
$script:bcDerived = @('selfwipe', 'hiddenapi', 'mixintarget', 'coretarget')

# --- reflective use of the same API ------------------------------------------
#
# The table above reads the constant pool's SYMBOL TABLE. That is what makes it
# survive obfuscation of a cheat's own names: to call a Minecraft method you must
# name it there.
#
# You can avoid naming it there at all, though. Class.forName("net.minecraft...")
# plus getDeclaredMethod("setYRot") moves every one of those names into STRING
# constants and the rules stop seeing them. Measured: an aim cheat rewritten that
# way scored Clean, 3/100 - one refactor evaded all twelve rules.
#
# Same vocabulary, matched against strings, minus the leading "\." that anchors a
# member ref - a reflective call names the method bare. Only the categories a
# cheat needs: a mod calling Class.forName to see whether another mod is present
# is ordinary, one reflectively assembling a movement packet is not.
$script:bcReflectiveApi = [ordered]@{
    'movepacket' = 'ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828|C03PacketPlayer|CPacketPlayer'
    'rotation' = '\bsetYRot\b|\bsetXRot\b|\bmethod_36456\b|\bmethod_36457\b|\brotationYaw\b|\brotationPitch\b'
    'attack' = 'ServerboundInteractPacket|PlayerInteractEntityC2SPacket|class_2824|MultiPlayerGameMode|\bswingHand\b|\bmethod_6104\b|C02PacketUseEntity|CPacketUseEntity|PlayerControllerMP|\bswingItem\b'
    'motion' = '\bsetDeltaMovement\b|\bgetDeltaMovement\b|\bmethod_18800\b|\bmethod_18798\b|\bmotionX\b|\bmotionY\b|\bmotionZ\b'
    'blockplace' = 'ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885|\bmethod_2896\b|C08PacketPlayerBlockPlacement|CPacketPlayerTryUseItemOnBlock'
    'blockbreak' = 'ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|\bmethod_2910\b|C07PacketPlayerDigging|CPacketPlayerDigging'
    'container' = 'ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|C0EPacketClickWindow|CPacketClickWindow'
    'pktlisten' = 'ClientPacketListener|ClientPlayNetworkHandler|class_634|class_2535|NetHandlerPlayClient'
}

# --- what a mixin names, and why the symbol table does not see it -------------
#
# A Mixin is not a mod calling the game. It is code the loader COMPILES INTO a
# game class. That changes where the evidence lives, and it opens the same hole
# reflection did.
#
# A mixin names its target in an ANNOTATION - @Mixin(ServerboundMovePlayerPacket.class)
# or @Mixin(targets = "net.minecraft...") - and its injection point by method NAME
# in @Inject(method = "aiStep"). Annotation values are Utf8 constants, not Class
# entries or member refs, so none of it reaches the symbol table. Everything it
# touches inside the target it reaches through @Shadow members declared on ITSELF,
# which resolve to the mixin class rather than to Minecraft.
#
# Worked example, and the reason this exists: silent rotations. Mixin into
# ServerboundMovePlayerPacket, shadow the yRot field, overwrite it in the
# constructor. Your view never turns; the server is told it did. Read through the
# symbol table that class calls nothing - movepacket 0, rotation 0 - and every
# combat rule is blind to it.
#
# Same vocabulary as the reflective table, matched against a mixin's strings, plus
# the movement path a mixin names at its injection point. NOT treated as hiding
# anything: naming your target in an annotation is how mixins are written.
$script:bcMixinApi = [ordered]@{
    'movepacket' = 'ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828|C03PacketPlayer|CPacketPlayer'
    'rotation' = '\bsetYRot\b|\bsetXRot\b|\bmethod_36456\b|\bmethod_36457\b|\brotationYaw\b|\brotationPitch\b'
    'attack' = 'ServerboundInteractPacket|PlayerInteractEntityC2SPacket|class_2824|MultiPlayerGameMode|\bswingHand\b|\bmethod_6104\b|C02PacketUseEntity|CPacketUseEntity|PlayerControllerMP|\bswingItem\b'
    'motion' = '\bsetDeltaMovement\b|\bgetDeltaMovement\b|\bmethod_18800\b|\bmethod_18798\b|\bdeltaMovement\b|\baiStep\b|\bmethod_6091\b'
    'blockplace' = 'ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885|\bmethod_2896\b|C08PacketPlayerBlockPlacement|CPacketPlayerTryUseItemOnBlock'
    'blockbreak' = 'ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|\bmethod_2910\b|C07PacketPlayerDigging|CPacketPlayerDigging'
    'container' = 'ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|C0EPacketClickWindow|CPacketClickWindow'
    'pktlisten' = 'ClientPacketListener|ClientPlayNetworkHandler|class_634|class_2535|NetHandlerPlayClient'
}
# Shadowed rotation FIELD names - and only for a mixin that targets an outgoing
# movement packet.
#
# The narrowing is the whole point. Plenty of legitimate mods shadow yRot: any
# camera, freelook or perspective mod names the same field, and reading a bare
# 'yRot' as "writes rotation" would accuse all of them. But a mixin whose target
# is the packet that REPORTS your rotation to the server, naming that packet's
# rotation fields, is rewriting what the server is told you are looking at. That
# is silent rotations, and it is the one shape a camera mod never has - a camera
# mixes into the player or the renderer, never into the outgoing packet.
$script:bcMixinPacketApi = @{
    'rotation' = '\byRot\b|\bxRot\b|\bfield_5982\b|\bfield_6031\b'
}
# Which part of the game a mixin injects into. Not a rule and not scored - it is
# for the moderator reading the report, because "rewrites the network handler and
# the player's movement" and "rewrites the options screen" are different mods and
# the score alone does not say which one is on the screen.
$script:bcMixinArea = [ordered]@{
    'player movement' = 'LocalPlayer|ClientPlayerEntity|class_746|LivingEntity|class_1309|\baiStep\b|\btravel\b|\bdeltaMovement\b|MovementInput|class_744|EntityPlayerSP|EntityLivingBase|\bmotionX\b|\brotationYaw\b'
    'network handler' = 'ClientPacketListener|ClientPlayNetworkHandler|class_634|class_2535|net/minecraft/network|Serverbound|C2SPacket|ClientboundS2CPacket|S2CPacket|NetHandlerPlayClient|C0[0-9A-F]Packet|CPacketPlayer'
    'world / blocks'  = 'ClientLevel|ClientWorld|class_638|BlockState|class_2680|ChunkRenderer|LevelChunk|WorldClient|RenderChunk|ChunkRenderDispatcher'
    'rendering'       = 'LevelRenderer|WorldRenderer|GameRenderer|EntityRenderer|class_761|class_757|RenderSystem|GuiGraphics|class_332|RenderGlobal|GlStateManager|GuiIngame'
    'inventory / containers' = 'AbstractContainerMenu|ScreenHandler|class_1703|Inventory|class_1661|InventoryPlayer|GuiContainer'
    'menus / screens' = 'net/minecraft/client/gui/screens|client/gui/screen|class_437|OptionsScreen|TitleScreen|GuiScreen|GuiMainMenu|GuiOptions'
}
# Names a dropper reaches REFLECTIVELY, so they land in a string constant rather
# than a Methodref. Deliberately tiny - broad names like setAccessible are
# everyday library code and would drag legitimate jars in.
$script:bcReflectiveNames = @{
    'classload'  = '^(defineClass|defineAnonymousClass|defineHiddenClass)$'
    'instrument' = '^(premain|agentmain|retransformClasses)$'
}

# Cheap pre-filter run over the raw decompressed head of EVERY class.
#
# Fully parsing every constant pool is not affordable here: a 200-mod pack is
# ~44k classes and real jars run to a median of 218 classes each. But sampling is
# worse than slow, it is WRONG - a cheat whose aura module sits at class #150 is
# invisible to a 40-class sample, which measured out as completely undetected.
#
# So every class gets searched cheaply and only matches get parsed precisely.
# Sound because these are API names: the JVM resolves classes and methods BY NAME,
# so they must appear literally in the pool. A cheat can encrypt its own strings;
# it cannot encrypt the Minecraft API it calls.
$script:bcPreFilter = [regex]::new(
    ('ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828|setYRot|setXRot|setYaw|setPitch|' +
     'method_36456|method_36457|MultiPlayerGameMode|ServerboundInteractPacket|' +
     'PlayerInteractEntityC2SPacket|class_2824|ClientPacketListener|ClientPlayNetworkHandler|class_634|' +
     'net/minecraft/network/Connection|class_2535|KeyboardHandler|MouseHandler|entitiesForRendering|' +
     'getEntities|method_18112|getEntityList|VertexConsumer|RenderSystem|BufferBuilder|MatrixStack|' +
     'PoseStack|Tessellator|class_4587|KeyMapping|KeyBinding|glfwGetKey|isPressed|client/input|class_304|' +
     'java/lang/reflect|getDeclaredMethod|setAccessible|forName|MethodHandles|getDeclaredField|defineClass|' +
     'URLClassLoader|defineAnonymousClass|defineHiddenClass|javax/crypto|Cipher|SecretKeySpec|' +
     'IvParameterSpec|getRuntime|ProcessBuilder|java/net/Socket|HttpURLConnection|openConnection|' +
     'java/net/http|openStream|sun/misc/Unsafe|jdk/internal/misc/Unsafe|java/lang/instrument|' +
     'Instrumentation|premain|agentmain|retransformClasses|ServerboundUseItemOnPacket|' +
     'PlayerInteractBlockC2SPacket|class_2885|useItemOn|interactBlock|method_2896|' +
     'ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|startDestroyBlock|destroyBlock|' +
     'method_2910|ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|' +
     'ScreenHandler|class_1703|setDeltaMovement|getDeltaMovement|setVelocity|method_18800|method_18798|' +
     'getProtectionDomain|getCodeSource|ProtectionDomain|CodeSource|deleteOnExit|deleteIfExists|' +
     'createTempFile|createTempDirectory|loadLibrary|tmpdir|java/util/jar|java/util/zip|JarFile|ZipFile|' +
     'JarOutputStream|ZipOutputStream|JarInputStream|ZipInputStream|JarEntry|ZipEntry|' +
     'org/spongepowered/asm/mixin|swingHand|method_6104|getLoadedEntityList|IClassTransformer|' +
     'IFMLLoadingPlugin|ITransformer|net/minecraftforge/coremod|cpw/mods/modlauncher|' +
     'net/minecraft/launchwrapper|LaunchClassLoader|C03PacketPlayer|CPacketPlayer|rotationYaw|' +
     'rotationPitch|C02PacketUseEntity|CPacketUseEntity|PlayerControllerMP|swingItem|attackEntity|' +
     'NetHandlerPlayClient|NetworkManager|loadedEntityList|playerEntities|GlStateManager|WorldRenderer|' +
     'isKeyDown|GameSettings|C08PacketPlayerBlockPlacement|CPacketPlayerTryUseItemOnBlock|' +
     'onPlayerRightClick|C07PacketPlayerDigging|CPacketPlayerDigging|onPlayerDamageBlock|clickBlock|' +
     'C0EPacketClickWindow|CPacketClickWindow|windowClick|InventoryPlayer|motionX|motionY|motionZ'),
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Read-ClassConstantPool([byte[]]$b) {
    # returns @{ Symbols = <string>; Strings = @(...) } or $null when unparseable
    if ($null -eq $b -or $b.Length -lt 10) { return $null }
    if ($b[0] -ne 0xCA -or $b[1] -ne 0xFE -or $b[2] -ne 0xBA -or $b[3] -ne 0xBE) { return $null }
    # Inlined 2-byte big-endian reads. A scriptblock call per read costs more than
    # the parse itself once a constant pool runs to thousands of entries.
    $count = ([int]$b[8] -shl 8) -bor [int]$b[9]
    $pos = 10
    $tags = New-Object 'int[]' ($count + 1)
    $utf  = New-Object 'string[]' ($count + 1)
    $refA = New-Object 'int[]' ($count + 1)
    $refB = New-Object 'int[]' ($count + 1)
    $i = 1
    while ($i -lt $count) {
        if ($pos -ge $b.Length) { return $null }
        $tag = [int]$b[$pos]; $pos++
        $tags[$i] = $tag
        switch ($tag) {
            1 {
                $len = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $pos += 2
                if ($pos + $len -gt $b.Length) { return $null }
                $utf[$i] = [System.Text.Encoding]::UTF8.GetString($b, $pos, $len)
                $pos += $len
            }
            7  { $refA[$i] = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $pos += 2 }
            8  { $pos += 2 }
            9  { $refA[$i] = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $refB[$i] = ([int]$b[$pos + 2] -shl 8) -bor [int]$b[$pos + 3]; $pos += 4 }
            10 { $refA[$i] = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $refB[$i] = ([int]$b[$pos + 2] -shl 8) -bor [int]$b[$pos + 3]; $pos += 4 }
            11 { $refA[$i] = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $refB[$i] = ([int]$b[$pos + 2] -shl 8) -bor [int]$b[$pos + 3]; $pos += 4 }
            12 { $refA[$i] = ([int]$b[$pos] -shl 8) -bor [int]$b[$pos + 1]; $refB[$i] = ([int]$b[$pos + 2] -shl 8) -bor [int]$b[$pos + 3]; $pos += 4 }
            15 { $pos += 3 }
            16 { $pos += 2 }
            17 { $pos += 4 }
            18 { $pos += 4 }
            19 { $pos += 2 }
            20 { $pos += 2 }
            3  { $pos += 4 }
            4  { $pos += 4 }
            5  { $pos += 8; $i++ }   # long and double take two pool slots
            6  { $pos += 8; $i++ }
            default { return $null }
        }
        $i++
    }
    $sb = New-Object System.Text.StringBuilder
    $strings = [System.Collections.Generic.List[string]]::new()
    for ($k = 1; $k -lt $count; $k++) {
        switch ($tags[$k]) {
            1 { [void]$strings.Add($utf[$k]) }
            7 { [void]$sb.AppendLine($utf[$refA[$k]]) }
            { $_ -in 9, 10, 11 } {
                $ci = $refA[$k]; $ni = $refB[$k]
                if ($tags[$ci] -eq 7 -and $tags[$ni] -eq 12) {
                    [void]$sb.AppendLine(($utf[$refA[$ci]] + "." + $utf[$refA[$ni]]))
                }
            }
        }
    }
    return @{ Symbols = $sb.ToString(); Strings = $strings }
}

function Add-DiskPackages([string]$JarPath) {
    # Entry names only - no decompression, no parsing. Cheap enough to run on every
    # jar including verified ones, which is required: a verified minimap's packages
    # being on disk is exactly what makes an absent package meaningful.
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
    } catch { return }
    try {
        foreach ($e in $zip.Entries) {
            $fn = $e.FullName
            if (-not $fn.EndsWith('.class')) { continue }
            $parts = $fn.Split('/')
            if ($parts.Count -ge 2) { [void]$script:DiskPackages.Add(($parts[0] + '/' + $parts[1])) }
            if ($parts.Count -ge 3) { [void]$script:DiskPackages.Add(($parts[0] + '/' + $parts[1] + '/' + $parts[2])) }
            if ($parts.Count -ge 1) { [void]$script:DiskPackages.Add($parts[0]) }
        }
    } finally { $zip.Dispose() }
}

function Test-LoadedFromDisk([string]$Token) {
    # Could anything on disk have supplied classes for this name?
    if ($script:DiskPackages.Count -eq 0) { return $true }   # nothing scanned -> cannot claim
    $t = ($Token -replace '[^A-Za-z0-9]', '').ToLower()
    if ($t.Length -lt 4) { return $true }
    foreach ($p in $script:DiskPackages) {
        if ((($p -replace '[^A-Za-z0-9]', '').ToLower()) -like "*$t*") { return $true }
    }
    return $false
}

# The class or classes a rule actually fired on, as a phrase to append to its
# reason line. A rule that pairs two behaviours is only answered by a class that
# carries both, so the caller passes the same categories the rule tested.
function Get-BcWitness($Bc, [string[]]$Cats, [int]$Max = 2) {
    if ($null -eq $Bc -or -not $Bc.ContainsKey('ClassHits')) { return "" }
    $out = [System.Collections.Generic.List[string]]::new()
    # Sorted, so two scans of the same jar name the same class.
    foreach ($cn in @($Bc.ClassHits.Keys | Sort-Object)) {
        $have = @($Bc.ClassHits[$cn])
        $all = $true
        foreach ($c in $Cats) { if ($have -notcontains $c) { $all = $false; break } }
        if ($all) {
            [void]$out.Add($cn)
            if ($out.Count -ge $Max) { break }
        }
    }
    if ($out.Count -gt 0) { return " [in $($out -join ', ')]" }
    # The rules compare jar-wide RATIOS, so the two halves of a pair can sit in
    # different classes. Say which, rather than saying nothing: one class doing
    # both is a sharper fact than two classes doing one each, and a person
    # reading the report should be able to tell those apart.
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $Cats) {
        $where = [System.Collections.Generic.List[string]]::new()
        foreach ($cn in @($Bc.ClassHits.Keys | Sort-Object)) {
            if (@($Bc.ClassHits[$cn]) -contains $c) {
                [void]$where.Add($cn)
                if ($where.Count -ge $Max) { break }
            }
        }
        if ($where.Count -gt 0) { [void]$parts.Add("$c in $($where -join ', ')") }
    }
    if ($parts.Count -eq 0) { return "" }
    return " [$($parts -join '; ')]"
}

function Get-BytecodeFeatures([string]$JarPath, [int]$MaxClasses = 40) {
    $f = @{ ClassesParsed = 0; ClassesFailed = 0; ObfNameRatio = 0.0
            StrReadableRatio = 0.0; StrEntropy = 0.0
            MixinAreas = [System.Collections.Generic.List[string]]::new()
            # Which class each behaviour was seen in. The rules combine two
            # categories ("forges movement AND writes a rotation"), so what a
            # person needs in order to check the finding themselves is the class
            # that carries BOTH - see Get-BcWitness. Without it the report says
            # "a class in here", which is not something anyone can verify.
            ClassHits = @{} }
    foreach ($k in $script:bcBehaviour.Keys) { $f[$k] = 0; $f[$k + 'Ratio'] = 0.0 }
    foreach ($k in $script:bcDerived) { $f[$k] = 0; $f[$k + 'Ratio'] = 0.0 }
    $short = 0; $names = 0; $readable = 0; $totalStr = 0; $entSum = 0.0; $entN = 0
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
    } catch { return $f }
    try {
        $classEntries = @($zip.Entries | Where-Object { $_.FullName.EndsWith('.class') })
        # Stratified, not first-N: nothing says a cheat's modules sit at the front of
        # the archive. MaxClasses now bounds only how many classes get their STRING
        # statistics measured - an average, which does not need full coverage.
        $statIdx = @{}
        if ($MaxClasses -gt 0 -and $classEntries.Count -gt $MaxClasses) {
            $step = [double]$classEntries.Count / [double]$MaxClasses
            for ($q = 0; $q -lt $MaxClasses; $q++) { $statIdx[[int]($q * $step)] = $true }
        } else {
            for ($q = 0; $q -lt $classEntries.Count; $q++) { $statIdx[$q] = $true }
        }
        $ei = -1
        foreach ($e in $classEntries) {
            $ei++
            if ($e.Length -gt 8MB) { $f.ClassesFailed++; continue }
            $bytes = $null
            try {
                # The pool sits at the head of a class file, and most of a large class is
                # method bytecode we never look at, so read a bounded prefix.
                $cap = [int][Math]::Min([int64]$e.Length, 262144)
                $bytes = New-Object byte[] $cap
                $st = $e.Open()
                $got = 0
                while ($got -lt $cap) {
                    $r = $st.Read($bytes, $got, $cap - $got)
                    if ($r -le 0) { break }
                    $got += $r
                }
                $st.Close()
                if ($got -lt $cap) { $bytes = $bytes[0..([Math]::Max($got - 1, 0))] }
            } catch { $bytes = $null }
            if ($null -eq $bytes -or $bytes.Length -lt 10) { $f.ClassesFailed++; continue }

            # cheap native scan of every class; precise parse only where it matters
            $head = [System.Text.Encoding]::ASCII.GetString($bytes)
            $hot = $script:bcPreFilter.IsMatch($head)
            $simple = [System.IO.Path]::GetFileNameWithoutExtension($e.FullName)
            if (-not $hot -and -not $statIdx.ContainsKey($ei)) {
                $f.ClassesParsed++
                $names++
                if ($simple.Length -le 2) { $short++ }
                continue
            }
            $cp = $null
            try { $cp = Read-ClassConstantPool $bytes } catch { $cp = $null }
            if ($null -eq $cp) { $f.ClassesFailed++; continue }
            $f.ClassesParsed++
            $hit = @{}
            foreach ($k in $script:bcBehaviour.Keys) {
                if ($cp.Symbols -match $script:bcBehaviour[$k]) { $hit[$k] = $true }
            }
            # Reflective use of the same API. Only counts when this class actually
            # reflects - a string alone is a mention, reflection makes it a call.
            $sblob = $null
            if ($hit['reflect']) {
                $sblob = ($cp.Strings | Where-Object { $_.Length -lt 200 }) -join "`n"
                foreach ($rk in $script:bcReflectiveApi.Keys) {
                    if (-not $hit[$rk] -and $sblob -match $script:bcReflectiveApi[$rk]) {
                        $hit[$rk] = $true
                        $hit['hiddenapi'] = $true
                    }
                }
            }
            # A mixin declares its target in an annotation, so the target reaches the
            # constant pool as a string and never as a symbol. Same vocabulary, same
            # treatment - but NOT recorded as hiding anything: naming your target in
            # an annotation is how mixins are written, not evasion.
            # The marker is a literal byte sequence in the pool, so the raw head the
            # pre-filter already read finds it in one search.
            if (-not $hit['mixin'] -and $head.IndexOf('org/spongepowered/asm/mixin', [System.StringComparison]::Ordinal) -ge 0) {
                $hit['mixin'] = $true
            }
            if ($hit['mixin']) {
                if ($null -eq $sblob) { $sblob = ($cp.Strings | Where-Object { $_.Length -lt 200 }) -join "`n" }
                foreach ($mk in $script:bcMixinApi.Keys) {
                    if (-not $hit[$mk] -and $sblob -match $script:bcMixinApi[$mk]) {
                        $hit[$mk] = $true
                        $hit['mixintarget'] = $true
                    }
                }
                if ($hit['movepacket']) {
                    foreach ($mk in $script:bcMixinPacketApi.Keys) {
                        if (-not $hit[$mk] -and $sblob -match $script:bcMixinPacketApi[$mk]) {
                            $hit[$mk] = $true
                            $hit['mixintarget'] = $true
                        }
                    }
                }
                foreach ($ak in $script:bcMixinArea.Keys) {
                    if (-not $f.MixinAreas.Contains($ak) -and $sblob -match $script:bcMixinArea[$ak]) {
                        [void]$f.MixinAreas.Add($ak)
                    }
                }
            }
            # A class transformer decides what to rewrite by COMPARING the class name
            # it is handed against string constants. Same shape as a mixin's
            # annotation and reflection's getDeclaredMethod: third door, same key.
            if ($hit['transformer']) {
                if ($null -eq $sblob) { $sblob = ($cp.Strings | Where-Object { $_.Length -lt 200 }) -join "`n" }
                foreach ($mk in $script:bcMixinApi.Keys) {
                    if (-not $hit[$mk] -and $sblob -match $script:bcMixinApi[$mk]) {
                        $hit[$mk] = $true
                        $hit['coretarget'] = $true
                    }
                }
                foreach ($ak in $script:bcMixinArea.Keys) {
                    if (-not $f.MixinAreas.Contains($ak) -and $sblob -match $script:bcMixinArea[$ak]) {
                        [void]$f.MixinAreas.Add($ak)
                    }
                }
            }
            # A class that finds its own jar and deletes a file, and is not
            # unpacking a native library: that is a jar removing itself.
            if ($hit['selfpath'] -and $hit['filedelete'] -and -not $hit['nativetemp'] -and -not $hit['archive']) {
                $hit['selfwipe'] = $true
            }
            foreach ($k in $script:bcReflectiveNames.Keys) {
                if ($hit.ContainsKey($k)) { continue }
                foreach ($s in $cp.Strings) {
                    if ($s -match $script:bcReflectiveNames[$k]) { $hit[$k] = $true; break }
                }
            }
            foreach ($k in $hit.Keys) { $f[$k]++ }
            # Bounded: a large obfuscated jar can hit on hundreds of classes and
            # the report only ever names two.
            if ($hit.Count -gt 0 -and $f.ClassHits.Count -lt 80) { $f.ClassHits[$e.FullName] = @($hit.Keys) }

            $names++
            if ($simple.Length -le 2) { $short++ }
            foreach ($s in $cp.Strings) {
                $totalStr++
                if ($s.Length -ge 4 -and $s -match '^[\x20-\x7e]+$') { $readable++ }
                elseif ($s.Length -ge 8 -and $entN -lt 40) {
                    # Entropy is only needed as an average; sampling keeps the cost bounded
                    # on jars whose pools hold tens of thousands of constants.
                    $entSum += (Get-ShannonEntropy ([System.Text.Encoding]::UTF8.GetBytes($s)))
                    $entN++
                }
            }
        }
    } finally { $zip.Dispose() }
    if ($f.ClassesParsed -gt 0) {
        foreach ($k in $script:bcBehaviour.Keys) { $f[$k + 'Ratio'] = [double]$f[$k] / [double]$f.ClassesParsed }
        foreach ($k in $script:bcDerived)        { $f[$k + 'Ratio'] = [double]$f[$k] / [double]$f.ClassesParsed }
    }
    # Report the areas in the order the table declares them, not in the order the
    # classes happened to be read, so two scans of the same jar read the same way.
    if ($f.MixinAreas.Count -gt 1) {
        $ordered = [System.Collections.Generic.List[string]]::new()
        foreach ($ak in $script:bcMixinArea.Keys) { if ($f.MixinAreas.Contains($ak)) { [void]$ordered.Add($ak) } }
        $f.MixinAreas = $ordered
    }
    if ($names -gt 0)    { $f.ObfNameRatio = [double]$short / [double]$names }
    if ($totalStr -gt 0) { $f.StrReadableRatio = [double]$readable / [double]$totalStr }
    if ($entN -gt 0)     { $f.StrEntropy = $entSum / [double]$entN }
    return $f
}

function Get-JarFeatures([string]$FilePath) {
    $f = @{
        StrongStrings = [System.Collections.Generic.List[string]]::new()
        WeakStrings   = [System.Collections.Generic.List[string]]::new()
        PackageHits   = [System.Collections.Generic.List[string]]::new()
        Patterns      = [System.Collections.Generic.List[string]]::new()
        FullwidthStr  = $false
        ClassCount    = 0
        FullwidthClsPct = 0.0; JapaneseClsPct = 0.0; SingleCharClsPct = 0.0
        NumericClsPct = 0.0; NoVowelClsPct = 0.0
        AvgEntropy = 0.0; HighEntropyPct = 0.0
        ReflectionCount = 0; RuntimeExec = $false; HttpDownload = $false; HttpExfil = $false
        NestedHollow = $false
        ModId = ""; MetaName = ""; FakeIdentity = $false
        JavaAgent = $false; AgentRetransform = $false; AgentClass = ""
        HiddenPayload = 0; PaddingEntry = 0
        # The entries themselves, not just how many. A count is a claim; a name is
        # something both sides can open the jar and look at.
        PayloadNames  = [System.Collections.Generic.List[string]]::new()
        PaddingNames  = [System.Collections.Generic.List[string]]::new()
        LoaderIds = [System.Collections.Generic.List[string]]::new()
        PayloadKinds  = [System.Collections.Generic.List[string]]::new()
        BlankMeta = $false; NativeJna = $false
        MixinConfigs = 0; MixinDeclared = 0; MixinClientOnly = $false
        CoreMod = $false; CoreModClass = ""; TweakClass = ""; CoreModJs = 0; AccessWidened = 0
    }
    $reflectionPatterns = @('Class\.forName','getMethod','getDeclaredMethod','getDeclaredField','setAccessible','java/lang/reflect','MethodHandle','sun/misc/Unsafe','defineClass','ByteBuddy','javassist','ASM\d')
    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath) } catch { return $f }

    $total = 0; $numeric = 0; $fullwidth = 0; $japanese = 0; $single = 0; $novowel = 0
    $payloadChecks = 0
    $entSum = 0.0; $entCnt = 0; $highEnt = 0; $nested = 0
    $sb = [System.Text.StringBuilder]::new(); $textLen = 0
    try {
        $entries = @($zip.Entries)
        foreach ($e in $entries) {
            $n = $e.FullName
            if ($n -match '^META-INF/jars/.+\.jar$') { $nested++ }
            if ($n -match 'fabric\.mod\.json$|quilt\.mod\.json$') { if (-not $f.LoaderIds.Contains('fabric')) { [void]$f.LoaderIds.Add('fabric') } }
            elseif ($n -match 'META-INF/(neoforge\.)?mods\.toml$') { if (-not $f.LoaderIds.Contains('forge')) { [void]$f.LoaderIds.Add('forge') } }
            elseif ($n -match '^mcmod\.info$') { if (-not $f.LoaderIds.Contains('forge-legacy')) { [void]$f.LoaderIds.Add('forge-legacy') } }
            elseif ($n -match '^plugin\.yml$|^bungee\.yml$') { if (-not $f.LoaderIds.Contains('bukkit')) { [void]$f.LoaderIds.Add('bukkit') } }
            elseif ($n -match '^addon\d*\.json$') { if (-not $f.LoaderIds.Contains('labymod')) { [void]$f.LoaderIds.Add('labymod') } }
            # Hidden payloads: an extensionless entry that is really a class / encrypted blob, OR a
            # resource with a normal extension whose bytes betray it (a .png with no PNG header, a
            # .json that is high-entropy ciphertext). Droppers hide their real payload this way.
            if ($e.Length -ge 1024 -and $e.Length -lt 3000000 -and $n -notmatch '/$' -and $payloadChecks -lt 60) {
                $leaf = ($n -split '/')[-1]
                $dot = $leaf.LastIndexOf('.')
                $ext = if ($dot -ge 0) { $leaf.Substring($dot + 1).ToLower() } else { "" }
                # Large blobs are always looked at, whatever they are called. The
                # padding test below only needs the bytes, and a file named pad.dat
                # would otherwise slip past a list of known extensions.
                $checkThis = ($ext -eq "") -or ($script:magicExt.ContainsKey($ext)) -or ($script:textExt -contains $ext) -or ($e.Length -ge 65536)
                if ($checkThis) {
                    try {
                        $payloadChecks++
                        $st = $e.Open()
                        $buf = New-Object byte[] 65536
                        $got = $st.Read($buf, 0, $buf.Length); $st.Close()
                        if ($got -ge 512) {
                            $isClass = ($buf[0] -eq 0xCA -and $buf[1] -eq 0xFE -and $buf[2] -eq 0xBA -and $buf[3] -eq 0xBE)
                            $slice = New-Object byte[] $got
                            [Array]::Copy($buf, $slice, $got)
                            $hit = $false; $why = ""
                            # A large entry made of one repeated byte. There is no
                            # innocent version of this: it is padding, and padding
                            # exists to change the file's SIZE - and with it the
                            # SHA1 - so a hash from the last download does not match
                            # this one. Doomsday's own download page offers it as a
                            # "Randomize size" checkbox. Measured at 0 hits across
                            # 179 real libraries and 1 on the real loader.
                            if ($got -ge 4096 -and $e.Length -ge 16384) {
                                $seen = New-Object 'bool[]' 256
                                $distinct = 0
                                for ($bi = 0; $bi -lt $got; $bi++) {
                                    $bv = [int]$slice[$bi]
                                    if (-not $seen[$bv]) { $seen[$bv] = $true; $distinct++; if ($distinct -gt 2) { break } }
                                }
                                if ($distinct -le 2) {
                                    $f.PaddingEntry++
                                    if ($f.PaddingNames.Count -lt 4) { [void]$f.PaddingNames.Add("$n ($([Math]::Round($e.Length / 1KB)) KB of byte 0x$('{0:X2}' -f $slice[0]))") }
                                    if (-not $f.PayloadKinds.Contains("padding")) { [void]$f.PayloadKinds.Add("padding") }
                                }
                            }
                            if ($ext -eq "") {
                                # A class file without the .class extension is hidden whatever
                                # its header says. High entropy alone is not, if the bytes name
                                # the format themselves (see Test-SelfIdentifyingBlob).
                                if ($isClass) { $hit = $true; $why = "extensionless" }
                                elseif ((Get-ShannonEntropy $slice) -gt 7.0 -and
                                        -not (Test-SelfIdentifyingBlob $slice $e.Length)) {
                                    $hit = $true; $why = "extensionless"
                                }
                            } elseif ($script:magicExt.ContainsKey($ext)) {
                                $magic = $script:magicExt[$ext]
                                $match = $true
                                for ($mi = 0; $mi -lt $magic.Count; $mi++) { if ($buf[$mi] -ne $magic[$mi]) { $match = $false; break } }
                                if (-not $match) { $hit = $true; $why = "$ext-magic" }
                            } elseif ($script:textExt -contains $ext) {
                                if ((Get-ShannonEntropy $slice) -gt 6.2) { $hit = $true; $why = "$ext-entropy" }
                            }
                            if ($hit) {
                                $f.HiddenPayload++
                                if ($f.PayloadNames.Count -lt 4) { [void]$f.PayloadNames.Add("$n ($why, $([Math]::Round($e.Length / 1KB)) KB, starts $('{0:x2}{1:x2}{2:x2}{3:x2}' -f $slice[0], $slice[1], $slice[2], $slice[3]))") }
                                if (-not $f.PayloadKinds.Contains($why)) { [void]$f.PayloadKinds.Add($why) }
                            }
                        }
                    } catch {}
                }
            }
            foreach ($p in $script:cheatPackagePaths) {
                if ($n.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and -not $f.PackageHits.Contains($p)) { [void]$f.PackageHits.Add($p) }
            }
        }
        foreach ($e in $entries) {
            $n = $e.FullName
            if ($n -match '\.class$') {
                $total++
                $cn = [System.IO.Path]::GetFileNameWithoutExtension(($n -split '/')[-1])
                if ($cn -match '^\d+$') { $numeric++ }
                if ($cn -match "[$([char]0xFF21)-$([char]0xFF3A)$([char]0xFF41)-$([char]0xFF5A)$([char]0xFF10)-$([char]0xFF19)]") { $fullwidth++ }
                if ($cn -match "[$([char]0x3040)-$([char]0x309F)$([char]0x30A0)-$([char]0x30FF)$([char]0x3400)-$([char]0x4DBF)$([char]0x4E00)-$([char]0x9FFF)]") { $japanese++ }
                if ($cn -match '^[a-zA-Z]$') { $single++ }
                if ($cn.Length -ge 3 -and $cn.Length -le 8 -and $cn -match '^[a-zA-Z]+$') {
                    $vc = ($cn.ToCharArray() | Where-Object { 'aeiouAEIOU'.IndexOf($_) -ge 0 }).Count
                    if ($vc -eq 0) { $novowel++ }
                }
                if ($e.Length -gt 200 -and $e.Length -lt 500000 -and ($entCnt -lt 500 -or $textLen -lt 500000)) {
                    try {
                        $st = $e.Open(); $ms = New-Object System.IO.MemoryStream; $st.CopyTo($ms); $st.Close()
                        $bytes = $ms.ToArray(); $ms.Dispose()
                        if ($entCnt -lt 500) { $ent = Get-ShannonEntropy $bytes; $entSum += $ent; $entCnt++; if ($ent -gt 7.2) { $highEnt++ } }
                        if ($textLen -lt 500000) { $ascii = [System.Text.Encoding]::ASCII.GetString($bytes); [void]$sb.Append($ascii); $textLen += $ascii.Length }
                    } catch {}
                }
            } elseif ($n -match '\.(json|txt|cfg|properties|toml|mf|xml)$' -or $n -match 'MANIFEST\.MF') {
                try {
                    $st = $e.Open(); $ms = New-Object System.IO.MemoryStream; $st.CopyTo($ms); $st.Close()
                    $bytes = $ms.ToArray(); $ms.Dispose()
                    $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
                    if ($textLen -lt 500000) { [void]$sb.Append($txt); $textLen += $txt.Length }
                    if ($n -match 'fabric\.mod\.json|quilt\.mod\.json') {
                        if ($f.ModId -eq "" -and $txt -match '"id"\s*:\s*"([^"]{2,60})"') { $f.ModId = $matches[1] }
                        if ($f.MetaName -eq "" -and $txt -match '"name"\s*:\s*"([^"]{2,60})"') { $f.MetaName = $matches[1] }
                    } elseif ($n -match 'mods\.toml') {
                        if ($f.ModId -eq "" -and $txt -match 'modId\s*=\s*"([^"]{2,60})"') { $f.ModId = $matches[1] }
                    } elseif ($n -match '\.mixins\.json$|^mixins\.[^/]+\.json$') {
                        # A mixin config says in plain text how many places in the game
                        # this mod rewrites, and whether it does so on the client. It
                        # names the mixin CLASSES, not their targets - the targets live
                        # in the annotations and are read out of the bytecode - so this
                        # is counted as scope, never scored. Its second job is honesty:
                        # a config that declares mixins the bytecode reader never saw is
                        # a gap in coverage, not a clean result.
                        $f.MixinConfigs++
                        foreach ($sec in @('mixins', 'client', 'server')) {
                            $mm = [regex]::Match($txt, '"' + $sec + '"\s*:\s*\[([^\]]*)\]')
                            if ($mm.Success) {
                                $cnt = ([regex]::Matches($mm.Groups[1].Value, '"[^"]+"')).Count
                                $f.MixinDeclared += $cnt
                                if ($sec -eq 'client' -and $cnt -gt 0) { $f.MixinClientOnly = $true }
                            }
                        }
                    } elseif ($n -match 'MANIFEST\.MF$') {
                        if ($txt -match '(?im)^(Premain-Class|Agent-Class)\s*:\s*(\S+)') {
                            $f.JavaAgent = $true
                            $f.AgentClass = $matches[2]
                        }
                        if ($txt -match '(?im)^Can-(Retransform|Redefine)-Classes\s*:\s*true') { $f.AgentRetransform = $true }
                        # The third way into the game's code, next to Mixin and a Java
                        # agent: a Forge coremod, or a LaunchWrapper tweaker. Both install
                        # a class transformer before the game starts, which is the same
                        # power - it can rewrite any class on the way in.
                        if ($txt -match '(?im)^(FMLCorePlugin|FMLCorePluginContainsFMLMod|MixinConfigs)\s*:\s*(\S+)') {
                            if ($matches[1] -ne 'MixinConfigs') { $f.CoreMod = $true; $f.CoreModClass = $matches[2] }
                        }
                        if ($txt -match '(?im)^TweakClass\s*:\s*(\S+)') {
                            $f.CoreMod = $true
                            $f.TweakClass = $matches[1]
                        }
                    } elseif ($n -match '^META-INF/coremods\.json$') {
                        # Forge 1.16+ JS coremods: the file lists script paths, and each
                        # script names the game classes it rewrites.
                        $f.CoreModJs = ([regex]::Matches($txt, '"[^"]+\.js"')).Count
                        if ($f.CoreModJs -gt 0) { $f.CoreMod = $true }
                    } elseif ($n -match 'accesstransformer\.cfg$|_at\.cfg$') {
                        # An access transformer makes private game members public. Normal
                        # Forge practice - counted as scope, never scored.
                        foreach ($ln in ($txt -split "`n")) {
                            $t = $ln.Trim()
                            if ($t -ne "" -and -not $t.StartsWith('#') -and $t -match '^(public|protected|private|default)') { $f.AccessWidened++ }
                        }
                    }
                } catch {}
            }
        }
    } catch {}
    try { $zip.Dispose() } catch {}

    $blob = $sb.ToString()
    foreach ($s in $script:cheatStringSet) {
        if ($blob.IndexOf($s, [System.StringComparison]::Ordinal) -ge 0) {
            $isPkg = $false
            foreach ($p in $script:cheatPackagePaths) { if ($s.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $isPkg = $true; break } }
            if ($isPkg) { if (-not $f.PackageHits.Contains($s)) { [void]$f.PackageHits.Add($s) } }
            elseif ($script:weakStringSet.Contains($s)) { [void]$f.WeakStrings.Add($s) }
            elseif ($s.Contains(' ') -and -not $script:strongPhraseSet.Contains($s)) { [void]$f.WeakStrings.Add($s) }
            else { [void]$f.StrongStrings.Add($s) }
        }
    }
    foreach ($m in $script:patternRegex.Matches($blob)) { if (-not $f.Patterns.Contains($m.Value)) { [void]$f.Patterns.Add($m.Value) } }
    if ($script:fullwidthRegex.IsMatch($blob)) { $f.FullwidthStr = $true }

    $refl = 0
    foreach ($rp in $reflectionPatterns) { if ([regex]::IsMatch($blob, $rp)) { $refl++ } }
    $f.ReflectionCount = $refl
    if ($blob.Contains('java/lang/Runtime') -and $blob.Contains('getRuntime') -and $blob.Contains('exec')) { $f.RuntimeExec = $true }
    if ($blob.Contains('openConnection') -and $blob.Contains('HttpURLConnection') -and $blob.Contains('FileOutputStream')) { $f.HttpDownload = $true }
    if ($blob.Contains('openConnection') -and $blob.Contains('setDoOutput') -and $blob.Contains('getOutputStream') -and $blob.Contains('getProperty')) { $f.HttpExfil = $true }
    if ($nested -eq 1 -and $total -lt 3) { $f.NestedHollow = $true }
    if ($blob.Contains('com/sun/jna/')) { $f.NativeJna = $true }
    if ($blob.Contains('cpw/mods/fml/') -and -not $f.LoaderIds.Contains('forge-cpw')) { [void]$f.LoaderIds.Add('forge-cpw') }
    if ($blob.Contains('net/labymod/api') -and -not $f.LoaderIds.Contains('labymod')) { [void]$f.LoaderIds.Add('labymod') }
    if ($blob.Contains('net/fabricmc/api/ModInitializer') -and -not $f.LoaderIds.Contains('fabric')) { [void]$f.LoaderIds.Add('fabric') }
    if ($blob.Contains('net/minecraftforge/fml/') -and -not $f.LoaderIds.Contains('forge')) { [void]$f.LoaderIds.Add('forge') }
    if ($blob -match '(?m)^BaseMod$' -and -not $f.LoaderIds.Contains('modloader')) { [void]$f.LoaderIds.Add('modloader') }
    if ($f.ModId -and $f.ModId.Length -le 3 -and $f.MetaName -eq "") { $f.BlankMeta = $true }

    if ($total -gt 0) {
        $f.ClassCount = $total
        $f.NumericClsPct = $numeric / $total
        $f.FullwidthClsPct = $fullwidth / $total
        $f.JapaneseClsPct = $japanese / $total
        $f.SingleCharClsPct = $single / $total
        $f.NoVowelClsPct = $novowel / $total
    }
    if ($entCnt -gt 0) { $f.AvgEntropy = $entSum / $entCnt; $f.HighEntropyPct = $highEnt / $entCnt }

    if ($f.MetaName) {
        $jarBase = ([System.IO.Path]::GetFileNameWithoutExtension($FilePath)).ToLower() -replace '[^a-z0-9]',''
        $mnClean = $f.MetaName.ToLower() -replace '[^a-z0-9]',''
        foreach ($km in @('optifine','sodium','lithium','iris','create','journeymap','fabricapi')) {
            if ($mnClean -match "^$km" -and $jarBase -notmatch $km) { $f.FakeIdentity = $true; break }
        }
    }
    return $f
}

function Get-ModFeatureVector($ctx) {
    $ft = $ctx.Features
    return @{
        pkgpath        = if ($ft.PackageHits.Count -gt 0) { 1 } else { 0 }
        cheatsite      = if ($ctx.CheatSite) { 1 } else { 0 }
        strong_sig     = [Math]::Min(($ft.StrongStrings.Count + $ft.Patterns.Count), 5) / 5.0
        weak_sig       = [Math]::Min($ft.WeakStrings.Count, 10) / 10.0
        fullwidth_str  = if ($ft.FullwidthStr) { 1 } else { 0 }
        fullwidth_cls  = [Math]::Min($ft.FullwidthClsPct, 1.0)
        japanese_cls   = [Math]::Min($ft.JapaneseClsPct, 1.0)
        singlechar_cls = [Math]::Min($ft.SingleCharClsPct, 1.0)
        numeric_cls    = [Math]::Min($ft.NumericClsPct, 1.0)
        novowel_cls    = [Math]::Min($ft.NoVowelClsPct, 1.0)
        avg_entropy    = [Math]::Min($ft.AvgEntropy / 8.0, 1.0)
        high_entropy   = [Math]::Min($ft.HighEntropyPct, 1.0)
        reflection     = [Math]::Min($ft.ReflectionCount, 6) / 6.0
        runtime_exec   = if ($ft.RuntimeExec) { 1 } else { 0 }
        http_download  = if ($ft.HttpDownload) { 1 } else { 0 }
        http_exfil     = if ($ft.HttpExfil) { 1 } else { 0 }
        nested_hollow  = if ($ft.NestedHollow) { 1 } else { 0 }
        fake_identity  = if ($ft.FakeIdentity) { 1 } else { 0 }
        filename_client = if ($ctx.FilenameClient) { 1 } else { 0 }
        random_name    = if ($ctx.RandomName) { 1 } else { 0 }
        verified       = if ($ctx.Verified) { 1 } else { 0 }
        legit_modid    = if ($ctx.LegitModId) { 1 } else { 0 }
    }
}

function Get-ModVerdict($ctx) {
    $raw = Get-ModFeatureVector $ctx
    $p = Invoke-MlModel $raw
    $score = [int][Math]::Round($p * 100)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $ft = $ctx.Features

    if ($ctx.HashKnownCheat) { $score = 100; [void]$reasons.Add("SHA1 matches the known-cheat database") }
    if ($ft.PackageHits.Count -gt 0) {
        $score = [Math]::Max($score, 80)
        [void]$reasons.Add("Cheat-client package path: " + ((@($ft.PackageHits) | Select-Object -Unique | Select-Object -First 3) -join ', '))
    }
    if ($ft.PaddingEntry -gt 0) {
        $score = [Math]::Max($score, 60)
        [void]$reasons.Add("$($ft.PaddingEntry) entr(y/ies) inside this jar are nothing but padding $([char]0x2014) one byte value repeated for kilobytes. Padding has no function; it exists to change the file's size and therefore its SHA1, so a hash taken from someone else's copy will not match this one. Nothing legitimate ships it" + $(if ($ft.PaddingNames.Count -gt 0) { " [" + (@($ft.PaddingNames) -join '; ') + "]" } else { "" }))
    }
    if ($ft.JavaAgent) {
        $score = [Math]::Max($score, $(if ($ft.AgentRetransform) { 90 } else { 80 }))
        $agentWhat = if ($ft.AgentRetransform) { "rewrites game code while it runs" } else { "loads as a Java agent" }
        [void]$reasons.Add("Injector: this jar $agentWhat ($($ft.AgentClass)) $([char]0x2014) normal mods never do this")
    }
    if ($ft.HiddenPayload -gt 0) {
        $score = [Math]::Max($score, 75)
        $pk = if (@($ft.PayloadKinds) -contains 'extensionless' -and @($ft.PayloadKinds).Count -eq 1) { "no extension" } else { "disguised as resources" }
        [void]$reasons.Add("Hidden payload: $($ft.HiddenPayload) encrypted/class file(s) $pk, decrypted at runtime" + $(if ($ft.PayloadNames.Count -gt 0) { " [" + (@($ft.PayloadNames) -join '; ') + "]" } else { "" }))
    }
    if (@($ft.LoaderIds).Count -ge 3) {
        $score = [Math]::Max($score, 70)
        [void]$reasons.Add("Claims $(@($ft.LoaderIds).Count) different mod-loader identities ($((@($ft.LoaderIds) | Select-Object -First 4) -join ', ')) $([char]0x2014) dropper pattern")
    }
    if ($ctx.CheatSite)     { $score = [Math]::Max($score, 75); [void]$reasons.Add("Downloaded from a known cheat site: $($ctx.CheatSiteName)") }
    if ($ft.FakeIdentity)   { $score = [Math]::Max($score, 70); [void]$reasons.Add("Fake mod identity $([char]0x2014) metadata does not match the file") }
    if ($ctx.FilenameClient){ $score = [Math]::Max($score, 60); [void]$reasons.Add("Filename matches a known cheat client: $($ctx.FilenameToken)") }

    [void]$reasons.Add("AI cheat probability: $([int][Math]::Round($p * 100))%")
    if ($ft.StrongStrings.Count -gt 0) { [void]$reasons.Add("Cheat signatures: " + ((@($ft.StrongStrings) | Select-Object -First 5) -join ', ')) }

    $contribs = @()
    foreach ($k in $script:mlFeatureOrder) {
        $v = [double]$raw[$k]
        if ($v -le 0) { continue }
        $c = [double]$script:mlWeights[$k] * $v
        if ($c -gt 0.2 -and $script:mlFactorLabels.ContainsKey($k)) { $contribs += [PSCustomObject]@{ Name = $script:mlFactorLabels[$k]; C = $c } }
    }
    foreach ($tp in (@($contribs | Sort-Object C -Descending | Select-Object -First 4))) { [void]$reasons.Add("Factor: $($tp.Name)") }

    # ---- behaviour, read out of the bytecode (survives string encryption) ----
    # Set when a behaviour is recognised for certain but its legality is a server
    # rule rather than a technical fact. It renames the band; it never raises it.
    $policy = $false
    # The highest score any BEHAVIOUR rule set, kept separate from $score so the
    # whole-scan model can see it. It used to reach that model only through the
    # flagged ratio, which a large modpack divides away to nothing.
    $bhv = 0
    $bc = $ctx.Bytecode
    if ($bc -and $bc.ClassesParsed -gt 0) {
        # The aim / killaura fingerprint, verified against real cheat source: forging your
        # own outgoing movement packet while writing a computed rotation into it. Measured
        # separation on the corpus was total - no legitimate mod fakes its own movement.
        if ($bc.movepacketRatio -gt 0 -and $bc.rotationRatio -gt 0) {
            $score = [Math]::Max($score, 85); $bhv = [Math]::Max($bhv, 85)
            [void]$reasons.Add("Behaviour: forges its own movement packet while writing a computed rotation $([char]0x2014) the aim/killaura fingerprint; normal mods never do this" + (Get-BcWitness $bc @('movepacket','rotation')))
        }
        # Loader / dropper: decrypt something, then define a class out of the plaintext.
        if ($bc.cryptoRatio -ge 0.5 -and ($bc.classloadRatio -gt 0 -or $bc.reflectRatio -ge 0.5)) {
            $score = [Math]::Max($score, 85); $bhv = [Math]::Max($bhv, 85)
            [void]$reasons.Add("Behaviour: decrypts data and defines classes from it at runtime $([char]0x2014) loader/dropper pattern" + (Get-BcWitness $bc @('crypto')))
        }
        # Forging your own movement is the line between automating the game and
        # lying to the server about where you are. Each of these pairs that forgery
        # with a second thing no legitimate mod combines it with. Measured on the
        # corpus at 0 hits across 405 clean jars, 177 of them real libraries.
        if ($bc.blockplaceRatio -gt 0 -and $bc.movepacketRatio -gt 0) {
            $score = [Math]::Max($score, 85); $bhv = [Math]::Max($bhv, 85)
            [void]$reasons.Add("Behaviour: places blocks while forging its own movement packet $([char]0x2014) the scaffold/tower fingerprint. A schematic printer places blocks too, but through the game's own interaction system and without touching movement" + (Get-BcWitness $bc @('blockplace','movepacket')))
        }
        if ($bc.movepacketRatio -gt 0 -and $bc.motionRatio -gt 0) {
            $score = [Math]::Max($score, 85); $bhv = [Math]::Max($bhv, 85)
            [void]$reasons.Add("Behaviour: writes its own velocity and then forges the movement packet to match $([char]0x2014) speed / no-fall / blink. The game never produced this movement" + (Get-BcWitness $bc @('movepacket','motion')))
        }
        if ($bc.containerRatio -gt 0 -and $bc.movepacketRatio -gt 0) {
            $score = [Math]::Max($score, 85); $bhv = [Math]::Max($bhv, 85)
            [void]$reasons.Add("Behaviour: clicks inventory slots while forging movement packets $([char]0x2014) moving with a container open, which the game does not allow. Inventory sorting mods click slots and never touch movement" + (Get-BcWitness $bc @('container','movepacket')))
        }
        # Strong, but not the same order of certainty as forging movement, so these
        # flag rather than confirm.
        if ($bc.movepacketRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: sends its own movement packets and never reads the keyboard $([char]0x2014) the movement is not coming from the player" + (Get-BcWitness $bc @('movepacket')))
        }
        if ($bc.entityscanRatio -gt 0 -and $bc.attackRatio -gt 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: attacks entities picked out of a full entity sweep $([char]0x2014) killaura / reach / triggerbot pick their target this way" + (Get-BcWitness $bc @('entityscan','attack')))
        }
        if ($bc.attackRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: attacks without ever reading a key or mouse button $([char]0x2014) the hits are not coming from the player (autoclicker / triggerbot)" + (Get-BcWitness $bc @('attack')))
        }
        if ($bc.pktlistenRatio -gt 0 -and $bc.motionRatio -gt 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: intercepts incoming packets and rewrites the player's velocity $([char]0x2014) anti-knockback / velocity. A replay recorder listens to packets and never writes motion back" + (Get-BcWitness $bc @('pktlisten','motion')))
        }
        if ($bc.blockbreakRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: breaks blocks without reading input $([char]0x2014) nuker. A vein miner breaks blocks too, but only while the player is mining" + (Get-BcWitness $bc @('blockbreak')))
        }
        if ($bc.rotationRatio -gt 0 -and $bc.renderRatio -gt 0 -and $bc.movepacketRatio -eq 0) {
            $score = [Math]::Max($score, 60); $bhv = [Math]::Max($bhv, 60)
            [void]$reasons.Add("Behaviour: writes the player's look direction and renders from it $([char]0x2014) freecam. A third-person camera derives its position from the player instead of writing to them" + (Get-BcWitness $bc @('rotation','render')))
        }
        # NOT a rule. A jar that locates its own file and deletes it is exactly the
        # wipe pattern, and it is still measured ($bc.selfwipeRatio) - but it does
        # not score, because it could not be made safe. Per jar it matched sixteen
        # legitimate bytecode libraries; per class, excluding native unpacking, it
        # was clean across 479 jars here and still flagged a real library in CI,
        # twice, on a corpus this sandbox cannot reach. Two narrowings did not fix
        # it, so it is reported rather than tuned until it goes quiet: a rule that
        # flags real code is worse than a gap, because this tool accuses people.
        # Reaching the Minecraft API through reflection so its names never enter
        # the symbol table. On its own this only says the mod hides which API it
        # calls - the rules above already scored whatever it was hiding - but a
        # moderator should see that it was hidden, because no ordinary mod does it.
        # The comment above said this was "reported rather than tuned". It was not:
        # four behaviour categories were parsed on every class to derive it and then
        # nothing was ever printed, which the dead-end audit found. A reason line
        # without a score cannot cause a false flag - it does not move the band - and
        # a jar that finds its own file and deletes it is worth a moderator seeing.
        if ($bc.selfwipeRatio -gt 0) {
            [void]$reasons.Add("Behaviour: a class in here locates its own jar and deletes a file $([char]0x2014) the shape of a mod that removes itself after running. NOT scored: this pattern also flagged real bytecode libraries twice, so it is written down for you rather than counted against the file" + (Get-BcWitness $bc @('selfwipe')))
        }
        if ($bc.hiddenapiRatio -gt 0) {
            [void]$reasons.Add("Behaviour: reaches Minecraft through reflection so the API names never appear in the class symbol table $([char]0x2014) deliberately hiding which game methods it calls. An ordinary mod imports what it uses" + (Get-BcWitness $bc @('hiddenapi')))
        }
        # Mixins. Not an accusation and not scored: a Fabric mod IS mixins - Sodium,
        # Lithium and the Fabric API are nothing else. What is worth writing down is
        # WHERE it injects, because "rewrites the network handler and the player's
        # movement" and "rewrites the options screen" are different mods and the
        # score alone does not say which one is on the screen.
        if ($bc.mixinRatio -gt 0 -and @($bc.MixinAreas).Count -gt 0) {
            # The declared count comes from *.mixins.json, which lists the injection
            # points in plain text; the areas come from the annotations in the
            # bytecode, which is where the TARGETS actually are.
            $mxN = if ($ft.MixinDeclared -gt 0) { " at $($ft.MixinDeclared) declared point(s)" } else { "" }
            [void]$reasons.Add("Scope: compiles itself into the game's own code (Mixin)$mxN, reaching " +
                ((@($bc.MixinAreas)) -join ", ") +
                ". Normal for a mod $([char]0x2014) recorded so it is visible what it can touch")
        }
        # A mixin names its target in an annotation, so the target is a string and
        # never a symbol. Where that is the only way a behaviour above was found,
        # say so: it explains why the finding is there at all.
        # A coremod or a LaunchWrapper tweaker installs a class transformer before the
        # game starts. That is the same power a Java agent has - it can rewrite any
        # class on the way in - and unlike an agent it is ordinary Forge practice, so
        # it is recorded as scope rather than scored. OptiFine is a tweaker.
        # A coremod whose manifest key is missing - or whose jar was read as bytecode
        # before the manifest - is still visibly a class transformer from the code
        # itself. Without this the scope line depended entirely on FMLCorePlugin
        # being present, which is a text field a cheat can simply leave out.
        if ($bc.transformerRatio -gt 0 -and -not $ft.CoreMod) {
            [void]$reasons.Add("Scope: contains a class transformer (the Forge/LaunchWrapper interface is implemented in the code) $([char]0x2014) it can rewrite game classes as they load. Ordinary for a Forge mod; recorded because its manifest does not declare it")
        }
        if ($ft.CoreMod) {
            $what = if ($ft.TweakClass) { "a LaunchWrapper tweaker ($($ft.TweakClass))" }
                    elseif ($ft.CoreModClass) { "a Forge coremod ($($ft.CoreModClass))" }
                    else { "$($ft.CoreModJs) JavaScript coremod script(s)" }
            [void]$reasons.Add("Scope: installs $what $([char]0x2014) a class transformer that runs before the game and can rewrite any class on the way in. Ordinary for a Forge mod; recorded so it is visible what it can touch")
        }
        if ($ft.AccessWidened -gt 0) {
            [void]$reasons.Add("Scope: an access transformer makes $($ft.AccessWidened) private game member(s) public. Normal Forge practice $([char]0x2014) listed, not scored")
        }
        if ($bc.coretargetRatio -gt 0) {
            [void]$reasons.Add("Behaviour: the game class it rewrites is named only as a string its class transformer compares against, so it never appears in the class symbol table $([char]0x2014) read out of that comparison instead")
        }
        if ($bc.mixintargetRatio -gt 0) {
            [void]$reasons.Add("Behaviour: the game class it rewrites is named only in its Mixin annotation, so it never appears in the class symbol table $([char]0x2014) read out of the annotation instead")
        }
        if ($bc.instrumentRatio -gt 0 -and $bc.ClassesParsed -gt 0) {
            $score = [Math]::Max($score, 80); $bhv = [Math]::Max($bhv, 80)
            [void]$reasons.Add("Behaviour: ships Java-agent instrumentation hooks $([char]0x2014) it can rewrite game code as it runs")
        }
        # ---- server-rule behaviours ------------------------------------------
        # Recognised for certain; whether they are allowed is not a technical
        # question. These never become proof - they are scored into Review and the
        # band is renamed so a moderator sees a rule question, not an accusation.
        if ($bc.renderRatio -gt 0 -and $bc.entityscanRatio -gt 0 -and -not ($ctx.Verified -or $ctx.LegitModId)) {
            $score = [Math]::Max($score, 35)
            $policy = $true
            [void]$reasons.Add("Behaviour: draws from a full entity sweep $([char]0x2014) that is what ESP does, and also exactly what a mob-radar minimap does. The bytecode does not contain what separates them")
        }
        if ($bc.blockplaceRatio -gt 0 -and $bc.inputRatio -gt 0 -and $bc.movepacketRatio -eq 0 -and
            -not ($ctx.Verified -or $ctx.LegitModId)) {
            $score = [Math]::Max($score, 35)
            $policy = $true
            [void]$reasons.Add("Behaviour: places blocks automatically while a key is held $([char]0x2014) a schematic printer. Banned on most survival servers and normal on build servers, so this is a rule question rather than a cheat")
        }

        # ---- behaviour beats text -------------------------------------------
        # A jar that only ever goes through the game's own systems - reads a keybind,
        # clicks a slot, draws to the screen - and never forges movement, writes
        # rotation, attacks, loads code, shells out or opens a socket, is not doing
        # anything a cheat needs to do. Obfuscated names and alarming strings do not
        # change that, so they must not be allowed to push it into Review on their
        # own: that is where inventory sorters and reach/ping/CPS displays were
        # being scored on how their code looks rather than on what it does.
        $forges = ($bc.movepacketRatio -gt 0 -or $bc.rotationRatio -gt 0 -or $bc.motionRatio -gt 0 -or
                   $bc.attackRatio -gt 0 -or $bc.classloadRatio -gt 0 -or $bc.instrumentRatio -gt 0 -or
                   $bc.unsafeRatio -gt 0 -or $bc.execRatio -gt 0 -or $bc.cryptoRatio -gt 0 -or
                   $bc.netRatio -gt 0)
        $usesGameOnly = ($bc.inputRatio -gt 0 -or $bc.containerRatio -gt 0 -or $bc.renderRatio -gt 0)
        # FilenameClient belongs in this list and was missing from it. The cap exists
        # so that obfuscated names and alarming STRINGS cannot push an inventory
        # sorter into Review - it is behaviour beating a text heuristic. A filename
        # that matches a known cheat client is not a text heuristic, it is identity,
        # the same kind of thing as a hash or a package path. Without this a file
        # called wurstclient-7.36.jar that only read the keyboard came out Clean 20.
        if (-not $policy -and -not $forges -and $usesGameOnly -and $bc.ClassesParsed -gt 0 -and
            -not $ctx.HashKnownCheat -and ($ft.PackageHits.Count -eq 0) -and -not $ctx.CheatSite -and
            -not $ctx.FilenameClient) {
            if ($score -gt 20) {
                [void]$reasons.Add("Behaviour: goes through the game's own input, container and rendering systems and forges nothing $([char]0x2014) no movement packet, no rotation write, no attack, no code loading. Whatever the file looks like, it cannot cheat with this")
            }
            $score = [Math]::Min($score, 20)
        }
    }

    # Random / hash-style filename on an unverified mod: never let it slip through as "unknown".
    # Floor it to Review (never a flag) so it is surfaced for a manual look. Verified / legit mods
    # are exempt (they are capped safe below), so a legitimately hash-renamed known mod is unaffected.
    if ($ctx.RandomName -and -not ($ctx.Verified -or $ctx.LegitModId)) {
        $floor = 35
        if ($ft.HighEntropyPct -ge 0.25 -or $ft.SingleCharClsPct -ge 0.25 -or $ft.FullwidthClsPct -gt 0 -or $ft.NestedHollow -or ($ft.ReflectionCount -ge 2 -and ($ft.HttpDownload -or $ft.RuntimeExec -or $ft.HttpExfil))) { $floor = 55 }
        if ($score -lt $floor) {
            $score = $floor
            [void]$reasons.Add("Unrecognized random / hash-style filename on an unverified mod $([char]0x2014) can't confirm what this is; review its source")
        }
    }

    # A cheat that hides inside / behind a legitimate mod:
    #   Verified   = the SHA1 matched an official release byte-for-byte. That file IS
    #                that mod, so its own behaviour is never a cheat. Cap stays.
    #   LegitModId = the mod id was read out of fabric.mod.json. That is SELF-DECLARED
    #                and trivially forged - a cheat can simply write "id":"sodium".
    #                Capping on it alone let an injector score 20/100 (Clean).
    # So a self-declared identity only protects a jar that carries no hard evidence.
    # Claiming to be a known mod WHILE carrying injector/cheat evidence is impersonation.
    $hardEvidence = $ctx.HashKnownCheat -or ($ft.PackageHits.Count -gt 0) -or $ft.JavaAgent -or
                    ($ft.HiddenPayload -gt 0) -or (@($ft.LoaderIds).Count -ge 3) -or $ctx.CheatSite -or $ft.FakeIdentity

    $capped = $false
    if ($ctx.Verified) {
        if ($score -gt 20) { $capped = $true }
        $score = [Math]::Min($score, 20)
    } elseif ($ctx.LegitModId) {
        if ($hardEvidence) {
            $claimed = if ($ft.ModId) { $ft.ModId } else { "a known mod" }
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Impersonation: claims to be '$claimed' but the hash matches no official release and it carries injector/cheat evidence $([char]0x2014) the real '$claimed' never does this")
        } else {
            if ($score -gt 20) { $capped = $true }
            $score = [Math]::Min($score, 20)
        }
    }
    if ($capped) { $reasons.Insert(0, "Known-good / verified mod $([char]0x2014) the matches below are part of the mod's own function, not a cheat") }

    $band = if ($score -ge 85) { "Confirmed" } elseif ($score -ge 60) { "Likely" } elseif ($score -ge 30) { "Review" } else { "Clean" }
    # A rule-dependent behaviour is only renamed while it sits in Review. If anything
    # else pushed the same jar to Likely or Confirmed, that finding stands - a printer
    # that also forges movement packets is not a printer.
    if ($policy -and $band -eq "Review") { $band = "ServerRule" }
    return @{ Score = $score; Band = $band; Probability = [int][Math]::Round($p * 100); Reasons = $reasons
              Policy = $policy; BehaviourScore = $bhv
              HiddenApi = $(if ($bc -and $bc.hiddenapiRatio -gt 0) { $true } else { $false }) }
}

function Split-CardText([string]$text, [int]$width) {
    $out = [System.Collections.Generic.List[string]]::new()
    $cur = ""
    foreach ($word in ([string]$text -split ' ')) {
        $wd = $word
        while ($wd.Length -gt $width) {
            if ($cur -ne "") { $out.Add($cur); $cur = "" }
            $out.Add($wd.Substring(0, $width))
            $wd = $wd.Substring($width)
        }
        if ($cur -eq "") { $cur = $wd }
        elseif (($cur.Length + 1 + $wd.Length) -le $width) { $cur = "$cur $wd" }
        else { $out.Add($cur); $cur = $wd }
    }
    if ($cur -ne "") { $out.Add($cur) }
    if ($out.Count -eq 0) { $out.Add("") }
    return $out
}

function Write-FinalVerdict($flagged, $review) {
    $w = 70
    $hasCheat = @($flagged).Count -gt 0
    $color = if ($hasCheat) { [ConsoleColor]::Red } elseif (@($review).Count -gt 0) { [ConsoleColor]::DarkYellow } else { [ConsoleColor]::Green }
    $head = if ($hasCheat) {
        "  $([char]0x26D4)  CHEAT FOUND $([char]0x2014) $(@($flagged).Count) mod(s) flagged as a cheat"
    } elseif (@($review).Count -gt 0) {
        "  $([char]0x26A0)  NO CONFIRMED CHEAT $([char]0x2014) but $(@($review).Count) mod(s) need a manual check"
    } else {
        "  $([char]0x2713)  NO CHEAT FOUND $([char]0x2014) every mod checked out clean"
    }
    Write-Host ""
    W ("  $([char]0x2554)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x2557)") $color
    W ("  $([char]0x2551)" + $head.PadRight($w + 1) + "$([char]0x2551)") $color
    W ("  $([char]0x255A)" + "$([char]0x2550)" * ($w + 1) + "$([char]0x255D)") $color
    Write-Host ""

    $n = 0
    foreach ($m in (@($flagged) + @($review) | Sort-Object Score -Descending)) {
        $n++
        $mColor = switch ($m.Band) { "Confirmed" { "Red" } "Likely" { "DarkYellow" } default { "Yellow" } }
        W ("   $n. ") DarkGray -NoNewline
        W ($m.FileName) White -NoNewline
        W ("   $($m.Band.ToUpper())  $($m.Score)/100  (AI $($m.Probability)%)") $mColor
        $why = @($m.Reasons) | Select-Object -First 3
        foreach ($r in $why) { W "      $([char]0x2192) $r" DarkGray }
        if (@($m.Reasons).Count -gt 3) { W "      $([char]0x2192) +$(@($m.Reasons).Count - 3) more reason(s) in the card above" DarkGray }
        if ($m.DownloadSource) { W "      $([char]0x2192) downloaded from: $($m.DownloadSource)" DarkGray }
        Write-Host ""
    }

    if ($hasCheat) {
        W "  What this means: a flagged mod is a cheat client, an injector, or a jar that" DarkGray
        W "  hides code it should not have. Remove it and re-download from Modrinth or" DarkGray
        W "  CurseForge. Review items are unproven $([char]0x2014) look at them before you judge." DarkGray
        Write-Host ""
    }
}

function Write-VerdictCard($mod) {
    $w = 72
    $bandColor = switch ($mod.Band) { "Confirmed" { "Red" } "Likely" { "DarkYellow" } "Review" { "Yellow" } default { "DarkGray" } }
    $title = " $($mod.Band.ToUpper())  $($mod.FileName)"
    if ($title.Length -gt ($w - 2)) { $title = $title.Substring(0, $w - 5) + "..." }
    $pad = [Math]::Max(0, $w - $title.Length - 2)
    W ("  $([char]0x250C)$([char]0x2500)" + $title + "$([char]0x2500)" * $pad + "$([char]0x2510)") $bandColor
    $sl = "  Score $($mod.Score)/100    AI cheat probability $($mod.Probability)%"
    W ("  $([char]0x2502)" + $sl.PadRight($w + 1) + "$([char]0x2502)") White
    if ($mod.Hash) { W ("  $([char]0x2502)  SHA1: $($mod.Hash)".PadRight($w + 2) + "$([char]0x2502)") DarkGray }
    if ($mod.DownloadSource) { W ("  $([char]0x2502)  Source: $($mod.DownloadSource)".PadRight($w + 2) + "$([char]0x2502)") DarkGray }
    W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") $bandColor
    foreach ($r in $mod.Reasons) {
        $first = $true
        foreach ($seg in (Split-CardText $r ($w - 8))) {
            $line = if ($first) { "    $([char]0x2022) $seg" } else { "      $seg" }
            $first = $false
            W ("  $([char]0x2502)" + $line.PadRight($w + 1) + "$([char]0x2502)") DarkYellow
        }
    }
    $tip = if ($mod.Band -eq "Review") { "  $([char]0x2139) Not confirmed $([char]0x2014) check the source before you trust this mod." } else { "  $([char]0x26A0) Remove this mod and re-download it from an official source." }
    W ("  $([char]0x251C)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2524)") $bandColor
    W ("  $([char]0x2502)" + $tip.PadRight($w + 1) + "$([char]0x2502)") $bandColor
    W ("  $([char]0x2514)" + "$([char]0x2500)" * ($w + 1) + "$([char]0x2518)") $bandColor
    Write-Host ""
}

function New-TestBytecode($over) {
    $b = @{ ClassesParsed = 10; ClassesFailed = 0; ObfNameRatio = 0.0; StrReadableRatio = 0.9; StrEntropy = 0.0
            MixinAreas = @() }
    foreach ($k in $script:bcBehaviour.Keys) { $b[$k] = 0; $b[$k + 'Ratio'] = 0.0 }
    # Derived signals belong here too. Left out they read as $null, which compares
    # false against every threshold - so a broken rule would look like a passing one.
    foreach ($k in $script:bcDerived) { $b[$k] = 0; $b[$k + 'Ratio'] = 0.0 }
    if ($over) { foreach ($k in $over.Keys) { $b[$k] = $over[$k] } }
    return $b
}

function New-TestFeatures($over) {
    $f = @{
        StrongStrings = @(); WeakStrings = @(); PackageHits = @(); Patterns = @(); FullwidthStr = $false
        FullwidthClsPct = 0.0; JapaneseClsPct = 0.0; SingleCharClsPct = 0.0; NumericClsPct = 0.0; NoVowelClsPct = 0.0
        AvgEntropy = 0.0; HighEntropyPct = 0.0; ReflectionCount = 0; RuntimeExec = $false; HttpDownload = $false
        HttpExfil = $false; NestedHollow = $false; ModId = ""; MetaName = ""; FakeIdentity = $false
        JavaAgent = $false; AgentRetransform = $false; AgentClass = ""; HiddenPayload = 0; PaddingEntry = 0
        LoaderIds = @(); BlankMeta = $false; NativeJna = $false; PayloadKinds = @()
        MixinConfigs = 0; MixinDeclared = 0; MixinClientOnly = $false
        CoreMod = $false; CoreModClass = ""; TweakClass = ""; CoreModJs = 0; AccessWidened = 0
    }
    if ($over) { foreach ($k in $over.Keys) { $f[$k] = $over[$k] } }
    return $f
}

function Invoke-SelfTest {
    W "  AsyncAnalyzer self-test $([char]0x2014) verifying the local AI model + verdict logic" Cyan
    Write-Host ""
    $base = @{ Verified = $false; LegitModId = $false; HashKnownCheat = $false; CheatSite = $false; CheatSiteName = $null; FilenameClient = $false; FilenameToken = ""; RandomName = $false; Bytecode = $null }
    $cases = @(
        @{ Label = "Doomsday-style cheat"; Bands = @("Confirmed", "Likely"); Over = @{ Features = (New-TestFeatures @{ PackageHits = @('org/chainlibs'); StrongStrings = @('AutoCrystal', 'KillAura', 'AutoAnchor', 'TriggerBot'); SingleCharClsPct = 0.35; HighEntropyPct = 0.35; AvgEntropy = 6.9; FullwidthStr = $true; ReflectionCount = 3 }) } }
        @{ Label = "Clean optimization mod (legit id)"; Bands = @("Clean"); Over = @{ LegitModId = $true; Features = (New-TestFeatures @{ ReflectionCount = 3; AvgEntropy = 6.3 }) } }
        @{ Label = "Anticheat full of detection names"; Bands = @("Clean"); Over = @{ LegitModId = $true; Features = (New-TestFeatures @{ StrongStrings = @('KillAura', 'AutoCrystal', 'TriggerBot', 'AimAssist', 'Scaffold'); ReflectionCount = 3 }) } }
        @{ Label = "Reflection-heavy clean library"; Bands = @("Clean", "Review"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 6; AvgEntropy = 5.7; HighEntropyPct = 0.05 }) } }
        @{ Label = "Token grabber"; Bands = @("Confirmed", "Likely"); Over = @{ Features = (New-TestFeatures @{ HttpExfil = $true; RuntimeExec = $true; WeakStrings = @('grabToken', 'webhookurl', 'discordwebhook', 'sendWebhook', 'exfiltrate', 'callHome'); HighEntropyPct = 0.5; AvgEntropy = 7.0; ReflectionCount = 2 }) } }
        @{ Label = "Verified mod that contains scary strings"; Bands = @("Clean"); Over = @{ Verified = $true; Features = (New-TestFeatures @{ StrongStrings = @('AutoCrystal', 'KillAura'); HttpDownload = $true; ReflectionCount = 2 }) } }
        @{ Label = "Random-named jar, unverified"; Bands = @("Review"); Over = @{ RandomName = $true; Features = (New-TestFeatures @{ AvgEntropy = 5.6; ReflectionCount = 1 }) } }
        @{ Label = "Random-named jar but verified"; Bands = @("Clean"); Over = @{ RandomName = $true; Verified = $true; Features = (New-TestFeatures @{ AvgEntropy = 5.6 }) } }
        @{ Label = "Cheat hiding behind a legit mod id"; Bands = @("Confirmed"); Over = @{ LegitModId = $true; Features = (New-TestFeatures @{ JavaAgent = $true; AgentRetransform = $true; HiddenPayload = 3; PackageHits = @('org/chainlibs'); StrongStrings = @('AutoCrystal','KillAura'); HighEntropyPct = 0.4; AvgEntropy = 7.0; ReflectionCount = 4 }) } }
        @{ Label = "Legit mod tampered with (agent added)"; Bands = @("Confirmed"); Over = @{ LegitModId = $true; Features = (New-TestFeatures @{ JavaAgent = $true; ReflectionCount = 3 }) } }
        @{ Label = "Real verified mod shipping its own agent"; Bands = @("Clean"); Over = @{ Verified = $true; Features = (New-TestFeatures @{ JavaAgent = $true }) } }
        @{ Label = "Aim cheat by behaviour alone"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; rotationRatio = 1.0; attackRatio = 1.0 }) } }
        @{ Label = "Chat macro (packet, no rotation)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Minimap w/ mob radar, unverified"; Bands = @("ServerRule"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ renderRatio = 1.0; entityscanRatio = 1.0 }) } }
        @{ Label = "Minimap w/ mob radar, verified"; Bands = @("Clean"); Over = @{ Verified = $true; Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ renderRatio = 1.0; entityscanRatio = 1.0 }) } }
        @{ Label = "Dropper by behaviour (encrypted)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ cryptoRatio = 1.0; classloadRatio = 1.0; reflectRatio = 1.0; StrReadableRatio = 0.1 }) } }
        # Measured on the real Doomsday loader: 175 KB of zeros in an entry called
        # "000", which is the vendor's own "Randomize size" option. 0 hits across
        # 179 real libraries.
        @{ Label = "Jar padded to change its own hash"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{ PaddingEntry = 1 }); Bytecode = (New-TestBytecode @{}) } }
        @{ Label = "Reflection-heavy lib, no cheat behaviour"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 5 }); Bytecode = (New-TestBytecode @{ reflectRatio = 1.0 }) } }
        # Mixins are how ordinary Fabric mods are built - Sodium and the Fabric API
        # are nothing else - so the technique on its own must never move the band.
        @{ Label = "Mod built entirely out of mixins"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ mixinRatio = 1.0; renderRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Mixin into rendering only"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ mixinRatio = 1.0; renderRatio = 1.0 }) } }
        # Silent rotations: the target is named in the annotation, so movepacket and
        # rotation are both found in strings rather than in the symbol table. Same
        # rule, same band - the mixin only changes where the evidence was read from.
        @{ Label = "Silent rotations via a packet mixin"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ mixinRatio = 1.0; mixintargetRatio = 1.0; movepacketRatio = 1.0; rotationRatio = 1.0 }) } }
        @{ Label = "Mixin that moves the player (jetpack)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ mixinRatio = 1.0; mixintargetRatio = 1.0; motionRatio = 1.0; inputRatio = 1.0 }) } }
        # A class transformer is how half of Forge works and OptiFine is a tweaker,
        # so installing one must never move the band on its own.
        @{ Label = "Forge coremod, rewrites the renderer"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ transformerRatio = 1.0; renderRatio = 1.0 }) } }
        @{ Label = "Coremod that spoofs the reported aim"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ transformerRatio = 1.0; coretargetRatio = 1.0; movepacketRatio = 1.0; rotationRatio = 1.0 }) } }
        # 1.8.9 in its own names: same rules, same bands, MCP vocabulary.
        @{ Label = "1.8.9 killaura (MCP names)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; rotationRatio = 1.0; attackRatio = 1.0; entityscanRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "1.8.9 sprint mod (MCP names)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ motionRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Agent injector (Premain + retransform)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{ JavaAgent = $true; AgentRetransform = $true; AgentClass = "net.java.a.b"; SingleCharClsPct = 0.4 }) } }
        @{ Label = "Encrypted-payload dropper"; Bands = @("Confirmed", "Likely"); Over = @{ Features = (New-TestFeatures @{ HiddenPayload = 6; SingleCharClsPct = 0.6; AvgEntropy = 6.8 }) } }
        @{ Label = "Multi-loader identity spoof"; Bands = @("Likely"); Over = @{ Features = (New-TestFeatures @{ LoaderIds = @('fabric', 'forge', 'labymod', 'bukkit', 'modloader') }) } }
        @{ Label = "Verified mod that ships an agent"; Bands = @("Clean"); Over = @{ Verified = $true; Features = (New-TestFeatures @{ JavaAgent = $true; AgentClass = "org.spongepowered.asm.launch.MixinAgent" }) } }
        @{ Label = "Architectury jar (fabric+forge only)"; Bands = @("Clean"); Over = @{ LegitModId = $true; Features = (New-TestFeatures @{ LoaderIds = @('fabric', 'forge'); ReflectionCount = 2 }) } }
        # ---- the behaviour families, each against the legit mod it resembles ----
        @{ Label = "Scaffold (places + forges movement)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockplaceRatio = 1.0; movepacketRatio = 1.0; rotationRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Schematic printer (places on a key)"; Bands = @("ServerRule"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockplaceRatio = 1.0; inputRatio = 1.0; renderRatio = 1.0 }) } }
        @{ Label = "Speed/no-fall (velocity + forged move)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; motionRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Inventory-move (slots + forged move)"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ containerRatio = 1.0; movepacketRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Inventory sorting (slots on a key)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ containerRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Obfuscated inventory sorter"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{ SingleCharClsPct = 0.7; HighEntropyPct = 0.5; AvgEntropy = 7.0 }); Bytecode = (New-TestBytecode @{ containerRatio = 1.0; inputRatio = 1.0; ObfNameRatio = 0.8; StrReadableRatio = 0.1 }) } }
        @{ Label = "Nuker (breaks blocks, no input)"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockbreakRatio = 1.0 }) } }
        @{ Label = "Vein miner (breaks on a key)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockbreakRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Triggerbot (attacks, no input)"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ attackRatio = 1.0; entityscanRatio = 1.0 }) } }
        @{ Label = "Reach display (crosshair, no attack)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ renderRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Velocity (packet listen + motion)"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ pktlistenRatio = 1.0; motionRatio = 1.0 }) } }
        @{ Label = "Replay recorder (listen, no motion)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ pktlistenRatio = 1.0; renderRatio = 1.0 }) } }
        @{ Label = "Freecam (writes rotation + renders)"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ rotationRatio = 1.0; renderRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Third-person camera (renders only)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ renderRatio = 1.0 }) } }
        @{ Label = "Baritone-style pathing"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; rotationRatio = 1.0 }) } }
        # A real Baritone jar: it ships baritone/ classes, which is an identity
        # match, so it is flagged for THAT rather than through the freecam rule it
        # happened to trip on the way past.
        @{ Label = "A jar that ships Baritone"; Bands = @("Likely", "Confirmed"); Over = @{ Features = (New-TestFeatures @{ PackageHits = @("baritone/") }); Bytecode = (New-TestBytecode @{ rotationRatio = 0.3; renderRatio = 0.3; inputRatio = 0.4 }) } }
        @{ Label = "Baritone by filename, no packages read"; Bands = @("Likely", "Confirmed"); Over = @{ FilenameClient = $true; FilenameToken = "baritone"; Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ inputRatio = 1.0 }) } }
        @{ Label = "Printer that ALSO forges movement"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockplaceRatio = 1.0; inputRatio = 1.0; movepacketRatio = 1.0 }) } }
        @{ Label = "Known cheat hash beats the clean cap"; Bands = @("Confirmed"); Over = @{ HashKnownCheat = $true; Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ containerRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Self-deleting jar is measured, not accused"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ selfwipeRatio = 1.0; selfpathRatio = 1.0; filedeleteRatio = 1.0 }) } }
        # A transformer that only its bytecode declares - no FMLCorePlugin in the
        # manifest - must still be recorded as scope, and must still not be flagged.
        @{ Label = "Transformer the manifest does not declare"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ transformerRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Library unpacking a native lib"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ selfpathRatio = 1.0; filedeleteRatio = 1.0; nativetempRatio = 1.0 }) } }
        @{ Label = "Mod that reads its own jar location"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ selfpathRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Jetpack mod (writes velocity)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ motionRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Update checker (http + reflection)"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 3 }); Bytecode = (New-TestBytecode @{ netRatio = 1.0; reflectRatio = 1.0; inputRatio = 1.0 }) } }
        @{ Label = "Aim cheat hidden behind reflection"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 4 }); Bytecode = (New-TestBytecode @{ movepacketRatio = 1.0; rotationRatio = 1.0; reflectRatio = 1.0; hiddenapiRatio = 1.0 }) } }
        @{ Label = "Compat shim reflecting on a MC class"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 3 }); Bytecode = (New-TestBytecode @{ reflectRatio = 1.0; inputRatio = 1.0 }) } }
    )
    $pass = 0; $fail = 0
    foreach ($c in $cases) {
        $ctx = @{}
        foreach ($k in $base.Keys) { $ctx[$k] = $base[$k] }
        foreach ($k in $c.Over.Keys) { $ctx[$k] = $c.Over[$k] }
        $v = Get-ModVerdict $ctx
        $ok = $c.Bands -contains $v.Band
        if ($ok) { $pass++ } else { $fail++ }
        $col = if ($ok) { "Green" } else { "Red" }
        $tag = if ($ok) { "PASS" } else { "FAIL" }
        W ("  [$tag] " + $c.Label.PadRight(40) + " score=$($v.Score)  band=$($v.Band)  (want $($c.Bands -join '/'))") $col
    }
    Write-Host ""
    W "  Overall-scan AI (judges the WHOLE scan, not one file)" Cyan
    Write-Host ""
    $sCases = @(
        @{ Label = "Perfectly clean scan"; Bands = @("Clean"); Raw = @{ total_mods = 25; verified = 25 } }
        @{ Label = "Normal player, nothing verified"; Bands = @("Clean"); Raw = @{ total_mods = 20; verified = 0 } }
        @{ Label = "Confirmed cheat jar found"; Bands = @("Confirmed"); Raw = @{ total_mods = 20; verified = 12; flagged = 1; hard_confirmed = 1 } }
        @{ Label = "Clean mods but JVM injection"; Bands = @("Likely", "Confirmed"); Raw = @{ total_mods = 18; verified = 18; jvm_inject = 2 } }
        @{ Label = "Cheat jars stashed outside mods"; Bands = @("Review", "Likely"); Raw = @{ total_mods = 10; verified = 8; stray_jars = 3; cheat_folders = 1 } }
        @{ Label = "Cheat client live in game memory"; Bands = @("Confirmed"); Raw = @{ total_mods = 20; verified = 20; mem_client = 1; jvm_inject = 1; mc_running = 1 } }
        @{ Label = "Jars deleted while MC still running"; Bands = @("Likely", "Confirmed"); Raw = @{ total_mods = 5; verified = 3; deleted_jars = 2; bam_deleted = 2; mc_running = 1 } }
        @{ Label = "Clean scan with Minecraft running"; Bands = @("Clean"); Raw = @{ total_mods = 25; verified = 25; mc_running = 1 } }
        # An autoclicker is never in the mods folder, so the mods can be spotless
        # and the scan still has to say what it found on the PC.
        @{ Label = "Spotless mods, autoclicker aimed at MC"; Bands = @("Confirmed"); Raw = @{ total_mods = 25; verified = 25; macro_cheat = 1; mc_running = 1 } }
        @{ Label = "Spotless mods, macro named as technique"; Bands = @("Confirmed"); Raw = @{ total_mods = 25; verified = 25; macro_named = 1 } }
        # The hole v3 closes: a behaviour-confirmed cheat reached this model only
        # through the flagged RATIO, which a large modpack divides away to nothing.
        @{ Label = "Big pack, ONE behaviour-confirmed cheat"; Bands = @("Confirmed"); Raw = @{ total_mods = 100; verified = 60; flagged = 1; behaviour_cheat = 1 } }
        @{ Label = "Big pack, a behaviour-LIKELY mod"; Bands = @("Likely"); Raw = @{ total_mods = 100; verified = 60; flagged = 1; behaviour_likely = 1 } }
        # A server-rule finding needs a person, and never more than that.
        @{ Label = "Server-rule findings only"; Bands = @("Review"); Raw = @{ total_mods = 40; verified = 20; review = 8; server_rule = 8 } }
        # The jar can be gone. The log line saying it loaded is not, and it is dated.
        @{ Label = "Mods clean, cheat named in the log"; Bands = @("Confirmed"); Raw = @{ total_mods = 20; verified = 20; log_cheat = 1 } }
        @{ Label = "Launcher profile starts a cheat class"; Bands = @("Confirmed"); Raw = @{ total_mods = 20; verified = 20; instance_cheat = 1 } }
        @{ Label = "A -javaagent in the launcher profile"; Bands = @("Likely"); Raw = @{ total_mods = 20; verified = 20; instance_agent = 1 } }
        # The property that makes it safe to REPORT weak observations at all.
        # A localhost listener, a chat message naming a cheat, a bootclasspath
        # flag: all real, all with innocent explanations, all counted here as
        # system issues. They must move the score and never decide the band -
        # otherwise a Gradle daemon convicts somebody.
        @{ Label = "Soft observations only, nothing proven"; Bands = @("Clean"); Raw = @{ total_mods = 25; verified = 25; sys_issues = 3 } }
        @{ Label = "Soft observations at the maximum"; Bands = @("Clean"); Raw = @{ total_mods = 25; verified = 25; sys_issues = 10 } }
    )
    $sBase = @{ total_mods = 0; verified = 0; flagged = 0; review = 0; random_named = 0; cheatsite_dl = 0; hard_confirmed = 0; sys_issues = 0; jvm_inject = 0; bam_deleted = 0; cheat_procs = 0; stray_jars = 0; cheat_folders = 0; deleted_jars = 0; mc_running = 0; mem_client = 0 }
    foreach ($sc in $sCases) {
        $raw = @{}
        foreach ($k in $sBase.Keys) { $raw[$k] = $sBase[$k] }
        foreach ($k in $sc.Raw.Keys) { $raw[$k] = $sc.Raw[$k] }
        $sv = Get-SessionVerdict $raw
        $ok = $sc.Bands -contains $sv.Band
        if ($ok) { $pass++ } else { $fail++ }
        $col = if ($ok) { "Green" } else { "Red" }
        $tag = if ($ok) { "PASS" } else { "FAIL" }
        W ("  [$tag] " + $sc.Label.PadRight(40) + " score=$($sv.Score)  band=$($sv.Band)  (want $($sc.Bands -join '/'))") $col
    }

    Write-Host ""
    W "  Screenshare report (the document staff actually read)" Cyan
    Write-Host ""
    # These run the real functions, not a copy of them. The last case renders the
    # whole report end to end - it is the only thing that proves the template
    # parses and every call inside it resolves on a real Windows PowerShell.
    $rCases = @(
        @{ Label = "Clean verdict never claims proof"; Test = { -not ((Get-BandStyle "Clean").say -match "proof") } }
        @{ Label = "Clean verdict points at the coverage box"; Test = { (Get-BandStyle "Clean").say -match "coverage" } }
        @{ Label = "Confirmed verdict is labelled CONFIRMED"; Test = { (Get-BandStyle "Confirmed").short -eq "CONFIRMED" } }
        @{ Label = "Unknown band falls back to clean"; Test = { (Get-BandStyle "nonsense").short -eq "CLEAN" } }
        @{ Label = "Score scale clamps a negative score"; Test = { (New-ScoreScale -14 "#fff") -match "width:0%" } }
        @{ Label = "Score scale clamps above 100"; Test = { (New-ScoreScale 250 "#fff") -match "width:100%" } }
        @{ Label = "Score scale draws the real band edges"; Test = {
            $sc = New-ScoreScale 50 "#fff"
            ($sc -match "left:30%") -and ($sc -match "left:60%") -and ($sc -match "left:85%") } }
        @{ Label = "A finding keeps its reasoning"; Test = {
            $before = $script:Findings.Count
            $f = Add-Finding "WARN" "SelfTest" "probe" @("item-a") "what" "why" "how" "fix"
            $ok = ($f.Level -eq "WARN") -and ($f.Items[0] -eq "item-a") -and ($f.Why -eq "why")
            while ($script:Findings.Count -gt $before) { $script:Findings.RemoveAt($script:Findings.Count - 1) }
            $ok } }
        @{ Label = "Write-Detail attaches to the flag before it"; Test = {
            $before = $script:Findings.Count
            Write-SystemFlag "OK" "self-test probe" | Out-Null
            Write-Detail "w" "y" "h" "f"
            $ok = ($script:Findings[$script:Findings.Count - 1].What -eq "w")
            while ($script:Findings.Count -gt $before) { $script:Findings.RemoveAt($script:Findings.Count - 1) }
            $ok } }
        # The filename heuristic, on names rather than on a flag. Every Python
        # mirror takes random_name as an INPUT, so none of them could ever have
        # caught this: 'aeiou' -contains $_ is always False - a string is a
        # collection of one element, itself - so the vowel count was always 0 and
        # "looks random" silently meant "has five letters and is not on the
        # prefix list". HikariCP and Java-WebSocket were both called random-named
        # and floored to Review. Found by running the tool for real.
        @{ Label = "Real mod filenames are not called random"; Test = {
            $real = @('HikariCP-5.1.0.jar','Java-WebSocket-1.5.6.jar','sodium-fabric-0.5.8.jar',
                      'journeymap-1.20.1-5.9.7.jar','amqp-client-5.21.0.jar','asm-analysis-9.7.jar',
                      'adventure-nbt-4.17.0.jar','ant-1.10.14.jar','wurstclient-7.36.jar')
            @($real | Where-Object { Test-RandomFilename $_ }).Count -eq 0 } }
        @{ Label = "...and a real random name still is"; Test = {
            # gzfjalsrvp is the name the DoomsDay download page actually produced.
            $rand = @('gzfjalsrvp.jar','xkcdvbnm.jar','qwrtzpfgh.jar','zzxcvbnmm.jar')
            @($rand | Where-Object { Test-RandomFilename $_ }).Count -eq $rand.Count } }
        @{ Label = "Vowels are counted, not compared to a whole word"; Test = {
            # The exact shape of the bug, kept as a case of its own so a future
            # rewrite of the heuristic cannot quietly reintroduce it.
            (('hikaricp'.ToCharArray() | Where-Object { 'aeiou'.Contains($_) }).Count -eq 3) } }
        @{ Label = "Gaps are reported, never swallowed"; Test = {
            $before = $script:ScanGaps.Count
            Add-ScanGap "self-test probe gap"
            Add-ScanGap "self-test probe gap"
            $ok = ($script:ScanGaps.Count -eq $before + 1)
            while ($script:ScanGaps.Count -gt $before) { $script:ScanGaps.RemoveAt($script:ScanGaps.Count - 1) }
            $ok } }
        @{ Label = "Full report renders and is written"; Test = {
            # GetTempPath, not $env:TEMP: the variable is not set on every host,
            # and a self-test that fails because it could not find a temp folder
            # reads exactly like a self-test that found a broken report.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "AsyncAnalyzer_SelfTest.html"
            $out = New-HtmlReport $tmp
            $ok = $false
            if ($out -and (Test-Path $out)) {
                $txt = Get-Content $out -Raw
                $ok = ($txt -match "COVERAGE|Coverage") -and ($txt -match "Could NOT be checked") -and
                      ($txt -match "</html>") -and ($txt.Length -gt 4000)
                Remove-Item $out -ErrorAction SilentlyContinue
            }
            $ok } }
    )
    foreach ($rc in $rCases) {
        $ok = $false
        try { $ok = [bool](& $rc.Test) } catch { $ok = $false }
        if ($ok) { $pass++ } else { $fail++ }
        $col = if ($ok) { "Green" } else { "Red" }
        $tag = if ($ok) { "PASS" } else { "FAIL" }
        W ("  [$tag] " + $rc.Label) $col
    }

    Write-Host ""
    if ($fail -eq 0) { W "  All $pass self-tests passed $([char]0x2014) model, verdict logic and report OK on this machine." Green }
    else { W "  $fail self-test(s) FAILED $([char]0x2014) do not trust results until fixed." Red }
    Write-Host ""
}

function Enc([string]$s) { return [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Invoke-HashOnly([string]$Folder) {
    # The single biggest gap in this tool is that signatures.json contains no real
    # cheat hashes, and the reason is not technical: whoever has the jars is not
    # the person who edits the file. So this does exactly one thing - turn a folder
    # of jars into a block of JSON that can be pasted straight in.
    #
    # It reads. It does not scan, upload, move, rename or delete anything, and it
    # does not need the internet. That matters, because the folders people would
    # run this on are the ones they are least willing to hand over.
    Write-Host ""
    W "  AsyncAnalyzer $([char]0x2014) hash only" Cyan
    Write-Host ""
    if (-not (Test-Path $Folder -PathType Container)) {
        W "  $([char]0x2717) Not a folder: $Folder" Red
        Write-Host ""
        return
    }
    W "  Reading $Folder" DarkGray
    W "  Nothing is uploaded, changed or deleted $([char]0x2014) this only computes SHA1." DarkGray
    Write-Host ""

    $files = @(Get-ChildItem -Path $Folder -Filter "*.jar" -File -ErrorAction SilentlyContinue)
    $files += @(Get-ChildItem -Path $Folder -Filter "*.litemod" -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        W "  No .jar or .litemod files in that folder." Yellow
        Write-Host ""
        return
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in ($files | Sort-Object Name)) {
        $h = Get-FileSHA1 $f.FullName
        if (-not $h) { W "  $([char]0x2717) could not read $($f.Name)" DarkYellow; continue }
        [void]$rows.Add(@{ Name = $f.Name; Hash = $h })
        W "  $h  " DarkGray -NoNewline; W $f.Name White
    }
    if ($rows.Count -eq 0) { Write-Host ""; return }

    # Ready to paste into ml/signatures.json -> knownCheatHashes.
    $json = ($rows | ForEach-Object { '    "' + $_.Hash + '",   // ' + $_.Name }) -join "`r`n"
    $json = $json -replace ',(\s+//[^\r\n]*)$', '$1'
    $out = @"
Paste this into ml/signatures.json, inside "knownCheatHashes":

$json
"@
    Write-Host ""
    W "  $($rows.Count) file(s) hashed." Green
    try {
        $dir = Join-Path $env:APPDATA "AsyncAnalyzer"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $file = Join-Path $dir "hashes.txt"
        $out | Out-File -FilePath $file -Encoding UTF8
        W "  Saved: $file" Green
        W "  Open it, copy the block, paste it into signatures.json $([char]0x2014) or just send the file." DarkGray
    } catch { W "  Could not write the file: $($_.Exception.Message)" Red }
    Write-Host ""
    W "  Only add hashes of files you are CERTAIN are cheats." Yellow
    W "  A pooled hash reaches every client on their next run, so a wrong one" DarkGray
    W "  becomes a team-wide false accusation. It is revocable, but it is easier" DarkGray
    W "  to be sure now than to explain later." DarkGray
    Write-Host ""
}

# The report is written for one reader: the staff member sitting in a screenshare
# with the suspect on the other side. It has to answer three things without them
# scrolling back through a console that already closed - what the verdict is, what
# it rests on, and what the scan could NOT check. Everything else is secondary.

function Get-BandStyle([string]$band) {
    switch ($band) {
        "Confirmed" { return @{ c = "#ff5f56"; label = "CHEATING CONFIRMED";   short = "CONFIRMED";
                                say = "This is proof, not a guess. The evidence below names the file, the process or the memory region it was found in." } }
        "Likely"    { return @{ c = "#ff9f43"; label = "LIKELY CHEATING";      short = "LIKELY";
                                say = "Strong signs of cheating. Every point below needs an answer before this is closed." } }
        "Review"    { return @{ c = "#ffcf4d"; label = "NEEDS A MANUAL LOOK";  short = "REVIEW";
                                say = "Something does not fit, but it is not proof. Read the points below and decide." } }
        # Violet on purpose: it must not read as a severity between amber and red.
        # This is a different KIND of finding, not a stronger one.
        "ServerRule" { return @{ c = "#a78bfa"; label = "SERVER RULE";          short = "SERVER RULE";
                                say = "Recognised for certain, and whether it is allowed is your server's rule rather than a technical question. This is not an accusation." } }
        default     { return @{ c = "#3ddc84"; label = "NOTHING FOUND";        short = "CLEAN";
                                say = "Nothing cheat-like was found in what was checked. Read the coverage box - it says what was not checked." } }
    }
}

function Get-LevelStyle([string]$level) {
    switch ($level) {
        "FAIL" { return @{ c = "#ff5f56"; label = "FINDING";  rank = 0 } }
        "WARN" { return @{ c = "#ffcf4d"; label = "WARNING";  rank = 1 } }
        # INFO never reaches a card - it is routed to the coverage gaps instead - but
        # it keeps a style so nothing renders blank if that ever changes.
        "INFO" { return @{ c = "#9aa8ba"; label = "NOT RUN";  rank = 2 } }
        # The state of the PC: real, worth seeing, and not evidence of cheating.
        # It has its own level so no filter that looks for FAIL/WARN can pick it
        # up by accident - a firewall turned off by an antivirus must never end
        # up in "Look at these first".
        "STATE" { return @{ c = "#9aa8ba"; label = "PC STATE"; rank = 4 } }
        default { return @{ c = "#3ddc84"; label = "CLEAR";   rank = 3 } }
    }
}

# One card, used for findings and for the PC-state block alike. They are the same
# object with a different level, and rendering them two different ways once meant
# writing the markup twice and letting the copies drift.
function New-FindingCard($f) {
    $ls = Get-LevelStyle $f.Level
    $itemHtml = ""
    if (@($f.Items).Count -gt 0) {
        $li = ""
        foreach ($i in @($f.Items)) { $li += "<li class='mono'>$(Enc $i)</li>" }
        $itemHtml = "<div class='why'><div class='eyebrow'>What exactly was found ($(@($f.Items).Count))</div><ul class='evidence'>$li</ul></div>"
    }
    $rz = ""
    if ($f.What) { $rz += "<div class='r'><span class='rl'>What this check does</span>$(Enc $f.What)</div>" }
    if ($f.Why)  { $rz += "<div class='r'><span class='rl'>Why it matters</span>$(Enc $f.Why)</div>" }
    if ($f.How)  { $rz += "<div class='r'><span class='rl'>How it gets there</span>$(Enc $f.How)</div>" }
    if ($f.Fix)  { $rz += "<div class='r'><span class='rl'>What to do</span>$(Enc $f.Fix)</div>" }
    $reasonHtml = if ($rz) { "<div class='why'><div class='eyebrow'>Reasoning</div><div class='reason-grid'>$rz</div></div>" } else { "" }
    return @"
<article class="find" style="--lc:$($ls.c);">
  <header class="find-head">
    <span class="tag" style="background:$($ls.c);">$($ls.label)</span>
    <h3>$(Enc $f.Title)</h3>
    <span class="area">$(Enc $f.Area)</span>
  </header>
  $itemHtml
  $reasonHtml
</article>
"@
}

function New-HtmlReport([string]$OutPath = "") {
    $sv      = Get-SessionVerdictCached
    $svStyle = Get-BandStyle $sv.Band
    $raw     = $script:SessionRaw

    $now      = Get-Date
    $stampLocal = $now.ToString("yyyy-MM-dd HH:mm:ss") + " (UTC" + $now.ToString("zzz") + ")"
    $stampUtc   = $now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
    $reportId   = $now.ToString("yyyyMMdd-HHmmss") + "-" + $env:COMPUTERNAME
    $isAdmin    = Test-IsAdmin
    $mcRunning  = ($raw -and $raw.mc_running -gt 0)

    $gapCount = @($script:ScanGaps).Count
    # A green headline on a scan that could not look everywhere reads as "proven
    # clean" if nothing says otherwise. It gets said in the headline, not only in
    # the coverage box further down.
    $mastCaveat = ""
    if ($gapCount -gt 0 -and ($sv.Band -eq "Clean" -or $sv.Band -eq "Review")) {
        $mastCaveat = "<p class='caveat'>$gapCount thing(s) could not be checked at all &mdash; this result does not cover them. See <b>Coverage</b> below.</p>"
    }

    # ---- verdict reasons ----------------------------------------------------
    $svReasons = ""
    $n = 0
    foreach ($r in @($sv.Reasons)) { $n++; $svReasons += "<li><span class='num'>$n</span><span>$(Enc $r)</span></li>" }

    # ---- scan record --------------------------------------------------------
    $targetItems = ""
    foreach ($t in @($script:ScanTargets | Where-Object { $_ })) { $targetItems += "<div class='mono'>$(Enc $t)</div>" }
    if (-not $targetItems) { $targetItems = "<div class='mono dim'>none</div>" }

    $depthWord = if ($script:DeepScan) { "deep (system, PC and memory included)" } else { "standard (mods and system)" }
    $recRows = @(
        @{ k = "Scanned at";       v = "$(Enc $stampLocal)<div class='dim'>$(Enc $stampUtc)</div>" }
        @{ k = "Time taken";       v = "$([Math]::Round(((Get-Date) - $script:ScanStart).TotalSeconds, 1)) seconds<div class='dim'>started $(Enc ($script:ScanStart.ToString('HH:mm:ss'))) &mdash; a report that claims to be from this scan has to fit in that window</div>" }
        @{ k = "PC";               v = "<span class='mono'>$(Enc $env:COMPUTERNAME)</span>" }
        @{ k = "Windows user";     v = "<span class='mono'>$(Enc $env:USERNAME)</span>" }
        @{ k = "Administrator";    v = $(if ($isAdmin) { "<span class='yes'>yes</span> &mdash; full access" } else { "<span class='no'>no</span> &mdash; some checks were skipped" }) }
        @{ k = "Minecraft";        v = $(if ($mcRunning) { "<span class='yes'>running during the scan</span>" } else { "<span class='no'>not running</span> &mdash; nothing could be read out of the live game" }) }
        @{ k = "Scan depth";       v = "$(Enc $depthWord)<div class='dim'>up to $($script:BcMaxClasses) classes analysed per jar</div>" }
        @{ k = "Folders scanned";  v = $targetItems }
        @{ k = "Second pass";      v = $(if ($script:LateScanned -gt 0) { "<span class='yes'>$($script:LateScanned) more jar(s)</span> found in $($script:LateScanDirs.Count) folder(s) the running game was reading that nothing on disk pointed at" } elseif ($script:LateScanDirs.Count -gt 0) { "the running game named $($script:LateScanDirs.Count) extra folder(s); they held nothing new" } else { "<span class='dim'>not needed &mdash; the running game loaded mods only from folders that were already scanned</span>" }) }
        @{ k = "Tool";             v = "AsyncAnalyzer $(Enc $script:Version) &mdash; mod model v$($script:mlModelVersion), $($script:mlSamples) examples learned" }
        @{ k = "Report ID";        v = "<span class='mono'>$(Enc $reportId)</span>" }
        @{ k = "Scan ID";          v = "<span class='mono big'>$(Enc $script:ScanId)</span>" }
        @{ k = "Code from staff";  v = $(if ($script:ScanCode) { "<span class='mono big yes'>$(Enc $script:ScanCode)</span>" } else { "<span class='no'>none was given</span> &mdash; this report cannot be shown to be fresh" }) }
    )
    $recordRows = ""
    foreach ($r in $recRows) { $recordRows += "<div class='rec'><div class='rk'>$($r.k)</div><div class='rv'>$($r.v)</div></div>" }

    # ---- is this report real? ------------------------------------------------
    # Worth being exact rather than reassuring. Somebody who controls the PC can
    # edit an HTML file or take a screenshot and change it, and no amount of
    # hashing inside that same file fixes it - they control the hash too. What
    # these two things actually do is narrower and still useful, so say which.
    $authRows = ""
    if ($script:ScanCode) {
        $authRows += "<li><b>Staff code <span class='mono'>$(Enc $script:ScanCode)</span> is in this report.</b> " +
            "It was said out loud before the scan started, so a report made earlier " +
            "cannot carry it. That dates this report; it does not prove the contents.</li>"
    } else {
        $authRows += "<li><b>No staff code was given.</b> Run the tool again with " +
            "<span class='mono'>-Code &lt;word&gt;</span> where the word comes from the moderator, " +
            "and the report can at least be shown to be fresh.</li>"
    }
    if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
        $authRows += "<li><b>This scan was uploaded as <span class='mono'>$(Enc $script:ScanId)</span>.</b> " +
            "Look that ID up in the team dashboard: that copy was written by the tool, " +
            "not by the person being checked, and it is the one to trust if the two disagree.</li>"
    } else {
        $authRows += "<li><b>Nothing was uploaded</b> &mdash; team mode is off, so this file is the only copy " +
            "and it lives on the scanned PC. With team mode on, every scan gets an ID the moderator can open themselves.</li>"
    }
    $authRows += "<li>Watch the scan run on the screenshare. A file can be edited afterwards; " +
        "the console output happening in front of you cannot.</li>"
    $authBox = "<div class='panel'><div class='eyebrow'>Is this report real?</div><ul class='plain'>$authRows</ul></div>"

    # ---- coverage: an area counts as checked only if it actually reported ----
    $areas = @()
    foreach ($f in @($script:Findings)) { if ($areas -notcontains $f.Area) { $areas += $f.Area } }
    $coverChecked = "<li><b>Mods folder</b> &mdash; $($script:TotalMods) file(s), each one read, hashed and analysed as bytecode</li>"
    foreach ($a in $areas) {
        $cnt = @($script:Findings | Where-Object { $_.Area -eq $a -and ($_.Level -eq "FAIL" -or $_.Level -eq "WARN") }).Count
        $tail = if ($cnt -gt 0) { "$cnt finding(s)" } else { "nothing found" }
        $coverChecked += "<li><b>$(Enc $a)</b> &mdash; $tail</li>"
    }
    $coverGaps = ""
    foreach ($g in @($script:ScanGaps)) { $coverGaps += "<li>$(Enc $g)</li>" }
    $gapBox = if ($gapCount -gt 0) {
        "<div class='panel gap'><div class='eyebrow warnfg'>Could NOT be checked &mdash; $gapCount</div><ul class='plain'>$coverGaps</ul>" +
        "<p class='note'>A clean result only covers what was actually checked. Anything listed here is unproven either way.</p></div>"
    } else {
        "<div class='panel'><div class='eyebrow goodfg'>Could NOT be checked &mdash; nothing</div><p class='note'>Every check this tool has ran to completion. Nothing was skipped.</p></div>"
    }

    # ---- mods ---------------------------------------------------------------
    $mods = @(@($flaggedMods) + @($reviewMods) | Where-Object { $_ } | Sort-Object Score -Descending)
    $srNote = if ($script:ServerRule -gt 0) {
        " <span class='srnote'>$($script:ServerRule) of them are server-rule questions, not accusations</span>"
    } else { "" }
    $modCards = ""
    foreach ($m in $mods) {
        $bm = Get-BandStyle $m.Band
        $reasonItems = ""
        foreach ($r in @($m.Reasons)) { $reasonItems += "<li>$(Enc $r)</li>" }
        $src = if ($m.DownloadSource) { "<span class='sep'>&bull;</span>downloaded from $(Enc $m.DownloadSource)" } else { "" }
        $sha = if ($m.Hash) { $m.Hash } else { "not readable" }
        $modCards += @"
<article class="find" style="--lc:$($bm.c);">
  <header class="find-head">
    <span class="tag" style="background:$($bm.c);">$($bm.short)</span>
    <h3 class="mono">$(Enc $m.FileName)</h3>
    <span class="score">$($m.Score)<small>/100</small></span>
  </header>
  $(New-ScoreScale $m.Score $bm.c)
  <div class="kv mono">SHA1 $sha<span class="sep">&bull;</span>AI cheat probability $($m.Probability)%$src</div>
  <div class="why"><div class="eyebrow">Why it scored this way</div><ul class="reasons">$reasonItems</ul></div>
</article>
"@
    }
    if (-not $modCards) {
        $modCards = "<div class='panel clear'><b class='goodfg'>No mod was flagged.</b> Every file in the scanned folders is either verified against Modrinth/CurseForge or came back clean on all rules.</div>"
    }

    $verified = @($verifiedMods | Where-Object { $_ })
    $verRows = ""
    foreach ($v in $verified) {
        $nm = if ($v.ModName) { $v.ModName } else { $v.FileName }
        $verRows += "<tr><td>$(Enc $nm)</td><td class='mono dim'>$(Enc $v.FileName)</td><td><span class='pill good'>Verified</span></td></tr>"
    }
    $verSection = if ($verified.Count -gt 0) {
        "<details><summary>Verified mods ($($verified.Count)) &mdash; hash matched a real release on Modrinth or CurseForge</summary><table><thead><tr><th>Mod</th><th>File</th><th>Status</th></tr></thead><tbody>$verRows</tbody></table></details>"
    } else { "" }

    # ---- the state of the PC, kept apart from the accusation ----------------
    # A third-party antivirus turns the Windows firewall off by itself; script
    # logging is off by default on home Windows. Counting either against a player
    # is how an innocent person collects "system issues". They are still shown,
    # because a Security log cleared an hour before the screenshare is something
    # a moderator wants to see - it just is not the tool's claim to make.
    $stateRows = ""
    foreach ($f in $state) { $stateRows += New-FindingCard $f }
    $stateBox = if ($state.Count -eq 0) {
        "<div class='panel clear'>Firewall on, script logging at its default, Security log not cleared. Nothing to note about how this PC is set up.</div>"
    } else { $stateRows }

    # ---- look at these first ------------------------------------------------
    # A moderator reads this during a call, with somebody waiting. The report is
    # thorough, which is the same thing as long: the verdict is at the top and
    # the specific files it is about are several screens down. This block closes
    # that gap - the actual items needing a person, strongest first, each with
    # where it is and one line of why. Nothing new is computed here; it is the
    # same findings, ordered for someone who has ninety seconds.
    $todo = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($flaggedMods) + @($reviewMods)) {
        $prio = switch ($m.Band) {
            "Confirmed" { 100 }
            "Likely"    { 70 }
            "ServerRule" { 30 }
            default     { 40 }
        }
        [void]$todo.Add([PSCustomObject]@{
            Prio = $prio
            What = "$($m.FileName)"
            Where = "$($m.FilePath)"
            Band = $m.Band
            Score = $m.Score
            Colour = $(switch ($m.Band) { "Confirmed" { "#ff5f56" } "Likely" { "#ff9f43" } "ServerRule" { "#9aa8ba" } default { "#ffcf4d" } })
            Why = $(if (@($m.Reasons).Count -gt 0) { @($m.Reasons)[0] } else { "" })
        })
    }
    foreach ($f in @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })) {
        [void]$todo.Add([PSCustomObject]@{
            Prio = $(if ($f.Level -eq "FAIL") { 90 } else { 50 })
            What = $f.Title
            Where = $f.Area
            Band = $(if ($f.Level -eq "FAIL") { "Found" } else { "Check" })
            Score = -1
            Colour = (Get-LevelStyle $f.Level).c
            Why = $(if (@($f.Items).Count -gt 0) { [string](@($f.Items)[0]) } else { $f.Why })
        })
    }
    $todoRows = ""
    $shown = 0
    foreach ($t in @($todo | Sort-Object -Property @{ e = 'Prio'; Descending = $true }, @{ e = 'Score'; Descending = $true })) {
        if ($shown -ge 8) { break }
        $shown++
        $badge = if ($t.Score -ge 0) { "$($t.Band) $($t.Score)/100" } else { $t.Band }
        $why = [string]$t.Why
        if ($why.Length -gt 220) { $why = $why.Substring(0, 217) + "..." }
        $todoRows += "<li style='--vc:$($t.Colour);'><div class='tl'><b>$(Enc $t.What)</b><span class='tb'>$(Enc $badge)</span></div>" +
                     "<div class='tw'>$(Enc $t.Where)</div>" +
                     $(if ($why) { "<div class='ty'>$(Enc $why)</div>" } else { "" }) + "</li>"
    }
    $todoBox = if ($todo.Count -eq 0) {
        "<div class='panel clear'><b class='goodfg'>Nothing here needs a person.</b> No mod was flagged or held for review, and no check outside the mods folder found anything. The sections below are the working, in full, so the result can be checked rather than taken on trust.</div>"
    } else {
        $more = if ($todo.Count -gt $shown) { "<p class='note'>$($todo.Count - $shown) more below, in full.</p>" } else { "" }
        "<ol class='todo'>$todoRows</ol>$more"
    }

    # ---- everything else that was found, grouped by area --------------------
    # INFO is not a result - it is a check that could not run, and it is already in
    # the coverage box as a gap. Repeating it here as a "finding" would pad the list
    # a staff member has to work through with things that were never findings.
    $real  = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })
    $clear = @($script:Findings | Where-Object { $_.Level -eq "OK" })
    $state = @($script:Findings | Where-Object { $_.Level -eq "STATE" })
    $findCards = ""
    foreach ($f in ($real | Sort-Object @{ e = { (Get-LevelStyle $_.Level).rank } }, Area)) {
        $findCards += New-FindingCard $f
    }
    if (-not $findCards) {
        $findCards = "<div class='panel clear'><b class='goodfg'>Nothing outside the mods folder.</b> Every check listed under coverage came back clear.</div>"
    }

    $clearRows = ""
    foreach ($f in $clear) { $clearRows += "<tr><td class='dim'>$(Enc $f.Area)</td><td>$(Enc $f.Title)</td></tr>" }
    $clearSection = if ($clear.Count -gt 0) {
        "<details><summary>Checks that came back clear ($($clear.Count)) &mdash; proof of what was looked at</summary><table><thead><tr><th>Area</th><th>Result</th></tr></thead><tbody>$clearRows</tbody></table></details>"
    } else { "" }

    # ---- full inventory -----------------------------------------------------
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $addRow = {
        param($name, $ext)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if (-not $seen.Add($name)) { return }
        $st = if ($script:FlaggedModsList.Contains($name)) { "<span class='pill bad'>Flagged</span>" }
              elseif ($script:ReviewModsList.Contains($name)) { "<span class='pill warn'>Review</span>" }
              elseif (@($verified | Where-Object { $_.FileName -eq $name }).Count -gt 0) { "<span class='pill good'>Verified</span>" }
              else { "<span class='pill neutral'>Clean</span>" }
        $script:_allRows += "<tr data-ext='$ext'><td class='mono'>$(Enc $name)</td><td class='dim'>.$ext</td><td>$st</td></tr>"
    }
    $script:_allRows = ""
    foreach ($f in @($jarFiles | Where-Object { $_ })) { & $addRow $f.Name "jar" }
    foreach ($f in @($exeFiles | Where-Object { $_ })) { & $addRow $f.Name "exe" }
    foreach ($f in @($pyFiles  | Where-Object { $_ })) { & $addRow $f.Name "py" }
    if ($null -ne $script:PCScannedExeNames) { foreach ($nm in @($script:PCScannedExeNames | Where-Object { $_ })) { & $addRow $nm "exe" } }
    if ($null -ne $script:PCScannedPyNames)  { foreach ($nm in @($script:PCScannedPyNames  | Where-Object { $_ })) { & $addRow $nm "py" } }
    $allRows = $script:_allRows

    # ---- plain text copy, for pasting into a ticket -------------------------
    $plain = New-PlainSummary $sv $svStyle $stampLocal $reportId $isAdmin

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screenshare Report &mdash; $(Enc $env:COMPUTERNAME) $(Enc $now.ToString('yyyy-MM-dd HH:mm'))</title>
<style>
:root{
  --ground:#0b0e14; --surface:#131922; --surface2:#1a212c; --line:#262f3d;
  --ink:#e8eef6; --ink2:#9aa8ba; --ink3:#6b7a8d;
  --critical:#ff5f56; --serious:#ff9f43; --warn:#ffcf4d; --good:#3ddc84;
  --accent:#5aa9ff;
  --ui:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--ground);color:var(--ink);font-family:var(--ui);font-size:15px;line-height:1.55;
     -webkit-font-smoothing:antialiased;padding-bottom:64px;}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px;}
.mono{font-family:var(--mono);font-size:.875em;word-break:break-all;}
/* the two values a moderator reads off the screen and compares */
.mono.big{font-size:1.05rem;font-weight:700;letter-spacing:.04em;}
.dim{color:var(--ink3);}
.goodfg{color:var(--good);} .warnfg{color:var(--warn);}
.yes{color:var(--good);font-weight:600;} .no{color:var(--warn);font-weight:600;}
.sep{color:var(--ink3);margin:0 .5em;}
.eyebrow{font-size:.68rem;text-transform:uppercase;letter-spacing:.13em;color:var(--ink3);font-weight:600;margin-bottom:8px;}

/* masthead - the verdict is the page, not a banner on top of it */
.mast{border-bottom:1px solid var(--line);background:var(--surface);}
.mast{background:radial-gradient(120% 140% at 12% 0%,color-mix(in oklab,var(--vc) 13%,transparent) 0%,transparent 62%),var(--surface);}
.mast .wrap{padding:34px 24px 30px;}
.tool{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap;
      font-size:.72rem;letter-spacing:.13em;text-transform:uppercase;color:var(--ink3);font-weight:600;}
.verdict{display:flex;align-items:flex-start;gap:18px;margin-top:22px;}
.chip{flex:none;width:11px;align-self:stretch;min-height:76px;border-radius:3px;background:var(--vc);}
.verdict h1{font-size:clamp(1.9rem,4.4vw,2.75rem);line-height:1.08;font-weight:800;letter-spacing:-.02em;
            color:var(--vc);text-wrap:balance;}
.verdict .say{color:var(--ink2);margin-top:9px;max-width:62ch;}
.caveat{margin-top:10px;max-width:62ch;font-size:.9em;color:var(--warn);border-left:2px solid var(--warn);padding-left:11px;}
.scoreline{display:flex;align-items:baseline;gap:10px;margin-top:16px;font-variant-numeric:tabular-nums;}
.scoreline b{font-size:1.7rem;font-weight:800;color:var(--vc);}
.scoreline span{color:var(--ink3);font-size:.86rem;}

/* the score scale shows the fixed decision thresholds, so a number is never
   just an opinion - the reader can see which band it falls in and by how much */
.scale{margin:12px 0 4px;}
.scale .track{position:relative;height:7px;border-radius:4px;background:var(--surface2);border:1px solid var(--line);}
.scale .fill{position:absolute;top:0;bottom:0;left:0;border-radius:4px;}
.scale .tick{position:absolute;top:-4px;bottom:-4px;width:1px;background:var(--line);}
.scale .tick{background:var(--ground);opacity:.85;}
.scale .marks{position:relative;height:1.05em;font-size:.63rem;color:var(--ink3);
              margin-top:5px;letter-spacing:.06em;text-transform:uppercase;font-variant-numeric:tabular-nums;}
.scale .marks span{position:absolute;transform:translateX(-50%);white-space:nowrap;}
.scale .marks span:first-child{transform:none;}
.scale .marks span:last-child{transform:translateX(-100%);}

section{padding-top:38px;}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.14em;color:var(--ink3);font-weight:700;
   padding-bottom:9px;border-bottom:1px solid var(--line);margin-bottom:18px;}
h2 .count{color:var(--ink);margin-left:.5em;}

.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;}
.panel.gap{border-color:var(--warn);border-color:color-mix(in oklab,var(--warn) 42%,var(--line));}
.panel.clear{color:var(--ink2);}
ol.todo{list-style:none;counter-reset:t;margin:0;padding:0;display:flex;flex-direction:column;gap:10px;}
ol.todo li{counter-increment:t;position:relative;background:var(--surface);border:1px solid var(--line);
  border-left:3px solid var(--vc,var(--warn));border-radius:8px;padding:12px 16px 12px 46px;}
ol.todo li::before{content:counter(t);position:absolute;left:14px;top:12px;font-weight:700;
  font-variant-numeric:tabular-nums;color:var(--ink3);}
.tl{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;}
.tb{font-size:.72rem;font-weight:600;letter-spacing:.04em;color:var(--vc,var(--ink3));
  border:1px solid color-mix(in oklab,var(--vc,var(--line)) 45%,var(--line));
  border-radius:999px;padding:1px 8px;white-space:nowrap;}
.tw{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;color:var(--ink3);
  margin-top:3px;overflow-wrap:anywhere;}
.ty{color:var(--ink2);margin-top:6px;font-size:.9rem;}
ul.plain{list-style:none;display:flex;flex-direction:column;gap:7px;}
ul.plain li{padding-left:16px;position:relative;font-size:.92em;}
ul.plain li:before{content:"";position:absolute;left:0;top:.62em;width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.45;}
.note{color:var(--ink3);font-size:.84em;margin-top:11px;padding-top:10px;border-top:1px solid var(--line);}

.rec-grid{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden;}
.rec{display:grid;grid-template-columns:minmax(130px,180px) 1fr;gap:16px;padding:9px 18px;border-top:1px solid var(--line);}
.rec:first-child{border-top:0;}
.rk{color:var(--ink3);font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;padding-top:2px;}
.rv{min-width:0;}

ol.verdict-reasons{list-style:none;display:flex;flex-direction:column;gap:9px;}
ol.verdict-reasons li{display:flex;gap:12px;background:var(--surface);border:1px solid var(--line);
                      border-left:3px solid var(--vc);border-radius:8px;padding:11px 14px;}
.num{flex:none;width:22px;height:22px;border-radius:5px;background:var(--surface2);color:var(--ink3);
     font-size:.72rem;font-weight:700;display:flex;align-items:center;justify-content:center;
     font-variant-numeric:tabular-nums;}

.find{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--lc);
      border-radius:10px;padding:15px 18px;margin-bottom:12px;}
.find-head{display:flex;align-items:center;gap:11px;flex-wrap:wrap;}
.find-head h3{flex:1;font-size:1rem;font-weight:600;min-width:200px;}
.tag{color:#0b0e14;font-weight:800;font-size:.63rem;letter-spacing:.09em;padding:3px 8px;border-radius:4px;flex:none;}
.score{font-size:1.35rem;font-weight:800;color:var(--lc);font-variant-numeric:tabular-nums;}
.score small{font-size:.5em;color:var(--ink3);font-weight:600;}
.area{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);}
.srnote{font-size:.7rem;text-transform:none;letter-spacing:0;color:#a78bfa;font-weight:500;margin-left:.6em;}
.kv{color:var(--ink3);margin:10px 0 2px;}
.why{margin-top:13px;padding-top:12px;border-top:1px solid var(--line);}
ul.reasons,ul.evidence{list-style:none;display:flex;flex-direction:column;gap:5px;}
ul.reasons li{background:var(--surface2);border-radius:6px;padding:7px 11px;font-size:.9em;}
ul.evidence li{background:var(--surface2);border-radius:6px;padding:6px 11px;color:var(--ink2);
               word-break:normal;overflow-wrap:anywhere;}
.reason-grid{display:flex;flex-direction:column;gap:9px;}
.r{font-size:.9em;color:var(--ink2);}
.rl{display:block;font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--ink3);font-weight:600;margin-bottom:2px;}

table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);
      border-radius:10px;overflow:hidden;font-variant-numeric:tabular-nums;}
th{background:var(--surface2);color:var(--ink3);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;
   padding:9px 14px;text-align:left;font-weight:600;}
td{padding:8px 14px;border-top:1px solid var(--line);font-size:.9em;}
.tscroll{overflow-x:auto;}
.pill{font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:20px;white-space:nowrap;}
.pill.good{background:var(--surface2);color:var(--good);}
.pill.warn{background:var(--surface2);color:var(--warn);}
.pill.bad{background:var(--surface2);color:var(--critical);}
.pill.good{background:color-mix(in oklab,var(--good) 17%,transparent);}
.pill.warn{background:color-mix(in oklab,var(--warn) 17%,transparent);}
.pill.bad{background:color-mix(in oklab,var(--critical) 17%,transparent);}
.pill.neutral{background:var(--surface2);color:var(--ink2);}

details{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:2px 16px 12px;margin-top:12px;}
details table{border:0;border-radius:0;background:transparent;}
summary{cursor:pointer;padding:11px 0;color:var(--ink2);font-size:.9em;}
summary:hover{color:var(--ink);}

.filter{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;}
.filter input{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--line);border-radius:8px;
              padding:8px 12px;color:var(--ink);outline:none;font-family:var(--ui);font-size:.9em;}
.filter input:focus-visible,.btn:focus-visible{border-color:var(--accent);outline:2px solid var(--accent);outline-offset:1px;}
.btn{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;color:var(--ink2);
     cursor:pointer;font-size:.84em;font-family:var(--ui);}
.btn.on,.btn:hover{border-color:var(--accent);color:var(--accent);}
#plain{display:none;}
footer{color:var(--ink3);font-size:.82em;margin-top:46px;padding-top:18px;border-top:1px solid var(--line);}
footer a{color:var(--accent);text-decoration:none;}
footer a:hover{text-decoration:underline;}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;}}

/* saved as PDF this becomes the attachment on a ban appeal, so it has to be
   readable on paper - ink on white, nothing collapsed, no interactive chrome */
@media print{
  body{background:#fff;color:#111;font-size:11pt;padding:0;}
  .wrap{max-width:100%;padding:0;}
  .mast{background:#fff;border-bottom:2px solid #111;}
  .mast .wrap{padding:0 0 14pt;}
  .verdict h1,.scoreline b,.score{color:#111;}
  .chip{background:#111;}
  .panel,.find,.rec-grid,table,details,ol.verdict-reasons li{background:#fff;border-color:#bbb;}
  ul.reasons li,ul.evidence li,.num{background:#f4f4f4;color:#111;}
  .scale .track{background:#eee;border-color:#bbb;} .scale .fill{background:#111!important;} .scale .tick{background:#fff;opacity:1;}
  th{background:#eee;color:#333;}
  .dim,.rk,.eyebrow,.r,.rl,.area,.note,footer,.scoreline span{color:#444;}
  .say,h2 .count,.kv,ul.evidence li,summary,footer a{color:#111;}
  .caveat{color:#111;border-left-color:#111;}
  .tag{background:#111!important;color:#fff;}
  .filter,.btn{display:none;}
  details{border:0;padding:0;}
  details>summary{list-style:none;font-weight:700;color:#111;}
  details[open],details:not([open]){padding:0;}
  .find,.panel,article,tr{break-inside:avoid;}
  section{padding-top:18pt;}
}
</style></head>
<body>
<div class="mast" style="--vc:$($svStyle.c);"><div class="wrap">
  <div class="tool">
    <span>AsyncAnalyzer $(Enc $script:Version) &bull; screenshare evidence report</span>
    <span>$(Enc $stampLocal)</span>
  </div>
  <div class="verdict">
    <div class="chip"></div>
    <div>
      <h1>$($svStyle.label)</h1>
      <p class="say">$($svStyle.say)</p>
      $mastCaveat
      <div class="scoreline"><b>$($sv.Score)</b><span>/ 100 &mdash; the overall-scan AI judged mods, system, processes, live game and history together</span></div>
      $(New-ScoreScale $sv.Score $svStyle.c)
    </div>
  </div>
</div></div>

<div class="wrap">

<section>
  <h2>Look at these first<span class="count">$($todo.Count)</span></h2>
  $todoBox
</section>

<section>
  <h2>What this verdict rests on<span class="count">$(@($sv.Reasons).Count)</span></h2>
  <ol class="verdict-reasons" style="--vc:$($svStyle.c);">$svReasons</ol>
</section>

<section>
  <h2>Coverage &mdash; what was checked, and what was not</h2>
  <div class="grid2">
    <div class="panel"><div class="eyebrow goodfg">Checked</div><ul class="plain">$coverChecked</ul></div>
    $gapBox
  </div>
</section>

<section>
  <h2>Mods &mdash; flagged and to review<span class="count">$($script:Flagged + $script:Review)</span>$srNote</h2>
  $modCards
  $verSection
</section>

<section>
  <h2>Everything else that was found<span class="count">$($real.Count)</span></h2>
  $findCards
  $clearSection
</section>

<section>
  <h2>Full file inventory<span class="count">$($seen.Count)</span></h2>
  <div class="filter">
    <input id="q" placeholder="Search files..." oninput="flt()" aria-label="Search files">
    <button class="btn on" data-e="all" onclick="setE(this)">All</button>
    <button class="btn" data-e="jar" onclick="setE(this)">.jar</button>
    <button class="btn" data-e="exe" onclick="setE(this)">.exe</button>
    <button class="btn" data-e="py" onclick="setE(this)">.py</button>
    <button class="btn" onclick="cp(this)">Copy summary</button>
  </div>
  <div class="tscroll"><table id="ft"><thead><tr><th>File</th><th>Type</th><th>Status</th></tr></thead><tbody>$allRows</tbody></table></div>
</section>

<section>
  <h2>How this PC is set up<span class="count">$($state.Count)</span></h2>
  <p class="note">Not cheat evidence and not counted against anyone &mdash; a third-party antivirus switches the Windows firewall off by itself. Here because a moderator should see it, and because the dates can matter.</p>
  $stateBox
</section>

<section>
  <h2>Scan record</h2>
  <div class="rec-grid">$recordRows</div>
  $authBox
</section>

<pre id="plain">$(Enc $plain)</pre>

<footer>
  <b>How to read this.</b> Every number above comes from a fixed rule or from a model with fixed weights &mdash;
  the same file scores the same on every PC. Nothing here was uploaded: the analysis ran entirely on this machine.
  The coverage box is part of the result, not a disclaimer &mdash; a clean verdict only covers what it lists.<br><br>
  Report ID <span class="mono">$(Enc $reportId)</span> &bull;
  <a href="https://github.com/QDHShamiro/AsyncAnalyzer">github.com/QDHShamiro/AsyncAnalyzer</a> &bull; discord.gg/asyncstudios
</footer>
</div>
<script>
var E="all";
function setE(b){E=b.dataset.e;document.querySelectorAll('.btn[data-e]').forEach(function(x){x.classList.remove('on')});b.classList.add('on');flt();}
function flt(){var q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#ft tbody tr').forEach(function(r){
    var n=r.cells[0].textContent.toLowerCase(),e=r.dataset.ext;
    r.style.display=((E=='all'||e==E)&&n.indexOf(q)>=0)?'':'none';});}
function cp(b){var t=document.getElementById('plain').textContent;
  var done=function(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o;},1400);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,function(){});return;}
  var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
  try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(a);}
</script>
</body></html>
"@
    try {
        $rp = if ($OutPath) { $OutPath } else { Join-Path $env:TEMP "AsyncAnalyzer_Report.html" }
        $html | Out-File -FilePath $rp -Encoding UTF8
        if ($OutPath) { return $rp }
        W "  $([char]0x2713) Report saved: $rp" Green
        W "    Open it yourself when you want it $([char]0x2014) the tool never opens windows on your PC." DarkGray
    } catch { W "  $([char]0x2717) Could not write report: $($_.Exception.Message)" Red }
    Write-Host ""
}

function New-ScoreScale($score, $color) {
    # 30 / 60 / 85 are the fixed band edges from Get-SessionVerdict and Get-ModVerdict.
    # Drawing them means the reader sees where a score sits, not just how big it is.
    $s = [Math]::Max(0, [Math]::Min(100, [int]$score))
    return "<div class='scale'><div class='track'><div class='fill' style='width:$s%;background:$color;'></div>" +
           "<div class='tick' style='left:30%;'></div><div class='tick' style='left:60%;'></div><div class='tick' style='left:85%;'></div>" +
           "</div><div class='marks'><span style='left:0%;'>0 clean</span><span style='left:30%;'>30 review</span>" +
           "<span style='left:60%;'>60 likely</span><span style='left:85%;'>85 confirmed</span><span style='left:100%;'>100</span></div></div>"
}

function New-PlainSummary($sv, $svStyle, $stamp, $reportId, $isAdmin) {
    # Staff paste this straight into a ticket or a Discord thread, so it has to
    # stand on its own without the HTML around it.
    $o = [System.Collections.Generic.List[string]]::new()
    [void]$o.Add("AsyncAnalyzer $($script:Version) - screenshare report")
    [void]$o.Add("$stamp   PC $env:COMPUTERNAME   user $env:USERNAME   admin: $(if ($isAdmin) { 'yes' } else { 'no' })")
    [void]$o.Add("Report ID: $reportId")
    # The two things a moderator compares against what they said and what the
    # dashboard shows. Pasted into a ticket, they are the whole point of the paste.
    [void]$o.Add("Scan ID:   $($script:ScanId)" + $(if ($script:ScanCode) { "   staff code: $($script:ScanCode)" } else { "   (no staff code was given - this cannot be shown to be fresh)" }))
    [void]$o.Add("")
    [void]$o.Add("VERDICT: $($svStyle.short) - $($sv.Score)/100")
    foreach ($r in @($sv.Reasons)) { [void]$o.Add("  - $r") }
    [void]$o.Add("")
    [void]$o.Add("Mods: $($script:TotalMods) scanned / $($script:Verified) verified / $($script:Review) review / $($script:Flagged) flagged")
    foreach ($m in @($flaggedMods | Where-Object { $_ })) { [void]$o.Add("  FLAGGED  $($m.FileName)  [$($m.Score)/100]  $(@($m.Reasons) -join '; ')") }
    foreach ($m in @($reviewMods  | Where-Object { $_ })) { [void]$o.Add("  REVIEW   $($m.FileName)  [$($m.Score)/100]") }
    $realF = @($script:Findings | Where-Object { $_.Level -eq "FAIL" -or $_.Level -eq "WARN" })
    if ($realF.Count -gt 0) {
        [void]$o.Add("")
        [void]$o.Add("Other findings:")
        foreach ($f in $realF) { [void]$o.Add("  [$($f.Level)] $($f.Area): $($f.Title)") }
    }
    [void]$o.Add("")
    if (@($script:ScanGaps).Count -gt 0) {
        [void]$o.Add("NOT CHECKED (a clean result does not cover these):")
        foreach ($g in @($script:ScanGaps)) { [void]$o.Add("  - $g") }
    } else {
        [void]$o.Add("NOT CHECKED: nothing - every check ran.")
    }
    return ($o -join "`n")
}

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

# ---------------------------------------------------------------------------
# Alternative clients keep their mods somewhere else - and under another name.
#
# Lunar, Badlion and Feather already had their mods folders looked up by exact
# path above, which works right up until they move one. LabyMod does not have a
# mods folder at all: its extensions are jars in addons/, and a cheat shipped as
# a LabyMod addon was simply never opened.
#
# So instead of guessing more exact paths, each client's ROOT is walked to a
# bounded depth and every directory literally named mods or addons is taken. That
# survives a version bump by construction.
#
# What is deliberately NOT taken: the loose jars a client ships itself. Lunar's
# own client jars sit in offline/multiver, they render entities and read the
# entity list because that is what nametags and waypoints are, and treating them
# as mods would put a SERVER-RULE finding on the report of every Lunar user alive.
# The walker only collects mods/ and addons/, which those are not in.
# ---------------------------------------------------------------------------
function Get-AltClientRoots {
    return @(
        @('Lunar Client',   "$env:USERPROFILE\.lunarclient"),
        @('Lunar Client',   "$env:APPDATA\.lunarclient"),
        @('Badlion Client', "$env:APPDATA\Badlion Client"),
        @('Badlion Client', "$env:LOCALAPPDATA\Badlion Client"),
        @('Badlion Client', "$env:APPDATA\.badlion"),
        @('Feather Client', "$env:APPDATA\.feather"),
        @('Feather Client', "$env:USERPROFILE\.feather"),
        @('Feather Client', "$env:APPDATA\feather"),
        @('LabyMod',        "$env:APPDATA\.minecraft\LabyMod"),
        @('LabyMod 4',      "$env:APPDATA\.minecraft\labymod-neo"),
        @('LabyMod 4',      "$env:APPDATA\LabyMod"),
        @('Salwyrr',        "$env:APPDATA\.salwyrrclient"),
        @('PvPLounge',      "$env:APPDATA\.pvplounge"),
        @('SKLauncher',     "$env:APPDATA\.minecraft\sklauncher")
    )
}

function Find-AltClientModDirs([string]$Root, [int]$MaxDepth = 4) {
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not [System.IO.Directory]::Exists($Root)) { return $out }
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([PSCustomObject]@{ P = $Root; D = 0 })
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 3000) {
        $node = $queue.Dequeue(); $visited++
        try {
            foreach ($sub in [System.IO.Directory]::GetDirectories($node.P)) {
                $leaf = [System.IO.Path]::GetFileName($sub).ToLower()
                if ($leaf -eq 'mods' -or $leaf -eq 'addons') { [void]$out.Add($sub); continue }
                if ($node.D -lt $MaxDepth) { $queue.Enqueue([PSCustomObject]@{ P = $sub; D = $node.D + 1 }) }
            }
        } catch {}
    }
    return $out
}

# --gameDir "E:\ModrinthApp\profiles\Cheats test"  or  --gameDir E:\mc\inst
# The natives path and a classpath jar under \mods\ name the same install, and
# are used when --gameDir is absent. Mirrors running_game_dirs in ml/autoscan.py.
function Get-RunningGameDirs {
    $out = [System.Collections.Generic.List[string]]::new()
    $pats = @(
        @{ Rx = '(?i)--gameDir(?:\s+|=)(?:"([^"]+)"|([^\s"]+))';           Trim = 0 },
        @{ Rx = '(?i)([A-Za-z]:\\(?:[^\s";]+\\)?mods)\\[^\s";\\]+\.jar'; Trim = 1 },
        @{ Rx = '(?i)-Djava\.library\.path=(?:"([^"]+)"|([^\s"]+))';       Trim = 1 }
    )
    foreach ($info in $script:javaProcessInfos) {
        $cl = $info.CommandLine
        if (-not $cl) { continue }
        foreach ($p in $pats) {
            foreach ($m in [regex]::Matches($cl, $p.Rx)) {
                $v = ""
                for ($g = 1; $g -lt $m.Groups.Count; $g++) { if ($m.Groups[$g].Success -and $m.Groups[$g].Value) { $v = $m.Groups[$g].Value; break } }
                if (-not $v) { continue }
                $v = $v.TrimEnd('\').Trim()
                # \...\mods\x.jar -> the instance is the mods folder's parent;
                # \...\natives\1.21 -> its parent as well.
                if ($p.Trim -eq 1) {
                    if ($v.LastIndexOf('\') -lt 3) { continue }
                    $v = $v.Substring(0, $v.LastIndexOf('\'))
                }
                if ($v.Length -gt 3 -and -not $out.Contains($v)) { [void]$out.Add($v) }
            }
        }
    }
    return $out
}

# E:\ModrinthApp\profiles\1.21.11  ->  E:\ModrinthApp\profiles
# A vanilla .minecraft stands alone and returns "".
function Get-SiblingInstanceRoot([string]$GameDir) {
    if (-not $GameDir -or $GameDir.LastIndexOf('\') -lt 3) { return "" }
    $parent = $GameDir.Substring(0, $GameDir.LastIndexOf('\'))
    # Split on the separator rather than using Path::GetFileName. That method
    # uses the CURRENT platform's separator, so on anything but Windows it hands
    # a backslash path straight back - which means this code could not be
    # verified anywhere except Windows. Splitting explicitly behaves the same
    # everywhere, and a Windows path always uses backslashes whoever reads it.
    $leaf = ($parent -split '\\')[-1].ToLower()
    if (@('profiles','instances','modpacks') -contains $leaf) { return $parent }
    return ""
}

function Find-MinecraftModFolders {
    $runningJava = @(Get-Process javaw,java -ErrorAction SilentlyContinue)

    $script:javaProcessInfos = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($runningJava.Count -gt 0) {
        # When the game started. This is the window the "deleted during this
        # session" rule uses: the Recycle Bin holds months of history, and
        # feeding all of it to a rule that says "wiped while the game was
        # running" would accuse somebody for tidying a modpack in May.
        foreach ($proc in $runningJava) {
            try {
                $st = $proc.StartTime
                if ($st -and (-not $script:GameStarted -or $st -lt $script:GameStarted)) { $script:GameStarted = $st }
            } catch {}
        }
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

    # ---- where a RUNNING game actually is ---------------------------------
    # Every launcher root below is anchored to %APPDATA%, %LOCALAPPDATA% or
    # %USERPROFILE% - all on C:. An install on another drive cannot be found by
    # that list at all: with two instances open under E:\ModrinthApp\profiles\,
    # this printed "Nothing open" and fell back to C:\Users\...\.minecraft\mods,
    # which was not the install being played.
    #
    # The running process carries the answer. Minecraft is launched with
    # --gameDir, and the classpath and natives path name the same install. So
    # ask the processes instead of guessing at locations. See ml/autoscan.py.
    foreach ($gd in @(Get-RunningGameDirs)) {
        $md = [System.IO.Path]::Combine($gd, "mods")
        # A candidate only counts if it really holds a mods folder. The natives
        # fallback in particular points at meta\natives in Modrinth's layout,
        # which is not an instance.
        if (-not [System.IO.Directory]::Exists($md)) { continue }
        if (-not $seen.Add($md)) { continue }
        $jars  = @([System.IO.Directory]::GetFiles($md, "*.jar"))
        $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($md) }
        [void]$results.Add([PSCustomObject]@{ Path=$md; Launcher="Running"; Instance=($gd -split '\\')[-1]; JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$true })

        # A running instance means its siblings are instances too - and the one
        # that is NOT open is exactly where a jar gets parked while the open one
        # is being watched.
        $sib = Get-SiblingInstanceRoot $gd
        if (-not $sib) { continue }
        foreach ($other in @([System.IO.Directory]::GetDirectories($sib) | Select-Object -First 60)) {
            foreach ($cand in @([System.IO.Path]::Combine($other, "mods"),
                                [System.IO.Path]::Combine($other, ".minecraft", "mods"))) {
                if (-not [System.IO.Directory]::Exists($cand)) { continue }
                if (-not $seen.Add($cand)) { continue }
                $j = @([System.IO.Directory]::GetFiles($cand, "*.jar"))
                $lw = if ($j.Count -gt 0) { ($j | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($cand) }
                [void]$results.Add([PSCustomObject]@{ Path=$cand; Launcher="Beside a running instance"; Instance=($other -split '\\')[-1]; JarCount=$j.Count; LastWrite=$lw; IsRunning=(IsJavaRunningIn $other) })
            }
        }
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

    # Alternative clients: LabyMod's addons/, and every mods/ the three clients above
    # may have moved since the exact paths were written. See Get-AltClientRoots.
    $script:AltClients = [System.Collections.Generic.List[string]]::new()
    $altSeenRoot = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ac in (Get-AltClientRoots)) {
        $acName = $ac[0]; $acRoot = $ac[1]
        if (-not [System.IO.Directory]::Exists($acRoot)) { continue }
        if (-not $altSeenRoot.Add($acRoot)) { continue }
        $acRunning = $false
        foreach ($info in $script:javaProcessInfos) {
            if ($info.CommandLine -and $info.CommandLine.IndexOf($acRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $acRunning = $true; break }
        }
        $acDirs = @(Find-AltClientModDirs $acRoot)
        $acJars = 0
        foreach ($d in $acDirs) {
            if (-not $seen.Add($d)) { continue }
            $jars  = @([System.IO.Directory]::GetFiles($d, "*.jar"))
            $acJars += $jars.Count
            $lastW = if ($jars.Count -gt 0) { ($jars | ForEach-Object { [System.IO.File]::GetLastWriteTime($_) } | Sort-Object -Descending | Select-Object -First 1) } else { [System.IO.Directory]::GetLastWriteTime($d) }
            [void]$results.Add([PSCustomObject]@{ Path=$d; Launcher=$acName; Instance=[System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($d)); JarCount=$jars.Count; LastWrite=$lastW; IsRunning=$acRunning; AltClient=$true })
        }
        try {
            $rootW = [System.IO.Directory]::GetLastWriteTime($acRoot).ToString('yyyy-MM-dd HH:mm')
        } catch { $rootW = "?" }
        [void]$script:AltClients.Add("$acName $([char]0x2014) $acRoot (last changed $rootW, $($acDirs.Count) mod/addon folder(s), $acJars jar(s))")
        if ($acDirs.Count -eq 0) {
            # The client is installed and nothing that looks like a mod folder was
            # found under it. That is not "clean" - it is a format this tool cannot
            # read, and saying so is the whole point of the coverage box.
            Add-ScanGap "$acName is installed ($acRoot) but no mods/addons folder was found in it $([char]0x2014) if it stores extensions in its own format, they were NOT checked"
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
    # Alternative clients are handled separately below and are ALWAYS scanned, so
    # they must not be counted here - neither as the best guess nor as a skipped
    # install. Reporting a folder as unchecked while checking it is the one kind of
    # wrong the coverage box cannot survive.
    $plain   = @($found | Where-Object { -not $_.AltClient })
    $running = @($plain | Where-Object { $_.IsRunning })

    if ($running.Count -gt 0) {
        foreach ($r in $running) {
            if (-not $targets.Contains($r.Path)) { [void]$targets.Add($r.Path) }
            W "  $([char]0x2713) Open now: " Green -NoNewline
            W "$($r.Launcher)" Cyan -NoNewline
            if ($r.Instance) { W " / $($r.Instance)" White -NoNewline }
            W "  ($($r.JarCount) mods)" DarkGray
        }
        $idle = @($plain | Where-Object { -not $_.IsRunning })
        if ($idle.Count -gt 0) {
            Add-ScanGap "$($idle.Count) other Minecraft install(s) exist but were not open, so they were not scanned"
        }
    } elseif ($plain.Count -gt 0) {
        [void]$targets.Add($plain[0].Path)
        W "  $([char]0x2713) Nothing open $([char]0x2014) checking the most likely install: $($plain[0].Launcher)" Yellow
        if ($plain.Count -gt 1) {
            Add-ScanGap "$($plain.Count) installs found and none was open $([char]0x2014) only the most likely one was scanned"
        }
    }

    # An alternative client's mods/addons folder is always scanned, open or not. It
    # holds a handful of jars rather than a modpack, so it costs almost nothing, and
    # it is exactly where a jar gets parked when the vanilla folder is the one being
    # watched.
    foreach ($a in @($found | Where-Object { $_.AltClient -and $_.JarCount -gt 0 })) {
        if (-not $targets.Contains($a.Path)) {
            [void]$targets.Add($a.Path)
            W "  $([char]0x2713) Alternative client: " Green -NoNewline
            W "$($a.Launcher)" Cyan -NoNewline
            W "  ($($a.JarCount) jar(s))" DarkGray
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
    # Which alternative clients are installed at all. Not a finding - Lunar and
    # Badlion are two of the most-played clients there are - but a moderator should
    # see that another Minecraft exists on this PC and when it was last touched.
    if ($script:AltClients.Count -gt 0) {
        Add-Finding "INFO" "Where this was scanned" "$($script:AltClients.Count) alternative Minecraft client(s) installed" `
            @($script:AltClients) `
            "The install folders of Lunar, Badlion, Feather, LabyMod and friends were located, and every mods/ or addons/ folder inside them was added to the scan." `
            "Owning one of these is completely normal. It is here because a jar parked in another client's folder is out of sight of a scan that only looks at .minecraft." | Out-Null
    }
    foreach ($t in $targets) { if (-not $script:ScanTargetDirs.Contains($t)) { [void]$script:ScanTargetDirs.Add($t) } }
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
        # How the PC is set up. Real, shown, and deliberately outside every filter
        # that decides anything: a third-party antivirus turns the Windows firewall
        # off by itself, and that must not become a coverage gap OR a finding.
        "STATE" { W "  $([char]0x2502) " DarkGray -NoNewline; W " STATE" White -NoNewline; W "  $Msg" DarkGray }
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

# A blob that says what it is in its own first bytes. "No extension + high
# entropy" is how a dropper hides a payload, but a Java keystore or a DER
# certificate is high-entropy BY NATURE and announces itself in its header.
# Checked structurally - the version field, or a declared length that has to
# equal the entry we are actually holding - so a payload cannot buy itself an
# exemption by prepending two magic bytes. Measured: exempts exactly 1 entry
# across 179 real libraries (WireMock's HTTPS keystore) and 0 of the 4
# encrypted payloads in a real ghost-client loader.
function Test-SelfIdentifyingBlob([byte[]]$data, [int]$size) {
    if ($data.Length -lt 8) { return $false }
    # Java keystore (JKS / JCEKS): FEEDFEED, then a version of 1 or 2.
    if ($data[0] -eq 0xFE -and $data[1] -eq 0xED -and $data[2] -eq 0xFE -and $data[3] -eq 0xED) {
        $ver = ([int]$data[4] -shl 24) -bor ([int]$data[5] -shl 16) -bor ([int]$data[6] -shl 8) -bor [int]$data[7]
        if ($ver -eq 1 -or $ver -eq 2) { return $true }
    }
    # DER (certificate, PKCS#12, private key): a SEQUENCE with a long-form
    # two-byte length, and that length has to describe this exact entry.
    if ($data[0] -eq 0x30 -and $data[1] -eq 0x82) {
        $len = ([int]$data[2] -shl 8) -bor [int]$data[3]
        if (($len + 4) -eq $size) { return $true }
    }
    return $false
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

# ---------------------------------------------------------------------------
# Everything one jar goes through: hash, provenance lookup, features, bytecode,
# verdict, evidence, and the one-shot online learning step.
#
# It lives in a function because the scan now runs it TWICE. The first pass is
# the mods folders the tool found on disk; the second is folders the running
# game turned out to be reading that nobody knew about - and a jar found by the
# second route has to be judged by exactly the same code as one found by the
# first, or the folder the cheat was actually in gets the weaker analysis.
#
# The four result lists are script-scope, so this appends to the same lists the
# main loop fills. Counters are $script:-qualified for the same reason.
# ---------------------------------------------------------------------------
function Invoke-JarAnalysis($jar) {

    $hash   = Get-FileSHA1 $jar.FullName
    $dlObj  = Get-DownloadSource $jar.FullName
    $dlName = if ($dlObj) { $dlObj.Name } else { $null }
    $dlUrl  = if ($dlObj) { $dlObj.RawUrl } else { $null }

    $verified = $false; $verifiedName = ""; $modUrl = ""; $verifiedVia = ""
    if ($hash -and $script:knownGoodHashes.Contains($hash)) {
        $verified = $true; $verifiedVia = "known-good list"
        $gm = $script:goodMeta[$hash]
        if ($gm) { $gp = $gm -split '\|', 2; $verifiedName = [string]$gp[0]; if ($gp.Count -gt 1) { $modUrl = [string]$gp[1] } }
    }
    if ($hash -and -not $verifiedName) {
        $mr = Get-ModrinthMeta $hash
        if ($mr.Slug) { $verified = $true; $verifiedName = $mr.Name; $modUrl = "https://modrinth.com/mod/$($mr.Slug)"; if (-not $verifiedVia) { $verifiedVia = "Modrinth" } }
        if (-not $verifiedName) {
            $fp = Get-FileMurmur2 $jar.FullName
            if ($null -ne $fp) {
                $cf = Get-CurseForgeMeta $fp
                if ($cf.Slug) { $verified = $true; $verifiedName = $cf.Name; $modUrl = "https://www.curseforge.com/minecraft/mc-mods/$($cf.Slug)"; if (-not $verifiedVia) { $verifiedVia = "CurseForge" } }
            }
        }
        if (-not $verifiedName) {
            $mb = Get-MegabaseMeta $hash
            if ($mb -and $mb.name) { $verified = $true; $verifiedName = $mb.name; $modUrl = if ($mb.modrinth_id) { "https://modrinth.com/mod/$($mb.modrinth_id)" } else { "" }; if (-not $verifiedVia) { $verifiedVia = "Megabase" } }
        }
        if ($verified -and $verifiedName) { $script:goodMeta[$hash] = "$verifiedName|$modUrl" }
    }

    Add-DiskPackages $jar.FullName
    $feat = Get-JarFeatures $jar.FullName
    $bcFeat = $null
    if (-not $verified) { $bcFeat = Get-BytecodeFeatures $jar.FullName $script:BcMaxClasses }

    $checkName = $jar.Name -replace '\.(temp|disabled|bak|old|backup)(\.jar)$','$2'
    $fnMatch   = Get-FilenameSimilarityMatch $checkName
    $filenameClient = $false; $filenameToken = ""
    if ($null -ne $fnMatch -and $script:distinctiveClientTokens.Contains($fnMatch.Token)) { $filenameClient = $true; $filenameToken = $fnMatch.Token }
    $randomName = (-not $filenameClient) -and (Test-RandomFilename $checkName)
    $modIdNorm  = if ($feat.ModId) { ($feat.ModId -replace '[^a-zA-Z0-9]','').ToLower() } else { "" }
    $legitModId = ($modIdNorm -ne "") -and $script:legitModIds.Contains($modIdNorm)
    $hashKnownCheat = ($null -ne $hash) -and $script:knownCheatHashes.Contains($hash)
    $cheatSite  = ($null -ne $dlName) -and ($script:cheatDownloadSources -contains $dlName)

    $ctx = @{
        Features = $feat; Verified = $verified; LegitModId = $legitModId
        HashKnownCheat = $hashKnownCheat; CheatSite = $cheatSite; CheatSiteName = $dlName
        FilenameClient = $filenameClient; FilenameToken = $filenameToken; RandomName = $randomName
        Bytecode = $bcFeat
    }
    $verdict = Get-ModVerdict $ctx
    $mechCheat = $feat.JavaAgent -or ($feat.HiddenPayload -gt 0)

    # A mixin config lists, in plain text, how many places in the game this
    # mod rewrites. If it declares mixins and the bytecode reader saw none of
    # them, the jar was not read - that is a gap in coverage, and a clean
    # result on an unread jar has to say so rather than look like an answer.
    if ($feat.MixinDeclared -gt 0 -and $null -ne $bcFeat -and $bcFeat.mixin -eq 0) {
        Add-ScanGap ("$($jar.Name): declares $($feat.MixinDeclared) mixin(s) in its config but none could be read from the bytecode $([char]0x2014) what it rewrites in the game was NOT checked")
    }

    # What the behaviour rules found, kept separate from the band so the
    # whole-scan model sees it directly. Only counted where the finding
    # actually stands: a verified mod is capped safe, and its behaviour is
    # part of the mod's own function rather than a cheat.
    if ($verdict.BehaviourScore -ge 85 -and $verdict.Band -eq "Confirmed") {
        $script:Evidence.BehaviourCheat++
    } elseif ($verdict.BehaviourScore -ge 60 -and ($verdict.Band -eq "Confirmed" -or $verdict.Band -eq "Likely")) {
        $script:Evidence.BehaviourLikely++
    }
    if ($verdict.HiddenApi -and -not $verified) { $script:Evidence.HiddenApi++ }
    if ($randomName) { $script:Evidence.RandomNamed++ }
    if ($cheatSite)  { $script:Evidence.CheatSiteDl++ }
    if ((-not $verified) -and ($hashKnownCheat -or $feat.PackageHits.Count -gt 0 -or $cheatSite -or $mechCheat)) { $script:Evidence.HardConfirmed++ }

    $rec = [PSCustomObject]@{
        FileName = $jar.Name; FilePath = $jar.FullName; Hash = $hash
        Verified = $verified; VerifiedName = $verifiedName; ModName = $verifiedName; VerifiedVia = $verifiedVia; ModUrl = $modUrl
        DownloadSource = $dlName; DownloadUrl = $dlUrl
        Score = $verdict.Score; Band = $verdict.Band; Probability = $verdict.Probability; Reasons = $verdict.Reasons
    }

    if ($verified) {
        [void]$script:verifiedMods.Add($rec)
    } elseif ($verdict.Band -eq "Confirmed" -or $verdict.Band -eq "Likely") {
        [void]$script:flaggedMods.Add($rec)
        [void]$script:FlaggedModsList.Add($jar.Name)
        $script:Flagged++
    } elseif ($verdict.Band -eq "Review" -or $verdict.Band -eq "ServerRule") {
        # A server-rule finding goes in the same list as Review - it needs a
        # person to look at it either way. It keeps its own band so the report
        # can say WHY: uncertainty in one case, a rule question in the other.
        [void]$script:reviewMods.Add($rec)
        [void]$script:ReviewModsList.Add($jar.Name)
        if ($verdict.Band -eq "ServerRule") { $script:ServerRule++ }
    } else {
        [void]$script:unknownMods.Add($rec)
    }

    # Only ever train on externally grounded labels, and only once per file hash: rescanning
    # the same folder must not re-weight the model toward whatever it already believes.
    if ($hash) {
        $rawv = Get-ModFeatureVector $ctx
        if ($verified) {
            $isNew = $script:knownGoodHashes.Add($hash)
            [void]$script:sessionGood.Add($hash)
            if ($isNew) {
                Update-ModelOnline $rawv 0
                [void]$script:sessionSamples.Add(@{ vec = @($script:mlFeatureOrder | ForEach-Object { [double]$rawv[$_] }); label = 0 })
            }
        } elseif ($verdict.Band -eq "Confirmed" -and ($hashKnownCheat -or $feat.PackageHits.Count -gt 0 -or $cheatSite -or $mechCheat)) {
            $isNew = $script:knownCheatHashes.Add($hash)
            [void]$script:sessionCheat.Add($hash)
            if ($isNew) {
                Update-ModelOnline $rawv 1
                [void]$script:sessionSamples.Add(@{ vec = @($script:mlFeatureOrder | ForEach-Object { [double]$rawv[$_] }); label = 1 })
            }
            if ($script:Share) { [void]$script:shareHashes.Add($hash) }
        }
    }
}

# ---------------------------------------------------------------------------
# The second pass.
#
# The file scan looks where Minecraft installs normally live. The RUNNING game
# knows better: its own memory holds the path of every jar it actually loaded,
# and some of those can sit in a folder nothing on disk pointed at - a second
# instance, a hand-made pack, a directory added to the classpath by hand. That
# is precisely where a jar goes when the obvious folder is the one being
# watched.
#
# Those folders arrive late, because reading them out needs the live process.
# So rather than printing "re-run with -Path <folder>" - advice nobody follows
# while a suspect is on the other end of the call - the tool scans them itself,
# through the same Invoke-JarAnalysis the first pass used. Same code, same
# thresholds, same model: a jar found the second way is judged exactly like a
# jar found the first way.
# ---------------------------------------------------------------------------
function Invoke-LateFolderScan {
    if ($script:LateScanDirs.Count -eq 0) { return }
    $extra = @()
    foreach ($d in $script:LateScanDirs) {
        if (-not (Test-Path $d -PathType Container)) {
            Add-ScanGap "The running game is loading mods from $d, but that folder could not be opened for scanning"
            continue
        }
        $extra += @(Get-ChildItem -Path $d -Filter "*.jar" -ErrorAction SilentlyContinue)
        $extra += @(Get-ChildItem -Path $d -Filter "*.litemod" -ErrorAction SilentlyContinue)
        if (-not $script:ScanTargetDirs.Contains($d)) { [void]$script:ScanTargetDirs.Add($d) }
        if (-not (@($script:ScanTargets) -contains $d)) { $script:ScanTargets = @($script:ScanTargets) + @($d) }
    }
    # A jar already analysed in the first pass must not be analysed again: it
    # would be counted twice in every total, and the report would show a
    # duplicate card for one file.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($lst in @($script:verifiedMods, $script:unknownMods, $script:reviewMods, $script:flaggedMods)) {
        foreach ($m in @($lst)) { if ($m.FilePath) { [void]$seen.Add([string]$m.FilePath) } }
    }
    $extra = @($extra | Where-Object { -not $seen.Contains($_.FullName) })
    if ($extra.Count -eq 0) { return }

    Write-Host ""
    Write-SectionHeader "FOLDERS THE RUNNING GAME REVEALED" $extra.Count Yellow Yellow
    Write-Rule "$([char]0x2500)" 76 DarkGray
    Write-Host ""
    foreach ($d in $script:LateScanDirs) { W "  $([char]0x2022) $d" DarkGray }
    Write-Host ""
    W "  Scanning $($extra.Count) more jar(s) found this way $([char]0x2014) same checks as the first pass..." DarkGray

    # Remember where each list ended, so only the jars this pass adds get a card.
    $nBefore = @{ flagged = $script:flaggedMods.Count; review = $script:reviewMods.Count }
    $before = $script:Flagged + $script:Review
    $i = 0
    foreach ($jar in $extra) {
        $i++
        Spin "[$i/$($extra.Count)] $($jar.Name)"
        Invoke-JarAnalysis $jar
    }
    SpinClear

    # The totals are derived from the lists, so they have to be taken again -
    # they were computed at the end of the first pass and are now stale.
    $script:TotalMods   = $script:verifiedMods.Count + $script:unknownMods.Count + $script:reviewMods.Count + $script:flaggedMods.Count
    $script:Verified    = $script:verifiedMods.Count
    $script:Unknown     = $script:unknownMods.Count
    $script:Review      = $script:reviewMods.Count
    $script:LateScanned = $extra.Count

    $found = ($script:Flagged + $script:Review) - $before
    if ($found -gt 0) {
        W "  $([char]0x26A0) $found of them need looking at $([char]0x2014) in a folder the file scan would never have opened." Red
        Write-Host ""
        # The first pass printed its cards before these jars existed as far as the
        # scan was concerned. Print theirs here, or the console shows a number
        # while the reasons sit only in the HTML.
        for ($k = $nBefore.flagged; $k -lt $script:flaggedMods.Count; $k++) { Write-VerdictCard $script:flaggedMods[$k] }
        for ($k = $nBefore.review;  $k -lt $script:reviewMods.Count;  $k++) { Write-VerdictCard $script:reviewMods[$k] }
    } else {
        W "  $([char]0x2713) Nothing in them, but they are now part of the result rather than a hole in it." DarkGray
    }
    Add-Finding $(if ($found -gt 0) { "FAIL" } else { "INFO" }) "Where this was scanned" `
        "$($extra.Count) extra jar(s) in $($script:LateScanDirs.Count) folder(s) the running game revealed" `
        @($script:LateScanDirs) `
        "The live game's own memory names every folder it loaded a mod from. These were not on the list the file scan built from disk." `
        "A jar parked in a folder no launcher points at is out of sight of any scan that only looks where Minecraft is normally installed." `
        "They were scanned with the same checks as everything else, so their results are in the totals above." `
        $(if ($found -gt 0) { "Look at the flagged jars from these folders first $([char]0x2014) someone put them somewhere deliberately." } else { "Nothing was found in them." }) | Out-Null
}

# ---------------------------------------------------------------------------
# The live game process.
#
# Everything this function observes is sorted into one of three buckets, and the
# difference matters more than any single check:
#
#   Findings - proof of injection. Only these raise jvm_inject, which is a HARD
#              rule: one finding forces the whole scan to at least "Likely".
#   Notes    - real observations that also have innocent explanations. Reported
#              in full, counted as system issues (so the model sees them), but
#              never allowed to force a band on their own.
#   Gaps     - things the scan could NOT check. These prove nothing in either
#              direction and must never look like evidence.
#
# Before this split, every one of them was one flat list whose COUNT became
# jvm_inject. A clean PC whose memory sweep simply ran out of its time budget
# added the sentence "Live-memory check stopped at its 120 s budget" to that
# list, and that sentence alone was enough to label the scan "Likely" - the more
# RAM a legitimate modpack used, the more likely it was to be accused.
# ---------------------------------------------------------------------------
function New-JvmScanResult {
    return @{
        Findings = [System.Collections.Generic.List[string]]::new()
        Notes    = [System.Collections.Generic.List[string]]::new()
        Gaps     = [System.Collections.Generic.List[string]]::new()
    }
}

# A running JVM keeps the URL of every jar it loaded, as a plain string, in its
# own memory. That record is not a file, so deleting the jar does not remove it -
# which makes it the one place a screenshare can still see a mod that was wiped
# thirty seconds before the call. It also names folders the file scan never
# visited, so the live game can say where else to look.
function Resolve-JarUrl([string]$Url) {
    # file:/C:/Users/... , file:///C:/... , jar:file:/C:/...!/foo - all reduce to
    # a Windows path. Percent-escapes have to be undone or a player whose name is
    # "Muller" spelled with an umlaut looks like a deleted file.
    try {
        $m = [regex]::Match($Url, '(?i)file:/{1,3}([A-Za-z]:[/\\][^\s"''<>|*?\r\n]{0,300}?\.jar)')
        if (-not $m.Success) { return $null }
        $p = [System.Uri]::UnescapeDataString($m.Groups[1].Value)
        $p = $p -replace '/', '\'
        while ($p -match '\\\\') { $p = $p -replace '\\\\', '\' }
        if ($p.Length -lt 6) { return $null }
        return $p
    } catch { return $null }
}

# Places a launcher does not put mods. Not proof of anything - a Note - but no
# launcher on earth loads a mod out of the Downloads folder.
$script:jarOddDirs = @('\temp\', '\tmp\', '\downloads\', '\desktop\', '\recycle')

function Test-OddJarLocation([string]$Path) {
    $lp = $Path.ToLower()
    foreach ($d in $script:jarOddDirs) { if ($lp.Contains($d)) { return $true } }
    return $false
}

function Test-ScannedDir([string]$Dir) {
    $d = $Dir.TrimEnd('\').ToLower()
    foreach ($t in $script:ScanTargetDirs) {
        $td = ([string]$t).TrimEnd('\').ToLower()
        if ($td -eq $d -or $d.StartsWith($td + '\')) { return $true }
    }
    return $false
}

function Run-JVMScan {
    $r = New-JvmScanResult

    $javaProcs = Get-WmiObject Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue
    if (-not $javaProcs) { return $r }

    foreach ($proc in $javaProcs) {
        $where = "$($proc.Name) (PID $($proc.ProcessId))"
        $cmdLine = [string]$proc.CommandLine
        # WMI returns a null command line for a process this account may not read.
        # That is a gap, not a clean result: the JVM flags are exactly where an
        # injected agent would be visible.
        if ([string]::IsNullOrWhiteSpace($cmdLine)) {
            $r.Gaps.Add("Could not read the command line of $where $([char]0x2014) its JVM flags (agents, bootclasspath) were not checked. Run as administrator.")
            $cmdLine = ""
        }

        if ($cmdLine) {
            $agentMatches = [regex]::Matches($cmdLine, '-javaagent:([^\s"]+)')
            foreach ($m in $agentMatches) {
                $agentPath = $m.Groups[1].Value.Trim('"').Trim("'")
                $agentName = [System.IO.Path]::GetFileName($agentPath)
                $legitAgents = @("jmxremote","yjp","jrebel","newrelic","jacoco","theseus")
                $isLegit = $false
                foreach ($la in $legitAgents) { if ($agentName -match $la) { $isLegit = $true; break } }
                if ($isLegit) {
                    # Named like a known-good agent - but the check is only the file
                    # NAME, and a file name is the cheapest thing in the world to
                    # copy. Say out loud that an agent is attached so a human can
                    # look at the path, instead of hiding it behind a whitelist.
                    $r.Notes.Add("JVM agent attached, name looks legitimate $([char]0x2014) -javaagent:$agentName (path: $agentPath) $([char]0x2014) matched the known-good list by file NAME only, so check the path is really that tool.")
                } else {
                    $r.Findings.Add("JVM Agent $([char]0x2014) -javaagent:$agentName (path: $agentPath)")
                }
            }

            # Split by what a normal player's launcher could plausibly do.
            # Findings: no launcher attaches a native agent or a remote debugger to
            # a game. Notes: -Xbootclasspath is how some legacy 1.8-era launchers
            # patch authlib, so it is reported but never forces a band by itself.
            $hardJvmFlags = @(
                @{ Flag = "-agentlib:jdwp"; Desc = "JDWP debug agent $([char]0x2014) anyone who can reach that port can run code inside the game" },
                @{ Flag = "-agentpath:";    Desc = "native agent loaded, bypasses the Java sandbox entirely" }
            )
            foreach ($sf in $hardJvmFlags) {
                if ($cmdLine -match [regex]::Escape($sf.Flag)) {
                    $r.Findings.Add("Suspicious JVM flag $([char]0x2014) $($sf.Flag) $([char]0x2014) $($sf.Desc)")
                }
            }
            $softJvmFlags = @(
                @{ Flag = "-Xbootclasspath/p:"; Desc = "prepends to the bootstrap classpath, overriding core Java classes" },
                @{ Flag = "-Xbootclasspath/a:"; Desc = "appends to the bootstrap classpath, loading below the mod loader" }
            )
            foreach ($sf in $softJvmFlags) {
                if ($cmdLine -match [regex]::Escape($sf.Flag)) {
                    $r.Notes.Add("Bootstrap classpath modified $([char]0x2014) $($sf.Flag) $([char]0x2014) $($sf.Desc). Some legacy launchers do this legitimately; read the path it points at.")
                }
            }
        }

        try {
            $netConn = Get-NetTCPConnection -OwningProcess $proc.ProcessId -ErrorAction Stop |
                       Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.State -eq 'Listen' }
            if ($netConn) {
                $ports = $netConn.LocalPort -join ', '
                # Deliberately NOT a finding. A Gradle daemon, a launcher catching a
                # Microsoft login redirect and a mod with a built-in web map all
                # listen on 127.0.0.1, and none of them is a cheat. It is worth a
                # moderator's eyes; it is not worth an accusation.
                $r.Notes.Add("Localhost listener $([char]0x2014) $where has server socket(s) open on port(s): $ports $([char]0x2014) the game itself does not need this, but launchers, dev tools and web-map mods do. Check what is on the port.")
            }
        } catch {}

        if ($script:DeepMemory) { try {
            $sig = @"
[DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr addr,byte[] buf,int sz,out int read);
[DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int acc,bool inh,int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr h,IntPtr addr,out MEMORY_BASIC_INFORMATION mbi,uint len);
[StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint   AllocationProtect;
    public uint   __alignment1;
    public IntPtr RegionSize;      // SIZE_T: pointer-sized. Declaring this uint shifted
    public uint   State;           // every field after it, so State read the high half of
    public uint   Protect;         // RegionSize (always 0) and the scan matched nothing.
    public uint   Type;
    public uint   __alignment2;
}
"@
            Add-Type -MemberDefinition $sig -Name MemAPI -Namespace Win32 -ErrorAction SilentlyContinue

            # The struct above is laid out for 64-bit. Rather than read misaligned
            # garbage on a 32-bit host, say so and skip.
            if ([IntPtr]::Size -ne 8) {
                $r.Gaps.Add("Live-memory check skipped for $where $([char]0x2014) it needs 64-bit PowerShell and this host is 32-bit. An injected client would not have been seen.")
            } else {
            $handle = [Win32.MemAPI]::OpenProcess(0x10 -bor 0x400, $false, $proc.ProcessId)
            if ($handle -eq [IntPtr]::Zero) {
                $r.Gaps.Add("Could not open $where for reading $([char]0x2014) its memory was not checked, so an injected client would not have been seen. Run as administrator.")
            } else {
                $addr      = [IntPtr]::Zero
                $mbi       = New-Object Win32.MemAPI+MEMORY_BASIC_INFORMATION
                $mbiSize   = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
                # A modded Minecraft holds several GB. Reading only the first 64 KB of
                # each of 512 regions saw a fraction of a percent of the heap, so an
                # injected client could sit anywhere and never be seen. Walk the whole
                # address space instead, bounded by time rather than by region count so
                # the cost is predictable regardless of how much RAM the game took.
                $memWatch  = [System.Diagnostics.Stopwatch]::StartNew()
                $memBudget = if ($script:Deep) { 600 } else { 120 }   # seconds
                $chunkSize = 1048576
                # Two kinds of memory evidence, kept apart because they answer
                # different questions:
                #   client  -> WHICH hack it is (community-extendable via signatures.json)
                #   module  -> WHAT it is doing (a cheat feature that is active)
                $memClientTerms = @($script:distinctiveClientTokens)
                $memModuleTerms = @(
                    "killaura","silentaura","autocrystal","crystalaura","aimassist","triggerbot",
                    "scaffoldhack","bunnyhop","freecam","autoanchor","autototem","holefill",
                    "webhookstealer","tokengrabber","reverseshell","connectback",
                    "walksyoptimizer","baritone","velocitybypass","packetfly","hitboxexpand"
                )
                $memClientSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($ct in $memClientTerms) { [void]$memClientSet.Add([string]$ct) }
                # One compiled alternation beats ~70 IndexOf passes per memory region.
                $memAllTerms = @($memClientTerms) + @($memModuleTerms)
                $memAlt = ($memAllTerms | Where-Object { $_ } | ForEach-Object { [regex]::Escape([string]$_) }) -join '|'
                $memRegex = [regex]::new("($memAlt)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                $memHits = @{}
                $scanLimit = 0
                # Every jar URL the JVM is holding on to. Capped so a pathological
                # heap cannot turn this into the thing that runs out of memory.
                $jarUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $jarUrlRegex = [regex]::new('(?i)file:/{1,3}[A-Za-z]:[/\\][^\s"''<>|*?\r\n]{0,300}?\.jar')
                # Coverage bookkeeping. The time budget stops the READING, not the
                # walk: VirtualQueryEx costs nothing, so keep enumerating regions to
                # the end of the address space and learn the real total. That turns
                # "we stopped early" into "we read 61% of 3.2 GB", which is a fact a
                # moderator can act on instead of a shrug.
                $memBudgetHit = $false
                $memRead      = [int64]0
                $memTotal     = [int64]0

                while ([Win32.MemAPI]::VirtualQueryEx($handle, $addr, [ref]$mbi, [uint32]$mbiSize) -and $scanLimit -lt 200000) {
                    $scanLimit++
                    # .ToInt64() rather than a cast: IntPtr does not implement IConvertible,
                    # so [int64]$ptr throws on PowerShell 5.1.
                    $regionSize = $mbi.RegionSize.ToInt64()
                    # committed, and readable+writable (the JVM heap) or RWX (JIT / injected code)
                    $readable = (($mbi.Protect -band 0x04) -ne 0) -or (($mbi.Protect -band 0x40) -ne 0)
                    if ($mbi.State -eq 0x1000 -and $readable -and $regionSize -gt 0) {
                        $memTotal += $regionSize
                        if (-not $memBudgetHit -and $memWatch.Elapsed.TotalSeconds -gt $memBudget) { $memBudgetHit = $true }
                        if (-not $memBudgetHit) {
                            $offset = [int64]0
                            while ($offset -lt $regionSize) {
                                if ($memWatch.Elapsed.TotalSeconds -gt $memBudget) { $memBudgetHit = $true; break }
                                $take = [int][Math]::Min([int64]$chunkSize, $regionSize - $offset)
                                $buf  = New-Object byte[] $take
                                $read = 0
                                $rAddr = [IntPtr]($mbi.BaseAddress.ToInt64() + $offset)
                                if (-not ([Win32.MemAPI]::ReadProcessMemory($handle, $rAddr, $buf, $take, [ref]$read)) -or $read -le 0) { break }
                                $memRead += $read
                                $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
                                # Pre-filter: an ordinal IndexOf over a megabyte costs a
                                # fraction of what a second regex pass would, and the time
                                # budget is the thing that decides how much of the heap
                                # gets looked at at all.
                                if ($jarUrls.Count -lt 4000 -and $str.IndexOf('file:/', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                    foreach ($um in $jarUrlRegex.Matches($str)) {
                                        if ($jarUrls.Count -ge 4000) { break }
                                        [void]$jarUrls.Add($um.Value)
                                    }
                                }
                                foreach ($mm in $memRegex.Matches($str)) {
                                    $term = $mm.Groups[1].Value
                                    $key  = $term.ToLower()
                                    if (-not $memHits.ContainsKey($key)) {
                                        $memHits[$key] = @{
                                            Label   = $term
                                            Kind    = $(if ($memClientSet.Contains($term)) { "client" } else { "module" })
                                            Hits    = 0
                                            Addr    = ("0x{0:X}" -f $mbi.BaseAddress.ToInt64())
                                            Regions = [System.Collections.Generic.HashSet[string]]::new()
                                        }
                                    }
                                    $memHits[$key].Hits++
                                    [void]$memHits[$key].Regions.Add(("0x{0:X}" -f $mbi.BaseAddress.ToInt64()))
                                }
                                $offset += $read
                            }
                        }
                    }
                    try { $addr = [IntPtr]($mbi.BaseAddress.ToInt64() + $regionSize) } catch { break }
                    if ($regionSize -le 0) { break }
                }
                [Win32.MemAPI]::CloseHandle($handle) | Out-Null
                $memWatch.Stop()

                if ($memBudgetHit) {
                    $pct = if ($memTotal -gt 0) { [Math]::Round(100.0 * $memRead / $memTotal, 1) } else { 0 }
                    $mb  = [Math]::Round($memTotal / 1MB)
                    $r.Gaps.Add("Live-memory check read $pct% of $mb MB in $where before its $memBudget s budget ran out $([char]0x2014) the rest was not looked at. Run with -Deep for a longer sweep.")
                }

                # -------------------------------------------------------------
                # What the live game says it loaded, checked against what is on
                # disk right now. Deliberately narrow: only jars under a mods
                # folder are judged, because .minecraft\libraries is full of
                # jars whose lifecycle belongs to the launcher, not the player.
                # -------------------------------------------------------------
                $missingMods = [System.Collections.Generic.List[string]]::new()
                $oddMods     = [System.Collections.Generic.List[string]]::new()
                $loadedDirs  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $unsureMods  = 0
                foreach ($u in $jarUrls) {
                    $jp = Resolve-JarUrl $u
                    if (-not $jp) { continue }
                    $isMod = $jp.ToLower().Contains('\mods\')
                    $exists = $false
                    try { $exists = [System.IO.File]::Exists($jp) } catch {}
                    if ($isMod) {
                        if ($exists) {
                            try { [void]$loadedDirs.Add([System.IO.Path]::GetDirectoryName($jp)) } catch {}
                        } else {
                            # Only claim a file is GONE if its folder is still
                            # there. If the folder is missing too, the more likely
                            # explanation is a path this code decoded wrongly or a
                            # drive that is no longer plugged in - and an accusation
                            # built on a decoding bug is exactly what must not ship.
                            $parentOk = $false
                            try { $parentOk = [System.IO.Directory]::Exists([System.IO.Path]::GetDirectoryName($jp)) } catch {}
                            # Every launcher worth the name turns a mod off by
                            # renaming it to .jar.disabled. The jar the running
                            # game loaded is then "missing" without anything
                            # having been wiped, so look for the twin first.
                            $disabled = $false
                            try { $disabled = [System.IO.File]::Exists($jp + '.disabled') } catch {}
                            if ($disabled) {
                                $oddMods.Add("$jp $([char]0x2014) turned off (renamed to .disabled) while the game had it loaded")
                            } elseif ($parentOk) { $missingMods.Add($jp) } else { $unsureMods++ }
                        }
                    } elseif ($exists -and (Test-OddJarLocation $jp)) {
                        $oddMods.Add("$jp $([char]0x2014) loaded from a folder no launcher keeps mods in. Installers and dev setups do use these paths, so read the file name before drawing a conclusion.")
                    }
                }
                foreach ($mp in $missingMods) {
                    [void]$script:DeletedJarPaths.Add($mp)
                    $r.Findings.Add("Mod loaded, then deleted while the game ran: $mp $([char]0x2014) $where is still running with this jar loaded, and the file is no longer on disk. The game's own memory still holds where it came from, which is why deleting it did not remove the trace.")
                }
                $script:Evidence.DeletedJars = $script:DeletedJarPaths.Count
                foreach ($op in $oddMods) {
                    $r.Notes.Add("Jar the running game loaded: $op")
                }
                if ($unsureMods -gt 0) {
                    $r.Gaps.Add("$unsureMods jar path(s) from $where could not be checked against the disk $([char]0x2014) their folder no longer exists, so whether the file is missing could not be decided either way.")
                }
                # The live game names the folders it is actually reading. Anything
                # in that list the file scan never opened is a hole in THIS scan,
                # and saying so is the difference between "clean" and "I looked".
                foreach ($ld in $loadedDirs) {
                    if (-not (Test-ScannedDir $ld)) {
                        # Not a gap - a target. The tool scans it itself a moment
                        # later (Invoke-LateFolderScan), because "re-run it
                        # yourself with -Path" is advice nobody follows while a
                        # suspect is sitting on the other end of the call.
                        if (-not $script:LateScanDirs.Contains($ld)) { [void]$script:LateScanDirs.Add($ld) }
                    }
                }

                # Report WHAT was found, WHERE, and whether it is a cheat.
                foreach ($mk in @($memHits.Keys | Sort-Object)) {
                    $mh = $memHits[$mk]
                    $spread = if ($mh.Regions.Count -gt 1) { ", across $($mh.Regions.Count) memory regions" } else { "" }
                    $at = "$where at $($mh.Addr), $($mh.Hits) hit(s)$spread"
                    # ONE bar for both kinds, because the reason is the same for both:
                    # a word in RAM can be a chat message, a server MOTD, a sign, a
                    # book or a scoreboard line. "killaura" is a word players type.
                    # Loaded code puts its own name in memory many times over - the
                    # class file, the metaspace, the interned pool - so repetition,
                    # not presence, is what separates code from conversation.
                    $strong = ($mh.Label.Length -ge 6 -and $mh.Hits -ge 3)
                    if ($mh.Kind -eq "client") {
                        if (-not $strong) {
                            $r.Notes.Add("Cheat client name seen in memory: $($mh.Label) $([char]0x2014) $at. Too few occurrences to call it loaded code; a chat message or a server MOTD looks exactly like this.")
                        } elseif (-not (Test-LoadedFromDisk $mh.Label)) {
                            # Nothing on disk could have supplied these classes.
                            $r.Findings.Add("INJECTED CHEAT CLIENT: $($mh.Label) $([char]0x2014) live in $at, and NO jar on disk contains it. It was injected straight into the running game, so deleting files cannot hide it and a file scan alone would never have found it.")
                            $script:Evidence.MemInjectedOnly++
                            $script:Evidence.MemCheatClient++
                        } else {
                            $r.Findings.Add("CHEAT CLIENT IN MEMORY: $($mh.Label) $([char]0x2014) identified live in $at. This IS a cheat and it is loaded in the running game right now.")
                            $script:Evidence.MemCheatClient++
                        }
                    } else {
                        if ($strong) {
                            $r.Findings.Add("Cheat module active in memory: $($mh.Label) $([char]0x2014) found in $at. A cheat feature is live in the running game.")
                            $script:Evidence.MemModule++
                        } else {
                            $r.Notes.Add("Cheat term seen in memory: $($mh.Label) $([char]0x2014) $at. One or two occurrences is what a chat message looks like, so this is reported, not counted as proof.")
                        }
                    }
                }
            }
            }   # end 64-bit guard
        } catch {} }
    }

    return $r
}

# ---------------------------------------------------------------------------
# Windows system checks.
#
# Every check in here used to decide by GUESSING AT NAMES, and every one of them
# fired on an ordinary gaming PC:
#
#   hosts     the line contains "aac"       -> any pi-hole blocklist
#   tasks     the name contains "updater"   -> Discord, OneDrive, Razer, Epic
#   Defender  the path contains "mod"       -> C:\Games\ModernWarfare
#   prefetch  the name contains "LOADER"    -> fabric-loader
#   startup   the value contains "java"     -> every Java application ever
#
# They are replaced by STRUCTURAL tests - what the entry actually does, not what
# it is called. See ml/sysscan.py, where each one has the clean case that used
# to trip it as a test.
#
# The second thing wrong here: none of these checks called Add-Finding. The whole
# section, IFEO hijacking included - javaw.exe replaced by an injector, about as
# conclusive as this tool gets - printed to the console, bumped a counter and
# reached the report, the upload and "Look at these first" not at all. After the
# call there was nothing left of it.
#
# Findings are now split in two, because they answer different questions:
#   Add-SysCheat  bears on cheating. Counts, and can reach the report's first page.
#   Add-SysState  is the state of the PC. Shown in its own block, never counted:
#                 a third-party antivirus turns the Windows firewall off by
#                 itself, and an innocent player must not collect "system issues"
#                 for owning one.
# ---------------------------------------------------------------------------
# Write-SystemFlag already records the finding, under $script:SysArea - calling
# Add-Finding here as well would put every system check in the report twice.
function Add-SysCheat([string]$Level, [string]$Title, [string[]]$Items = @()) {
    $script:SysArea = "System forensics"
    Write-SystemFlag $Level $Title $Items
    $script:SystemIssues++
}

function Add-SysState([string]$Title, [string[]]$Items = @()) {
    $script:SysArea = "PC state"
    Write-SystemFlag "STATE" $Title $Items
}

# A hosts line that really sends a name that matters to nowhere.
# Returns "cheatsite", "auth" or "" - see hosts_block() in ml/sysscan.py.
function Test-HostsBlock([string]$Line, [string[]]$CheatDomains) {
    $l = ($Line -split '#', 2)[0].Trim()
    if (-not $l) { return @{ Kind = ""; Host = "" } }
    $parts = @($l -split '\s+' | Where-Object { $_ })
    if ($parts.Count -lt 2) { return @{ Kind = ""; Host = "" } }
    if ($script:sysBlackhole -notcontains $parts[0]) { return @{ Kind = ""; Host = "" } }
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $h = $parts[$i].Trim('.').ToLower()
        foreach ($d in $CheatDomains) {
            $dl = ([string]$d).ToLower()
            if ($dl -and ($h -eq $dl -or $h.EndsWith("." + $dl))) { return @{ Kind = "cheatsite"; Host = $h } }
        }
        foreach ($a in $script:sysAuthHosts) {
            if ($h -eq $a -or $h.EndsWith("." + $a)) { return @{ Kind = "auth"; Host = $h } }
        }
    }
    return @{ Kind = ""; Host = "" }
}

function Test-DefenderExclusion([string]$Path) {
    $p = ([string]$Path).ToLower().Replace('/', '\')
    foreach ($m in $script:sysMcMarkers) { if ($p.Contains($m)) { return $true } }
    if ($p.TrimEnd('\').EndsWith('\mods')) { return $true }
    # A process exclusion on the game's own runtime: nothing inside Minecraft is
    # ever scanned again, which is the point of adding it.
    if ($p -match '(?:^|\\)javaw?\.exe$') { return $true }
    return $false
}

# Why this startup entry or scheduled task is worth reporting, or "".
function Test-AutostartAction([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($Command)) { return "" }
    $hit = Test-CheatName $Command
    if ($hit) { return "names a known cheat client ($hit)" }
    if ($Command.ToLower().Contains('-javaagent:')) { return "attaches a Java agent to the process it starts" }
    # The switch alone would match -Execute; an encoded command is the switch
    # followed by a base64 blob long enough to be a command.
    if ($Command -match '(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{40,}') { return "runs a base64-encoded PowerShell command" }
    if ($Command -match '(?i)\.jar(?:"|\s|$)' -and $Command -match '(?i)(?:^|[\\/"\s])javaw?(?:\.exe)?(?:"|\s|$)') {
        return "starts a .jar with Java at login"
    }
    return ""
}

# FOO.EXE-1A2B3C4D.pf -> foo.exe. The hash suffix is not part of the name, and
# leaving it on is why "PROJECTOR.EXE" once matched a search for "INJECT".
function Get-PrefetchImage([string]$FileName) {
    $m = [regex]::Match($FileName, '(?i)^(.+)-[0-9A-F]{8}\.pf$')
    return $(if ($m.Success) { $m.Groups[1].Value } else { $FileName }).ToLower()
}

function Run-SystemChecks {
    Write-SysSection "SYSTEM FORENSICS"
    $script:SysArea = "System forensics"

    # ---- hosts file --------------------------------------------------------
    # Only lines that point a name at a blackhole address, and only for names
    # that have no business being in a hosts file: a cheat vendor's own domain,
    # or the game's login servers. Blocking Modrinth or CurseForge is a parental
    # filter, not a cheat, and used to be flagged as one.
    $hostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsCheat  = @()
    $hostsAuth   = @()
    $hostDomains = @(@($script:cheatDomainMap | ForEach-Object { $_.match }) | Where-Object { $_ -and ([string]$_).Contains('.') })
    foreach ($line in @(Get-Content $hostsPath -ErrorAction SilentlyContinue)) {
        $hb = Test-HostsBlock $line $hostDomains
        if ($hb.Kind -eq "cheatsite") { $hostsCheat += "$($hb.Host)  <-  $($line.Trim())" }
        elseif ($hb.Kind -eq "auth")  { $hostsAuth  += "$($hb.Host)  <-  $($line.Trim())" }
    }
    if ($hostsCheat.Count -gt 0) {
        Add-SysCheat "FAIL" "A cheat vendor's own domain is redirected in the hosts file:" $hostsCheat
        Write-Detail "The hosts file overrides DNS: these names resolve to nowhere on this PC." `
            "The domain belongs to a cheat client. Nothing puts it in a hosts file except software that talks to it $([char]0x2014) usually a cracked build being kept from phoning home for a licence check." `
            "Added by editing C:\Windows\System32\drivers\etc\hosts, which needs administrator rights." `
            "Open that file and remove the flagged lines."
    } elseif ($hostsAuth.Count -gt 0) {
        Add-SysCheat "WARN" "The game's own login servers are blackholed in the hosts file:" $hostsAuth
        Write-Detail "These are Mojang's session and authentication servers." `
            "Blocking them stops the client talking to Mojang while the game still runs $([char]0x2014) offline-mode and cracked setups do this, and so does anything that does not want its session seen." `
            "Added by editing C:\Windows\System32\drivers\etc\hosts." `
            "Open that file and remove the flagged lines, then check the game still logs in."
    } else { Write-SystemFlag "OK" "Hosts file $([char]0x2014) nothing that matters is redirected" }

    # ---- Defender exclusions -----------------------------------------------
    try {
        $mpExcReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction Stop
        $defExc   = @($mpExcReg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name)
        $javaExc  = @($defExc | Where-Object { Test-DefenderExclusion $_ })
        if ($javaExc.Count -gt 0) {
            Add-SysCheat "WARN" "Windows Defender is told never to scan the Minecraft install:" $javaExc
            Write-Detail "An exclusion tells Windows Security to skip a folder or a process entirely." `
                "Anything inside the excluded path is never scanned again $([char]0x2014) which is exactly what a cheat installer wants, and also what somebody chasing frames might set by hand." `
                "Set in Windows Security, or by a script writing to the Defender registry key." `
                "Windows Security > Virus & threat protection > Manage settings > Exclusions."
        } else { Write-SystemFlag "OK" "Defender exclusions $([char]0x2014) the Minecraft install is not excluded" }
    } catch { Add-ScanGap "Windows Defender exclusions could not be read $([char]0x2014) that needs Administrator, so an exclusion hiding the mods folder would not have been seen" }

    # ---- IFEO -------------------------------------------------------------
    # Replacing an executable with another one. On a game PC this has no
    # innocent version, and when the hijacked image is the game's own runtime it
    # is as close to proof as this tool gets.
    $ifeoFlags = @()
    $ifeoGame  = $false
    $rp = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $rp) {
        foreach ($child in @(Get-ChildItem $rp -ErrorAction SilentlyContinue)) {
            $prop = Get-ItemProperty -Path $child.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($prop -and $prop.Debugger -notmatch 'vsjitdebugger|drwatson|ntsd|windbg') {
                $ifeoFlags += "$($child.PSChildName) -> $($prop.Debugger)"
                if ($child.PSChildName -match '(?i)^(javaw?|minecraft.*|.*launcher)\.exe$') { $ifeoGame = $true }
            }
        }
    }
    if ($ifeoFlags.Count -gt 0) {
        Add-SysCheat $(if ($ifeoGame) { "FAIL" } else { "WARN" }) `
            $(if ($ifeoGame) { "The game's own executable is hijacked (IFEO):" } else { "An executable is hijacked (IFEO):" }) $ifeoFlags
        Write-Detail "Image File Execution Options lets Windows run a different program whenever a named executable is launched." `
            $(if ($ifeoGame) { "The hijacked name is the game's own runtime, so every Minecraft launch runs the listed program FIRST. That is what an injector is." } else { "Whatever launches the name on the left actually runs the program on the right." }) `
            "Set under HKLM\...\Image File Execution Options\<name>\Debugger, which needs administrator rights." `
            "Open regedit, go to the flagged key and delete its 'Debugger' value."
    } else { Write-SystemFlag "OK" "IFEO $([char]0x2014) no executable is hijacked" }

    # ---- execution history: prefetch ---------------------------------------
    # Through the same boundary-anchored client matcher the log and instance
    # readers use, on the image name with its hash suffix removed. The old
    # substring list matched fabric-loader, examiner.exe and projector.exe.
    $prefetchDir = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchDir) {
        $prefFlags = @()
        foreach ($pf in @(Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue)) {
            $img = Get-PrefetchImage $pf.Name
            $hit = Test-CheatName $img
            if ($hit) { $prefFlags += "$img  ($hit, last run $($pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" }
        }
        if ($prefFlags.Count -gt 0) {
            Add-SysCheat "FAIL" "Windows recorded a known cheat client being executed:" $prefFlags
            Write-Detail "Windows writes a .pf file the first time any program runs, to make later starts faster." `
                "The recorded name matches a known cheat client. The record survives deleting the program $([char]0x2014) it is proof that it ran on this PC, with the date it last did." `
                "C:\Windows\Prefetch, one file per executable." `
                "Nothing to fix: this is evidence, and deleting it destroys it."
        } else { Write-SystemFlag "OK" "Prefetch $([char]0x2014) no known client in the execution history" }
    } else { Add-ScanGap "Windows Prefetch could not be read, so programs that ran and were then deleted could not be checked there" }

    # ---- autostart: Run keys ------------------------------------------------
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $runFlags = @()
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk)) { continue }
        $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
        foreach ($pr in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $val = [string]$pr.Value
            $why = Test-AutostartAction $val
            if ($why) { $runFlags += "$($pr.Name) $([char]0x2014) $why$([char]0x0A)      $val" }
        }
    }
    if ($runFlags.Count -gt 0) {
        Add-SysCheat "WARN" "A startup entry does something a launcher does not:" $runFlags
        Write-Detail "Run and RunOnce start programs automatically at every login." `
            "Starting a jar, attaching a Java agent or running an encoded PowerShell command at login is not how any launcher or game installs itself." `
            "Registry, under Software\Microsoft\Windows\CurrentVersion\Run." `
            "Open regedit, go to the flagged key and delete the entry after reading what it points at."
    } else { Write-SystemFlag "OK" "Startup entries $([char]0x2014) nothing starts a jar or an agent at login" }

    # ---- autostart: scheduled tasks ----------------------------------------
    # By ACTION, not by name. The check this replaces flagged any task whose name
    # contained update/sync/helper/service/loader/check/runner/java and was not
    # from one of eight vendors - which is Discord, OneDrive, Epic, Razer,
    # Logitech, Corsair, Spotify and Brave on an ordinary PC.
    try {
        $taskFlags = @()
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($a in @($t.Actions)) {
                $cmd = (("$($a.Execute) $($a.Arguments)").Trim())
                $why = Test-AutostartAction $cmd
                if ($why) { $taskFlags += "$($t.TaskPath)$($t.TaskName) $([char]0x2014) $why$([char]0x0A)      $cmd" }
            }
        }
        if ($taskFlags.Count -gt 0) {
            Add-SysCheat "WARN" "A scheduled task does something a launcher does not:" $taskFlags
            Write-Detail "Scheduled tasks run programs at login, on a timer or on an event." `
                "The task's ACTION starts a jar, attaches a Java agent or runs an encoded command $([char]0x2014) none of which any game or launcher schedules." `
                "Task Scheduler (taskschd.msc)." `
                "Open the flagged task, read its Actions tab, and delete it if you do not recognise what it starts."
        } else { Write-SystemFlag "OK" "Scheduled tasks $([char]0x2014) none starts a jar, an agent or an encoded command" }
    } catch { Add-ScanGap "Scheduled tasks could not be listed $([char]0x2014) a task starting a cheat at login would not have been seen" }

    # ---- PC state: real, reported, deliberately not counted ----------------
    Write-Host ""
    W "  $([char]0x2502)  PC state $([char]0x2014) not cheat evidence, but a moderator should see it" DarkCyan
    $script:SysArea = "PC state"

    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Enabled -eq $false })
        if ($fw.Count -gt 0) {
            Add-SysState ("Windows Firewall is off on: " + ($fw.Name -join ', '))
            Write-Detail "The firewall blocks connections this PC did not ask for." `
                "Most third-party antivirus suites turn the Windows firewall off and use their own, so this on its own says nothing about cheating." `
                "" "If no other firewall is installed, turn it back on in Windows Security."
        } else { Write-SystemFlag "OK" "Firewall $([char]0x2014) on for every profile" }
    } catch { Add-ScanGap "Firewall status could not be read" }

    $psLogKey  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psLogging = if (Test-Path $psLogKey) { (Get-ItemProperty $psLogKey -ErrorAction SilentlyContinue).EnableScriptBlockLogging } else { $null }
    if ($psLogging -eq 0) {
        Add-SysState "PowerShell script logging is switched off by policy"
        Write-Detail "Script Block Logging records PowerShell commands to the event log." `
            "It is off by default on home Windows, so this is only interesting if somebody turned it off deliberately." `
            "" "Set EnableScriptBlockLogging to 1 under HKLM\...\PowerShell\ScriptBlockLogging."
    } else { Write-SystemFlag "OK" "PowerShell script logging $([char]0x2014) enabled or left at the default" }

    try {
        $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1 -ErrorAction Stop)
        if ($ev.Count -gt 0) {
            Add-SysState ("The Security event log was cleared on " + $ev[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'))
            Write-Detail "Windows writes event 1102 whenever somebody clears the Security log." `
                "Clearing it removes the record of what ran and when. Ordinary users have no reason to, so the DATE is the interesting part $([char]0x2014) compare it with when the screenshare was arranged." `
                "" ""
        } else { Write-SystemFlag "OK" "Security event log $([char]0x2014) not cleared in the last 30 days" }
    } catch { Write-SystemFlag "OK" "Security event log $([char]0x2014) no clearing recorded" }

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
            Add-Finding "WARN" "Windows services" "$($svc.DisplayName) is $status, expected $($svc.Expected)" `
                @() $svc.WhatDoes $svc.WhySecurity "" "Open services.msc and set '$($svc.Name)' back to $($svc.Expected)." | Out-Null
        }
    } else {
        W "  $([char]0x2502)" DarkCyan
        Write-SystemFlag "OK" "All security-relevant services are in their expected state"
    }

    Write-SysSectionEnd
}

Show-Banner

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

function Run-UsnScan {
    $res = @{ Hits = [System.Collections.Generic.List[string]]::new(); Read = 0 }
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
            $hit = Test-CheatName $d.Name
            $isJar = $d.Name -match '(?i)\.(jar|litemod)$'
            # Built before the string, not inside it. A $( ) subexpression that
            # contains a double quote cannot sit inside a double-quoted string:
            # the inner quote closes the outer one and the whole file stops
            # parsing. That is what broke the first Windows run of this tool.
            $whenPart = ""
            if ($d.When) { $whenPart = ", " + $d.When }
            if ($hit) {
                $res.Hits.Add("$($d.Name)  ($hit, $($d.Reason.Trim())$whenPart)")
            } elseif ($isJar -and $script:FlaggedModsList.Contains($d.Name)) {
                $res.Hits.Add("$($d.Name)  (a jar this scan flagged, $($d.Reason.Trim())$whenPart)")
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
    if ($shim.Hits.Count -eq 0 -and $usn.Hits.Count -eq 0) {
        Write-SystemFlag "OK" "Deleted-file history $([char]0x2014) no cheat client in the compatibility cache or the change journal"
    }
    Write-SysSectionEnd
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
    "pyroclient","drip","drippy","entropy","nightx","blaze","blazemod",
    "autocrystal","auto-crystal","crystalmacro","crystal-macro","crystalaura","crystal-aura",
    "anchorbot","anchor-bot","anchormacro","anchor-macro","anchoraura","anchor-aura",
    "macroclient","macro-client","autoanchor","auto-anchor"
) | ForEach-Object { [void]$script:cheatProcessNames.Add($_) }
# External ghost clients (Koid and friends) never appear in the mods folder at all -
# they run as their own process. Let signatures.json add those names too. This list is
# built further down the file than Invoke-CloudUpdate runs, hence the pending stash.
if ($script:pendingProcessNames) {
    foreach ($pn in $script:pendingProcessNames) { if ($pn) { [void]$script:cheatProcessNames.Add([string]$pn) } }
}

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

function Run-BamScan {
    Write-Host ""
    W ("$([char]0x2501)" * 76) Blue
    Write-Host ""
    W "  BAM SCAN $([char]0x2014) Background Activity Monitor" Cyan
    Write-Host ""

    # Test-IsAdmin, not a raw IsInRole call: the raw one can throw, and when it
    # does the guard is skipped rather than failing closed - the admin-only block
    # below then runs unguarded. Test-IsAdmin catches and returns false.
    if (-not (Test-IsAdmin)) {
        W "  $([char]0x26A0)  Administrator privileges required for BAM scan. Skipping." Yellow
        Add-ScanGap "BAM history not read $([char]0x2014) programs that ran and were then deleted could not be checked"
        Write-Host ""

        $script:BamDeleted = @()
        New-HtmlReport
        return
    }

    $oldestLogon = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } |
        Sort-Object -Property StartTime |
        Select-Object -First 1
    $bamConnectTime = if ($oldestLogon) { $oldestLogon.StartTime } else { $null }

    $bamDynAssembly = New-Object System.Reflection.AssemblyName('BamSysUtils')
    $bamAssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($bamDynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $bamModuleBuilder = $bamAssemblyBuilder.DefineDynamicModule('BamSysUtils', $False)
    $bamTypeBuilder = $bamModuleBuilder.DefineType('BamKernel32', 'Public, Class')
    $bamPInvoke = $bamTypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $bamDllCtor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $bamSetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $bamAttr = New-Object Reflection.Emit.CustomAttributeBuilder($bamDllCtor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($bamSetLastError), @($true))
    $bamPInvoke.SetCustomAttribute($bamAttr)
    $bamKernel32 = $bamTypeBuilder.CreateType()
    $bamSb = New-Object System.Text.StringBuilder(65536)
    $bamMappings = Get-WmiObject Win32_Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object {
        if ($bamKernel32::QueryDosDevice($_.DriveLetter, $bamSb, 65536)) {
            @{ DriveLetter = $_.DriveLetter; DevicePath = $bamSb.ToString().ToLower() }
        }
    }

    $bamBias = -([convert]::ToInt32([Convert]::ToString(
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).ActiveTimeBias, 2), 2))

    $bamUsers = @()
    foreach ($ii in @("bam","bam\State")) {
        $bamUsers += Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\$ii\UserSettings\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
    }

    if ($bamUsers.Count -eq 0) {
        W "  $([char]0x26A0)  No BAM entries found on this system." Yellow
        Write-Host ""
        return
    }

    $bamRaw     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $bamOldPref = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($sid in $bamUsers) {
        foreach ($rp in @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")) {
            $bamItems = Get-Item "$($rp)UserSettings\$sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
            foreach ($item in $bamItems) {
                $ext = [System.IO.Path]::GetExtension($item).ToLower()
                if ($ext -ne ".exe" -and $ext -ne ".jar") { continue }
                $k = Get-ItemProperty "$($rp)UserSettings\$sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $item
                if ($k.Length -eq 24) {
                    $hex = [System.BitConverter]::ToString($k[7..0]) -replace "-",""
                    $ts  = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($hex,16))).AddMinutes($bamBias) -Format "yyyy-MM-dd HH:mm:ss"
                    if ($bamConnectTime -and ([DateTime]::ParseExact($ts,"yyyy-MM-dd HH:mm:ss",$null) -ge $bamConnectTime)) {
                        $devPath = $item
                        foreach ($m in $bamMappings) {
                            if ($devPath -like ($m.DevicePath + "*")) { $devPath = $devPath -replace [regex]::Escape($m.DevicePath), $m.DriveLetter; break }
                        }
                        $bamRaw.Add([PSCustomObject]@{ Time=$ts; Path=$devPath; FileName=[System.IO.Path]::GetFileName($devPath) })
                    }
                }
            }
        }
    }
    $ErrorActionPreference = $bamOldPref

    $existingPaths = $bamRaw | Where-Object { Test-Path $_.Path } | Select-Object -ExpandProperty Path
    $sigMap = @{}
    if ($existingPaths.Count -gt 0) {
        Get-AuthenticodeSignature -LiteralPath $existingPaths | ForEach-Object {
            $sigMap[$_.Path] = if ($_.Status -eq 'Valid') {
                if ($_.SignerCertificate.Subject -like "*Manthe Industries*") { "Not signed (vapeclient)" }
                elseif ($_.SignerCertificate.Subject -like "*Slinkware*") { "Not signed (slinky)" }
                else { "Signed" }
            } else { "Not signed" }
        }
    }

    $bamEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($r in $bamRaw) {
        $sig = if ($sigMap.ContainsKey($r.Path)) { $sigMap[$r.Path] } else { "Deleted" }
        $bamEntries.Add([PSCustomObject]@{ Time=$r.Time; Path=$r.Path; Signature=$sig; FileName=$r.FileName })
    }

    $deletedEntries = @($bamEntries | Where-Object { $_.Signature -eq "Deleted" })
    $script:BamDeleted = @($deletedEntries)
    # .jar specifically: a mod that ran on this PC and is now gone is a much sharper
    # signal than any deleted .exe, so the session AI scores it separately.
    foreach ($de in @($deletedEntries | Where-Object { $_.FileName -match '\.jar$' })) {
        [void]$script:DeletedJarPaths.Add([string]$de.Path)
    }
    $script:Evidence.DeletedJars = $script:DeletedJarPaths.Count
    if ($deletedEntries.Count -gt 0) {
        $delJars = @($deletedEntries | Where-Object { $_.FileName -match '\.jar$' })
        $lvl = if ($delJars.Count -gt 0) { "FAIL" } else { "WARN" }
        Add-Finding $lvl "Execution history (BAM)" "$($deletedEntries.Count) program(s) ran on this PC and are no longer on disk" `
            @($deletedEntries | ForEach-Object { "$($_.Time)   $($_.Path)" }) `
            "Windows records every executable that starts (Background Activity Monitor). The recorded paths were checked against the disk." `
            "$(if ($delJars.Count -gt 0) { "$($delJars.Count) of them are .jar files. A mod that ran on this PC and was then deleted is the classic 'wiped it before the screenshare' pattern." } else { "The file was deleted after it ran, so a file scan alone can no longer see it." })" `
            "BAM only keeps entries since the last logon, so this list is what ran in this session $([char]0x2014) not the full history." `
            "Ask what each of these was before accepting an explanation." | Out-Null
    } else {
        Add-Finding "OK" "Execution history (BAM)" "Execution history $([char]0x2014) every program that ran since the last logon is still on disk" | Out-Null
    }
    New-HtmlReport
    Write-Host ""

    if ($bamEntries.Count -eq 0) {
        W "  $([char]0x2713) BAM $([char]0x2014) no .exe/.jar executions found since last logon." DarkGray
        Write-Host ""
        return
    }

    Write-Host ""
}

# Folders the user can write to without asking anybody. A DLL loaded into the
# game out of one of these is at least worth a look; out of Program Files or
# System32 it is a product, and checking its signature is time wasted.
$script:userWritableMarkers = @('\users\', '\appdata\', '\temp\', '\downloads\', '\public\', '\programdata\')

function Test-UserWritablePath([string]$Path) {
    $p = ([string]$Path).ToLower().Replace('/', '\')
    foreach ($m in $script:userWritableMarkers) { if ($p.Contains($m)) { return $true } }
    return $false
}

function Test-CheatName([string]$Value) {
    # Mirror of _names_hit() in ml/instscan.py: is this class or path naming a known
    # cheat? A package path is matched as a substring (it IS a path); a client token
    # only on a separator boundary, so 'impactclient' is not found in 'impactful'.
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    $low = $Value.ToLower()
    foreach ($p in $script:cheatPackagePaths) {
        $pl = $p.ToLower()
        foreach ($form in @($pl, ($pl -replace '/', '.'))) {
            if ($low.IndexOf($form, [System.StringComparison]::Ordinal) -ge 0) { return $form }
        }
    }
    foreach ($t in $script:distinctiveClientTokens) {
        $tl = $t.ToLower()
        if ($tl.Length -lt $script:tokenFloor) { continue }
        if ($low -match ('(?:^|[/.\\_\-])' + [regex]::Escape($tl) + '(?:$|[/.\\_\-])')) { return $tl }
    }
    return ""
}

function Test-CheatConfigDir([string]$Name) {
    # EXACT on the normalised name, and the difference is not academic: a boundary
    # match reads "doomsday-realms-datapack-helper" as the Doomsday client, because
    # doomsday is also an English word with a hyphen after it. A config folder is
    # named after the client and nothing else, so compare the whole thing.
    if ([string]::IsNullOrEmpty($Name)) { return "" }
    $n = ($Name.ToLower() -replace '[^a-z0-9]', '')
    if ($n.Length -lt $script:tokenFloor) { return "" }
    foreach ($t in $script:distinctiveClientTokens) {
        if ($n -eq ($t.ToLower() -replace '[^a-z0-9]', '')) { return $t.ToLower() }
    }
    return ""
}

# ---------------------------------------------------------------------------
# The game jar itself.
#
# versions/<v>/ was read for its .json only. The <v>.jar next to it - the game's
# own code - was never hashed and never analysed, so a patched client jar with
# an aura compiled straight into it was invisible: not in the mods folder, not
# scanned, not hashed. It is the oldest trick there is.
#
# It needs no heuristic. Mojang's own launcher JSON carries the official SHA1 of
# the client jar it describes, so this can PROVE whether the file on disk is the
# one Mojang published. Zero false positives by construction: either the hash
# matches or it does not. A profile with no hash of its own (Forge, Fabric and
# OptiFine inherit the jar from a parent version) claims nothing.
#
# When it does not match, the same bytecode analysis that runs over every mod
# runs over the jar, so the report says WHAT is in there rather than only that
# something is.
# ---------------------------------------------------------------------------
function Run-ClientJarScan {
    $res = @{
        Official = [System.Collections.Generic.List[string]]::new()
        Patched  = [System.Collections.Generic.List[object]]::new()
        NoHash   = [System.Collections.Generic.List[string]]::new()
    }
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($script:ScanTargetDirs)) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        try { $d = [System.IO.Path]::GetDirectoryName(([string]$t).TrimEnd('\')); if ($d) { [void]$roots.Add($d) } } catch {}
    }
    foreach ($root in $roots) {
        $vdir = [System.IO.Path]::Combine($root, 'versions')
        if (-not [System.IO.Directory]::Exists($vdir)) { continue }
        foreach ($vd in @([System.IO.Directory]::GetDirectories($vdir) | Select-Object -First 60)) {
            $name = [System.IO.Path]::GetFileName($vd)
            $vj   = [System.IO.Path]::Combine($vd, "$name.json")
            $jar  = [System.IO.Path]::Combine($vd, "$name.jar")
            if (-not [System.IO.File]::Exists($vj) -or -not [System.IO.File]::Exists($jar)) { continue }
            $official = ""
            try {
                $fi = [System.IO.FileInfo]::new($vj)
                if ($fi.Length -le 4MB) {
                    $txt = [System.IO.File]::ReadAllText($vj)
                    # Read the sha1 out of downloads.client without a JSON parse:
                    # these files nest deeply and ConvertFrom-Json on PowerShell
                    # 5.1 is both slow and depth-limited.
                    $m = [regex]::Match($txt, '(?s)"client"\s*:\s*\{.*?"sha1"\s*:\s*"([0-9a-fA-F]{40})"')
                    if ($m.Success) { $official = $m.Groups[1].Value.ToLower() }
                }
            } catch {}
            if (-not $official) {
                # Forge, Fabric and OptiFine profiles inherit the jar from a
                # parent version and describe only what to add. Nothing to
                # compare against, so nothing is claimed.
                [void]$res.NoHash.Add("$name  (this profile carries no official hash of its own)")
                continue
            }
            $have = Get-FileSHA1 $jar
            if (-not $have) { [void]$res.NoHash.Add("$name  (the jar could not be read)"); continue }
            if ($have.ToLower() -eq $official) {
                [void]$res.Official.Add("$name  (matches Mojang's published SHA1)")
            } else {
                $bc = Get-BytecodeFeatures $jar $script:BcMaxClasses
                $why = [System.Collections.Generic.List[string]]::new()
                if ($bc -and $bc.ClassesParsed -gt 0) {
                    if ($bc.movepacketRatio -gt 0 -and $bc.rotationRatio -gt 0) {
                        [void]$why.Add("forges its own movement packet while writing a computed rotation $([char]0x2014) the aim/killaura fingerprint" + (Get-BcWitness $bc @('movepacket','rotation')))
                    }
                    if ($bc.entityscanRatio -gt 0 -and $bc.attackRatio -gt 0) {
                        [void]$why.Add("attacks entities picked out of a full entity sweep" + (Get-BcWitness $bc @('entityscan','attack')))
                    }
                    if ($bc.blockplaceRatio -gt 0 -and $bc.movepacketRatio -gt 0) {
                        [void]$why.Add("places blocks while forging its own movement packet" + (Get-BcWitness $bc @('blockplace','movepacket')))
                    }
                    if ($bc.cryptoRatio -ge 0.5 -and ($bc.classloadRatio -gt 0 -or $bc.reflectRatio -ge 0.5)) {
                        [void]$why.Add("decrypts data and defines classes from it at runtime" + (Get-BcWitness $bc @('crypto')))
                    }
                }
                [void]$res.Patched.Add([PSCustomObject]@{
                    Version = $name; Jar = $jar; Have = $have; Official = $official
                    Why = @($why)
                })
            }
        }
    }
    return $res
}

function Show-ClientJarScan {
    $cj = Run-ClientJarScan
    if ($cj.Official.Count -eq 0 -and $cj.Patched.Count -eq 0 -and $cj.NoHash.Count -eq 0) { return }
    $script:SysArea = "The game's own jar"
    Write-SysSection "THE GAME'S OWN JAR"
    W "  $([char]0x2502)  Checked $($cj.Official.Count + $cj.Patched.Count) version jar(s) against Mojang's published hashes" DarkGray
    foreach ($p in $cj.Patched) {
        $items = @("$($p.Jar)", "on disk : $($p.Have)", "Mojang  : $($p.Official)") + @($p.Why | ForEach-Object { "behaviour: $_" })
        Write-SystemFlag "FAIL" "The game jar for $($p.Version) is NOT the one Mojang published:" $items
        Write-Detail "Every versions/<v>/<v>.json carries the official SHA1 of the client jar it describes. The jar on disk was hashed and compared against it." `
            $(if ($p.Why.Count -gt 0) { "The jar does not match, and reading its bytecode found cheat behaviour in it: $($p.Why -join '; ')." } else { "The jar does not match. The bytecode reader found no cheat behaviour in it, so this could also be an old or hand-modified install $([char]0x2014) but it is not the file Mojang shipped." }) `
            "There is no heuristic here: either the hash matches or it does not." `
            "Compare the two hashes yourself, and re-download the version through the launcher to get the official jar back."
        $script:SystemIssues++
        if ($p.Why.Count -gt 0) { $script:Evidence.HardConfirmed++ }
    }
    if ($cj.Official.Count -gt 0 -and $cj.Patched.Count -eq 0) {
        Write-SystemFlag "OK" "The game's own jar $([char]0x2014) $($cj.Official.Count) version(s) match Mojang's published hash exactly"
    }
    foreach ($n in $cj.NoHash) {
        Add-ScanGap "The game jar for $n could not be checked against an official hash, so whether it was modified is unknown"
    }
    Write-SysSectionEnd
}

function Run-InstanceScan {
    # Everything in a .minecraft folder that is not the mods folder.
    $res = @{
        Launch = [System.Collections.Generic.List[object]]::new()   # version / launcher profiles
        Packs  = [System.Collections.Generic.List[object]]::new()   # packs carrying bytecode
        Configs = [System.Collections.Generic.List[string]]::new()  # cheat config folders
        UnknownMain = [System.Collections.Generic.List[string]]::new()
        Checked = 0
    }
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($script:ScanTargetDirs)) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        try { $d = [System.IO.Path]::GetDirectoryName($t.TrimEnd('\')); if ($d) { [void]$roots.Add($d) } } catch {}
    }
    foreach ($root in $roots) {
        # --- version profiles: what the launcher actually starts -----------------
        $vdir = [System.IO.Path]::Combine($root, 'versions')
        if ([System.IO.Directory]::Exists($vdir)) {
            try {
                foreach ($vd in ([System.IO.Directory]::GetDirectories($vdir) | Select-Object -First 60)) {
                    foreach ($vj in [System.IO.Directory]::GetFiles($vd, '*.json')) {
                        try {
                            $fi = [System.IO.FileInfo]::new($vj)
                            if ($fi.Length -gt 4MB) { continue }
                            $txt = [System.IO.File]::ReadAllText($vj)
                        } catch { continue }
                        $res.Checked++
                        foreach ($m in ([regex]::Matches($txt, $script:instMainClass))) {
                            $cls = $m.Groups[1].Value
                            $hit = Test-CheatName $cls
                            if ($hit) {
                                [void]$res.Launch.Add([PSCustomObject]@{ Kind='mainclass'; Value=$cls; File=$vj })
                            } elseif ($script:instKnownMain -notcontains $cls) {
                                if (-not $res.UnknownMain.Contains($cls)) { [void]$res.UnknownMain.Add("$cls  ($vj)") }
                            }
                        }
                        foreach ($m in ([regex]::Matches($txt, $script:instTweakClass))) {
                            if (Test-CheatName $m.Groups[1].Value) {
                                [void]$res.Launch.Add([PSCustomObject]@{ Kind='tweakclass'; Value=$m.Groups[1].Value; File=$vj })
                            }
                        }
                        foreach ($m in ([regex]::Matches($txt, $script:instJavaAgent))) {
                            [void]$res.Launch.Add([PSCustomObject]@{ Kind='javaagent'; Value=$m.Groups[1].Value; File=$vj })
                        }
                    }
                }
            } catch {}
        }
        # --- the launcher's own profiles ----------------------------------------
        foreach ($lp in @('launcher_profiles.json', 'launcher_profiles_microsoft_store.json')) {
            $lpf = [System.IO.Path]::Combine($root, $lp)
            if (-not [System.IO.File]::Exists($lpf)) { continue }
            try {
                $fi = [System.IO.FileInfo]::new($lpf)
                if ($fi.Length -gt 8MB) { continue }
                $txt = [System.IO.File]::ReadAllText($lpf)
            } catch { continue }
            $res.Checked++
            foreach ($m in ([regex]::Matches($txt, $script:instJavaAgent))) {
                [void]$res.Launch.Add([PSCustomObject]@{ Kind='javaagent'; Value=$m.Groups[1].Value; File=$lpf })
            }
        }
        # --- resource and shader packs carrying bytecode -------------------------
        foreach ($pdir in @('resourcepacks', 'shaderpacks')) {
            $pd = [System.IO.Path]::Combine($root, $pdir)
            if (-not [System.IO.Directory]::Exists($pd)) { continue }
            try {
                foreach ($pk in ([System.IO.Directory]::GetFiles($pd, '*.zip') | Select-Object -First 80)) {
                    $res.Checked++
                    try {
                        $fi = [System.IO.FileInfo]::new($pk)
                        if ($fi.Length -gt 512MB) { continue }
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($pk)
                    } catch { continue }
                    try {
                        $bad = [System.Collections.Generic.List[string]]::new()
                        foreach ($e in $zip.Entries) {
                            if ($e.FullName -match $script:instPackExec) {
                                [void]$bad.Add($e.FullName)
                                if ($bad.Count -ge 5) { break }
                            }
                        }
                        if ($bad.Count -gt 0) {
                            [void]$res.Packs.Add([PSCustomObject]@{ Path=$pk; Entries=@($bad) })
                        }
                    } finally { $zip.Dispose() }
                }
            } catch {}
        }
        # --- config folders named after a client ---------------------------------
        $cd = [System.IO.Path]::Combine($root, 'config')
        foreach ($base in @($cd, $root)) {
            if (-not [System.IO.Directory]::Exists($base)) { continue }
            try {
                foreach ($sub in [System.IO.Directory]::GetDirectories($base)) {
                    $nm = [System.IO.Path]::GetFileName($sub)
                    $hit = Test-CheatConfigDir $nm
                    if ($hit -and -not $res.Configs.Contains($sub)) {
                        $when = try { [System.IO.Directory]::GetLastWriteTime($sub).ToString('yyyy-MM-dd HH:mm') } catch { "?" }
                        [void]$res.Configs.Add("$sub  ($([char]0x2192) $hit, last changed $when)")
                    }
                }
            } catch {}
        }
    }
    return $res
}

function Show-InstanceScan {
    $inst = Run-InstanceScan
    # A -javaagent line is counted separately: it is the one entry here with an
    # innocent reading (a profiler, a dev setup), so it flags for a person at Likely
    # rather than joining the things that are proof.
    $agents = @($inst.Launch | Where-Object { $_.Kind -eq 'javaagent' })
    $script:InstanceAgents = $agents.Count
    $script:InstanceHits = ($inst.Launch.Count - $agents.Count) + $inst.Packs.Count + $inst.Configs.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) THE REST OF THE MINECRAFT FOLDER " + "$([char]0x2500)" * 37 + "$([char]0x2510)") DarkCyan
    $iLine = "  $([char]0x2502)  Checked $($inst.Checked) profile(s) and pack(s)"
    W ($iLine + (" " * [Math]::Max(0, 75 - $iLine.Length)) + "$([char]0x2502)") DarkGray
    if ($script:InstanceHits -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) launcher profiles, packs and configs are ordinary" + (" " * 19) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($l in $inst.Launch) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) $($l.Kind.ToUpper())  $($l.Value)" Red
            W "  $([char]0x2502)    $($l.File)" DarkYellow
        }
        foreach ($pk in $inst.Packs) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) PACK WITH CODE  $($pk.Path)" Red
            foreach ($e in $pk.Entries) { W "  $([char]0x2502)    $e" DarkYellow }
        }
        foreach ($c in $inst.Configs) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) CHEAT CONFIG  $c" Red
        }
    }
    foreach ($u in ($inst.UnknownMain | Select-Object -First 5)) {
        W "  $([char]0x2502)  $([char]0x2022) launcher starts an unrecognised class: $u" DarkGray
    }
    W ("  $([char]0x2514)" + "$([char]0x2500)" * 73 + "$([char]0x2518)") DarkCyan
    Write-Host ""

    $script:SysArea = "Launcher, packs & configs"
    if ($inst.Launch.Count -gt 0) {
        Add-Finding "FAIL" "Launcher, packs & configs" "$($inst.Launch.Count) launcher profile entr(y/ies) that start something other than the game" `
            @($inst.Launch | ForEach-Object { "$($_.Kind): $($_.Value)  $([char]0x2014) $($_.File)" }) `
            "Every versions/<v>/<v>.json and launcher_profiles.json was read for the class the launcher starts, the tweaker it passes, and any -javaagent it attaches." `
            "An injected client installs itself as a custom version profile and writes its own class name in there in plain text. A -javaagent line is how a ghost client is attached to the game at launch." `
            "" "This is written down before the game starts, so it is there even if the jar is not." | Out-Null
    }
    if ($inst.Packs.Count -gt 0) {
        Add-Finding "FAIL" "Launcher, packs & configs" "$($inst.Packs.Count) resource/shader pack(s) containing executable code" `
            @($inst.Packs | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Entries) -join ', ')" }) `
            "Resource and shader packs were opened and their entry names read." `
            "A pack is textures, sounds, json and shader source. Java classes or a jar inside one is a jar in a costume $([char]0x2014) packs are not loaded from the mods folder, so this is a hiding place." | Out-Null
    }
    if ($inst.Configs.Count -gt 0) {
        Add-Finding "FAIL" "Launcher, packs & configs" "$($inst.Configs.Count) config folder(s) named after a cheat client" `
            @($inst.Configs) `
            "Folder names under config/ and the instance root were compared, whole and normalised, against the known-client list." `
            "A config folder outlives the jar: it is what is left when somebody deletes the mod and not its settings. The date says when it was last used." | Out-Null
    }
    if ($inst.UnknownMain.Count -gt 0) {
        Add-Finding "INFO" "Launcher, packs & configs" "$($inst.UnknownMain.Count) launcher profile(s) start a class this tool does not recognise" `
            @($inst.UnknownMain) `
            "The mainClass of every version profile was compared against the ones vanilla, Forge, Fabric and Quilt use." `
            "Not a finding $([char]0x2014) custom launchers and wrappers are ordinary. It is listed because an injected client also looks exactly like this." | Out-Null
    }
    if ($script:InstanceHits -eq 0 -and $inst.Checked -gt 0) {
        Add-Finding "OK" "Launcher, packs & configs" "Launcher profiles, resource packs and config folders $([char]0x2014) nothing out of place" `
            @() "$($inst.Checked) version profile(s), launcher profile(s) and pack(s) were read." | Out-Null
    }
}

function Test-LogLine([string]$Line) {
    # Mirror of classify_line() in ml/logscan.py. Returns @{ Kind = ""|"package"|"client"; Evidence = "" }.
    $out = @{ Kind = ""; Evidence = "" }
    if ([string]::IsNullOrWhiteSpace($Line)) { return $out }
    # Chat first, always. Everything after this point is about CODE.
    if ($Line -match $script:logChatLine) { return $out }
    $low = $Line.ToLower()
    foreach ($p in $script:cheatPackagePaths) {
        $pl = $p.ToLower()
        foreach ($form in @($pl, ($pl -replace '/', '.'))) {
            if ($low.IndexOf($form, [System.StringComparison]::Ordinal) -ge 0) {
                $out.Kind = "package"; $out.Evidence = $form; return $out
            }
        }
    }
    if ($Line -match $script:logCodeContext) {
        foreach ($t in $script:distinctiveClientTokens) {
            $tl = $t.ToLower()
            if ($tl.Length -lt $script:tokenFloor) { continue }
            # must sit next to a package or class separator, not float in prose
            if ($low -match ('(?:^|[/.\\_\-\s"''()\[\]])' + [regex]::Escape($tl) + '(?:$|[/.\\_\-\s"''()\[\]:])')) {
                $out.Kind = "client"; $out.Evidence = $tl; return $out
            }
        }
    }
    return $out
}

function Read-LogText([string]$Path, [int]$MaxBytes = 4194304) {
    # latest.log is plain, the rotated ones are gzip. Both are read; a cheat that
    # ran last week is in logs/2026-08-21-1.log.gz and nowhere else.
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.Length -gt 64MB) { return $null }
        if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            $fs = [System.IO.File]::OpenRead($Path)
            try {
                $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
                try {
                    $ms = New-Object System.IO.MemoryStream
                    $buf = New-Object byte[] 65536
                    while ($ms.Length -lt $MaxBytes) {
                        $n = $gz.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                    }
                    return [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
                } finally { $gz.Dispose() }
            } finally { $fs.Dispose() }
        }
        if ($fi.Length -le $MaxBytes) { return [System.IO.File]::ReadAllText($Path) }
        # only the tail of a very large log - the newest lines are the ones that matter
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $fs.Seek(-$MaxBytes, [System.IO.SeekOrigin]::End) | Out-Null
            $buf = New-Object byte[] $MaxBytes
            $got = $fs.Read($buf, 0, $MaxBytes)
            return [System.Text.Encoding]::UTF8.GetString($buf, 0, $got)
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Run-LogScan {
    # Minecraft's own logs and crash reports, for every instance folder that was
    # scanned. This runs on every scan: it is cheap, and it is the only evidence
    # that survives deleting the jar.
    $res = @{
        Hits = [System.Collections.Generic.List[object]]::new()
        Files = 0; Lines = 0
        LoadedMods = [System.Collections.Generic.List[string]]::new()
    }
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($script:ScanTargetDirs)) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        try {
            $inst = [System.IO.Path]::GetDirectoryName($t.TrimEnd('\'))
            if ($inst) { [void]$roots.Add($inst) }
        } catch {}
    }
    $seenEvidence = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($root in $roots) {
        foreach ($sub in @('logs', 'crash-reports')) {
            $dir = [System.IO.Path]::Combine($root, $sub)
            if (-not [System.IO.Directory]::Exists($dir)) { continue }
            $files = @()
            try {
                $files = @([System.IO.Directory]::GetFiles($dir) |
                           Where-Object { $_ -match '\.(log|log\.gz|txt)$' } |
                           Sort-Object { [System.IO.File]::GetLastWriteTime($_) } -Descending |
                           Select-Object -First 25)
            } catch {}
            foreach ($lf in $files) {
                $txt = Read-LogText $lf
                if ($null -eq $txt) { continue }
                $res.Files++
                # "Loading 147 mods:" followed by "  - modid 1.2.3" - Fabric and
                # Forge both print it. Inside that block a name is definitionally
                # LOADED CODE: chat cannot appear there, and neither can a server
                # MOTD. That is a stronger context than any single line gives, and
                # the general line classifier throws these lines away because
                # "- doomsday 1.0" has no package dots, no .jar and no stack frame
                # to prove it is code. Read only from latest.log: one file, the
                # session that is actually being screenshared.
                if ([System.IO.Path]::GetFileName($lf) -ieq 'latest.log') {
                    $armed = $false
                    foreach ($mlLine in ($txt -split "`r?`n")) {
                        # Chat first, as everywhere else: a player can type
                        # "Loading 3 mods:" and must not arm the parser with it.
                        if ($mlLine -match $script:logChatLine) { continue }
                        if ($mlLine -match $script:logModListHeader) { $armed = $true; continue }
                        if (-not $armed) { continue }
                        $tail = ($mlLine -split '\]: ')[-1]
                        $mm = [regex]::Match($tail, $script:logModListItem)
                        if ($mm.Success) {
                            $mid = $mm.Groups[1].Value
                            if (-not $res.LoadedMods.Contains($mid)) { [void]$res.LoadedMods.Add($mid) }
                            $cn = Test-CheatName $mid
                            if ($cn) {
                                $key = "log-modlist|$cn"
                                if ($seenEvidence.Add($key)) {
                                    [void]$res.Hits.Add([PSCustomObject]@{
                                        Kind = "cheat"; Evidence = $cn
                                        File = $lf
                                        When = $(try { [System.IO.File]::GetLastWriteTime($lf).ToString('yyyy-MM-dd HH:mm') } catch { "?" })
                                        Line = "mod list: $($mlLine.Trim())"
                                    })
                                }
                            }
                        } elseif ($res.LoadedMods.Count -gt 0) { $armed = $false }
                    }
                }
                # One search over the whole file before any line is looked at
                # individually. A clean player's logs contain none of these names,
                # and Test-LogLine costs ~75 string operations per line - over 25
                # files that is minutes in PowerShell, which is not a scan anyone
                # can sit through at a screenshare.
                if (-not $script:logPreFilter.IsMatch($txt)) { continue }
                $when = try { [System.IO.File]::GetLastWriteTime($lf).ToString('yyyy-MM-dd HH:mm') } catch { "?" }
                foreach ($line in ($txt -split "`r?`n")) {
                    $res.Lines++
                    if (-not $script:logPreFilter.IsMatch($line)) { continue }
                    $v = Test-LogLine $line
                    if ($v.Kind -eq "") { continue }
                    $key = "$($v.Kind)|$($v.Evidence)"
                    if (-not $seenEvidence.Add($key)) { continue }
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -gt 200) { $trimmed = $trimmed.Substring(0, 197) + "..." }
                    [void]$res.Hits.Add([PSCustomObject]@{
                        Kind = $v.Kind; Evidence = $v.Evidence
                        File = $lf; When = $when; Line = $trimmed
                    })
                }
            }
        }
    }
    return $res
}

function Show-LogScan {
    $lg = Run-LogScan
    $script:LogHits = $lg.Hits.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) GAME LOGS AND CRASH REPORTS " + "$([char]0x2500)" * 42 + "$([char]0x2510)") DarkCyan
    $lLine = "  $([char]0x2502)  Read $($lg.Files) log file(s), $($lg.Lines) line(s)"
    W ($lLine + (" " * [Math]::Max(0, 75 - $lLine.Length)) + "$([char]0x2502)") DarkGray
    if ($lg.Files -eq 0) {
        W ("  $([char]0x2502)   $([char]0x2139) No logs folder found $([char]0x2014) nothing to read" + (" " * 32) + "$([char]0x2502)") DarkGray
        Add-ScanGap "No Minecraft logs folder was found, so the record of what the game LOADED $([char]0x2014) which survives deleting the jar $([char]0x2014) could not be read"
    } elseif ($lg.Hits.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) no cheat package or client name in any log" + (" " * 25) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($h in $lg.Hits) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FOUND IN LOG  $($h.Evidence)" Red
            W "  $([char]0x2502)    $($h.File)  (last written $($h.When))" DarkYellow
            W "  $([char]0x2502)    $($h.Line)" DarkGray
        }
    }
    W ("  $([char]0x2514)" + "$([char]0x2500)" * 73 + "$([char]0x2518)") DarkCyan
    Write-Host ""

    $script:SysArea = "Game logs"
    if ($lg.Hits.Count -gt 0) {
        Add-Finding "FAIL" "Game logs" "$($lg.Hits.Count) cheat name(s) in the game's own logs" `
            @($lg.Hits | ForEach-Object { "$($_.Evidence)  $([char]0x2014) $($_.File) ($($_.When)): $($_.Line)" }) `
            "Minecraft's logs and crash reports were read for cheat package paths and known client names, in code contexts only." `
            "This is the evidence that survives deleting the jar. A log line is dated: it says the cheat was LOADED, and when. Chat is excluded before anything is matched, so this cannot be someone typing a cheat name at another player." `
            "" "Keep the log file. It is the strongest thing in this report." | Out-Null
    } elseif ($lg.Files -gt 0) {
        Add-Finding "OK" "Game logs" "Game logs and crash reports $([char]0x2014) no cheat package or client name loaded" `
            @() `
            "$($lg.Files) log file(s) and crash report(s) were read, chat lines excluded." | Out-Null
    }
}

function Test-MacroFile([string]$Name, [string]$Text) {
    # Mirror of classify() in ml/macro.py; the tables live in $script:macroLangs and
    # the reasoning is written out there. Returns @{ Level = ""|"macro"|"cheat" }.
    $out = @{ Level = ""; Reasons = @() }
    if ($null -eq $Name -or $null -eq $Text) { return $out }
    $dot = $Name.LastIndexOf('.')
    if ($dot -lt 0) { return $out }
    $ext = $Name.Substring($dot).ToLower()
    if (-not $script:macroLangs.Contains($ext)) { return $out }
    $tbl = $script:macroLangs[$ext]
    $stem = ($Name.Substring(0, $dot).ToLower() -replace ' ', '')
    $named = ""
    foreach ($n in $script:macroCheatNames) { if ($stem.Contains($n)) { $named = $n; break } }

    # A driver script that never touches a mouse button is a lighting or key-remap
    # profile, and there are a great many of those.
    if ($ext -eq '.lua' -and -not ($Text -match $tbl['driver'])) { return $out }

    $clicks = $Text -match $tbl['click']
    $loops  = $Text -match $tbl['repeat']
    $mc     = $Text -match $tbl['mc']
    $human  = $Text -match $tbl['human']

    if (-not ($clicks -and $loops)) {
        # Named after the technique but with no click loop in it: worth a line, but
        # it could be a readme or a leftover config, so it is never the accusation.
        if ($named -ne "" -and $clicks) {
            $out.Level = "macro"
            $out.Reasons = @("named after '$named' and sends mouse input")
        }
        return $out
    }
    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($ext -eq '.lua') { [void]$reasons.Add("runs inside the mouse driver, below the game") }
    [void]$reasons.Add("repeats mouse input in a loop")
    if ($human) { [void]$reasons.Add("randomises its own delay $([char]0x2014) imitating a human hand") }
    if ($mc)    { [void]$reasons.Add("scoped to Minecraft (window, launcher or JVM named in the file)") }
    if ($named -ne "") { [void]$reasons.Add("file is named after the technique ('$named')") }
    $out.Level = if ($mc) { "cheat" } elseif ($named -ne "") { "named" } else { "macro" }
    $out.Reasons = @($reasons)
    return $out
}

function Expand-MacroPath([string]$P) {
    try { return [System.Environment]::ExpandEnvironmentVariables($P) } catch { return $P }
}

function Run-MacroScan {
    # The half of an autoclicker that is not a mod. Three places are looked at:
    # loose script files where people keep them, the script folders a mouse driver
    # runs code out of, and the driver's own profile store - the last only as
    # "a macro profile exists and was last changed on X", because those are binary.
    $res = @{
        Cheat = [System.Collections.Generic.List[object]]::new()
        Named = [System.Collections.Generic.List[object]]::new()
        Macro = [System.Collections.Generic.List[object]]::new()
        Profiles = [System.Collections.Generic.List[string]]::new()
        Scanned = 0
    }
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
        $env:TEMP
    )) {
        if ([string]::IsNullOrEmpty($base)) { continue }
        [void]$roots.Add($base)
        try {
            foreach ($sub in [System.IO.Directory]::GetDirectories($base)) {
                [void]$roots.Add($sub)
                try { foreach ($sub2 in [System.IO.Directory]::GetDirectories($sub)) { [void]$roots.Add($sub2) } } catch {}
            }
        } catch {}
    }
    # The driver script folders. A macro that runs in the mouse is the one people
    # assume a screenshare cannot see, and for the drivers that keep their scripts
    # as plain files, it can.
    foreach ($d in $script:macroDriverPaths) {
        $p = Expand-MacroPath $d[1]
        if ([System.IO.Directory]::Exists($p)) {
            [void]$roots.Add($p)
            try { foreach ($sub in [System.IO.Directory]::GetDirectories($p)) { [void]$roots.Add($sub) } } catch {}
            try {
                $di = [System.IO.DirectoryInfo]::new($p)
                [void]$res.Profiles.Add("$($d[0]): $p $([char]0x2014) $($d[2]), last changed $($di.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))")
            } catch {}
        } elseif ([System.IO.File]::Exists($p)) {
            try {
                $fi = [System.IO.FileInfo]::new($p)
                [void]$res.Profiles.Add("$($d[0]): $p $([char]0x2014) $($d[2]), $([math]::Round($fi.Length/1KB,1)) KB, last changed $($fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))")
            } catch {}
        }
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($root in $roots) {
        if (-not [System.IO.Directory]::Exists($root)) { continue }
        foreach ($ext in $script:macroExtList) {
            try {
                foreach ($mf in [System.IO.Directory]::EnumerateFiles($root, "*$ext", [System.IO.SearchOption]::TopDirectoryOnly)) {
                    if (-not $seen.Add($mf)) { continue }
                    $mn = [System.IO.Path]::GetFileName($mf)
                    Spin "Scanning macro: $mn"
                    $res.Scanned++
                    try {
                        $fi = [System.IO.FileInfo]::new($mf)
                        if ($fi.Length -gt 2MB) { continue }
                        $txt = [System.IO.File]::ReadAllText($mf)
                    } catch { continue }
                    $v = Test-MacroFile $mn $txt
                    if ($v.Level -eq "") { continue }
                    $rec = [PSCustomObject]@{
                        Path = $mf; Reasons = $v.Reasons
                        Meta = "size: $([math]::Round($fi.Length/1KB,1)) KB  modified: $($fi.LastWriteTime.ToString('yyyy-MM-dd'))"
                    }
                    if     ($v.Level -eq "cheat") { [void]$res.Cheat.Add($rec) }
                    elseif ($v.Level -eq "named") { [void]$res.Named.Add($rec) }
                    else                          { [void]$res.Macro.Add($rec) }
                }
            } catch {}
        }
    }
    SpinClear
    return $res
}

function Show-MacroScan {
    # Runs on EVERY scan, not only the deep one. An autoclicker is not in the mods
    # folder and it does not need the game to be open - closing Minecraft before the
    # screenshare used to hide it completely, which is the opposite of the point.
    $script:SysArea = "Macros & autoclickers"
    W "  Scanning for macro / autoclicker files..." DarkGray
    $macro = Run-MacroScan
    $script:MacroResult = $macro
    $script:Evidence.MacroCheat = $macro.Cheat.Count
    $script:Evidence.MacroNamed = $macro.Named.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) MACRO / AUTOCLICKER SCAN " + "$([char]0x2500)" * 45 + "$([char]0x2510)") DarkCyan
    $mScanLine = "  $([char]0x2502)  Scanned $($macro.Scanned) script file(s) $([char]0x2014) .ahk .ahk2 .au3 .lua .vbs"
    W ($mScanLine + (" " * [Math]::Max(0, 75 - $mScanLine.Length)) + "$([char]0x2502)") DarkGray
    if ($macro.Cheat.Count -eq 0 -and $macro.Named.Count -eq 0 -and $macro.Macro.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) no click macro found" + (" " * 48) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($f in $macro.Cheat) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
        foreach ($f in $macro.Named) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
        foreach ($f in $macro.Macro) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x2022) MACRO    $($f.Path)" Yellow
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkGray }
            W "  $([char]0x2502)    nothing in the file names Minecraft $([char]0x2014) not an accusation" DarkGray
        }
    }
    foreach ($pr in $macro.Profiles) { W "  $([char]0x2502)  $([char]0x2022) $pr" DarkGray }
    W ("  $([char]0x2514)" + "$([char]0x2500)" * 73 + "$([char]0x2518)") DarkCyan

    if ($macro.Cheat.Count -gt 0) {
        Add-Finding "FAIL" "Macros & autoclickers" "$($macro.Cheat.Count) click macro(s) aimed at Minecraft" `
            @($macro.Cheat | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Reasons) -join ", ")" }) `
            "AutoHotkey, AutoIt, mouse-driver Lua and VBScript files were read and checked for input sent in a loop." `
            "An autoclicker does not live in the mods folder. These repeat mouse input automatically AND name Minecraft, the launcher or the technique $([char]0x2014) there is no other reading of that." `
            "" "Note the paths and the modification dates before anything is deleted." | Out-Null
    }
    if ($macro.Named.Count -gt 0) {
        Add-Finding "FAIL" "Macros & autoclickers" "$($macro.Named.Count) click macro(s) named after a cheat technique" `
            @($macro.Named | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Reasons) -join ", ")" }) `
            "The same scan; these repeat mouse input in a loop and the file is named after the technique." `
            "Butterfly-click, blockhit, autocrystal and the rest are Minecraft terms. A file with that name containing a click loop IS an autoclicker; what the file does not prove is which game it was used in." | Out-Null
    }
    if ($macro.Macro.Count -gt 0) {
        Add-Finding "WARN" "Macros & autoclickers" "$($macro.Macro.Count) click macro(s) with no link to Minecraft in the file" `
            @($macro.Macro | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Reasons) -join ", ")" }) `
            "The same scan; these repeat mouse input in a loop but nothing in the file names the game or the technique." `
            "Reported because a click macro is worth a person seeing during a screenshare. It is NOT an accusation: a recoil script for a shooter has exactly this shape and is not a Minecraft cheat." | Out-Null
    }
    if ($macro.Profiles.Count -gt 0) {
        Add-Finding "INFO" "Macros & autoclickers" "$($macro.Profiles.Count) mouse/keyboard driver macro store(s) present" `
            @($macro.Profiles) `
            "The folders and profile databases where gaming mice and keyboards keep their macros were located." `
            "Owning this hardware is not suspicious $([char]0x2014) millions of people do. The dates are here so a macro profile changed just before the screenshare is visible." | Out-Null
    }
    if ($macro.Cheat.Count -eq 0 -and $macro.Named.Count -eq 0 -and $macro.Macro.Count -eq 0) {
        Add-Finding "OK" "Macros & autoclickers" "Macro and autoclicker files $([char]0x2014) nothing that repeats mouse input" | Out-Null
    }
    # The limit that can never be ruled out from the PC side, so it is stated on
    # every scan rather than only when something was found: a macro burned into a
    # mouse's ONBOARD memory runs on the device and leaves nothing here at all.
    Add-ScanGap "Macros stored in a mouse or keyboard's ONBOARD memory (Bloody, A4Tech, and the onboard profiles of Razer/Logitech devices) run on the device itself and leave nothing on the PC $([char]0x2014) they cannot be detected by any PC scan"
}

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

        # A LOCATION is not evidence. This used to be enough on its own, and
        # "runs from AppData\Roaming" is where Zoom, Slack, Signal, Telegram and
        # Obsidian live. Measured: with Zoom running, a scan of 25 mods that were
        # all verified and nothing else wrong came out Likely 60 - because the
        # count fed cheat_procs, which is a hard rule. Only a KNOWN cheat process
        # name is a finding now (handled above); everything else here is a note
        # that is shown and counts for nothing.
        if ($isSuspiciousName -or $isSuspiciousPath) {
            $why = if ($isSuspiciousName -and $isSuspiciousPath) { "unusual name, and $pathReason" }
                   elseif ($isSuspiciousName) { "unrecognised process-name pattern" }
                   else { $pathReason }
            $unknownProcs.Add([PSCustomObject]@{ Name = $name; PID = $proc.Id; Path = $path; Reason = $why })
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
    $devJarLimit = if ($script:_DevMode) { 10 } else { [int]::MaxValue }
    :jarCollect foreach ($root in $scanRoots) {
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
                    if (-not $skip -and $seenJars.Add($f)) {
                        $allJars.Add($f); $jarCollectCount++
                        if ($jarCollectCount -ge $devJarLimit) { break jarCollect }
                    }
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
        "autoclicker","autoclick","auto_clicker","clickspeed","cps_boost",
        "aimbot","aim_bot","aimassist","aim_assist","aimlock","smooth_aim",
        "triggerbot","trigger_bot","auto_trigger","triggerdelay",
        "cheatclient","cheat_client","ghosthack","ghost_hack","ghostclient",
        "autototem","auto_totem","autocrystal","auto_crystal","crystal_bot",
        "killaura","kill_aura","forcefield","force_field","multiaura",
        "antiknockback","anti_knockback","velocity_hack","novelocity","nofall",
        "wallhack","wall_hack","flyhack","fly_hack","freecam","noclip",
        "esp_hack","player_esp","entity_esp","chest_esp","item_esp",
        "bunnyhop","speed_hack","speedhack","speed_boost","fastmove",
        "xray","x_ray","xray_hack","ore_finder","block_esp","tracers",
        "critaura","crit_aura","reach_hack","reachhack","hitbox_expand",
        "scaffold","scaffoldwalk","scaffold_walk","tower_hack","towerhack",
        "dll_inject","dll_injector","process_inject","processinjector",
        "keyboard.hook","pynput","pywin32","win32api","SendInput",
        "GetAsyncKeyState","GetForegroundWindow","SetForegroundWindow",
        "pymem","ReadProcessMemory","WriteProcessMemory","ctypes.windll",
        "VirtualAllocEx","CreateRemoteThread","OpenProcess","kernel32",
        "bhop","bunny_hop","crystal_pvp","crystalpvp","surroundaura",
        "stealer","token_grab","discord_token","browser_token","cookie_steal",
        "password_grab","credential_steal","keylogger","keylog","screenshot",
        "webhook","requests.post","base64.b64decode","exec(base64","eval(base64",
        "subprocess.Popen","os.system","os.popen","os.startfile",
        "socket.connect","bind_shell","reverse_shell","connect_back",
        "mouse_event","keybd_event","SetWindowsHookEx","win32con",
        "screen_capture","ImageGrab","mss.mss","cv2.matchTemplate",
        "send_keys","pyautogui","pynput.mouse","pynput.keyboard",
        "minecraft","mineflayer","mc_client","mc_bot","mc_protocol",
        "entity_list","player_list","packet_intercept","packet_modify",
        "forge_inject","fabric_inject","optifine_bypass","liteloader",
        "obfuscate","marshal.loads","compile(","__import__('os')",
        "bypass_anticheat","watchdog_bypass","ncp_bypass","aac_bypass",
        "anchor_macro","anchormacro","anchor_bot","anchorbot","auto_anchor","autoanchor",
        "crystal_macro","crystalmacro","crystal_aura","crystalaura","anchor_aura","anchoraura",
        "macro_key","macroclient","macro_client","crystal_pvp"
    )
    $pyCheatKeywordsCritical = @(
        "ReadProcessMemory","WriteProcessMemory",
        "VirtualAllocEx","CreateRemoteThread","OpenProcess",
        "NtWriteVirtualMemory","NtAllocateVirtualMemory",
        "ZwWriteVirtualMemory","CreateRemoteThreadEx",
        "RtlCreateUserThread","shellcode","meterpreter",
        "reverse_shell","keyboard.hook","GetAsyncKeyState"
    )
    $pyCheatFileNames = @(
        "cheat","hack","inject","aimbot","killaura","autoclicker",
        "triggerbot","bhop","esp","xray","wallhack","stealer","grabber",
        "autocrystal","autototem","ghostclient","cheatclient",
        "token_grab","discord_grab","cookie_grab","password_grab",
        "keylogger","keylog","rat","trojan","payload","dropper",
        "bypass","exploit","loader","crypter","obfuscate",
        "autobot","macro","speedhack","speed_hack","noclip",
        "flyhack","fly_hack","freecam","anticheat_bypass",
        "reach_hack","hitbox_hack","scaffold_bot","crystal_bot",
        "pvpbot","pvp_bot","combat_bot","combatbot","aurabot",
        "tokenstealer","token_stealer","discordstealer","grabber",
        "anchormacro","anchor_macro","crystalmacro","crystal_macro",
        "macroclient","anchor_bot","anchorbot","crystal_aura","anchor_aura"
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
                try {
                    foreach ($sub2 in [System.IO.Directory]::GetDirectories($sub)) {
                        [void]$pyRoots.Add($sub2)
                    }
                } catch {}
            }
        } catch {}
    }
    $pyScanned = 0
    $script:PCScannedPyNames = [System.Collections.Generic.List[string]]::new()
    $pyAllNamesSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pySeenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pyDevLimit = if ($script:_DevMode) { 10 } else { [int]::MaxValue }
    $pyDevCount = 0
    :pyDrvLoop foreach ($drv in ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
        try {
            foreach ($pf in [System.IO.Directory]::EnumerateFiles($drv.RootDirectory.FullName, '*.py',  [System.IO.SearchOption]::AllDirectories)) {
                $pfn = [System.IO.Path]::GetFileName($pf)
                if ($pyAllNamesSeen.Add($pfn)) { [void]$script:PCScannedPyNames.Add($pfn); $pyDevCount++ }
                Spin "Scanning .py: $pfn"
                if ($pyDevCount -ge $pyDevLimit) { break pyDrvLoop }
            }
            foreach ($pf in [System.IO.Directory]::EnumerateFiles($drv.RootDirectory.FullName, '*.pyw', [System.IO.SearchOption]::AllDirectories)) {
                $pfn = [System.IO.Path]::GetFileName($pf)
                if ($pyAllNamesSeen.Add($pfn)) { [void]$script:PCScannedPyNames.Add($pfn); $pyDevCount++ }
                Spin "Scanning .pyw: $pfn"
                if ($pyDevCount -ge $pyDevLimit) { break pyDrvLoop }
            }
        } catch {}
    }
    SpinClear
    foreach ($pyRoot in $pyRoots) {
        if (-not [System.IO.Directory]::Exists($pyRoot)) { continue }
        try {
            $pyFiles = [System.Collections.Generic.List[string]]::new()
            foreach ($pf in [System.IO.Directory]::EnumerateFiles($pyRoot, '*.py',  [System.IO.SearchOption]::TopDirectoryOnly)) { [void]$pyFiles.Add($pf) }
            foreach ($pf in [System.IO.Directory]::EnumerateFiles($pyRoot, '*.pyw', [System.IO.SearchOption]::TopDirectoryOnly)) { [void]$pyFiles.Add($pf) }
            foreach ($pyFile in $pyFiles) {
                if (-not $pySeenPaths.Add($pyFile)) { continue }
                $pyName     = [System.IO.Path]::GetFileName($pyFile)
                $pyNameStem = [System.IO.Path]::GetFileNameWithoutExtension($pyFile).ToLower()
                $pyScanned++
                Spin "Scanning $(([System.IO.Path]::GetExtension($pyFile))): $pyName"
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
    W "  Scanning for obfuscated files..." DarkGray
    $obfFlags = [System.Collections.Generic.List[object]]::new()
    $obfRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        $env:TEMP
    )) {
        [void]$obfRoots.Add($base)
        try {
            foreach ($sub in [System.IO.Directory]::GetDirectories($base)) {
                [void]$obfRoots.Add($sub)
                try {
                    foreach ($sub2 in [System.IO.Directory]::GetDirectories($sub)) {
                        [void]$obfRoots.Add($sub2)
                    }
                } catch {}
            }
        } catch {}
    }
    $obfSeenPaths  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $obfScanTotal  = 0
    $obfDevLimit   = if ($script:_DevMode) { 10 } else { [int]::MaxValue }
    $pyObfPatterns = @(
        "exec(base64","eval(base64","exec(compile","eval(compile",
        "exec(__import__","marshal.loads","__import__('marshal')",
        "zlib.decompress","lzma.decompress","bz2.decompress",
        "base64.b64decode","base64.urlsafe_b64decode",
        "bytes.fromhex","bytearray.fromhex",
        "compile(base64","compile(zlib","compile(bytes",
        "lambda _","lambda __","lambda ___",
        "globals()['__builtins__']","__builtins__.__dict__",
        "getattr(__builtins__","getattr(globals",
        "chr("+[char]0x29,"chr(0x","''.join(chr","map(chr",
        "uu.decode","codecs.decode","rot_13","rot13",
        "pyc\x00\x00\x00","import sys; sys.exit","PyInstaller"
    )
    foreach ($obfRoot in $obfRoots) {
        if (-not [System.IO.Directory]::Exists($obfRoot)) { continue }
        try {
            $obfFiles = [System.Collections.Generic.List[string]]::new()
            foreach ($f in [System.IO.Directory]::EnumerateFiles($obfRoot, '*.jar', [System.IO.SearchOption]::TopDirectoryOnly)) { [void]$obfFiles.Add($f) }
            foreach ($f in [System.IO.Directory]::EnumerateFiles($obfRoot, '*.py',  [System.IO.SearchOption]::TopDirectoryOnly)) { [void]$obfFiles.Add($f) }
            foreach ($f in [System.IO.Directory]::EnumerateFiles($obfRoot, '*.pyw', [System.IO.SearchOption]::TopDirectoryOnly)) { [void]$obfFiles.Add($f) }
            foreach ($obfFile in $obfFiles) {
                if (-not $obfSeenPaths.Add($obfFile)) { continue }
                if ($obfScanTotal -ge $obfDevLimit) { break }
                $obfScanTotal++
                $ext = [System.IO.Path]::GetExtension($obfFile).ToLower()
                Spin "Obf-scan: $([System.IO.Path]::GetFileName($obfFile))"
                $reasons = [System.Collections.Generic.List[string]]::new()
                if ($ext -eq ".jar") {
                    try {
                        $oFlags = Invoke-ObfuscationScan -FilePath $obfFile
                        foreach ($of in $oFlags) { [void]$reasons.Add("[OBFUSCATION] $of") }
                    } catch {}
                } elseif ($ext -eq ".py" -or $ext -eq ".pyw") {
                    try {
                        $src = [System.IO.File]::ReadAllText($obfFile)
                        $srcL = $src.ToLower()
                        $hits = [System.Collections.Generic.List[string]]::new()
                        foreach ($pat in $pyObfPatterns) {
                            if ($src.Contains($pat) -or $srcL.Contains($pat.ToLower())) { [void]$hits.Add($pat) }
                        }
                        $longBase64 = [regex]::Matches($src, "[A-Za-z0-9+/]{200,}={0,2}")
                        if ($longBase64.Count -gt 0) { [void]$hits.Add("long base64 blob ($($longBase64.Count) occurrence(s))") }
                        $hexBlobs = [regex]::Matches($src, "\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){19,}")
                        if ($hexBlobs.Count -gt 0) { [void]$hits.Add("hex-encoded blob ($($hexBlobs.Count) occurrence(s))") }
                        $chrCalls = [regex]::Matches($src, "chr\(\d+\)")
                        if ($chrCalls.Count -ge 10) { [void]$hits.Add("chr() obfuscation ($($chrCalls.Count) calls)") }
                        if ($hits.Count -gt 0) {
                            $reasons.Add("[OBFUSCATION] $( ($hits | Select-Object -First 5) -join ' | ' )")
                        }
                    } catch {}
                }
                if ($reasons.Count -gt 0) {
                    $fi = try { [System.IO.FileInfo]::new($obfFile) } catch { $null }
                    $meta = if ($fi) { "size: $([math]::Round($fi.Length/1KB,1)) KB  modified: $($fi.LastWriteTime.ToString('yyyy-MM-dd'))" } else { "" }
                    [void]$obfFlags.Add([PSCustomObject]@{ Path = $obfFile; Reasons = $reasons; Meta = $meta })
                }
            }
        } catch {}
    }
    SpinClear
    $pcIssues += $obfFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) OBFUSCATED FILE SCAN " + "$([char]0x2500)" * 49 + "$([char]0x2510)") DarkCyan
    if ($obfFlags.Count -eq 0) {
        W "  $([char]0x2502)   OK $([char]0x2014) no obfuscated files detected                              $([char]0x2502)" DarkCyan
    } else {
        foreach ($f in $obfFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
        Write-Host ""
        W "  $([char]0x2502)  $($obfFlags.Count) obfuscated file(s) detected $([char]0x2014) review immediately" Red
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
        "speedhack","flyhack","wallhack","xrayhack","reachhack",
        "anchormacro","crystalmacro","autoanchor","macroclient","anchoraura"
    )
    $exeCheatStrings = @(
        "autoclicker","killaura","aimbot","triggerbot","cheat client","ghost client",
        "dll inject","process inject","ReadProcessMemory","WriteProcessMemory",
        "VirtualAllocEx","CreateRemoteThread",
        "discord token","webhook url","grab passwords","steal cookies",
        "autocrystal","auto crystal","auto totem","crystal pvp",
        "minhook","easyhook","detours","polyhook","subhook",
        "xenos injector","extreme injector","process hacker",
        "anchor macro","crystal macro","auto anchor","macro key","anchor bot"
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
    $exeGuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$'
    $exeNameWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($w in @("tinytask","obs64","obs32","streamlabs","discord","chrome","firefox","edge","steam","epicgameslauncher","gog galaxy","playnite","geforce","nvidiacontrolpanel","amdradeon","logitech","corsair","razer")) { [void]$exeNameWhitelist.Add($w) }
    $exeFlags   = [System.Collections.Generic.List[object]]::new()
    $exeScanned = 0
    $exeSeenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:PCScannedExeNames = [System.Collections.Generic.List[string]]::new()
    $exeAllNamesSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $exeDevLimit = if ($script:_DevMode) { 10 } else { [int]::MaxValue }
    $exeDevCount = 0
    :exeDrvLoop foreach ($drv in ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
        try {
            foreach ($ef in [System.IO.Directory]::EnumerateFiles($drv.RootDirectory.FullName, '*.exe', [System.IO.SearchOption]::AllDirectories)) {
                $efn = [System.IO.Path]::GetFileName($ef)
                if ($exeAllNamesSeen.Add($efn)) { [void]$script:PCScannedExeNames.Add($efn); $exeDevCount++ }
                Spin "Scanning EXE: $efn"
                if ($exeDevCount -ge $exeDevLimit) { break exeDrvLoop }
            }
        } catch {}
    }
    SpinClear
    foreach ($exeRoot in $exeSuspiciousDirs) {
        if (-not [System.IO.Directory]::Exists($exeRoot)) { continue }
        try {
            foreach ($exeFile in [System.IO.Directory]::EnumerateFiles($exeRoot, '*.exe', [System.IO.SearchOption]::TopDirectoryOnly)) {
                if (-not $exeSeenPaths.Add($exeFile)) { continue }
                $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exeFile).ToLower()
                $exeScanned++
                Spin "Scanning EXE: $([System.IO.Path]::GetFileName($exeFile))"
                if ($exeName -match $exeInstallerPattern) { continue }
                if ($exeNameWhitelist.Contains($exeName)) { continue }
                $exeBaseName = [System.IO.Path]::GetFileName($exeFile)
                if ($exeBaseName -match $exeGuidPattern) { continue }
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
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) EXE SCAN " + "$([char]0x2500)" * 61 + "$([char]0x2510)") DarkCyan
    if ($exeFlags.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) no suspicious EXE files found" + (" " * 36) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($f in $exeFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  $($f.Path)" Red
            foreach ($r in $f.Reasons) { W "  $([char]0x2502)    $r" DarkYellow }
            if ($f.Meta) { W "  $([char]0x2502)    $($f.Meta)" DarkGray }
        }
    }
    W ("  $([char]0x2514)" + "$([char]0x2500)" * 73 + "$([char]0x2518)") DarkCyan

    Write-Host ""
    W "  Scanning loaded DLLs in javaw.exe for injection indicators..." DarkGray
    # This check used to search the whole DLL path for substrings, two of which
    # were "hook" and "esp". Measured against nine real, common DLLs it flagged
    # six: OBS's graphics-hook64.dll (which OBS injects into every game it
    # records, so the person most likely to trip it was the one recording the
    # screenshare), RivaTuner's RTSSHooks64.dll (the FPS counter), Overwolf,
    # an NVIDIA component, and a game with "esp" in its name.
    #
    # What actually separates those from an injector: they are signed by their
    # vendor. So a FINDING now needs both - unsigned AND a name the same
    # boundary-anchored client matcher recognises. That is deliberately strict
    # and misses an injector with a dull name; an unsigned DLL out of a
    # user-writable folder is still shown, as a note that counts for nothing.
    $dllFlags = [System.Collections.Generic.List[object]]::new()
    $dllNotes = [System.Collections.Generic.List[object]]::new()
    $dllScanned = 0
    $javaProcs = Get-Process -Name @("javaw","java") -ErrorAction SilentlyContinue
    foreach ($jp in $javaProcs) {
        try {
            $modules = $jp.Modules | Select-Object -ExpandProperty FileName -ErrorAction SilentlyContinue
            foreach ($dll in $modules) {
                $dllScanned++
                $dllShort = [System.IO.Path]::GetFileName($dll)
                Write-Host "`r  Scanning DLL: $($dllShort.Substring(0,[Math]::Min($dllShort.Length,38)).PadRight(38))  checked: $dllScanned  flagged: $($dllFlags.Count)" -NoNewline -ForegroundColor DarkGray
                # Only DLLs out of a folder the user can write to get their
                # signature checked. Everything under System32 or Program Files
                # is a product, and Get-AuthenticodeSignature over a hundred
                # system modules is time the scan does not need to spend.
                if (-not (Test-UserWritablePath $dll)) { continue }
                $signed = $false
                try { $signed = ((Get-AuthenticodeSignature -LiteralPath $dll -ErrorAction Stop).Status -eq 'Valid') } catch {}
                if ($signed) { continue }
                # The LEAF only. Run over the whole path, a Windows user called
                # "sigma" would have had every unsigned DLL on their PC flagged,
                # because C:\Users\sigma\ matches on separator boundaries.
                $hit = Test-CheatName ([System.IO.Path]::GetFileName($dll))
                if ($hit) {
                    $dllFlags.Add([PSCustomObject]@{ PID = $jp.Id; Process = $jp.Name; DLL = $dll; Why = "unsigned, and named after a known cheat client ($hit)" })
                } else {
                    $dllNotes.Add([PSCustomObject]@{ PID = $jp.Id; Process = $jp.Name; DLL = $dll; Why = "unsigned, loaded from a folder the user can write to" })
                }
            }
        } catch {}
    }
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    $pcIssues += $dllFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) INJECTABLE DLL SCAN (javaw) " + "$([char]0x2500)" * 42 + "$([char]0x2510)") DarkCyan
    $dllScannedLine = "  $([char]0x2502)  Scanned $dllScanned module(s) in Java process"
    W ($dllScannedLine + (" " * [Math]::Max(0, 75 - $dllScannedLine.Length)) + "$([char]0x2502)") DarkGray
    if ($dllFlags.Count -eq 0 -and $dllNotes.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) every module in the game process is signed or from a system folder" + (" " * 3) + "$([char]0x2502)") DarkCyan
    }
    foreach ($f in $dllFlags) {
        Write-Host ""
        W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  PID $($f.PID) ($($f.Process))" Red
        W "  $([char]0x2502)    DLL    : $($f.DLL)" DarkYellow
        W "  $([char]0x2502)    Why    : $($f.Why)" DarkGray
    }
    foreach ($f in $dllNotes) {
        Write-Host ""
        W "  $([char]0x2502)  $([char]0x2139) worth a look  PID $($f.PID) ($($f.Process))" DarkYellow
        W "  $([char]0x2502)    DLL    : $($f.DLL)" DarkGray
        W "  $([char]0x2502)    Why    : $($f.Why) $([char]0x2014) not counted, plenty of small legitimate tools are unsigned" DarkGray
    }
    W ("  $([char]0x2514)" + "$([char]0x2500)" * 73 + "$([char]0x2518)") DarkCyan

    Write-Host ""
    W ("$([char]0x2501)" * 76) Blue
    Write-Host ""
    W "  PC SCAN SUMMARY" Cyan
    Write-Host ""
    W "  Flagged processes   : " DarkGray -NoNewline; W "$($flaggedProcs.Count)" $(if($flaggedProcs.Count -gt 0){"Red"}else{"Green"})
    W "  Unknown processes   : " DarkGray -NoNewline; W "$($unknownProcs.Count)" $(if($unknownProcs.Count -gt 0){"Yellow"}else{"Green"})
    $script:Evidence.CheatProcs   = $flaggedProcs.Count
    $script:Evidence.CheatFolders = $foundFolders.Count
    $script:Evidence.StrayJars    = $fsFlags.Count

    # Same numbers as the summary above, but recorded with the actual names behind
    # them - a count on its own proves nothing to the staff member reading this.
    $script:SysArea = "Rest of the PC"
    if ($flaggedProcs.Count -gt 0) {
        Add-Finding "FAIL" "Rest of the PC" "$($flaggedProcs.Count) running process(es) match a known cheat" `
            @($flaggedProcs | ForEach-Object { "$($_.Name) (PID $($_.PID))  $($_.Path)  $([char]0x2014) $($_.Reason)" }) `
            "Every running process was compared against the known cheat-client and injector names." `
            "A cheat client does not have to sit in the mods folder - plenty run as their own program next to the game." `
            "" "Note the PIDs before anything is closed." | Out-Null
    }
    if ($foundFolders.Count -gt 0) {
        Add-Finding "FAIL" "Rest of the PC" "$($foundFolders.Count) known cheat folder(s) on disk" @($foundFolders) `
            "Folder names across the user profile were matched against known cheat-client install paths." `
            "An install folder stays behind even when the jar itself was deleted before the screenshare." | Out-Null
    }
    if ($fsFlags.Count -gt 0) {
        Add-Finding "FAIL" "Rest of the PC" "$($fsFlags.Count) suspicious .jar file(s) outside the mods folder" `
            @($fsFlags | ForEach-Object { "$($_.Path)  $([char]0x2014) $($_.Hits)" }) `
            "Jars outside the scanned mods folders were checked with the same rules as the mods themselves." `
            "Moving a cheat jar out of the mods folder before a screenshare is the most common hiding place." | Out-Null
    }
    if ($pyFlags.Count -gt 0) {
        Add-Finding "WARN" "Rest of the PC" "$($pyFlags.Count) suspicious .py script(s)" `
            @($pyFlags | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Reasons) -join ", ")" }) `
            "Python scripts were scanned for autoclicker, macro and packet-sending code." `
            "Not every macro is a cheat - a script that moves the mouse for you on a server that bans it, is." | Out-Null
    }
    if ($exeFlags.Count -gt 0) {
        Add-Finding "WARN" "Rest of the PC" "$($exeFlags.Count) suspicious .exe file(s)" `
            @($exeFlags | ForEach-Object { "$($_.Path)  $([char]0x2014) $(@($_.Reasons) -join ", ")" }) `
            "Executables in the usual download and game folders were matched against known injector and cheat-loader names." | Out-Null
    }
    if ($dllNotes.Count -gt 0) {
        # Shown, never counted: plenty of small legitimate tools are unsigned.
        $script:SysArea = "Rest of the PC"
        Write-SystemFlag "STATE" "$($dllNotes.Count) unsigned module(s) loaded into the game from a user-writable folder" `
            @($dllNotes | ForEach-Object { "$($_.DLL)  (PID $($_.PID))" })
        Write-Detail "Every module loaded inside the running javaw/java process was listed, and the ones outside system folders had their digital signature checked." `
            "Unsigned is not the same as malicious - small tools, older software and anything home-built are unsigned too - so this is not counted against anyone." `
            "It is here because an injector is almost never signed, and this is the shortest list a moderator can eyeball." `
            "Look at what each file is before drawing any conclusion."
    }
    if ($dllFlags.Count -gt 0) {
        Add-Finding "FAIL" "Rest of the PC" "$($dllFlags.Count) suspicious DLL(s) loaded inside the Java process" `
            @($dllFlags | ForEach-Object { "PID $($_.PID) ($($_.Process))  $($_.DLL)" }) `
            "The module list of the running Java process was read and compared against known injector DLLs." `
            "A DLL loaded into javaw.exe is running inside the game with full access to it." | Out-Null
    }
    if ($startupFlags.Count -gt 0) {
        Add-Finding "WARN" "Rest of the PC" "$($startupFlags.Count) suspicious autostart entr(y/ies)" `
            @($startupFlags | ForEach-Object { "$($_.Key) $([char]0x2192) $($_.Name) = $($_.Value)" }) `
            "Autostart locations were read to see what launches itself at login." `
            "Cheat loaders use autostart so they are running again before the game is." | Out-Null
    }
    # The limit that can never be ruled out from the PC side, so it is stated on
    # every scan rather than only when something was found: a macro burned into a
    # mouse's ONBOARD memory runs on the device and leaves nothing here at all.
    if ($flaggedProcs.Count -eq 0 -and $foundFolders.Count -eq 0 -and $fsFlags.Count -eq 0 -and
        $pyFlags.Count -eq 0 -and $exeFlags.Count -eq 0 -and $dllFlags.Count -eq 0 -and $startupFlags.Count -eq 0) {
        Add-Finding "OK" "Rest of the PC" "Processes, folders, stray jars, scripts, executables, loaded DLLs and autostart $([char]0x2014) nothing cheat-like" | Out-Null
    }
    W "  Startup flags       : " DarkGray -NoNewline; W "$($startupFlags.Count)" $(if($startupFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Cheat folders found : " DarkGray -NoNewline; W "$($foundFolders.Count)" $(if($foundFolders.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged JARs        : " DarkGray -NoNewline; W "$($fsFlags.Count)" $(if($fsFlags.Count -gt 0){"Red"}else{"Green"})
    W "  Flagged .py scripts : " DarkGray -NoNewline; W "$($pyFlags.Count)" $(if($pyFlags.Count -gt 0){"Red"}else{"Green"})
    $macroHard = 0
    if ($null -ne $script:MacroResult) { $macroHard = $script:MacroResult.Cheat.Count + $script:MacroResult.Named.Count }
    W "  Click macros        : " DarkGray -NoNewline; W "$macroHard" $(if($macroHard -gt 0){"Red"}else{"Green"})
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
if ($SelfTest) { Invoke-SelfTest; return }
if ($HashOnly) { Invoke-HashOnly $HashOnly; return }

if (Invoke-SelfElevate) { return }   # an elevated window took over; nothing left to do here
[void](Set-AutoDepth)
if (-not (Test-IsAdmin)) {
    Add-ScanGap "Ran without Administrator $([char]0x2014) deleted-program history (BAM), Defender exclusions and scheduled tasks were NOT checked"
}

W "  Scan ID: " DarkGray -NoNewline; W "$($script:ScanId)" Cyan -NoNewline
if ($script:ScanCode) {
    W "    Code from staff: " DarkGray -NoNewline; W "$($script:ScanCode)" Yellow
} else {
    W "    (no staff code given $([char]0x2014) run with -Code <word> so this report can be dated)" DarkGray
}
Write-Host ""
W "  What this tool does $([char]0x2014) and does not do:" Cyan
W "    $([char]0x2713) Read-only. It never changes, deletes, or quarantines your files." Green
W "    $([char]0x2713) Runs fully on your PC. It never uploads your files or your data." Green
W "    $([char]0x2713) Network use is limited to looking mods up by hash on Modrinth /" DarkGray
W "      CurseForge / Megabase $([char]0x2014) only the file hash is sent, never the file." DarkGray
W "    $([char]0x2713) The cheat verdict is scored by a local AI model (no cloud, no key)." Green
W "    $([char]0x2713) Verified mods are never flagged. Flags come with a reason + score." Green
W "    $([char]0x2139) Inside Minecraft it reads: the mods folder, the game's own logs and" DarkGray
W "      crash reports, the launcher profiles under versions/, and resource and" DarkGray
W "      shader packs. Nothing outside Minecraft except the folders below." DarkGray
W "    $([char]0x2139) A deep, whole-PC scan (processes, stray jars, autostart) is separate" DarkGray
W "      and turns itself on when Minecraft is running or something turns up." DarkGray
W "    $([char]0x2139) Every scan also reads macro scripts (.ahk .ahk2 .au3 .lua .vbs) in" DarkGray
W "      Downloads, Desktop, Documents, Temp and your mouse driver's script folder," DarkGray
W "      because an autoclicker is never in the mods folder and does not need the" DarkGray
W "      game to be open. Read-only, like everything else here." DarkGray
W "    $([char]0x2139) It also reads what Windows remembers about files that are GONE:" DarkGray
W "      the Recycle Bin's own records (original path and deletion time), the" DarkGray
W "      list of programs you started by double-clicking them, and with" DarkGray
W "      Administrator the NTFS change journal and the compatibility cache." DarkGray
W "      Those are the only places a jar deleted before a screenshare still" DarkGray
W "      exists. All read-only: nothing is mounted, copied or restored." DarkGray
if ($script:MemoryAuto) {
    W "    $([char]0x2139) Minecraft is running $([char]0x2014) the live-memory check is ON automatically." Yellow
    W "      That is the only way to catch a ghost client injected into the game." DarkGray
    W "      It only READS the game's memory. Nothing is changed, nothing uploaded." DarkGray
} elseif ($script:DeepMemory) {
    W "    $([char]0x2139) Live-memory check is ON (-DeepMemory) $([char]0x2014) read-only, changes nothing." DarkGray
} else {
    W "    $([char]0x2139) Minecraft is not running, so there is no live game memory to check." DarkGray
}
W "    $([char]0x2713) Self-improving: it learns from every scan (all local) and auto-updates" Green
W "      its model from GitHub, so detection keeps getting better over time." Green
Write-Host ""
W ("$([char]0x2501)" * 76) DarkCyan
Write-Host ""

Load-LearnState
# Self-hosters / testing: point the tool at your own backend without publishing the key.
if ($env:ASYNCANALYZER_ENDPOINT) {
    $script:Telemetry = @{ enabled = $true; endpoint = $env:ASYNCANALYZER_ENDPOINT; key = $env:ASYNCANALYZER_KEY; pullSignatures = $true }
}
Invoke-CloudUpdate
if ($script:mlSamples -gt 0 -or $script:knownGoodHashes.Count -gt 0 -or $script:knownCheatHashes.Count -gt 0) {
    W "  $([char]0x25CF) AI memory: " DarkGray -NoNewline
    W "$($script:knownGoodHashes.Count)" Green -NoNewline; W " known-good  " DarkGray -NoNewline
    W "$($script:knownCheatHashes.Count)" Red -NoNewline; W " known-cheat  " DarkGray -NoNewline
    W "$($script:mlSamples)" Cyan -NoNewline; W " examples learned (model v$($script:mlModelVersion))" DarkGray
    Write-Host ""
}

if ($script:Telemetry -and $script:Telemetry.enabled -and $script:Telemetry.endpoint) {
    W "  $([char]0x25CF) NOTICE $([char]0x2014) team mode is ON: this scan's result (mod list, hashes, verdict," Yellow
    W "    your Windows & Minecraft name, PC name) will be uploaded to the AsyncStudios team" DarkGray
    W "    dashboard so staff can review it. Your personal files are NOT uploaded." DarkGray
    Write-Host ""
}

if ($Dev) {
    W "  [DEV MODE] Quick scan $([char]0x2014) max 10 items per category, heavy checks skipped." DarkYellow
    Write-Host ""
    $ModPath = if ([string]::IsNullOrWhiteSpace($DevPath)) { "$env:APPDATA\.minecraft\mods" } else { $DevPath.Trim('"').Trim("'").Trim() }
    if (-not (Test-Path $ModPath -PathType Container)) {
        W "  $([char]0x2717) Dev path does not exist: $ModPath" Red
        Write-Host ""
        return
    }
    W "  Target : " DarkGray -NoNewline; W $ModPath White
    Write-Host ""
    $SkipSystemCheck  = $true
    $SkipServiceCheck = $true
    $SkipMemoryCheck  = $true
    $SkipModCheck     = $false
    $script:_DevMode  = $true
    $script:_DevLimit = 10
} else {
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $script:ScanTargets = @($Path) }
    elseif ($script:Ask) { $script:ScanTargets = @(Ask-ModPath) }
    else { $script:ScanTargets = @(Get-ScanTargets) }
    $script:ScanTargets = @($script:ScanTargets | ForEach-Object { ([string]$_).Trim('"').Trim("'").Trim() } | Where-Object { $_ })
    $ModPath = if ($script:ScanTargets.Count -gt 0) { $script:ScanTargets[0] } else { "" }

    if (-not (Test-Path $ModPath -PathType Container)) {
        W "" White
        W "  $([char]0x2717) Invalid path $([char]0x2014) directory does not exist:" Red
        W "    $ModPath" DarkGray
        W "" White
        return
    }

    Write-Host ""
    if ($script:ScanTargets.Count -eq 1) {
        W "  Target : " DarkGray -NoNewline; W $ModPath White
    } else {
        W "  Targets: " DarkGray -NoNewline; W "$($script:ScanTargets.Count) folders" White
        foreach ($t in $script:ScanTargets) { W "           $t" DarkGray }
    }
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

    $SkipSystemCheck  = $false
    $SkipServiceCheck = $false
    $SkipMemoryCheck  = $false
    $script:_DevMode  = $false
}

if ($null -eq $SkipSystemCheck)  { $SkipSystemCheck  = $false }
if ($null -eq $SkipServiceCheck) { $SkipServiceCheck = $false }
if ($null -eq $SkipModCheck)     { $SkipModCheck     = $false }
if ($null -eq $SkipMemoryCheck)  { $SkipMemoryCheck  = $false }

if (-not $SkipSystemCheck)  { Run-SystemChecks }
if (-not $SkipServiceCheck) { Run-ServiceCheck }

if (-not $SkipModCheck) {
    # Every target, not just the first: the whole point is that a second open
    # instance cannot hide. Everything downstream works per jar and records
    # FilePath, so nothing else in the loop has to change.
    $jarFiles = @()
    foreach ($t in $script:ScanTargets) {
        if (-not (Test-Path $t -PathType Container)) {
            Add-ScanGap "Folder could not be read: $t"
            continue
        }
        $jarFiles += @(Get-ChildItem -Path $t -Filter "*.jar" -ErrorAction SilentlyContinue)
        $jarFiles += @(Get-ChildItem -Path $t -Filter "*.litemod" -ErrorAction SilentlyContinue)
    }
    $jarFiles = @($jarFiles)
    if ($script:_DevLimit) { $jarFiles = @($jarFiles | Select-Object -First $script:_DevLimit) }
    $script:TotalMods = @($jarFiles).Count

    $exeFiles = @()
    $pyFiles  = @()
    if ($script:_DevMode) {
        $exeFiles = @(Get-ChildItem -Path $ModPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10)
        $pyFiles  = @(Get-ChildItem -Path $ModPath -Filter "*.py"  -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10)
    }

    if ($script:TotalMods -eq 0) {
        Write-Host ""
        W "  $([char]0x26A0)  No JAR files found in: $ModPath" Yellow
    } else {
        Write-Host ""
        W "  $([char]0x25CF) Found $($script:TotalMods) JAR file(s) to analyze" Cyan
        Write-Host ""

        $verifiedMods   = [System.Collections.Generic.List[object]]::new()
        $unknownMods    = [System.Collections.Generic.List[object]]::new()

        $reviewMods  = [System.Collections.Generic.List[object]]::new()
        $flaggedMods = [System.Collections.Generic.List[object]]::new()

        $idx = 0
        W "  Analyzing mods $([char]0x2014) verify hash, extract features, AI score..." DarkGray
        foreach ($jar in $jarFiles) {
            $idx++
            Spin "[$idx/$($script:TotalMods)] $($jar.Name)"
            Invoke-JarAnalysis $jar
        }
        SpinClear

        if ($script:Flagged -gt 0) {
            Request-DeepEscalation "a mod was flagged, so the rest of the system is worth a closer look"
        } elseif ($reviewMods.Count -gt 0 -or $script:Evidence.HardConfirmed -gt 0 -or $script:Evidence.RandomNamed -gt 0) {
            Request-DeepEscalation "something here could not be accounted for"
        }

        $script:Verified = $verifiedMods.Count
        $script:Unknown  = $unknownMods.Count
        $script:Review   = $reviewMods.Count

        if ($verifiedMods.Count -gt 0) {
            Write-SectionHeader "VERIFIED MODS" $verifiedMods.Count Green Green
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            $vw = 70
            foreach ($mod in $verifiedMods) {
                $nameLine  = "$([char]0x2022) $($mod.ModName)"
                $fileLine  = "  $([char]0x2192) $($mod.FileName)"
                $sep = "$([char]0x2550)" * ($vw + 1)
                W ("  $([char]0x2554)$sep$([char]0x2557)") Green
                W ("  $([char]0x2551)  " + $nameLine.PadRight($vw - 1) + "$([char]0x2551)") Green
                W ("  $([char]0x2551)  " + $fileLine.PadRight($vw - 1) + "$([char]0x2551)") DarkGray
                if ($mod.ModUrl) {
                    $urlTxt = "[URL] $($mod.ModUrl)"
                    W ("  $([char]0x2551)  " + $urlTxt.PadRight($vw - 1) + "$([char]0x2551)") Cyan
                }
                W ("  $([char]0x255A)$sep$([char]0x255D)") Green
                Write-Host ""
            }
        }

        if ($unknownMods.Count -gt 0) {
            Write-SectionHeader "UNKNOWN MODS" $unknownMods.Count Yellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in $unknownMods) {
                $fname = if ($mod.FileName.Length -gt 50) { $mod.FileName.Substring(0,47) + "..." } else { $mod.FileName }
                $src = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: unknown" }
                $padT = "$([char]0x2500)" * [Math]::Max(0, 65 - $fname.Length)
                W ("  $([char]0x2554)$([char]0x2550) ? " + $fname + " " + $padT + "$([char]0x2557)") Yellow
                if ($mod.DownloadUrl) {
                    $uDisp = if ($mod.DownloadUrl.Length -gt 63) { $mod.DownloadUrl.Substring(0,60) + "..." } else { $mod.DownloadUrl }
                    $uLabel = "[URL] $uDisp"
                    $padU = "$([char]0x2500)" * [Math]::Max(0, 67 - $uLabel.Length)
                    $Host.UI.Write("Yellow", $Host.UI.RawUI.BackgroundColor, "  $([char]0x255A)$([char]0x2550) ")
                    $Host.UI.Write("DarkYellow", $Host.UI.RawUI.BackgroundColor, $uLabel)
                    $Host.UI.WriteLine("Yellow", $Host.UI.RawUI.BackgroundColor, " $padU$([char]0x255D)")
                } else {
                    $padB = "$([char]0x2500)" * [Math]::Max(0, 67 - $src.Length)
                    W ("  $([char]0x255A)$([char]0x2550) " + $src + " " + $padB + "$([char]0x255D)") Yellow
                }
                Write-Host ""
            }
        }

        if ($reviewMods.Count -gt 0) {
            Write-SectionHeader "REVIEW $([char]0x2014) verify these manually" $reviewMods.Count DarkYellow Yellow
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in ($reviewMods | Sort-Object Score -Descending)) { Write-VerdictCard $mod }
        }

        if ($flaggedMods.Count -gt 0) {
            Write-SectionHeader "FLAGGED $([char]0x2014) likely cheats" $flaggedMods.Count Red Red
            Write-Rule "$([char]0x2500)" 76 DarkGray
            Write-Host ""
            foreach ($mod in ($flaggedMods | Sort-Object Score -Descending)) { Write-VerdictCard $mod }
        }
    }

    if ($script:_DevMode -and ($exeFiles.Count -gt 0 -or $pyFiles.Count -gt 0)) {
        Write-Host ""
        W "  $([char]0x25CF) Dev mode: scanning $($exeFiles.Count) .exe and $($pyFiles.Count) .py file(s)..." Cyan
        Write-Host ""

        foreach ($exeFile in $exeFiles) {
            $exeFlags = Invoke-ExeScan -FilePath $exeFile.FullName
            if ($exeFlags.Count -gt 0) {
                $hash = Get-FileSHA1 $exeFile.FullName
                $emptySet = [System.Collections.Generic.HashSet[string]]::new()
                $strSet   = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($f in $exeFlags) { [void]$strSet.Add($f) }
                Write-FlaggedCard $exeFile.Name $hash $false "" $null $null $emptySet $strSet $emptySet
                [void]$script:FlaggedModsList.Add($exeFile.Name)
                $script:Flagged++
            } else {
                W "  $([char]0x2713) $($exeFile.Name) $([char]0x2014) clean" Green
            }
        }

        foreach ($pyFile in $pyFiles) {
            $pyFlags = Invoke-PyScan -FilePath $pyFile.FullName
            if ($pyFlags.Count -gt 0) {
                $hash = Get-FileSHA1 $pyFile.FullName
                $emptySet = [System.Collections.Generic.HashSet[string]]::new()
                $strSet   = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($f in $pyFlags) { [void]$strSet.Add($f) }
                Write-FlaggedCard $pyFile.Name $hash $false "" $null $null $emptySet $strSet $emptySet
                [void]$script:FlaggedModsList.Add($pyFile.Name)
                $script:Flagged++
            } else {
                W "  $([char]0x2713) $($pyFile.Name) $([char]0x2014) clean" Green
            }
        }
    }
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
W "  Done." Green
Write-Host ""
# Nothing waits for a keypress any more, so the result must survive the window
# closing: it is written to the HTML report and to last-scan.txt (see Save-ScanSummary).
