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

    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
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
    $script:Evidence.DeletedJars = @($deletedEntries | Where-Object { $_.FileName -match '\.jar$' }).Count
    New-HtmlReport
    Write-Host ""

    if ($bamEntries.Count -eq 0) {
        W "  $([char]0x2713) BAM $([char]0x2014) no .exe/.jar executions found since last logon." DarkGray
        Write-Host ""
        return
    }

    Write-Host ""
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
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    $pcIssues += $dllFlags.Count
    W ("  $([char]0x250C)$([char]0x2500)$([char]0x2500) INJECTABLE DLL SCAN (javaw) " + "$([char]0x2500)" * 42 + "$([char]0x2510)") DarkCyan
    $dllScannedLine = "  $([char]0x2502)  Scanned $dllScanned module(s) in Java process"
    W ($dllScannedLine + (" " * [Math]::Max(0, 75 - $dllScannedLine.Length)) + "$([char]0x2502)") DarkGray
    if ($dllFlags.Count -eq 0) {
        W ("  $([char]0x2502)   OK $([char]0x2014) no suspicious DLLs loaded in Java process" + (" " * 24) + "$([char]0x2502)") DarkCyan
    } else {
        foreach ($f in $dllFlags) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) FLAGGED  PID $($f.PID) ($($f.Process))" Red
            W "  $([char]0x2502)    DLL    : $($f.DLL)" DarkYellow
        }
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