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

    # Filtered in the query: Win32_LogonSession holds every session since boot,
    # and every one of them was fetched to keep the two interactive types.
    $oldestLogon = Get-WmiOrCim 'Win32_LogonSession' 'LogonType=2 OR LogonType=10' |
        Sort-Object -Property StartTime |
        Select-Object -First 1
    $bamConnectTime = $null
    if ($oldestLogon) {
        $bamConnectTime = $oldestLogon.StartTime
        # Get-WmiObject hands StartTime over as a DMTF string, and a string on the
        # right of -ge against a DateTime throws - every BAM entry would then be
        # skipped as "before the login". CIM gives a DateTime already.
        if ($bamConnectTime -is [string]) {
            try { $bamConnectTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($bamConnectTime) } catch { $bamConnectTime = $null }
        }
    }

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
    # The letters come from DriveInfo, not from Win32_Volume: the same set of
    # lettered volumes, without a WMI call.
    $bamMappings = @(foreach ($dv in [System.IO.DriveInfo]::GetDrives()) {
        $dl = $dv.Name.TrimEnd('\')
        if ($dl.Length -ne 2) { continue }
        if ($bamKernel32::QueryDosDevice($dl, $bamSb, 65536)) {
            @{ DriveLetter = $dl; DevicePath = $bamSb.ToString().ToLower() }
        }
    })

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
        # -ErrorAction cannot save a cmdlet that is not there to be called, and
        # under $ErrorActionPreference = 'Stop' an unguarded call ends the whole
        # scan rather than this one lookup.
        try {
            Get-AuthenticodeSignature -LiteralPath $existingPaths -ErrorAction Stop | ForEach-Object {
                $sigMap[$_.Path] = if ($_.Status -eq 'Valid') {
                    if ($_.SignerCertificate.Subject -like "*Manthe Industries*") { "Not signed (vapeclient)" }
                    elseif ($_.SignerCertificate.Subject -like "*Slinkware*") { "Not signed (slinky)" }
                    else { "Signed" }
                } else { "Not signed" }
            }
        } catch {
            Add-ScanGap "The signatures of the programs in the BAM history could not be read, so a cheat executable there is listed without saying whether it was signed."
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

function Get-PngAlphaStats([byte[]]$Bytes) {
    <#
        How much of a texture is transparent, without System.Drawing (which
        needs libgdiplus off Windows and is not a dependency this tool takes on
        anywhere else). Reads just enough of PNG to answer one question: what
        fraction of pixels have an alpha below a threshold.

        Supports the color types and bit depth every real Minecraft texture
        actually uses (8-bit Grayscale/RGB/Indexed/GrayAlpha/RGBA,
        non-interlaced). Anything else - 16-bit, Adam7 interlacing, a corrupt
        or truncated file - returns Ok=$false: a coverage gap, not a guess.
    #>
    $r = @{ Ok = $false; Width = 0; Height = 0; HasAlpha = $false; TransparentFraction = 0.0; Reason = "" }
    try {
        if ($null -eq $Bytes -or $Bytes.Length -lt 8) { $r.Reason = "too short"; return $r }
        $sig = [byte[]]@(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)
        for ($i = 0; $i -lt 8; $i++) { if ($Bytes[$i] -ne $sig[$i]) { $r.Reason = "not a PNG"; return $r } }

        $pos = 8
        $width = 0; $height = 0; $bitDepth = 0; $colorType = -1; $interlace = 0
        $palette = $null
        $trns = $null
        $idatChunks = [System.Collections.Generic.List[byte[]]]::new()
        $haveIHDR = $false

        while ($pos + 8 -le $Bytes.Length) {
            $len = ([int]$Bytes[$pos] -shl 24) -bor ([int]$Bytes[$pos+1] -shl 16) -bor ([int]$Bytes[$pos+2] -shl 8) -bor [int]$Bytes[$pos+3]
            if ($len -lt 0 -or $pos + 8 + $len + 4 -gt $Bytes.Length) { break }
            $tag = [System.Text.Encoding]::ASCII.GetString($Bytes, $pos + 4, 4)
            $dataStart = $pos + 8
            switch ($tag) {
                'IHDR' {
                    $width     = ([int]$Bytes[$dataStart] -shl 24) -bor ([int]$Bytes[$dataStart+1] -shl 16) -bor ([int]$Bytes[$dataStart+2] -shl 8) -bor [int]$Bytes[$dataStart+3]
                    $height    = ([int]$Bytes[$dataStart+4] -shl 24) -bor ([int]$Bytes[$dataStart+5] -shl 16) -bor ([int]$Bytes[$dataStart+6] -shl 8) -bor [int]$Bytes[$dataStart+7]
                    $bitDepth  = [int]$Bytes[$dataStart+8]
                    $colorType = [int]$Bytes[$dataStart+9]
                    $interlace = [int]$Bytes[$dataStart+12]
                    $haveIHDR = $true
                }
                'PLTE' { $palette = $Bytes[$dataStart..($dataStart+$len-1)] }
                'tRNS' { $trns    = $Bytes[$dataStart..($dataStart+$len-1)] }
                'IDAT' { [void]$idatChunks.Add($Bytes[$dataStart..($dataStart+$len-1)]) }
                'IEND' { $pos = $Bytes.Length; break }
            }
            $pos = $dataStart + $len + 4
        }

        if (-not $haveIHDR) { $r.Reason = "no IHDR"; return $r }
        $r.Width = $width; $r.Height = $height
        if ($width -le 0 -or $height -le 0 -or $width -gt 8192 -or $height -gt 8192) { $r.Reason = "unreasonable dimensions"; return $r }
        if ($interlace -ne 0) { $r.Reason = "interlaced (Adam7) - not decoded"; return $r }
        if ($bitDepth -ne 8) { $r.Reason = "bit depth $bitDepth not decoded (only 8-bit)"; return $r }
        if ($idatChunks.Count -eq 0) { $r.Reason = "no image data"; return $r }

        $channels = switch ($colorType) { 0 {1} 2 {3} 3 {1} 4 {2} 6 {4} default { -1 } }
        if ($channels -lt 0) { $r.Reason = "unknown color type $colorType"; return $r }

        $total = 0; foreach ($c in $idatChunks) { $total += $c.Length }
        $z = New-Object byte[] $total
        $off = 0
        foreach ($c in $idatChunks) { [Array]::Copy($c, 0, $z, $off, $c.Length); $off += $c.Length }
        if ($z.Length -lt 6) { $r.Reason = "IDAT too short"; return $r }
        $ms = New-Object System.IO.MemoryStream(,$z)
        [void]$ms.Seek(2, [System.IO.SeekOrigin]::Begin)
        $raw = $null
        $inflate = $null; $outMs = $null
        try {
            $inflate = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $outMs = New-Object System.IO.MemoryStream
            $inflate.CopyTo($outMs)
            $raw = $outMs.ToArray()
        } catch { $r.Reason = "inflate failed: $($_.Exception.Message)"; return $r }
        finally { if ($inflate) { $inflate.Dispose() }; if ($outMs) { $outMs.Dispose() }; $ms.Dispose() }

        $stride = [int][Math]::Ceiling(($width * $channels * $bitDepth) / 8.0)
        $bpp = [Math]::Max(1, [int][Math]::Ceiling(($channels * $bitDepth) / 8.0))
        $need = $height * ($stride + 1)
        if ($raw.Length -lt $need) { $r.Reason = "truncated pixel data ($($raw.Length) of $need bytes)"; return $r }

        $prevRow = New-Object byte[] $stride
        $currRow = New-Object byte[] $stride
        $transparent = 0L
        $counted = 0L
        # Below this (out of 255) counts as "transparent" for an x-ray texture -
        # not zero, because a soft anti-aliased edge against nothing still reads
        # as see-through in game.
        $alphaCut = 32
        $hasAlphaChannel = ($colorType -eq 4 -or $colorType -eq 6 -or ($colorType -eq 3 -and $null -ne $trns) -or (($colorType -eq 0 -or $colorType -eq 2) -and $null -ne $trns))
        $r.HasAlpha = $hasAlphaChannel

        $srcPos = 0
        for ($y = 0; $y -lt $height; $y++) {
            $ftype = $raw[$srcPos]; $srcPos++
            [Array]::Copy($raw, $srcPos, $currRow, 0, $stride); $srcPos += $stride
            switch ($ftype) {
                0 { }
                1 { for ($x = 0; $x -lt $stride; $x++) { $a = if ($x -ge $bpp) { $currRow[$x-$bpp] } else { 0 }; $currRow[$x] = [byte](($currRow[$x] + $a) -band 0xFF) } }
                2 { for ($x = 0; $x -lt $stride; $x++) { $b = $prevRow[$x]; $currRow[$x] = [byte](($currRow[$x] + $b) -band 0xFF) } }
                3 { for ($x = 0; $x -lt $stride; $x++) { $a = if ($x -ge $bpp) { [int]$currRow[$x-$bpp] } else { 0 }; $b = [int]$prevRow[$x]; $currRow[$x] = [byte](($currRow[$x] + [Math]::Floor(($a+$b)/2.0)) -band 0xFF) } }
                4 {
                    for ($x = 0; $x -lt $stride; $x++) {
                        $a = if ($x -ge $bpp) { [int]$currRow[$x-$bpp] } else { 0 }
                        $b = [int]$prevRow[$x]
                        $c = if ($x -ge $bpp) { [int]$prevRow[$x-$bpp] } else { 0 }
                        $p = $a + $b - $c
                        $pa = [Math]::Abs($p - $a); $pb = [Math]::Abs($p - $b); $pc = [Math]::Abs($p - $c)
                        $pr = if ($pa -le $pb -and $pa -le $pc) { $a } elseif ($pb -le $pc) { $b } else { $c }
                        $currRow[$x] = [byte](($currRow[$x] + $pr) -band 0xFF)
                    }
                }
                default { $r.Reason = "unknown filter type $ftype at row $y"; return $r }
            }

            for ($x = 0; $x -lt $width; $x++) {
                $counted++
                $alpha = 255
                switch ($colorType) {
                    6 { $alpha = $currRow[$x*4 + 3] }
                    4 { $alpha = $currRow[$x*2 + 1] }
                    3 {
                        $idx = $currRow[$x]
                        if ($trns -and $idx -lt $trns.Length) { $alpha = $trns[$idx] }
                    }
                    2 {
                        if ($trns -and $trns.Length -ge 6) {
                            $rr = ([int]$trns[0] -shl 8) -bor [int]$trns[1]
                            $gg = ([int]$trns[2] -shl 8) -bor [int]$trns[3]
                            $bb = ([int]$trns[4] -shl 8) -bor [int]$trns[5]
                            if ([int]$currRow[$x*3] -eq $rr -and [int]$currRow[$x*3+1] -eq $gg -and [int]$currRow[$x*3+2] -eq $bb) { $alpha = 0 }
                        }
                    }
                    0 {
                        if ($trns -and $trns.Length -ge 2) {
                            $gv = ([int]$trns[0] -shl 8) -bor [int]$trns[1]
                            if ([int]$currRow[$x] -eq $gv) { $alpha = 0 }
                        }
                    }
                }
                if ($alpha -lt $alphaCut) { $transparent++ }
            }

            $tmp = $prevRow; $prevRow = $currRow; $currRow = $tmp
        }

        $r.TransparentFraction = if ($counted -gt 0) { [double]$transparent / [double]$counted } else { 0.0 }
        $r.Ok = $true
        return $r
    } catch {
        $r.Reason = "exception: $($_.Exception.Message)"
        return $r
    }
}

function Get-OptionsTxtValue([string]$OptionsPath, [string]$Key) {
    # options.txt is one "key:value" per line. Returns $null if the file or the
    # key is not there - never guessed at, since a missing file just means the
    # game has not written one with this launcher/profile yet.
    if (-not [System.IO.File]::Exists($OptionsPath)) { return $null }
    try {
        foreach ($line in [System.IO.File]::ReadLines($OptionsPath)) {
            $ci = $line.IndexOf(':')
            if ($ci -lt 0) { continue }
            if ($line.Substring(0, $ci) -eq $Key) { return $line.Substring($ci + 1) }
        }
    } catch {}
    return $null
}

function Get-ActiveResourcePackNames([string]$OptionsPath) {
    # resourcePacks:["vanilla","file/SomePack.zip","file/Other (1)"] - only the
    # file/ entries name an actual file on disk; "vanilla" and a loader's own
    # programmatic entries are not files and are skipped.
    $out = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $raw = Get-OptionsTxtValue $OptionsPath 'resourcePacks'
    if (-not $raw) { return $out }
    foreach ($m in [regex]::Matches($raw, '"file/([^"]+)"')) { [void]$out.Add($m.Groups[1].Value) }
    return $out
}

function Test-HighGamma([string]$OptionsPath) {
    # Above 1.0 is outside the brightness slider's own range (0.0-1.0). Most
    # often OptiFine's "Full Bright" three-way toggle, which writes an
    # extreme value here - a supported client feature, not an exploit, and
    # banned on plenty of servers anyway for the same reason x-ray is: it
    # shows something the game is not supposed to let you see. Sometimes a
    # hand-edited value doing the same thing without OptiFine at all. Either
    # way it is a rule question, never proof by itself.
    $raw = Get-OptionsTxtValue $OptionsPath 'gamma'
    if (-not $raw) { return $null }
    $val = 0.0
    if (-not [double]::TryParse($raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$val)) { return $null }
    if ($val -le 1.0) { return $null }
    return $val
}

function Get-PackEntryBytes($Zip, [string]$DirPath, [string]$RelPath, [long]$MaxBytes) {
    # One texture/model/shader file, wherever the pack actually is - a .zip
    # (via the open ZipArchive the caller already holds) or a plain unpacked
    # folder. Returns $null on anything from "not present" to "too large to
    # read safely", which the caller treats the same way: skip, do not guess.
    if ($Zip) {
        $e = $Zip.GetEntry($RelPath)
        if (-not $e -or $e.Length -gt $MaxBytes) { return $null }
        try {
            $ms = New-Object System.IO.MemoryStream
            $st = $e.Open(); $st.CopyTo($ms); $st.Close()
            return $ms.ToArray()
        } catch { return $null }
    }
    $fp = Join-Path $DirPath ($RelPath -replace '/', '\')
    if (-not [System.IO.File]::Exists($fp)) { return $null }
    try {
        if ([System.IO.FileInfo]::new($fp).Length -gt $MaxBytes) { return $null }
        return [System.IO.File]::ReadAllBytes($fp)
    } catch { return $null }
}

function Test-XrayPack([string]$PackPath) {
    <#
        Decodes a curated list of always-opaque block textures out of a
        resource pack and reports which ones are mostly see-through, plus any
        block model whose "elements" array is literally empty - a model that
        renders nothing while the block stays solid. No legitimate resource
        pack, whatever its art style, has a reason to do either to stone, ore
        or bedrock: the block is still there, it is just not being SHOWN.

        Model matching does not resolve "parent" inheritance - a model that
        gets its shape from a parent and only overrides textures is correctly
        left alone; only a model that says outright "no elements" is named.
    #>
    $textureHits = [System.Collections.Generic.List[object]]::new()
    $modelHits   = [System.Collections.Generic.List[string]]::new()
    $gaps        = [System.Collections.Generic.List[string]]::new()
    $isZip = $PackPath.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)
    $zip = $null
    try {
        if ($isZip) {
            $fi = [System.IO.FileInfo]::new($PackPath)
            if ($fi.Length -gt 1GB) { return @{ TextureHits = @(); ModelHits = @(); Gaps = @("$PackPath is too large to open safely") } }
            $zip = [System.IO.Compression.ZipFile]::OpenRead($PackPath)
        } elseif (-not [System.IO.Directory]::Exists($PackPath)) {
            return @{ TextureHits = @(); ModelHits = @(); Gaps = @() }
        }
        foreach ($blk in $script:xrayOpaqueTextures) {
            $texBytes = Get-PackEntryBytes $zip $PackPath "assets/minecraft/textures/block/$blk.png" 8MB
            if ($texBytes) {
                $stats = Get-PngAlphaStats $texBytes
                if (-not $stats.Ok) {
                    if ($stats.Reason -notin @('no IHDR', 'not a PNG')) { [void]$gaps.Add("$PackPath : textures/block/$blk.png $($stats.Reason)") }
                } elseif ($stats.HasAlpha -and $stats.TransparentFraction -ge 0.5) {
                    [void]$textureHits.Add(@{ Texture = $blk; TransparentFraction = $stats.TransparentFraction })
                }
            }
            $modelBytes = Get-PackEntryBytes $zip $PackPath "assets/minecraft/models/block/$blk.json" 256KB
            if ($modelBytes) {
                try { $modelTxt = [System.Text.Encoding]::UTF8.GetString($modelBytes) } catch { $modelTxt = $null }
                if ($modelTxt -match '"elements"\s*:\s*\[\s*\]') { [void]$modelHits.Add($blk) }
            }
        }
    } catch {
    } finally { if ($zip) { $zip.Dispose() } }
    return @{ TextureHits = @($textureHits); ModelHits = @($modelHits); Gaps = @($gaps) }
}

function Test-XrayShaders([string]$PackPath) {
    <#
        A heuristic, and the report says so. Two signals:
          - a HARDCODED low alpha written to a terrain fragment's output,
            unconditionally: no legitimate shader makes every solid block
            uniformly translucent as a rendering STYLE - that is the x-ray
            shader's actual mechanism, not an artistic choice.
          - 'discard' present in a terrain shader at all, kept SEPARATE and
            always weaker: cutout rendering for leaf and glass edges is a
            completely ordinary reason a terrain shader discards a fragment,
            so this alone is worth a look and never proof.
        Covers both a core-shader resource pack (assets/minecraft/shaders/core,
        1.17+) and an Iris/OptiFine shaderpack (shaders/ at the pack root).
    #>
    $lowAlpha = [System.Collections.Generic.List[string]]::new()
    $discardOnly = [System.Collections.Generic.List[string]]::new()
    $isZip = $PackPath.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)
    $zip = $null
    $isTerrainShader = '^(gbuffers_terrain|rendertype_solid|rendertype_cutout)'
    try {
        $names = [System.Collections.Generic.List[string]]::new()
        if ($isZip) {
            try { $zip = [System.IO.Compression.ZipFile]::OpenRead($PackPath) } catch { return @{ LowAlpha = @(); DiscardOnly = @() } }
            foreach ($e in $zip.Entries) {
                if ($e.Length -gt 512KB) { continue }
                if ($e.FullName -notmatch '\.fsh$') { continue }
                if ([System.IO.Path]::GetFileNameWithoutExtension($e.FullName) -match $isTerrainShader) { [void]$names.Add($e.FullName) }
            }
        } else {
            if (-not [System.IO.Directory]::Exists($PackPath)) { return @{ LowAlpha = @(); DiscardOnly = @() } }
            foreach ($f in [System.IO.Directory]::EnumerateFiles($PackPath, '*.fsh', [System.IO.SearchOption]::AllDirectories)) {
                if ([System.IO.Path]::GetFileNameWithoutExtension($f) -match $isTerrainShader) { [void]$names.Add($f) }
            }
        }
        foreach ($n in $names) {
            # $n is a zip-relative entry name in the zip case, an already-
            # resolved full path in the folder case - read each the way it
            # actually needs, not through Get-PackEntryBytes's pack-root-plus-
            # relative-path join, which assumes the zip shape.
            $bytes = $null
            if ($isZip) { $bytes = Get-PackEntryBytes $zip $PackPath $n 512KB }
            else { try { if ([System.IO.FileInfo]::new($n).Length -le 512KB) { $bytes = [System.IO.File]::ReadAllBytes($n) } } catch {} }
            if (-not $bytes) { continue }
            $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
            if ($txt -match '(?im)\.a\s*=\s*0\.[0-4]\d*\s*;') { [void]$lowAlpha.Add($n) }
            elseif ($txt -match '\bdiscard\b') { [void]$discardOnly.Add($n) }
        }
    } catch {
    } finally { if ($zip) { $zip.Dispose() } }
    return @{ LowAlpha = @($lowAlpha); DiscardOnly = @($discardOnly) }
}

function Test-CheatFeatureConfigs([string]$InstanceRoot) {
    <#
        A named mod's OWN config, not its code. Owning Xaero's minimap,
        Tweakeroo or Litematica is completely ordinary - among the most-used
        utility mods there are - so this never scores anything on its own; it
        surfaces the mod and, where a config file could be read, whatever in
        it LOOKS like a feature worth asking about, for a moderator to judge.
    #>
    $out = [System.Collections.Generic.List[object]]::new()
    $searchDirs = @($InstanceRoot, (Join-Path $InstanceRoot 'config')) | Where-Object { [System.IO.Directory]::Exists($_) }
    foreach ($modLabel in $script:xrayConfigMods.Keys) {
        $needle = $script:xrayConfigMods[$modLabel]
        $matches = [System.Collections.Generic.List[string]]::new()
        $flagHits = [System.Collections.Generic.List[string]]::new()
        foreach ($sd in $searchDirs) {
            try {
                foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($sd)) {
                    $nm = [System.IO.Path]::GetFileName($entry)
                    if ($nm.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                    if (-not $matches.Contains($entry)) { [void]$matches.Add($entry) }
                    $filesToRead = @()
                    if ([System.IO.File]::Exists($entry)) {
                        $filesToRead = @($entry)
                    } elseif ([System.IO.Directory]::Exists($entry)) {
                        try { $filesToRead = @([System.IO.Directory]::GetFiles($entry, '*.*', [System.IO.SearchOption]::TopDirectoryOnly) | Select-Object -First 20) } catch {}
                    }
                    foreach ($f in $filesToRead) {
                        try {
                            if ([System.IO.FileInfo]::new($f).Length -gt 512KB) { continue }
                            $txt = [System.IO.File]::ReadAllText($f)
                            foreach ($m in [regex]::Matches($txt, $script:xrayConfigFlagPattern)) {
                                $v = $m.Value.Trim()
                                if (-not $flagHits.Contains($v)) { [void]$flagHits.Add($v) }
                            }
                        } catch {}
                    }
                }
            } catch {}
        }
        if ($matches.Count -gt 0) { [void]$out.Add(@{ Mod = $modLabel; Paths = @($matches); Flags = @($flagHits) }) }
    }
    return @($out)
}

function Run-InstanceScan {
    # Everything in a .minecraft folder that is not the mods folder.
    $res = @{
        Launch = [System.Collections.Generic.List[object]]::new()   # version / launcher profiles
        Packs  = [System.Collections.Generic.List[object]]::new()   # packs carrying bytecode
        Configs = [System.Collections.Generic.List[string]]::new()  # cheat config folders
        UnknownMain = [System.Collections.Generic.List[string]]::new()
        XrayTextures = [System.Collections.Generic.List[object]]::new()  # x-ray via transparent block textures
        XrayModels   = [System.Collections.Generic.List[object]]::new()  # x-ray via hollow block models
        ShaderXray   = [System.Collections.Generic.List[object]]::new()  # x-ray/ESP heuristic in a core/Iris/OptiFine shader
        HighGamma    = [System.Collections.Generic.List[object]]::new()  # fullbright via options.txt gamma > 1.0
        ConfigMods   = [System.Collections.Generic.List[object]]::new()  # Xaero/Tweakeroo/Litematica/Freecam/Baritone configs
        Checked = 0
    }
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($script:ScanTargetDirs)) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        try { $d = [System.IO.Path]::GetDirectoryName($t.TrimEnd('\')); if ($d) { [void]$roots.Add($d) } } catch {}
    }
    foreach ($root in $roots) {
        # --- options.txt: fullbright via gamma ------------------------------------
        $optionsPath = [System.IO.Path]::Combine($root, 'options.txt')
        $gammaVal = Test-HighGamma $optionsPath
        if ($null -ne $gammaVal) {
            $res.Checked++
            [void]$res.HighGamma.Add(@{ Root = $root; Gamma = $gammaVal })
        }
        $activePacks = Get-ActiveResourcePackNames $optionsPath
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
        # --- resource and shader packs: bytecode, x-ray, shader heuristics -------
        foreach ($pdir in @('resourcepacks', 'shaderpacks')) {
            $pd = [System.IO.Path]::Combine($root, $pdir)
            if (-not [System.IO.Directory]::Exists($pd)) { continue }
            $packPaths = [System.Collections.Generic.List[string]]::new()
            try { foreach ($z in ([System.IO.Directory]::GetFiles($pd, '*.zip') | Select-Object -First 80)) { [void]$packPaths.Add($z) } } catch {}
            # Unpacked (folder) packs too - a pack being actively edited, or one
            # extracted rather than left zipped, is exactly as capable of shipping
            # an x-ray texture as a zip is.
            try { foreach ($d in ([System.IO.Directory]::GetDirectories($pd) | Select-Object -First 40)) { [void]$packPaths.Add($d) } } catch {}
            foreach ($pk in $packPaths) {
                $res.Checked++
                $isActive = $activePacks.Contains([System.IO.Path]::GetFileName($pk))
                if ($pk.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)) {
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

                $xray = Test-XrayPack $pk
                foreach ($th in $xray.TextureHits) {
                    [void]$res.XrayTextures.Add(@{ Pack = $pk; Texture = $th.Texture; TransparentFraction = $th.TransparentFraction; Active = $isActive })
                }
                foreach ($mh in $xray.ModelHits) {
                    [void]$res.XrayModels.Add(@{ Pack = $pk; Block = $mh; Active = $isActive })
                }
                foreach ($g in $xray.Gaps) { Add-ScanGap $g }

                $shd = Test-XrayShaders $pk
                foreach ($la in $shd.LowAlpha) { [void]$res.ShaderXray.Add(@{ Pack = $pk; File = $la; Kind = 'lowalpha'; Active = $isActive }) }
                foreach ($dc in $shd.DiscardOnly) { [void]$res.ShaderXray.Add(@{ Pack = $pk; File = $dc; Kind = 'discard'; Active = $isActive }) }
            }
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
        # --- named mods whose CONFIG can carry a rule-question feature -----------
        foreach ($cm in (Test-CheatFeatureConfigs $root)) {
            $res.Checked++
            [void]$res.ConfigMods.Add($cm)
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
    $configModFlagged = @($inst.ConfigMods | Where-Object { @($_.Flags).Count -gt 0 })
    $script:InstanceHits = ($inst.Launch.Count - $agents.Count) + $inst.Packs.Count + $inst.Configs.Count +
        $inst.XrayTextures.Count + $inst.XrayModels.Count + $inst.ShaderXray.Count + $inst.HighGamma.Count + $configModFlagged.Count
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
        foreach ($t in $inst.XrayTextures) {
            Write-Host ""
            $tag = if ($t.Active) { "X-RAY TEXTURE (active)" } else { "X-RAY TEXTURE (present)" }
            $col = if ($t.Active) { "Red" } else { "DarkYellow" }
            W "  $([char]0x2502)  $([char]0x26A0) $tag  $($t.Pack)" $col
            W "  $([char]0x2502)    $($t.Texture).png is $([int]($t.TransparentFraction * 100))% transparent" DarkYellow
        }
        foreach ($m in $inst.XrayModels) {
            Write-Host ""
            $tag = if ($m.Active) { "X-RAY MODEL (active)" } else { "X-RAY MODEL (present)" }
            $col = if ($m.Active) { "Red" } else { "DarkYellow" }
            W "  $([char]0x2502)  $([char]0x26A0) $tag  $($m.Pack)" $col
            W "  $([char]0x2502)    $($m.Block).json has no visible elements" DarkYellow
        }
        foreach ($sh in $inst.ShaderXray) {
            Write-Host ""
            $what = if ($sh.Kind -eq 'lowalpha') { "SHADER $([char]0x2014) hardcoded low alpha" } else { "SHADER $([char]0x2014) discard in terrain (not proof alone)" }
            W "  $([char]0x2502)  $([char]0x26A0) $what  $($sh.Pack)" DarkYellow
            W "  $([char]0x2502)    $($sh.File)" DarkGray
        }
        foreach ($g in $inst.HighGamma) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) GAMMA $($g.Gamma) $([char]0x2014) above the slider's 0.0-1.0 range" DarkYellow
            W "  $([char]0x2502)    $($g.Root)\options.txt" DarkGray
        }
        foreach ($cm in $configModFlagged) {
            Write-Host ""
            W "  $([char]0x2502)  $([char]0x26A0) $($cm.Mod) config $([char]0x2014) looks like an enabled feature worth asking about" DarkYellow
            foreach ($fl in $cm.Flags) { W "  $([char]0x2502)    $fl" DarkGray }
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
    if ($inst.XrayTextures.Count -gt 0) {
        $activeT = @($inst.XrayTextures | Where-Object { $_.Active })
        $level = if ($activeT.Count -gt 0) { "FAIL" } else { "WARN" }
        Add-Finding $level "Launcher, packs & configs" "$($inst.XrayTextures.Count) resource-pack texture(s) make a solid block mostly transparent" `
            @($inst.XrayTextures | ForEach-Object { "$($_.Texture).png $([int]($_.TransparentFraction * 100))% transparent, $(if($_.Active){'ACTIVE'}else{'present, not currently active'}) $([char]0x2014) $($_.Pack)" }) `
            "Every resource pack's stone/deepslate/ore/bedrock textures were decoded (a from-scratch PNG reader, no external dependency) and checked for how much of the image is see-through." `
            "The block is still solid $([char]0x2014) only the texture is gone. No legitimate pack, whatever its art style, has a reason to make ore or bedrock transparent; this is how x-ray works without a single line of Java." `
            "" "$(if($activeT.Count -gt 0){'This pack is currently selected in options.txt - remove it and check what the person can see through walls without it.'}else{'This pack is not currently active. It is still worth asking why it is installed.'})" | Out-Null
    }
    if ($inst.XrayModels.Count -gt 0) {
        $activeM = @($inst.XrayModels | Where-Object { $_.Active })
        $level = if ($activeM.Count -gt 0) { "FAIL" } else { "WARN" }
        Add-Finding $level "Launcher, packs & configs" "$($inst.XrayModels.Count) resource-pack block model(s) render nothing" `
            @($inst.XrayModels | ForEach-Object { "$($_.Block).json $(if($_.Active){'ACTIVE'}else{'present, not currently active'}) $([char]0x2014) $($_.Pack)" }) `
            "Every resource pack's block models for the same always-solid blocks were read for a literal empty elements array - the JSON says outright that the model has nothing to draw." `
            "A block with no model renders nothing while the game still treats it as solid. Same effect as an x-ray texture, done through the model instead of the image." | Out-Null
    }
    if ($inst.ShaderXray.Count -gt 0) {
        Add-Finding "WARN" "Launcher, packs & configs" "$($inst.ShaderXray.Count) shader file(s) in a resource/shaderpack worth a manual look" `
            @($inst.ShaderXray | ForEach-Object { "$($_.Kind): $($_.File) $(if($_.Active){'(pack active)'}else{'(pack present)'})" }) `
            "Core shaders (assets/minecraft/shaders/core, built into resource packs since 1.17) and Iris/OptiFine shaderpacks were scanned for a terrain fragment shader that either hardcodes a low, unconditional alpha or contains 'discard' at all." `
            "A hardcoded low alpha makes every solid block uniformly see-through - that is the x-ray shader's actual mechanism, not a rendering style. 'discard' alone is much weaker: cutout rendering for leaves and glass edges is a completely ordinary reason a terrain shader discards a fragment." `
            "" "This is pattern-matched GLSL text, not a real shader compiler $([char]0x2014) treat it as a lead to check by eye or by disabling the pack, never as proof on its own." | Out-Null
    }
    if ($inst.HighGamma.Count -gt 0) {
        Add-Finding "WARN" "Launcher, packs & configs" "Gamma above the slider's own range (fullbright)" `
            @($inst.HighGamma | ForEach-Object { "gamma $($_.Gamma) $([char]0x2014) $($_.Root)\options.txt" }) `
            "options.txt's gamma value was read directly; the in-game brightness slider only ever writes 0.0 to 1.0." `
            "A value above 1.0 most often comes from OptiFine's 'Full Bright' video setting - a supported client feature, not a technical exploit - and sometimes from a hand-edited options.txt doing the same thing without OptiFine. Either way it lights areas the game means to leave dark, which plenty of servers treat as a rule question the same way they treat x-ray." | Out-Null
    }
    if ($configModFlagged.Count -gt 0) {
        Add-Finding "WARN" "Launcher, packs & configs" "$($configModFlagged.Count) mod config(s) contain what looks like an enabled feature worth asking about" `
            @($configModFlagged | ForEach-Object { $mm = $_; @($mm.Flags | ForEach-Object { "$($mm.Mod): $_" }) }) `
            "Xaero's Minimap/World Map, Tweakeroo, Litematica, Freecam and Baritone are among the most-used utility mods there are, so owning one is not a finding. Where a config file for one could be read, it was checked for text that LOOKS like a free-camera, cave-mode, entity-radar, flexible-placement or x-ray-style setting turned on." `
            "The match is a loose, name-based pattern - not one exact config schema, since different mod versions spell the same setting differently - so it is never proof. A moderator has to open the file and read the line to know what it actually means for this server's rules." | Out-Null
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

function Get-PcInventoryNames {
    <#
        The names of the .exe, .py and .pyw files on the fixed drives, for the
        report's inventory. Names only: nothing here is opened or judged, and the
        folders the EXE and Python checks DO examine are walked by those checks.

        One pass for all three. There were three, each EnumerateFiles over the
        whole disk, and each had the same three faults. It threw on the first
        folder it may not enter - $Recycle.Bin, System Volume Information - and
        the catch around it ended the walk, so the "inventory" was usually a few
        names from the root, presented as the PC. It followed junctions, so
        C:\Users\All Users and its kind were listed twice. And with Administrator,
        where nothing throws, it read the entire disk to list the component
        store's tens of thousands of Microsoft binaries, with a console write
        per file: minutes, for a list.

        So: a folder that cannot be entered is skipped. Junctions are not
        followed. The two folders that are the component store are not entered.
        And the walk is BUDGETED, by names and by seconds, breadth-first so the
        user folders come before the deep system trees. When the budget ends it,
        Partial is set and the coverage box says so - which is what the old walk
        should have said every time.
    #>
    param([string[]]$Roots = $null, [int]$MaxPerType = 12000, [double]$Seconds = 8.0)
    $r = @{
        Exe     = [System.Collections.Generic.List[string]]::new()
        Py      = [System.Collections.Generic.List[string]]::new()
        Partial = $false
        Dirs    = 0
        Seconds = $Seconds
    }
    if ($script:_DevMode) { $MaxPerType = 10 }
    $seenExe = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenPy  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $skip    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @('WinSxS', 'servicing', '$Recycle.Bin', 'System Volume Information', 'Windows.old')) { [void]$skip.Add($n) }
    if ($null -eq $Roots -or $Roots.Count -eq 0) {
        $Roots = @([System.IO.DriveInfo]::GetDrives() |
            Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
            ForEach-Object { $_.RootDirectory.FullName })
    }
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($root in $Roots) { if ($root) { $queue.Enqueue([string]$root) } }
    $reparse = [System.IO.FileAttributes]::ReparsePoint
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($queue.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -gt $Seconds) { break }
        if ($seenExe.Count -ge $MaxPerType -and $seenPy.Count -ge $MaxPerType) { break }
        $dir = $queue.Dequeue()
        $r.Dirs++
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                $ext = [System.IO.Path]::GetExtension($f)
                if ($ext.Length -lt 3) { continue }
                if ($ext -ieq '.exe') {
                    $nm = [System.IO.Path]::GetFileName($f)
                    if ($seenExe.Count -lt $MaxPerType) { if ($seenExe.Add($nm)) { [void]$r.Exe.Add($nm) } }
                    elseif (-not $seenExe.Contains($nm)) { $r.Partial = $true }
                } elseif ($ext -ieq '.py' -or $ext -ieq '.pyw') {
                    $nm = [System.IO.Path]::GetFileName($f)
                    if ($seenPy.Count -lt $MaxPerType) { if ($seenPy.Add($nm)) { [void]$r.Py.Add($nm) } }
                    elseif (-not $seenPy.Contains($nm)) { $r.Partial = $true }
                }
            }
        } catch {}
        try {
            foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                if ($skip.Contains([System.IO.Path]::GetFileName($sub))) { continue }
                try { if (([System.IO.File]::GetAttributes($sub) -band $reparse) -ne 0) { continue } } catch { continue }
                $queue.Enqueue($sub)
            }
        } catch {}
        if (($r.Dirs % 250) -eq 0) { Spin "Listing programs and scripts on the PC: $($r.Exe.Count) exe, $($r.Py.Count) py" }
    }
    SpinClear
    $sw.Stop()
    if ($queue.Count -gt 0) { $r.Partial = $true }
    return $r
}

function Invoke-PcInventory {
    # Once, for whichever of the Python and EXE scans runs first.
    if ($null -ne $script:PCScannedExeNames) { return }
    $inv = Get-PcInventoryNames
    $script:PCScannedExeNames = $inv.Exe
    $script:PCScannedPyNames  = $inv.Py
    if ($inv.Partial) {
        Add-ScanGap ("The inventory of program and script names on this PC is partial $([char]0x2014) " +
            "$($inv.Exe.Count) .exe and $($inv.Py.Count) .py names were listed in $($inv.Seconds)s before the listing was stopped. " +
            "It is a list of names for the report and nothing in it is examined; the folders the EXE and Python checks examine were walked in full.")
    }
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
    $pySeenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Invoke-PcInventory
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
    Invoke-PcInventory
    $exeCheatStringsLower = @($exeCheatStrings | ForEach-Object { $_.ToLower() })
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
                    # The printable runs of five bytes or more, space-separated: the
                    # same text a byte-by-byte loop produced, checked identical on
                    # 400 random buffers. That loop was two million PowerShell
                    # iterations per file - 0.7 to 1.1 s on a real 2 MB binary,
                    # against 0.1 s for the regex over the latin-1 view of it.
                    $latin1  = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes, 0, $maxRead)
                    $sb      = [System.Text.StringBuilder]::new()
                    foreach ($m in [regex]::Matches($latin1, '[\x20-\x7E]{5,}')) { [void]$sb.Append($m.Value).Append(' ') }
                    $exeText = $sb.ToString().ToLower()
                    $strHits = [System.Collections.Generic.List[string]]::new()
                    for ($si = 0; $si -lt $exeCheatStringsLower.Count; $si++) {
                        if ($exeText.Contains($exeCheatStringsLower[$si])) { [void]$strHits.Add($exeCheatStrings[$si]) }
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

function Invoke-PackScanSelfTest {
    <#
        Resource-pack / shader / config detection, pinned the same way
        Invoke-SelfTest pins the verdict logic: real bytes in, exact answer
        checked out. The PNG fixtures are tiny (4x4) real PNGs, base64-embedded
        so this needs no test-data files shipped alongside the script.
    #>
    W "  AsyncAnalyzer self-test $([char]0x2014) resource pack / shader / config detection" Cyan
    Write-Host ""
    $pass = 0; $fail = 0
    function Check([string]$Label, [bool]$Ok) {
        if ($Ok) { $script:pngPass++ } else { $script:pngFail++ }
        W ("  [$(if($Ok){'PASS'}else{'FAIL'})] " + $Label) $(if ($Ok) { "Green" } else { "Red" })
    }
    $script:pngPass = 0; $script:pngFail = 0

    $opaquePng  = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAEklEQVR42mNISUn5j4wZSBcAAI1YIrHuBbCJAAAAAElFTkSuQmCC')
    $xrayPng    = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAFklEQVR42mNISUn5D8QMMMyAzCFOAADHAhPA4bXRxwAAAABJRU5ErkJggg==')
    $rgbonlyPng = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAIAAAAmkwkpAAAAEElEQVR42mPgEpGDIwbiOABgdAPBBG3GkAAAAABJRU5ErkJggg==')

    $o = Get-PngAlphaStats $opaquePng
    Check "Opaque 4x4 RGBA decodes, low transparent fraction" ($o.Ok -and $o.HasAlpha -and $o.TransparentFraction -lt 0.3)
    $x = Get-PngAlphaStats $xrayPng
    Check "X-ray-shaped 4x4 RGBA decodes, high transparent fraction" ($x.Ok -and $x.HasAlpha -and $x.TransparentFraction -gt 0.5)
    $g = Get-PngAlphaStats $rgbonlyPng
    Check "RGB (no alpha channel) decodes, HasAlpha=false" ($g.Ok -and (-not $g.HasAlpha))
    $bad = Get-PngAlphaStats ([byte[]]@(1,2,3))
    Check "Malformed bytes: Ok=false, no throw" (-not $bad.Ok)
    $empty = Get-PngAlphaStats $null
    Check "Null input: Ok=false, no throw" (-not $empty.Ok)

    Check "Config flag: tweakFreeCamera=true matches" ('"tweakFreeCamera": true' -match $script:xrayConfigFlagPattern)
    Check "Config flag: tweakFlexibleBlockPlacement=true matches (word between halves)" ('"tweakFlexibleBlockPlacement": true' -match $script:xrayConfigFlagPattern)
    Check "Config flag: caveMode=true matches" ('caveMode = true' -match $script:xrayConfigFlagPattern)
    Check "Config flag: tweakFreeCamera=FALSE does not match" (-not ('"tweakFreeCamera": false' -match $script:xrayConfigFlagPattern))
    Check "Config flag: unrelated setting does not match" (-not ('"someOtherSetting": true' -match $script:xrayConfigFlagPattern))

    Check "Shader: hardcoded low alpha constant matches" ('fragColor.a = 0.15;' -match '(?im)\.a\s*=\s*0\.[0-4]\d*\s*;')
    Check "Shader: alpha read from a variable does not match the constant pattern" (-not ('fragColor.a = albedo.a;' -match '(?im)\.a\s*=\s*0\.[0-4]\d*\s*;'))
    Check "Shader: alpha assigned a high constant does not match (not low)" (-not ('fragColor.a = 0.9;' -match '(?im)\.a\s*=\s*0\.[0-4]\d*\s*;'))
    Check "Shader: legitimate cutout discard is recognised (weaker signal)" ('if (albedo.a < 0.1) discard;' -match '\bdiscard\b')

    $pass = $script:pngPass; $fail = $script:pngFail
    Write-Host ""
    if ($fail -eq 0) { W "  All $pass self-tests passed $([char]0x2014) pack/shader/config detection OK on this machine." Green }
    else { W "  $fail self-test(s) FAILED $([char]0x2014) do not trust results until fixed." Red }
    Write-Host ""
}

