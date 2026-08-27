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
        HiddenPayload = 0; LoaderIds = [System.Collections.Generic.List[string]]::new()
        PayloadKinds  = [System.Collections.Generic.List[string]]::new()
        BlankMeta = $false; NativeJna = $false
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
                $checkThis = ($ext -eq "") -or ($script:magicExt.ContainsKey($ext)) -or ($script:textExt -contains $ext)
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
                            if ($ext -eq "") {
                                if ($isClass -or (Get-ShannonEntropy $slice) -gt 7.0) { $hit = $true; $why = "extensionless" }
                            } elseif ($script:magicExt.ContainsKey($ext)) {
                                $magic = $script:magicExt[$ext]
                                $match = $true
                                for ($mi = 0; $mi -lt $magic.Count; $mi++) { if ($buf[$mi] -ne $magic[$mi]) { $match = $false; break } }
                                if (-not $match) { $hit = $true; $why = "$ext-magic" }
                            } elseif ($script:textExt -contains $ext) {
                                if ((Get-ShannonEntropy $slice) -gt 6.2) { $hit = $true; $why = "$ext-entropy" }
                            }
                            if ($hit) { $f.HiddenPayload++; if (-not $f.PayloadKinds.Contains($why)) { [void]$f.PayloadKinds.Add($why) } }
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
                    } elseif ($n -match 'MANIFEST\.MF$') {
                        if ($txt -match '(?im)^(Premain-Class|Agent-Class)\s*:\s*(\S+)') {
                            $f.JavaAgent = $true
                            $f.AgentClass = $matches[2]
                        }
                        if ($txt -match '(?im)^Can-(Retransform|Redefine)-Classes\s*:\s*true') { $f.AgentRetransform = $true }
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
    if ($ft.JavaAgent) {
        $score = [Math]::Max($score, $(if ($ft.AgentRetransform) { 90 } else { 80 }))
        $agentWhat = if ($ft.AgentRetransform) { "rewrites game code while it runs" } else { "loads as a Java agent" }
        [void]$reasons.Add("Injector: this jar $agentWhat ($($ft.AgentClass)) $([char]0x2014) normal mods never do this")
    }
    if ($ft.HiddenPayload -gt 0) {
        $score = [Math]::Max($score, 75)
        $pk = if (@($ft.PayloadKinds) -contains 'extensionless' -and @($ft.PayloadKinds).Count -eq 1) { "no extension" } else { "disguised as resources" }
        [void]$reasons.Add("Hidden payload: $($ft.HiddenPayload) encrypted/class file(s) $pk, decrypted at runtime")
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
    $bc = $ctx.Bytecode
    if ($bc -and $bc.ClassesParsed -gt 0) {
        # The aim / killaura fingerprint, verified against real cheat source: forging your
        # own outgoing movement packet while writing a computed rotation into it. Measured
        # separation on the corpus was total - no legitimate mod fakes its own movement.
        if ($bc.movepacketRatio -gt 0 -and $bc.rotationRatio -gt 0) {
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Behaviour: forges its own movement packet while writing a computed rotation $([char]0x2014) the aim/killaura fingerprint; normal mods never do this")
        }
        # Loader / dropper: decrypt something, then define a class out of the plaintext.
        if ($bc.cryptoRatio -ge 0.5 -and ($bc.classloadRatio -gt 0 -or $bc.reflectRatio -ge 0.5)) {
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Behaviour: decrypts data and defines classes from it at runtime $([char]0x2014) loader/dropper pattern")
        }
        # Forging your own movement is the line between automating the game and
        # lying to the server about where you are. Each of these pairs that forgery
        # with a second thing no legitimate mod combines it with. Measured on the
        # corpus at 0 hits across 405 clean jars, 177 of them real libraries.
        if ($bc.blockplaceRatio -gt 0 -and $bc.movepacketRatio -gt 0) {
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Behaviour: places blocks while forging its own movement packet $([char]0x2014) the scaffold/tower fingerprint. A schematic printer places blocks too, but through the game's own interaction system and without touching movement")
        }
        if ($bc.movepacketRatio -gt 0 -and $bc.motionRatio -gt 0) {
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Behaviour: writes its own velocity and then forges the movement packet to match $([char]0x2014) speed / no-fall / blink. The game never produced this movement")
        }
        if ($bc.containerRatio -gt 0 -and $bc.movepacketRatio -gt 0) {
            $score = [Math]::Max($score, 85)
            [void]$reasons.Add("Behaviour: clicks inventory slots while forging movement packets $([char]0x2014) moving with a container open, which the game does not allow. Inventory sorting mods click slots and never touch movement")
        }
        # Strong, but not the same order of certainty as forging movement, so these
        # flag rather than confirm.
        if ($bc.movepacketRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: sends its own movement packets and never reads the keyboard $([char]0x2014) the movement is not coming from the player")
        }
        if ($bc.entityscanRatio -gt 0 -and $bc.attackRatio -gt 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: attacks entities picked out of a full entity sweep $([char]0x2014) killaura / reach / triggerbot pick their target this way")
        }
        if ($bc.attackRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: attacks without ever reading a key or mouse button $([char]0x2014) the hits are not coming from the player (autoclicker / triggerbot)")
        }
        if ($bc.pktlistenRatio -gt 0 -and $bc.motionRatio -gt 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: intercepts incoming packets and rewrites the player's velocity $([char]0x2014) anti-knockback / velocity. A replay recorder listens to packets and never writes motion back")
        }
        if ($bc.blockbreakRatio -gt 0 -and $bc.inputRatio -eq 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: breaks blocks without reading input $([char]0x2014) nuker. A vein miner breaks blocks too, but only while the player is mining")
        }
        if ($bc.rotationRatio -gt 0 -and $bc.renderRatio -gt 0 -and $bc.movepacketRatio -eq 0) {
            $score = [Math]::Max($score, 60)
            [void]$reasons.Add("Behaviour: writes the player's look direction and renders from it $([char]0x2014) freecam. A third-person camera derives its position from the player instead of writing to them")
        }
        if ($bc.instrumentRatio -gt 0 -and $bc.ClassesParsed -gt 0) {
            $score = [Math]::Max($score, 80)
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
        if (-not $policy -and -not $forges -and $usesGameOnly -and $bc.ClassesParsed -gt 0 -and
            -not $ctx.HashKnownCheat -and ($ft.PackageHits.Count -eq 0) -and -not $ctx.CheatSite) {
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
    return @{ Score = $score; Band = $band; Probability = [int][Math]::Round($p * 100); Reasons = $reasons; Policy = $policy }
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
    $b = @{ ClassesParsed = 10; ClassesFailed = 0; ObfNameRatio = 0.0; StrReadableRatio = 0.9; StrEntropy = 0.0 }
    foreach ($k in $script:bcBehaviour.Keys) { $b[$k] = 0; $b[$k + 'Ratio'] = 0.0 }
    if ($over) { foreach ($k in $over.Keys) { $b[$k] = $over[$k] } }
    return $b
}

function New-TestFeatures($over) {
    $f = @{
        StrongStrings = @(); WeakStrings = @(); PackageHits = @(); Patterns = @(); FullwidthStr = $false
        FullwidthClsPct = 0.0; JapaneseClsPct = 0.0; SingleCharClsPct = 0.0; NumericClsPct = 0.0; NoVowelClsPct = 0.0
        AvgEntropy = 0.0; HighEntropyPct = 0.0; ReflectionCount = 0; RuntimeExec = $false; HttpDownload = $false
        HttpExfil = $false; NestedHollow = $false; ModId = ""; MetaName = ""; FakeIdentity = $false
        JavaAgent = $false; AgentRetransform = $false; AgentClass = ""; HiddenPayload = 0
        LoaderIds = @(); BlankMeta = $false; NativeJna = $false; PayloadKinds = @()
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
        @{ Label = "Reflection-heavy lib, no cheat behaviour"; Bands = @("Clean"); Over = @{ Features = (New-TestFeatures @{ ReflectionCount = 5 }); Bytecode = (New-TestBytecode @{ reflectRatio = 1.0 }) } }
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
        @{ Label = "Printer that ALSO forges movement"; Bands = @("Confirmed"); Over = @{ Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ blockplaceRatio = 1.0; inputRatio = 1.0; movepacketRatio = 1.0 }) } }
        @{ Label = "Known cheat hash beats the clean cap"; Bands = @("Confirmed"); Over = @{ HashKnownCheat = $true; Features = (New-TestFeatures @{}); Bytecode = (New-TestBytecode @{ containerRatio = 1.0; inputRatio = 1.0 }) } }
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
        @{ Label = "Gaps are reported, never swallowed"; Test = {
            $before = $script:ScanGaps.Count
            Add-ScanGap "self-test probe gap"
            Add-ScanGap "self-test probe gap"
            $ok = ($script:ScanGaps.Count -eq $before + 1)
            while ($script:ScanGaps.Count -gt $before) { $script:ScanGaps.RemoveAt($script:ScanGaps.Count - 1) }
            $ok } }
        @{ Label = "Full report renders and is written"; Test = {
            $tmp = Join-Path $env:TEMP "AsyncAnalyzer_SelfTest.html"
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
