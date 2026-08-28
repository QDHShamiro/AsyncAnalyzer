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
