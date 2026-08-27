$script:bcPreFilter = [regex]::new(
    ('ServerboundMovePlayerPacket|PlayerMoveC2SPacket|class_2828|setYRot|setXRot|setYaw|setPitch|' +
     'method_36456|method_36457|MultiPlayerGameMode|ServerboundInteractPacket|' +
     'PlayerInteractEntityC2SPacket|class_2824|ClientPacketListener|ClientPlayNetworkHandler|' +
     'class_634|entitiesForRendering|getEntities|method_18112|getEntityList|VertexConsumer|' +
     'RenderSystem|BufferBuilder|MatrixStack|PoseStack|Tessellator|class_4587|KeyMapping|' +
     'KeyBinding|glfwGetKey|isPressed|client/input|class_304|KeyboardHandler|MouseHandler|' +
     'net/minecraft/network/Connection|class_2535|java/lang/reflect|getDeclaredMethod|' +
     'setAccessible|forName|MethodHandles|getDeclaredField|defineClass|URLClassLoader|' +
     'defineAnonymousClass|defineHiddenClass|javax/crypto|Cipher|SecretKeySpec|IvParameterSpec|' +
     'getRuntime|ProcessBuilder|java/net/Socket|HttpURLConnection|openConnection|java/net/http|' +
     'openStream|sun/misc/Unsafe|jdk/internal/misc/Unsafe|java/lang/instrument|Instrumentation|' +
     'premain|agentmain|retransformClasses|' +
     'ServerboundUseItemOnPacket|PlayerInteractBlockC2SPacket|class_2885|useItemOn|interactBlock|method_2896|ServerboundPlayerActionPacket|PlayerActionC2SPacket|class_2846|startDestroyBlock|destroyBlock|method_2910|ServerboundContainerClickPacket|ClickSlotC2SPacket|class_2813|AbstractContainerMenu|ScreenHandler|class_1703|setDeltaMovement|getDeltaMovement|setVelocity|method_18800|method_18798|' +
     'getProtectionDomain|getCodeSource|ProtectionDomain|CodeSource|deleteOnExit|deleteIfExists'),
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

function Get-BytecodeFeatures([string]$JarPath, [int]$MaxClasses = 40) {
    $f = @{ ClassesParsed = 0; ClassesFailed = 0; ObfNameRatio = 0.0
            StrReadableRatio = 0.0; StrEntropy = 0.0 }
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
            # A class that finds its own jar and deletes a file, and is not
            # unpacking a native library: that is a jar removing itself.
            if ($hit['selfpath'] -and $hit['filedelete'] -and -not $hit['nativetemp']) {
                $hit['selfwipe'] = $true
            }
            foreach ($k in $script:bcReflectiveNames.Keys) {
                if ($hit.ContainsKey($k)) { continue }
                foreach ($s in $cp.Strings) {
                    if ($s -match $script:bcReflectiveNames[$k]) { $hit[$k] = $true; break }
                }
            }
            foreach ($k in $hit.Keys) { $f[$k]++ }

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
    if ($names -gt 0)    { $f.ObfNameRatio = [double]$short / [double]$names }
    if ($totalStr -gt 0) { $f.StrReadableRatio = [double]$readable / [double]$totalStr }
    if ($entN -gt 0)     { $f.StrEntropy = $entSum / [double]$entN }
    return $f
}
