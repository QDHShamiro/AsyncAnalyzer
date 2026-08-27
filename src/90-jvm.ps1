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
                $jvmFlags.Add("Live-memory check skipped $([char]0x2014) needs 64-bit PowerShell (this host is 32-bit)")
            } else {
            $handle = [Win32.MemAPI]::OpenProcess(0x10 -bor 0x400, $false, $proc.ProcessId)
            if ($handle -ne [IntPtr]::Zero) {
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

                while ([Win32.MemAPI]::VirtualQueryEx($handle, $addr, [ref]$mbi, [uint32]$mbiSize) -and $scanLimit -lt 200000) {
                    $scanLimit++
                    if ($memWatch.Elapsed.TotalSeconds -gt $memBudget) {
                        $jvmFlags.Add("Live-memory check stopped at its $memBudget s budget $([char]0x2014) run with -Deep for a longer sweep")
                        break
                    }
                    # .ToInt64() rather than a cast: IntPtr does not implement IConvertible,
                    # so [int64]$ptr throws on PowerShell 5.1.
                    $regionSize = $mbi.RegionSize.ToInt64()
                    # committed, and readable+writable (the JVM heap) or RWX (JIT / injected code)
                    $readable = (($mbi.Protect -band 0x04) -ne 0) -or (($mbi.Protect -band 0x40) -ne 0)
                    if ($mbi.State -eq 0x1000 -and $readable -and $regionSize -gt 0) {
                        $offset = [int64]0
                        while ($offset -lt $regionSize) {
                            if ($memWatch.Elapsed.TotalSeconds -gt $memBudget) { break }
                            $take = [int][Math]::Min([int64]$chunkSize, $regionSize - $offset)
                            $buf  = New-Object byte[] $take
                            $read = 0
                            $rAddr = [IntPtr]($mbi.BaseAddress.ToInt64() + $offset)
                            if (-not ([Win32.MemAPI]::ReadProcessMemory($handle, $rAddr, $buf, $take, [ref]$read)) -or $read -le 0) { break }
                            $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
                            foreach ($mm in $memRegex.Matches($str)) {
                                $term = $mm.Groups[1].Value
                                $key  = $term.ToLower()
                                if (-not $memHits.ContainsKey($key)) {
                                    $memHits[$key] = @{
                                        Label = $term
                                        Kind  = $(if ($memClientSet.Contains($term)) { "client" } else { "module" })
                                        Hits  = 0
                                        Addr  = ("0x{0:X}" -f $mbi.BaseAddress.ToInt64())
                                    }
                                }
                                $memHits[$key].Hits++
                            }
                            $offset += $read
                        }
                    }
                    try { $addr = [IntPtr]($mbi.BaseAddress.ToInt64() + $regionSize) } catch { break }
                    if ($regionSize -le 0) { break }
                }
                [Win32.MemAPI]::CloseHandle($handle) | Out-Null
                $memWatch.Stop()

                # Report WHAT was found, WHERE, and whether it is a cheat.
                foreach ($mk in @($memHits.Keys | Sort-Object)) {
                    $mh = $memHits[$mk]
                    $where = "$($proc.Name) (PID $($proc.ProcessId)) at $($mh.Addr), $($mh.Hits) hit(s)"
                    if ($mh.Kind -eq "client") {
                        # The strong claim - "injected, nothing on disk could have loaded
                        # it" - needs stronger evidence than a plain memory hit, because a
                        # short word can appear in RAM by coincidence (a chat message, a
                        # server MOTD). Require a distinctive token AND repeated hits, which
                        # is what loaded code looks like versus one stray string.
                        if ($mh.Label.Length -ge 6 -and $mh.Hits -ge 3 -and -not (Test-LoadedFromDisk $mh.Label)) {
                            # Nothing on disk could have supplied these classes.
                            $jvmFlags.Add("INJECTED CHEAT CLIENT: $($mh.Label) $([char]0x2014) live in $where, and NO jar on disk contains it. It was injected straight into the running game, so deleting files cannot hide it and a file scan alone would never have found it.")
                            $script:Evidence.MemInjectedOnly++
                        } else {
                            $jvmFlags.Add("INJECTED CHEAT CLIENT: $($mh.Label) $([char]0x2014) identified live in $where. This IS a cheat and it is loaded in the running game right now.")
                        }
                        $script:Evidence.MemCheatClient++
                    } else {
                        $jvmFlags.Add("Cheat module active in memory: $($mh.Label) $([char]0x2014) found in $where. A cheat feature is live in the running game.")
                        $script:Evidence.MemModule++
                    }
                }
            }
            }   # end 64-bit guard
        } catch {} }
    }

    return $jvmFlags
}
