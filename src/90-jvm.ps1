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
                        $r.Gaps.Add("The running game is loading mods from $ld, which this scan did not look at $([char]0x2014) re-run with -Path '$ld' to include it.")
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
