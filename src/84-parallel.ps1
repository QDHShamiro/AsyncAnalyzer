# ---------------------------------------------------------------------------
# The same analysis, on more than one core.
#
# Measured on 60 real libraries from Maven Central, PowerShell 7.4, one jar at a
# time:
#
#     Bytecode      840.6 ms/jar   (only runs for jars that are NOT verified)
#     Murmur2       583.5 ms/jar   (only for the CurseForge lookup)
#     JarFeatures   367.9 ms/jar   (every jar)
#     Filename       15.7 ms/jar
#     DiskPackages    4.5 ms/jar
#     SHA1            2.9 ms/jar
#
# A normal modpack is mostly VERIFIED mods, which skip the bytecode pass - so the
# floor everybody pays is SHA1 + features + packages, about 375 ms a jar. On the
# real 78-mod pack this was measured against, that is half a minute of a
# screenshare spent waiting, and it is all file reading and parsing with nothing
# shared between one jar and the next.
#
# So those three run in a runspace pool (PowerShell 5.1 has no
# ForEach-Object -Parallel) and the results are handed to the unchanged
# per-jar analysis. Two rules make that safe to do to a tool whose whole job is
# being right:
#
#   1. THE WORKER ONLY READS. It computes; it decides nothing. Every verdict is
#      still reached one jar at a time, in the original order, by the same code as
#      before - so a scan cannot come out differently because a machine has more
#      cores. $script:DiskPackages is the one piece of shared state involved, and
#      the worker returns a list instead of touching it.
#   2. THE WORKER RUNS THE SHIPPED FUNCTIONS. It is handed Get-JarFeatures itself,
#      not a copy of it, along with the transitive closure of everything those
#      functions call and every $script: table they read - all worked out from
#      their own ASTs at runtime. A second implementation that drifts from the
#      first is exactly the bug this tool cannot afford.
#
# If anything about the pool fails, Invoke-JarAnalysis computes inline as it
# always did. Same functions, same results, just slower.
# ---------------------------------------------------------------------------

# What the worker computes. Everything else stays on the main thread.
$script:parRoots = @('Get-FileSHA1', 'Get-JarFeatures', 'Get-JarPackages')

# Mutable shared state must never be copied into a worker: each runspace would get
# its own and the additions would be lost, or worse, kept.
$script:parNeverCopy = @('DiskPackages')

function Get-ParallelClosure {
    <#
        Every function the roots reach, and every $script: name they read.

        Derived, not maintained. A hand-written list rots silently here: a helper
        that is missing from the worker does not throw, it just is not found, and
        the jar comes back with a feature quietly unset - which is the kind of
        thing that turns into a wrong verdict rather than an error message.
    #>
    if ($script:parClosure) { return $script:parClosure }
    $funcs = @{}
    $vars  = @{}
    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($r in $script:parRoots) { $queue.Enqueue($r) }
    while ($queue.Count -gt 0) {
        $name = $queue.Dequeue()
        if ($funcs.ContainsKey($name)) { continue }
        $cmd = Get-Command $name -CommandType Function -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $funcs[$name] = $cmd.ScriptBlock.ToString()
        $ast = $cmd.ScriptBlock.Ast
        foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $n = $c.GetCommandName()
            if ($n -and -not $funcs.ContainsKey($n)) {
                if (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue) { $queue.Enqueue($n) }
            }
        }
        foreach ($v in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
            $u = $v.VariablePath.UserPath
            if ($u -like 'script:*') {
                $vn = $u -replace '^script:', ''
                if ($script:parNeverCopy -notcontains $vn) { $vars[$vn] = $true }
            }
        }
    }
    $script:parClosure = @{ Functions = $funcs; Variables = @($vars.Keys) }
    return $script:parClosure
}

function New-ParallelPool([int]$Size) {
    <#
        A pool whose runspaces already contain the closure. The tables go in as
        InitialSessionState variables, which land where $script:X inside those
        functions reads them - verified, not assumed.
    #>
    $cl = Get-ParallelClosure
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($n in $cl.Functions.Keys) {
        $iss.Commands.Add(
            (New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $n, $cl.Functions[$n]))
    }
    foreach ($n in $cl.Variables) {
        $val = Get-Variable -Name $n -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $val) { continue }
        $iss.Variables.Add(
            (New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry $n, $val, ''))
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, $Size, $iss, $Host)
    $pool.Open()
    return $pool
}

# One jar's worth of reading. No decisions, no shared state, no output.
$script:parWorker = {
    param([string]$Path)
    $r = @{ Path = $Path; Sha1 = $null; Features = $null; Packages = @() }
    try { $r.Sha1     = Get-FileSHA1 $Path }     catch {}
    try { $r.Features = Get-JarFeatures $Path }  catch {}
    try { $r.Packages = @(Get-JarPackages $Path) } catch {}
    return $r
}

function Invoke-JarPrecompute($Jars) {
    <#
        path -> @{ Sha1; Features; Packages } for every jar, computed in parallel.

        Returns an empty table on any failure, and on a job that came back without
        features: the caller then computes that jar inline, which is what it did
        before this file existed. Never a partial answer presented as a whole one.
    #>
    $out = @{}
    $list = @($Jars)
    $cores = [Environment]::ProcessorCount
    # Below this the pool costs more than it saves - a runspace pool takes a few
    # hundred milliseconds to stand up, and a four-jar folder is done by then.
    if ($list.Count -lt 6 -or $cores -lt 2) { return $out }
    $size = [Math]::Min([Math]::Max(2, $cores), 8)

    $pool = $null
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $pool = New-ParallelPool $size
        $jobs = New-Object System.Collections.Generic.List[object]
        foreach ($j in $list) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($script:parWorker).AddArgument($j.FullName)
            [void]$jobs.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $j.Name })
        }
        $done = 0
        foreach ($job in $jobs) {
            try {
                $res = $job.PS.EndInvoke($job.Handle)
                foreach ($r in @($res)) {
                    if ($r -and $r.Path -and $r.Features) { $out[[string]$r.Path] = $r }
                }
            } catch {
            } finally { $job.PS.Dispose() }
            $done++
            Spin "[$done/$($list.Count)] reading $($job.Name)"
        }
        SpinClear
        $sw.Stop()
        if ($out.Count -gt 0) {
            W ("  $([char]0x2713) Read $($out.Count) jar(s) on $size cores in " +
               ("{0:N1}s" -f $sw.Elapsed.TotalSeconds) + " $([char]0x2014) the analysis itself is unchanged.") DarkGray
        }
    } catch {
        # Not a coverage gap: nothing was skipped. The same work happens inline.
        $out = @{}
    } finally {
        if ($pool) { try { $pool.Close(); $pool.Dispose() } catch {} }
    }
    return $out
}
