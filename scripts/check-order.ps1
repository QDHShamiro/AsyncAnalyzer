<#
    Is every function DEFINED before the point where it is first CALLED?

    The shipped script is one file assembled from src/*.ps1 in filename order,
    and PowerShell executes it top to bottom. A function call is resolved when it
    runs, not when it is parsed - so calling a function whose "function Foo {}"
    line has not been reached yet fails at runtime with

        Test-CheatName : The term ... is not recognized

    and nothing before that moment can see it coming. That is exactly what
    happened: Run-SystemChecks (defined in 91-system) called Test-CheatName
    (defined in what was then 94-pcscan), and 95-main.ps1 ran the scan in
    between. It parsed cleanly, the 90-case self-test passed, and it died on the
    first real Windows run - twice in a row, on two different bugs, which is what
    finally bought this check.

    It could not be caught by running the tool here either: that branch sits
    behind Test-Path $env:SystemRoot\Prefetch, and $env:SystemRoot is empty on
    Linux, so it was skipped in silence.

    So this walks it statically instead:

      1. every function definition, with the line it appears on;
      2. every command invocation, with its line and the function enclosing it;
      3. from the calls that sit at TOP LEVEL, follow the call graph and work out
         the earliest line at which each function can actually run;
      4. a function that runs at line L while its own definition sits at line
         D > L is the bug.

    Run:  pwsh -File scripts/check-order.ps1 [path]
#>
param([string]$Path = "$PSScriptRoot/../AsyncAnalyzer.ps1")

$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $Path), [ref]$null, [ref]$errs)
if ($errs) {
    $errs | ForEach-Object { "PARSE {0}:{1}  {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message }
    exit 1
}

# ---- 1. definitions -------------------------------------------------------
$defLine = @{}
foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    $n = $f.Name
    # A name defined twice: the first definition is the one that exists early,
    # so that is the line to judge by.
    if (-not $defLine.ContainsKey($n) -or $f.Extent.StartLineNumber -lt $defLine[$n]) {
        $defLine[$n] = $f.Extent.StartLineNumber
    }
}

# ---- 2. calls, and what encloses them -------------------------------------
# The enclosing function of a call is the innermost FunctionDefinitionAst whose
# extent contains it. Nested definitions exist in this file, so "innermost"
# matters rather than "any".
$funcs = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
function Get-Enclosing([int]$line) {
    $best = $null
    foreach ($f in $funcs) {
        if ($line -ge $f.Extent.StartLineNumber -and $line -le $f.Extent.EndLineNumber) {
            if ($null -eq $best -or $f.Extent.StartLineNumber -gt $best.Extent.StartLineNumber) { $best = $f }
        }
    }
    return $(if ($best) { $best.Name } else { "" })
}

$topCalls = @{}          # function name -> earliest top-level line calling it
$edges    = @{}          # caller name  -> @(callee names)
foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $c.GetCommandName()
    if (-not $name -or -not $defLine.ContainsKey($name)) { continue }
    $line = $c.Extent.StartLineNumber
    $enc = Get-Enclosing $line
    if (-not $enc) {
        if (-not $topCalls.ContainsKey($name) -or $line -lt $topCalls[$name]) { $topCalls[$name] = $line }
    } else {
        if (-not $edges.ContainsKey($enc)) { $edges[$enc] = New-Object System.Collections.Generic.List[string] }
        if (-not $edges[$enc].Contains($name)) { [void]$edges[$enc].Add($name) }
    }
}

# ---- 3. the earliest line at which each function can run ------------------
# A function called from top level at line L runs at L. Anything IT calls also
# runs at L, and so on down the graph - the earliest reachable line wins.
$runsAt = @{}
foreach ($k in $topCalls.Keys) { $runsAt[$k] = $topCalls[$k] }
$changed = $true
$rounds = 0
while ($changed -and $rounds -lt 200) {
    $changed = $false; $rounds++
    foreach ($caller in @($runsAt.Keys)) {
        if (-not $edges.ContainsKey($caller)) { continue }
        foreach ($callee in $edges[$caller]) {
            $at = $runsAt[$caller]
            if (-not $runsAt.ContainsKey($callee) -or $at -lt $runsAt[$callee]) {
                $runsAt[$callee] = $at; $changed = $true
            }
        }
    }
}

# ---- 4. the ones that would not exist yet ---------------------------------
$bad = New-Object System.Collections.Generic.List[string]
foreach ($n in $runsAt.Keys) {
    if ($defLine[$n] -gt $runsAt[$n]) {
        $bad.Add(("{0}  is defined on line {1} but can run at line {2}" -f $n, $defLine[$n], $runsAt[$n]))
    }
}

if ($bad.Count -gt 0) {
    "FUNCTIONS THAT CAN RUN BEFORE THEY EXIST:"
    $bad | Sort-Object | ForEach-Object { "  $_" }
    ""
    "Move the definition into an earlier src/ section (the file is assembled in"
    "filename order), or move the call later."
    exit 1
}

# ---- 5. $script: read but never $script: assigned --------------------------
# A variable ASSIGNED at top level without the prefix and READ inside a function
# WITH it only lands in the same scope when the file is run with -File. This tool
# is delivered as iex (irm ...), where it does not - and the scan died on the
# fourth jar with "you cannot call a method on a null-valued expression",
# because $script:verifiedMods was $null.
#
# Running it here could not have caught that: -File creates a script scope and
# iex does not. So it is checked instead of tested around.
$scriptRead = @{}
foreach ($v in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    $u = $v.VariablePath.UserPath
    if ($u -like 'script:*') { $scriptRead[($u -replace '^script:', '')] = $true }
}
$scriptAssigned = @{}
foreach ($a in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $l = $a.Left
    if ($l -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $u = $l.VariablePath.UserPath
        if ($u -like 'script:*') { $scriptAssigned[($u -replace '^script:', '')] = $true }
    }
}
$unset = @($scriptRead.Keys | Where-Object { -not $scriptAssigned.ContainsKey($_) } | Sort-Object)
if ($unset.Count -gt 0) {
    "READ AS `$script: BUT NEVER ASSIGNED AS `$script::"
    $unset | ForEach-Object { "  $_" }
    ""
    "An unqualified top-level assignment lands in the same scope only under -File."
    "This tool is delivered as iex (irm ...). Assign and read the same way."
    exit 1
}

# ---- 6. cmdlets that may simply not be there ------------------------------
# -ErrorAction handles errors a cmdlet RAISES. It cannot handle the cmdlet not
# existing: that is a CommandNotFoundException thrown before the cmdlet is
# reached, and under $ErrorActionPreference = 'Stop' - which GitHub Actions sets
# for every pwsh step - it ends the script.
#
# Two of these were real rather than theoretical. Get-WmiObject was REMOVED in
# PowerShell 7, and Run-JVMScan called it unguarded: on a PC where pwsh is the
# default shell the injected-client check found no java processes and returned an
# empty result, which reads exactly like "checked, nothing there". And `chcp`,
# eight lines into the script, killed every CI self-test before one check ran.
#
# So: a call to anything on this list has to sit inside a try, where the failure
# becomes a coverage gap instead of the end of the scan.
$optional = @(
    'Get-Service', 'Get-MpPreference', 'Get-ScheduledTask', 'Get-NetFirewallProfile',
    'Get-NetTCPConnection', 'Get-WinEvent', 'Get-ComputerInfo', 'Get-LocalUser',
    'Get-Volume', 'Get-Disk', 'Get-AuthenticodeSignature', 'Get-EventLog',
    'Test-NetConnection', 'Get-WmiObject', 'Get-CimInstance', 'chcp'
)
$unguarded = New-Object System.Collections.Generic.List[string]
foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if ($optional -notcontains $n) { continue }
    # Inside the helper that exists to probe for them, guarded by Get-Command.
    if ((Get-Enclosing $c.Extent.StartLineNumber) -eq 'Get-WmiOrCim') { continue }
    $p = $c.Parent; $ok = $false
    while ($p) {
        if ($p -is [System.Management.Automation.Language.TryStatementAst]) {
            # the TRY block itself - a call inside the catch is not protected
            if ($p.Body.Extent.StartOffset -le $c.Extent.StartOffset -and
                $c.Extent.EndOffset -le $p.Body.Extent.EndOffset) { $ok = $true }
            break
        }
        # `if (Get-Command X ...) { X ... }` is the other honest guard
        if ($p -is [System.Management.Automation.Language.IfStatementAst] -and
            $p.Clauses[0].Item1.Extent.Text -match "Get-Command\s+$n\b") { $ok = $true; break }
        $p = $p.Parent
    }
    if (-not $ok) { $unguarded.Add(("{0,6}  {1}" -f $c.Extent.StartLineNumber, $n)) }
}
if ($unguarded.Count -gt 0) {
    "CALLED WITHOUT A GUARD, AND MAY NOT EXIST:"
    $unguarded | ForEach-Object { "  $_" }
    ""
    "-ErrorAction cannot suppress a command that is not there. Wrap it in try/catch"
    "and record a coverage gap, or test for it with Get-Command first."
    exit 1
}

"call order: {0} function(s), {1} reachable from top level, none used before it exists" -f $defLine.Count, $runsAt.Count
"script scope: {0} name(s) read with the prefix, every one of them assigned with it" -f $scriptRead.Count
"optional cmdlets: every call to one that may not exist is guarded"
exit 0
