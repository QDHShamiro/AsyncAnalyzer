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

"call order: {0} function(s), {1} reachable from top level, none used before it exists" -f $defLine.Count, $runsAt.Count
exit 0
