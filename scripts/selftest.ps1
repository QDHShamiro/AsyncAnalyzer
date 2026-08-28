<#
    Run the shipped script's own -SelfTest, the way CI runs it.

    Two details decide whether this proves anything, and both were wrong at once:

      *>&1, not 2>&1. Everything the tool prints goes through W, which is
      Write-Host, which writes to the INFORMATION stream. 2>&1 merges only errors,
      so the captured output was 324 characters of nothing and the pass/fail test
      below was reading an empty string - the step could only ever fail.

      $ErrorActionPreference = 'stop'. GitHub Actions sets it for every pwsh step.
      Under it, a missing EXTERNAL command is fatal, and `chcp` does not exist off
      Windows - so the script died on line 33 before one check had run, while the
      same run without Stop passed. Running it here the lenient way is how that was
      missed.

    So there is one script, used by the workflow and by hand, and the two cannot
    drift apart.

    Run:  pwsh -File scripts/selftest.ps1 [path-to-AsyncAnalyzer.ps1]
#>
param([string]$Path = "$PSScriptRoot/../AsyncAnalyzer.ps1")

$ErrorActionPreference = 'stop'
$out = & (Resolve-Path $Path) -SelfTest *>&1 | Out-String
$out
if ($out -match 'self-test\(s\) FAILED') {
    "one or more self-tests failed"
    exit 1
}
if ($out -notmatch 'All \d+ self-tests passed') {
    "the self-test never reached its summary line - it died partway through"
    exit 1
}
exit 0
