[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RunnerArguments
)

$ErrorActionPreference = 'Stop'
$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
Set-Location -LiteralPath $resolvedRepositoryRoot

Write-Host 'Phase 2A.5 must be started manually from this independently opened terminal.'
Write-Host ("Repository: {0}" -f $resolvedRepositoryRoot)

$pythonCommand = Get-Command -Name 'py' -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) {
    $pythonCommand = Get-Command -Name 'python' -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        throw 'Python 3 was not found. Install Python 3 or make python.exe available on PATH.'
    }
    $pythonArguments = @('-m', 'scripts.windows.phase2a5_host_validation')
} else {
    $pythonArguments = @('-3', '-m', 'scripts.windows.phase2a5_host_validation')
}

if ($null -ne $RunnerArguments) {
    $pythonArguments += $RunnerArguments
}

# This is a foreground invocation only.  The Python process must prove its own
# package identity state; the launch mechanism is not treated as evidence.
& $pythonCommand.Source @pythonArguments
exit $LASTEXITCODE
