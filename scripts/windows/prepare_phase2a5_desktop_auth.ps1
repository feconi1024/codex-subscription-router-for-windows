[CmdletBinding(PositionalBinding = $false)]
param(
    # Keep Python-style flags in RunnerArguments.  In particular, a flag such
    # as --ci-verified must never be mistaken for this optional path.
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))),
    [int]$TimeoutSeconds = 900,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RunnerArguments
)

$ErrorActionPreference = 'Stop'
if ($TimeoutSeconds -lt 60) {
    throw 'TimeoutSeconds must be at least 60 seconds for interactive Desktop authentication.'
}

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
Set-Location -LiteralPath $resolvedRepositoryRoot

Write-Host 'Phase 2A.5 Desktop authentication preparation'
Write-Host ("Repository: {0}" -f $resolvedRepositoryRoot)
Write-Host 'A patched Router-owned Desktop window will open with a persistent isolated profile.'
Write-Host 'Complete normal ChatGPT login in that window. Do not enter credentials in this terminal.'
Write-Host ("Authentication wait bound: {0} seconds" -f $TimeoutSeconds)

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

$pythonArguments += @(
    '--prepare-desktop-auth',
    '--timeout-seconds',
    [string]$TimeoutSeconds
)
if ($null -ne $RunnerArguments) {
    $pythonArguments += $RunnerArguments
}

# Foreground invocation is intentional: the user must see and complete the
# normal login in the opened validation window.  No credential material is
# read, supplied, copied, or printed by this workflow.
& $pythonCommand.Source @pythonArguments
exit $LASTEXITCODE
