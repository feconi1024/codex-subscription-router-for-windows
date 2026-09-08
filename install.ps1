[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Codex Subscription Router'),
    [string]$Ref = 'main',
    [string]$Source,
    [string]$RealCodex,
    [string]$SigningThumbprint,
    [switch]$AdoptValidationProfile,
    [switch]$RequireNative,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'This installer requires Windows.' }

# A checked-out installer uses that exact checkout. Piped execution obtains
# source only; no OpenAI executable or patched bundle is downloaded.
$routerSourceRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($routerSourceRoot)) {
    $routerSourceRoot = Join-Path $InstallRoot 'Source'
    if (Test-Path -LiteralPath $routerSourceRoot) {
        throw "A source directory already exists. Run its install.ps1 to review and reuse that checkout: $routerSourceRoot"
    }
    $null = Get-Command git -ErrorAction Stop
    & git clone --branch $Ref --single-branch 'https://github.com/feconi1024/codex-subscription-router-for-windows.git' $routerSourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'Could not obtain Router source.' }
}
if (!(Test-Path -LiteralPath (Join-Path $routerSourceRoot 'scripts/routerctl.py'))) { throw 'Router source checkout is incomplete.' }
$routerPython = (Get-Command python.exe -ErrorAction Stop).Source
$null = Get-Command go.exe -ErrorAction Stop
$null = Get-Command node.exe -ErrorAction Stop
$routerNpm = (Get-Command npm.cmd -ErrorAction Stop).Source
& $routerPython -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'
if ($LASTEXITCODE -ne 0) { throw 'Unsupported Python runtime.' }
Push-Location -LiteralPath $routerSourceRoot
try {
    & $routerNpm ci --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw 'Locked build dependency installation failed.' }
    $routerArguments = @((Join-Path $routerSourceRoot 'scripts/routerctl.py'), '--root', $InstallRoot, 'install')
    if ($Source) { $routerArguments += @('--source', $Source) }
    if ($RealCodex) { $routerArguments += @('--real-codex', $RealCodex) }
    if ($SigningThumbprint) { $routerArguments += @('--signing-thumbprint', $SigningThumbprint) }
    if ($AdoptValidationProfile) { $routerArguments += '--adopt-validation-profile' }
    if ($RequireNative) { $routerArguments += '--require-native' }
    & $routerPython @routerArguments
    if ($LASTEXITCODE -ne 0) { throw 'Router installation did not pass. Any previous build and account data were retained.' }
} finally {
    Pop-Location
}
if (!$NoLaunch) {
    Start-Process -FilePath (Join-Path $InstallRoot 'Codex Subscription Router.exe') -WindowStyle Hidden
}
