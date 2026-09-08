"""Owner/SYSTEM-only state DACLs; never grants AppContainer access to secrets."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .managed_paths import reject_reparse


def secure_directory(path: Path) -> None:
    reject_reparse(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
        return
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        raise RuntimeError("PowerShell is required to protect Windows state")
    literal = "'" + str(path.absolute()).replace("'", "''") + "'"
    script = """
$ErrorActionPreference = 'Stop'
$target = PATH_LITERAL
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($principal in @($sid, [System.Security.Principal.SecurityIdentifier]'S-1-5-18')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $target -AclObject $acl
$observed = Get-Acl -LiteralPath $target
if (!$observed.AreAccessRulesProtected) { throw 'State DACL inheritance is not protected' }
$entries = @($observed.Access)
if ($entries.Count -ne 2) { throw 'Unexpected private state access entries' }
foreach ($entry in $entries) {
    $id = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($id -notin @($sid.Value, 'S-1-5-18') -or $entry.AccessControlType -ne 'Allow' -or $entry.FileSystemRights -ne 'FullControl') {
        throw 'Private state DACL verification failed'
    }
}
""".replace("PATH_LITERAL", literal)
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("could not verify owner/SYSTEM-only state DACL: " + result.stderr.strip()[:600])
