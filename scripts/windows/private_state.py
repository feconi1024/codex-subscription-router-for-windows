"""Owner/SYSTEM-only state DACLs; never grants AppContainer access to secrets."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .managed_paths import reject_reparse


def secure_directory(path: Path, *, verify_only: bool = False) -> None:
    reject_reparse(path)
    if not verify_only:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        if verify_only:
            if path.stat().st_mode & 0o077:
                raise RuntimeError("private state permissions allow other users")
        else:
            path.chmod(0o700)
        return
    powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not powershell:
        raise RuntimeError("PowerShell is required to protect Windows state")
    literal = "'" + str(path.absolute()).replace("'", "''") + "'"
    apply_acl = r'''
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RouterPrivateDacl {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, IntPtr size);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint SetNamedSecurityInfoW(string path, uint type, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static void Protect(string path, string sid) {
        IntPtr sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)", 1, out sd, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            bool present, defaulted;
            IntPtr dacl;
            if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            uint error = SetNamedSecurityInfoW(path, 1, 0x80000004, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (error != 0) throw new Win32Exception((int)error);
        } finally { LocalFree(sd); }
    }
}
'@
[RouterPrivateDacl]::Protect($target, $sid.Value)
'''
    script = """
$ErrorActionPreference = 'Stop'
$target = PATH_LITERAL
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
APPLY_ACL
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
""".replace("PATH_LITERAL", literal).replace("APPLY_ACL", "" if verify_only else apply_acl)
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("could not verify owner/SYSTEM-only state DACL: " + result.stderr.strip()[:600])
