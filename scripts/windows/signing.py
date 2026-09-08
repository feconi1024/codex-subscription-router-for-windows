"""Sign only Router-owned executables; never re-sign patched OpenAI programs."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .discovery import read_authenticode
from .managed_paths import reject_reparse


def sign_project_binaries(build: Path, thumbprint: str) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", thumbprint):
        raise ValueError("signing thumbprint must contain exactly 40 hexadecimal characters")
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        raise RuntimeError("PowerShell is required for signing")
    result = {}
    for relative in ("Codex Subscription Router.exe", "runtime/codex-mux.exe"):
        path = build / relative
        reject_reparse(path)
        literal = "'" + str(path).replace("'", "''") + "'"
        script = f"""
$ErrorActionPreference = 'Stop'
$cert = Get-Item -LiteralPath 'Cert:\CurrentUser\My\{thumbprint}'
if (!$cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)) {{ throw 'A valid private code-signing key is required' }}
if ('1.3.6.1.5.5.7.3.3' -notin @($cert.EnhancedKeyUsageList.ObjectId)) {{ throw 'Certificate does not permit code signing' }}
$signature = Set-AuthenticodeSignature -LiteralPath {literal} -Certificate $cert -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
if ($signature.Status -ne 'Valid') {{ throw 'Authenticode signing did not validate' }}
"""
        completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=90)
        if completed.returncode:
            raise RuntimeError("project binary signing failed: " + completed.stderr[:500])
        signature = read_authenticode(path)
        if signature.status.casefold() != "valid":
            raise RuntimeError("signed project binary did not validate")
        result[relative] = {"status": signature.status, "signer": signature.signer}
    return result
