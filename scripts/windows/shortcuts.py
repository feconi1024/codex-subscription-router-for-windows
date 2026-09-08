"""Own one per-user Start Menu entry without overwriting another installation."""
import os
import shutil
import subprocess
from pathlib import Path

from .managed_paths import reject_reparse


def start_menu(layout, *, remove: bool = False) -> str:
    if os.name != "nt" or not os.environ.get("APPDATA"):
        return "NOT_AVAILABLE"
    shortcut = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Codex Subscription Router.lnk"
    reject_reparse(shortcut)
    target = layout.root / "Codex Subscription Router.exe"
    quote = lambda path: "'" + str(path).replace("'", "''") + "'"
    script = """
$ErrorActionPreference = 'Stop'
$linkPath = LINK
$target = TARGET
$shell = New-Object -ComObject WScript.Shell
if (Test-Path -LiteralPath $linkPath) {
    $existing = $shell.CreateShortcut($linkPath)
    if ($existing.TargetPath -ne $target) { Write-Output 'OTHER_INSTALLATION'; exit 0 }
}
""".replace("LINK", quote(shortcut)).replace("TARGET", quote(target))
    if remove:
        script += "Remove-Item -LiteralPath $linkPath -Force -ErrorAction SilentlyContinue\nWrite-Output 'REMOVED'"
    else:
        shortcut.parent.mkdir(parents=True, exist_ok=True)
        script += "$link = $shell.CreateShortcut($linkPath)\n$link.TargetPath = $target\n$link.WorkingDirectory = Split-Path -LiteralPath $target\n$link.Description = 'Codex Subscription Router'\n$link.Save()\nWrite-Output 'CREATED'"
    powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not powershell:
        return "NOT_AVAILABLE"
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Start Menu shortcut operation failed: " + result.stderr[:500])
    return result.stdout.strip()
