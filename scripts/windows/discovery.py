"""Windows AppX desktop and per-user native Codex discovery."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


WINDOWS_NATIVE_MACHINES = {0x014C, 0x8664, 0xAA64}


@dataclass(frozen=True)
class PackageMetadata:
    name: str = "unknown"
    package_full_name: str = "unknown"
    version: str = "unknown"
    install_location: Path | None = None
    architecture: str = "unknown"
    status: str = "unknown"


@dataclass(frozen=True)
class DesktopSource:
    source_root: Path
    app_dir: Path
    executable: Path
    resources_dir: Path
    app_asar: Path
    package: PackageMetadata
    source_kind: str
    file_version: str


@dataclass(frozen=True)
class AuthenticodeMetadata:
    status: str
    signer: str | None


@dataclass(frozen=True)
class RealCodexCandidate:
    path: Path
    version: str
    sha256: str
    authenticode: AuthenticodeMetadata
    modified_time: float
    valid_native: bool


def _powershell_executable() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_powershell_json(script: str) -> Any:
    executable = _powershell_executable()
    if executable is None:
        return None
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def query_appx_packages() -> list[PackageMetadata]:
    """Query the current user's AppX metadata without touching WindowsApps ACLs."""
    script = """
$packages = @(Get-AppxPackage -ErrorAction Stop | Where-Object {
  $_.Name -match 'OpenAI|ChatGPT|Codex' -or
  $_.PackageFullName -match 'OpenAI|ChatGPT|Codex' -or
  $_.InstallLocation -match 'OpenAI|ChatGPT|Codex'
} | Select-Object Name,PackageFullName,Version,InstallLocation,Architecture,Status)
if ($packages.Count -gt 0) { $packages | ConvertTo-Json -Compress }
"""
    try:
        parsed = _run_powershell_json(script)
    except (OSError, subprocess.SubprocessError):
        return []
    if parsed is None:
        return []
    rows = parsed if isinstance(parsed, list) else [parsed]
    packages: list[PackageMetadata] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        location = row.get("InstallLocation")
        packages.append(
            PackageMetadata(
                name=str(row.get("Name") or "unknown"),
                package_full_name=str(row.get("PackageFullName") or "unknown"),
                version=str(row.get("Version") or "unknown"),
                install_location=Path(location) if isinstance(location, str) and location else None,
                architecture=str(row.get("Architecture") or "unknown"),
                status=str(row.get("Status") or "unknown"),
            )
        )
    return packages


def is_windowsapps_path(path: Path) -> bool:
    return any(part.casefold() == "windowsapps" for part in path.resolve(strict=False).parts)


def is_native_windows_executable(path: Path) -> bool:
    """Validate the PE header and machine type before considering a candidate."""
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as handle:
            header = handle.read(0x1000)
    except OSError:
        return False
    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 6 > len(header):
        try:
            with path.open("rb") as handle:
                handle.seek(pe_offset)
                pe_header = handle.read(6)
        except OSError:
            return False
    else:
        pe_header = header[pe_offset : pe_offset + 6]
    return pe_header[:4] == b"PE\0\0" and int.from_bytes(pe_header[4:6], "little") in WINDOWS_NATIVE_MACHINES


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_file_version(path: Path) -> str:
    """Read PE version metadata through PowerShell when available."""
    script = (
        f"$i=(Get-Item -LiteralPath {_powershell_quote(str(path))}).VersionInfo; "
        "[pscustomobject]@{FileVersion=$i.FileVersion;ProductVersion=$i.ProductVersion} "
        "| ConvertTo-Json -Compress"
    )
    try:
        parsed = _run_powershell_json(script)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if isinstance(parsed, dict):
        value = parsed.get("FileVersion") or parsed.get("ProductVersion")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def read_authenticode(path: Path) -> AuthenticodeMetadata:
    """Inspect signature status only; no credential or app profile data is read."""
    script = (
        f"$s=Get-AuthenticodeSignature -LiteralPath {_powershell_quote(str(path))}; "
        "[pscustomobject]@{Status=[string]$s.Status;Signer="
        "$(if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null})} "
        "| ConvertTo-Json -Compress"
    )
    try:
        parsed = _run_powershell_json(script)
    except (OSError, subprocess.SubprocessError):
        parsed = None
    if isinstance(parsed, dict):
        return AuthenticodeMetadata(
            status=str(parsed.get("Status") or "Unknown"),
            signer=str(parsed["Signer"]) if parsed.get("Signer") else None,
        )
    return AuthenticodeMetadata(status="Unknown", signer=None)


def read_codex_version(path: Path) -> str:
    try:
        result = subprocess.run(
            [str(path), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0].strip() if output else "unknown"


def _candidate_modified_time(path: Path) -> float:
    try:
        return max(path.stat().st_mtime, path.parent.stat().st_mtime)
    except OSError:
        return 0.0


def _iter_codex_candidates(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return ()
    try:
        return tuple(path for path in root.rglob("codex.exe") if path.is_file())
    except OSError:
        return ()


def discover_real_codex(
    explicit: Path | None = None,
    *,
    bin_root: Path | None = None,
) -> tuple[RealCodexCandidate, list[RealCodexCandidate]]:
    """Select the newest valid native executable, preferring valid OpenAI signatures."""
    if explicit is not None:
        path = explicit.expanduser().resolve(strict=False)
        if is_windowsapps_path(path):
            raise RuntimeError(
                "refusing to use a bundled WindowsApps codex.exe; provide the "
                "relocated per-user OpenAI Codex binary instead"
            )
        paths = [path]
    else:
        root = bin_root or (
            Path(os.environ["LOCALAPPDATA"]) / "OpenAI" / "Codex" / "bin"
            if os.environ.get("LOCALAPPDATA")
            else Path.home() / "AppData" / "Local" / "OpenAI" / "Codex" / "bin"
        )
        paths = sorted(set(_iter_codex_candidates(root)), key=lambda item: str(item).casefold())
    candidates: list[RealCodexCandidate] = []
    for path in paths:
        if is_windowsapps_path(path):
            continue
        if not is_native_windows_executable(path):
            continue
        candidates.append(
            RealCodexCandidate(
                path=path,
                version=read_codex_version(path),
                sha256=sha256_file(path),
                authenticode=read_authenticode(path),
                modified_time=_candidate_modified_time(path),
                valid_native=True,
            )
        )
    if not candidates:
        source = str(explicit) if explicit is not None else str(bin_root or "%LOCALAPPDATA%\\OpenAI\\Codex\\bin")
        raise RuntimeError(f"no valid native codex.exe candidate found under {source}")

    def rank(candidate: RealCodexCandidate) -> tuple[int, int, float, str]:
        status_valid = int(candidate.authenticode.status.casefold() == "valid")
        signer_openai = int("openai" in (candidate.authenticode.signer or "").casefold())
        return status_valid, signer_openai, candidate.modified_time, str(candidate.path).casefold()

    candidates.sort(key=rank, reverse=True)
    return candidates[0], candidates


def _executable_candidates(app_dir: Path) -> list[Path]:
    try:
        files = [item for item in app_dir.iterdir() if item.is_file() and item.suffix.casefold() == ".exe"]
    except OSError:
        return []
    names = {item.name.casefold(): item for item in files}
    preferred = [names[name] for name in ("chatgpt.exe", "codex.exe") if name in names]
    return preferred


def _source_layout(root: Path, package: PackageMetadata, source_kind: str) -> DesktopSource | None:
    root = root.expanduser().resolve(strict=False)
    layout_roots = [root]
    if root.name.casefold() == "resources":
        layout_roots.insert(0, root.parent)
    if (root / "app").is_dir():
        layout_roots.insert(0, root / "app")
    seen: set[Path] = set()
    for app_dir in layout_roots:
        if app_dir in seen:
            continue
        seen.add(app_dir)
        resources = app_dir / "resources"
        app_asar = resources / "app.asar"
        if not app_asar.is_file():
            continue
        executables = _executable_candidates(app_dir)
        if not executables:
            continue
        executable = executables[0]
        file_version = read_file_version(executable)
        return DesktopSource(
            source_root=root if root.name.casefold() != "resources" else root.parent,
            app_dir=app_dir,
            executable=executable,
            resources_dir=resources,
            app_asar=app_asar,
            package=package,
            source_kind=source_kind,
            file_version=file_version,
        )
    return None


def locate_desktop_source(explicit: Path | None = None) -> DesktopSource:
    if explicit is not None:
        package = PackageMetadata(install_location=explicit.expanduser().resolve(strict=False))
        found = _source_layout(explicit, package, "explicit")
        if found is None:
            raise RuntimeError(
                "not a supported Windows ChatGPT source: expected "
                "<source>\\app\\ChatGPT.exe (or Codex.exe) and "
                "<source>\\app\\resources\\app.asar"
            )
        return found

    packages = query_appx_packages()
    package_candidates = sorted(
        [package for package in packages if package.install_location is not None],
        key=lambda package: (
            int(package.name.casefold() == "openai.codex"),
            int("chatgpt" in package.name.casefold()),
            package.version,
        ),
        reverse=True,
    )
    for package in package_candidates:
        found = _source_layout(package.install_location, package, "appx")
        if found is not None:
            return found

    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    conventional = (
        local / "Programs" / "ChatGPT",
        local / "Programs" / "Codex",
        local / "OpenAI" / "ChatGPT",
        local / "OpenAI" / "Codex",
    )
    for root in conventional:
        found = _source_layout(root, PackageMetadata(install_location=root), "conventional")
        if found is not None:
            return found

    package_text = "; ".join(
        f"{package.name} at {package.install_location or '(location hidden)'}"
        for package in packages
    ) or "Get-AppxPackage returned no accessible OpenAI/Codex package"
    tried = ", ".join(str(path) for path in conventional)
    raise RuntimeError(
        "Windows ChatGPT source not found. The official installation was not "
        "modified or ACL-bypassed. Packages: " + package_text + ". Tried: " + tried
    )


def copy_byte_identical(source: Path, destination: Path) -> str:
    """Copy a selected executable through a temporary file and verify both hashes."""
    source = source.expanduser().resolve(strict=True)
    if is_windowsapps_path(source):
        raise RuntimeError("refusing to copy a protected WindowsApps executable")
    destination = destination.expanduser().resolve(strict=False)
    if source == destination:
        raise RuntimeError("real Codex source and staged destination must differ")
    source_hash = sha256_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", dir=destination.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        shutil.copy2(source, temporary)
        copied_hash = sha256_file(temporary)
        if copied_hash != source_hash:
            raise RuntimeError(
                f"real Codex hash changed during staging: source={source_hash} copied={copied_hash}"
            )
        os.replace(temporary, destination)
        final_hash = sha256_file(destination)
        if final_hash != source_hash:
            raise RuntimeError(
                f"real Codex hash changed after staging: source={source_hash} final={final_hash}"
            )
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return source_hash
