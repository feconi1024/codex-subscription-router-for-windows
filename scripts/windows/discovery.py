"""Windows AppX desktop, running-process, and native Codex discovery."""

from __future__ import annotations

import ctypes
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


WINDOWS_NATIVE_MACHINES = {0x014C, 0x8664, 0xAA64}
PROBE_PASS = "PASS"
PROBE_FAIL = "FAIL"
PROBE_NOT_AVAILABLE = "NOT AVAILABLE"
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = -1
WAIT_OBJECT_0 = 0x00000000
DESKTOP_EXECUTABLE_NAMES = ("ChatGPT.exe", "Codex.exe")
OPENAI_AUMID_PATTERNS = ("OpenAI.Codex_*!App", "OpenAI.ChatGPT_*!App")
EXACT_26_820_PACKAGE_NAME = "OpenAI.Codex"
EXACT_26_820_PACKAGE_VERSION = "26.820.7780.0"


def _is_known_aumid(value: str) -> bool:
    lowered = value.casefold()
    return any(fnmatch.fnmatchcase(lowered, pattern.casefold()) for pattern in OPENAI_AUMID_PATTERNS)


@dataclass(frozen=True)
class SourceProbeResult:
    """A non-sensitive result from one source-discovery mechanism."""

    method: str
    status: str
    candidates: tuple[str, ...] = ()
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {PROBE_PASS, PROBE_FAIL, PROBE_NOT_AVAILABLE}:
            raise ValueError(f"unknown source probe status: {self.status}")

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "method": self.method,
            "status": self.status,
            "candidates": list(self.candidates),
        }
        if self.error:
            result["error"] = self.error
        return result


@dataclass(frozen=True)
class PackageMetadata:
    name: str = "unknown"
    package_full_name: str = "unknown"
    version: str = "unknown"
    install_location: Path | None = None
    architecture: str = "unknown"
    status: str = "unknown"
    publisher: str = "unknown"


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
class DesktopExecutableCandidate:
    """Evidence for a root-level Windows Desktop shell candidate."""

    path: Path
    relative_path: str
    present: bool
    file_size: int | None
    file_version: str | None
    product_version: str | None
    authenticode: AuthenticodeMetadata
    pe_machine: int | None
    appx_manifest_declared: bool
    fuse_wire_present: bool
    fuse: dict[str, object] | None
    fuse_error: str | None
    integrity_resource_present: bool
    integrity_resources: tuple[dict[str, object], ...]
    integrity_error: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "present": self.present,
            "file_size": self.file_size,
            "file_version": self.file_version,
            "product_version": self.product_version,
            "authenticode": {
                "status": self.authenticode.status,
                "signer": self.authenticode.signer,
            },
            "pe_machine": self.pe_machine,
            "pe_machine_hex": f"0x{self.pe_machine:04x}" if self.pe_machine is not None else None,
            "appx_manifest_declared": self.appx_manifest_declared,
            "fuse_wire_present": self.fuse_wire_present,
            "fuse": self.fuse,
            "fuse_error": self.fuse_error,
            "integrity_resource_present": self.integrity_resource_present,
            "integrity_resources": list(self.integrity_resources),
            "integrity_error": self.integrity_error,
        }


@dataclass(frozen=True)
class RealCodexCandidate:
    path: Path
    version: str
    sha256: str
    authenticode: AuthenticodeMetadata
    modified_time: float
    valid_native: bool


@dataclass(frozen=True)
class RunningProcessCandidate:
    """A process name and its best-effort query-limited executable path."""

    pid: int
    name: str
    parent_pid: int | None = None
    executable: Path | None = None
    error: str | None = None

    def label(self) -> str:
        if self.executable is not None:
            return str(self.executable)
        return f"{self.name} (pid {self.pid}; path unavailable)"

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "pid": self.pid,
            "name": self.name,
            "parent_pid": self.parent_pid,
            "executable": str(self.executable) if self.executable else None,
        }
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class SourceDiagnostics:
    """Structured, printable source acquisition evidence."""

    probes: list[SourceProbeResult] = field(default_factory=list)
    aumids: list[str] = field(default_factory=list)
    manifest_aumids: list[str] = field(default_factory=list)
    selected_aumid: str | None = None
    selected_source: DesktopSource | None = None
    access: list[SourceProbeResult] = field(default_factory=list)

    def add(self, probe: SourceProbeResult) -> None:
        self.probes.append(probe)

    def to_dict(self) -> dict[str, object]:
        source = self.selected_source
        return {
            "registered_aumids": list(self.aumids),
            "manifest_aumids": list(self.manifest_aumids),
            "selected_aumid": self.selected_aumid,
            "probes": [probe.to_dict() for probe in self.probes],
            "access": [probe.to_dict() for probe in self.access],
            "selected_source": (
                {
                    "source_root": str(source.source_root),
                    "app_dir": str(source.app_dir),
                    "executable": str(source.executable),
                    "resources_dir": str(source.resources_dir),
                    "app_asar": str(source.app_asar),
                    "source_kind": source.source_kind,
                    "file_version": source.file_version,
                    "package": package_to_dict(source.package),
                }
                if source is not None
                else None
            ),
        }


class SourceDiscoveryError(RuntimeError):
    """Source discovery failed; the diagnostics remain available to callers."""

    def __init__(self, message: str, diagnostics: SourceDiagnostics) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


def package_to_dict(package: PackageMetadata) -> dict[str, object]:
    return {
        "name": package.name,
        "package_full_name": package.package_full_name,
        "version": package.version,
        "install_location": str(package.install_location) if package.install_location else None,
        "architecture": package.architecture,
        "status": package.status,
        "publisher": package.publisher,
    }


def _safe_error(error: BaseException | str, *, limit: int = 300) -> str:
    if isinstance(error, str):
        message = error
    else:
        message = str(error) or type(error).__name__
    message = " ".join(message.replace("\r", " ").replace("\n", " ").split())
    if message:
        return message[:limit]
    return type(error).__name__ if not isinstance(error, str) else "unknown error"


def _powershell_executable() -> str | None:
    # PowerShell 7 exposes the Windows signature cmdlets reliably in the
    # managed desktop runtime; fall back to inbox Windows PowerShell when it
    # is the only available host.
    return shutil.which("pwsh.exe") or shutil.which("powershell.exe") or shutil.which("pwsh")


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_powershell_json_with_error(script: str) -> tuple[Any | None, str | None]:
    executable = _powershell_executable()
    if executable is None:
        return None, "PowerShell executable unavailable"
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, _safe_error(error)
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        suffix = f": {_safe_error(detail[0])}" if detail else ""
        return None, f"PowerShell exited with code {result.returncode}{suffix}"
    if not result.stdout.strip():
        return None, "PowerShell returned no JSON output"
    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError as error:
        return None, f"PowerShell returned invalid JSON: {_safe_error(error)}"


def _run_powershell_json(script: str) -> Any:
    parsed, _ = _run_powershell_json_with_error(script)
    return parsed


def query_appx_packages_with_probe() -> tuple[list[PackageMetadata], SourceProbeResult]:
    """Query AppX metadata without touching WindowsApps ACLs."""
    script = r"""
$packages = @(Get-AppxPackage -ErrorAction Stop | Where-Object {
  $_.Name -match 'OpenAI|ChatGPT|Codex' -or
  $_.PackageFullName -match 'OpenAI|ChatGPT|Codex' -or
  $_.InstallLocation -match 'OpenAI|ChatGPT|Codex'
} | Select-Object Name,PackageFullName,Version,InstallLocation,Architecture,Status,Publisher)
ConvertTo-Json -InputObject $packages -Compress
"""
    parsed, error = _run_powershell_json_with_error(script)
    if error:
        return [], SourceProbeResult("Get-AppxPackage", PROBE_FAIL, (), error)
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
                publisher=str(row.get("Publisher") or "unknown"),
            )
        )
    return packages, SourceProbeResult(
        "Get-AppxPackage",
        PROBE_PASS,
        tuple(str(package.install_location) for package in packages if package.install_location),
    )


def query_appx_packages() -> list[PackageMetadata]:
    return query_appx_packages_with_probe()[0]


def query_start_apps_with_probe() -> tuple[list[str], SourceProbeResult]:
    """Read stable OpenAI AUMIDs as identity evidence, not display names."""
    script = r"""
$apps = @(Get-StartApps -ErrorAction Stop | Where-Object {
  $_.AppID -like 'OpenAI.Codex_*!App' -or $_.AppID -like 'OpenAI.ChatGPT_*!App'
} | Select-Object Name,AppID)
ConvertTo-Json -InputObject $apps -Compress
"""
    parsed, error = _run_powershell_json_with_error(script)
    if error:
        return [], SourceProbeResult("Get-StartApps", PROBE_FAIL, (), error)
    rows = parsed if isinstance(parsed, list) else [parsed]
    aumids = sorted(
        {
            str(row.get("AppID"))
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("AppID"), str)
            and _is_known_aumid(str(row["AppID"]))
        },
        key=str.casefold,
    )
    return aumids, SourceProbeResult("Get-StartApps", PROBE_PASS, tuple(aumids))


def recognize_start_app_aumids(rows: Iterable[dict[str, object]]) -> tuple[str, ...]:
    """Return only stable OpenAI AUMIDs from StartApps-like rows."""
    return tuple(
        sorted(
            {
                str(row["AppID"])
                for row in rows
                if isinstance(row.get("AppID"), str)
                and _is_known_aumid(str(row["AppID"]))
            },
            key=str.casefold,
        )
    )


def _win32_error(prefix: str) -> str:
    code = ctypes.get_last_error()
    return f"{prefix} (Win32 error {code})"


def _query_process_image_path(kernel32: Any, pid: int) -> tuple[Path | None, str | None]:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None, _win32_error(f"OpenProcess query-limited-information failed for pid {pid}")
    try:
        size = 1024
        while size <= 32768:
            buffer = ctypes.create_unicode_buffer(size)
            length = ctypes.c_uint32(size)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                return Path(buffer.value[: length.value]), None
            if ctypes.get_last_error() != 122:  # ERROR_INSUFFICIENT_BUFFER
                return None, _win32_error(f"QueryFullProcessImageNameW failed for pid {pid}")
            size *= 2
        return None, "executable path exceeded the query buffer limit"
    finally:
        kernel32.CloseHandle(handle)


def discover_running_processes_native() -> tuple[list[RunningProcessCandidate], SourceProbeResult]:
    """Enumerate ChatGPT.exe/Codex.exe using query-limited Windows APIs."""
    if os.name != "nt":
        return [], SourceProbeResult(
            "running-process-native",
            PROBE_NOT_AVAILABLE,
            (),
            "native Toolhelp32 process APIs are Windows-only",
        )
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as error:
        return [], SourceProbeResult("running-process-native", PROBE_NOT_AVAILABLE, (), _safe_error(error))

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(INVALID_HANDLE_VALUE).value:
        return [], SourceProbeResult("running-process-native", PROBE_FAIL, (), _win32_error("CreateToolhelp32Snapshot failed"))
    candidates: list[RunningProcessCandidate] = []
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(ProcessEntry32W)
    target_names = {item.casefold() for item in DESKTOP_EXECUTABLE_NAMES}
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return [], SourceProbeResult("running-process-native", PROBE_FAIL, (), _win32_error("Process32FirstW failed"))
        while True:
            name = str(entry.szExeFile)
            if name.casefold() in target_names:
                path, error = _query_process_image_path(kernel32, int(entry.th32ProcessID))
                candidates.append(
                    RunningProcessCandidate(
                        pid=int(entry.th32ProcessID),
                        name=name,
                        parent_pid=int(entry.th32ParentProcessID),
                        executable=path,
                        error=error,
                    )
                )
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    errors = [candidate.error for candidate in candidates if candidate.error]
    return candidates, SourceProbeResult(
        "running-process-native",
        PROBE_PASS,
        tuple(candidate.label() for candidate in candidates),
        "; ".join(error for error in errors if error) or None,
    )


def discover_process_snapshot_native() -> list[RunningProcessCandidate]:
    """Return a best-effort native snapshot of all processes and parent IDs."""
    if os.name != "nt":
        return []
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        return []

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(INVALID_HANDLE_VALUE).value:
        return []
    result: list[RunningProcessCandidate] = []
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(ProcessEntry32W)
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return []
        while True:
            pid = int(entry.th32ProcessID)
            path, error = _query_process_image_path(kernel32, pid)
            result.append(
                RunningProcessCandidate(
                    pid=pid,
                    name=str(entry.szExeFile),
                    parent_pid=int(entry.th32ParentProcessID),
                    executable=path,
                    error=error,
                )
            )
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def process_tree_pids(root_pid: int, snapshot: Iterable[RunningProcessCandidate]) -> tuple[int, ...]:
    """Return only the root and descendants visible in one native snapshot."""
    rows = list(snapshot)
    children: dict[int, list[int]] = {}
    for row in rows:
        if row.parent_pid is not None:
            children.setdefault(row.parent_pid, []).append(row.pid)
    result: list[int] = [root_pid]
    seen = {root_pid}
    pending = [root_pid]
    while pending:
        parent = pending.pop(0)
        for child in children.get(parent, []):
            if child in seen:
                continue
            seen.add(child)
            result.append(child)
            pending.append(child)
    return tuple(result)


def attributable_process_pids(
    root_pid: int,
    baseline_pids: Iterable[int],
    snapshot: Iterable[RunningProcessCandidate],
    mirrored_root: Path,
    *,
    seed_pids: Iterable[int] = (),
    additional_executable_paths: Iterable[Path] = (),
) -> tuple[int, ...]:
    """Track new descendants or mirror-path processes for one launch probe."""
    baseline = {int(pid) for pid in baseline_pids}
    rows = list(snapshot)
    tracked = {int(root_pid), *(int(pid) for pid in seed_pids)}
    additional = {
        path.expanduser().resolve(strict=False)
        for path in additional_executable_paths
    }
    changed = True
    while changed:
        changed = False
        for row in rows:
            if row.pid in tracked or row.pid in baseline:
                continue
            path_match = row.executable is not None and (
                path_is_within(row.executable, mirrored_root)
                or row.executable.expanduser().resolve(strict=False) in additional
            )
            parent_match = row.parent_pid in tracked
            if path_match or parent_match:
                tracked.add(row.pid)
                changed = True
    return tuple(sorted(tracked))


def enumerate_windows_for_processes(pids: Iterable[int]) -> list[dict[str, object]]:
    """Collect visible top-level window evidence without sending input."""
    wanted = {int(pid) for pid in pids}
    if os.name != "nt" or not wanted:
        return []
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
    except (AttributeError, OSError):
        return []
    enum_proc_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    rows: list[dict[str, object]] = []

    user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
    user32.IsWindowVisible.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    user32.GetWindowThreadProcessId.restype = ctypes.c_uint32
    user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int

    @enum_proc_type
    def callback(hwnd: int, _lparam: int) -> int:
        if not user32.IsWindowVisible(hwnd):
            return 1
        process_id = ctypes.c_uint32()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
        pid = int(process_id.value)
        if pid not in wanted:
            return 1
        title_length = max(1, user32.GetWindowTextLengthW(hwnd) + 1)
        title = ctypes.create_unicode_buffer(title_length)
        user32.GetWindowTextW(hwnd, title, title_length)
        class_name = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_name, 256)
        rows.append(
            {
                "hwnd": int(hwnd),
                "pid": pid,
                "title": title.value,
                "class_name": class_name.value,
                "visible": True,
            }
        )
        return 1

    user32.EnumWindows.argtypes = [enum_proc_type, ctypes.c_void_p]
    user32.EnumWindows.restype = ctypes.c_int
    user32.EnumWindows(callback, 0)
    return rows


def terminate_process_tree(root_pid: int, snapshot: Iterable[RunningProcessCandidate]) -> dict[str, object]:
    """Terminate only a test process root and descendants from the supplied snapshot."""
    if os.name != "nt":
        return {"requested": [root_pid], "terminated": [], "errors": ["Windows-only process termination"]}
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as error:
        return {"requested": [root_pid], "terminated": [], "errors": [str(error)]}
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    snapshot_rows = list(snapshot)
    targets = process_tree_pids(root_pid, snapshot_rows)
    # Never open a PID that disappeared before the cleanup snapshot; it could
    # have been reused by an unrelated process. Descendants are retained only
    # when their parent relationship is present in that same snapshot.
    if root_pid not in {row.pid for row in snapshot_rows}:
        targets = tuple(pid for pid in targets if pid != root_pid)
    terminated: list[int] = []
    errors: list[str] = []
    for pid in reversed(targets):
        handle = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
        if not handle:
            # A process that exited between snapshots is already safe to ignore.
            continue
        try:
            if kernel32.TerminateProcess(handle, 0xC0DE):
                result = kernel32.WaitForSingleObject(handle, 5_000)
                if result == WAIT_OBJECT_0:
                    terminated.append(pid)
                else:
                    errors.append(f"pid {pid} did not exit after termination (wait={result})")
            else:
                errors.append(_win32_error(f"TerminateProcess failed for pid {pid}"))
        finally:
            kernel32.CloseHandle(handle)
    return {"requested": list(targets), "terminated": terminated, "errors": errors}


def terminate_attributed_processes(
    process_pids: Iterable[int],
    snapshot: Iterable[RunningProcessCandidate],
    mirrored_root: Path,
    *,
    root_pid: int | None = None,
    allowed_executable_paths: Iterable[Path] = (),
) -> dict[str, object]:
    """Terminate only PIDs tracked for a probe, never protected package processes."""
    if os.name != "nt":
        return {"requested": [], "terminated": [], "errors": ["Windows-only process termination"]}
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as error:
        return {"requested": [], "terminated": [], "errors": [str(error)]}
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    rows = {row.pid: row for row in snapshot}
    tracked = tuple(dict.fromkeys(int(pid) for pid in process_pids))
    requested: list[int] = []
    skipped: list[str] = []
    external_processes_observed: list[dict[str, object]] = []
    external_process_pids: set[int] = set()
    allowed_paths = {
        path.expanduser().resolve(strict=False)
        for path in allowed_executable_paths
    }

    for pid in tracked:
        row = rows.get(pid)
        if row is None:
            continue
        if row.executable is None:
            skipped.append(f"pid {pid}: executable path unavailable")
            continue
        owned_path = path_is_within(row.executable, mirrored_root) or row.executable.resolve(strict=False) in allowed_paths
        if not owned_path:
            # Parentage alone does not make an external OAuth browser Router
            # owned. Keep the ownership boundary strict: only mirror paths and
            # explicitly allowed executable paths can be cleanup targets.
            if pid not in external_process_pids:
                name = Path(row.name).name[:100]
                external_processes_observed.append(
                    {
                        "name": name,
                        "cleanup_required": False,
                    }
                )
                external_process_pids.add(pid)
            continue
        if is_windowsapps_path(row.executable):
            skipped.append(f"pid {pid}: refusing protected WindowsApps process {row.executable}")
            continue
        requested.append(pid)

    def depth(pid: int) -> int:
        count = 0
        current = rows.get(pid)
        visited: set[int] = set()
        while current is not None and current.parent_pid is not None and current.parent_pid not in visited:
            visited.add(current.parent_pid)
            count += 1
            current = rows.get(current.parent_pid)
        return count

    terminated: list[int] = []
    errors: list[str] = list(skipped)
    for pid in sorted(requested, key=depth, reverse=True):
        handle = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
        if not handle:
            continue
        try:
            if kernel32.TerminateProcess(handle, 0xC0DE):
                result = kernel32.WaitForSingleObject(handle, 5_000)
                if result == WAIT_OBJECT_0:
                    terminated.append(pid)
                else:
                    errors.append(f"pid {pid} did not exit after termination (wait={result})")
            else:
                errors.append(_win32_error(f"TerminateProcess failed for pid {pid}"))
        finally:
            kernel32.CloseHandle(handle)
    return {
        "tracked": list(tracked),
        "requested": requested,
        "terminated": terminated,
        "errors": errors,
        "external_processes_observed": external_processes_observed,
    }


def _rows_to_process_candidates(parsed: Any) -> list[RunningProcessCandidate]:
    rows = parsed if isinstance(parsed, list) else [parsed]
    candidates: list[RunningProcessCandidate] = []
    target_names = {item.casefold() for item in DESKTOP_EXECUTABLE_NAMES}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("Name")
        pid = row.get("ProcessId")
        if not isinstance(name, str) or name.casefold() not in target_names:
            continue
        try:
            process_id = int(pid)
        except (TypeError, ValueError):
            continue
        parent = row.get("ParentProcessId")
        try:
            parent_id = int(parent) if parent is not None else None
        except (TypeError, ValueError):
            parent_id = None
        executable = row.get("ExecutablePath")
        candidates.append(
            RunningProcessCandidate(
                pid=process_id,
                name=name,
                parent_pid=parent_id,
                executable=Path(executable) if isinstance(executable, str) and executable else None,
                error=None if isinstance(executable, str) and executable else "CIM did not return an executable path",
            )
        )
    return candidates


def query_running_processes_powershell() -> tuple[list[RunningProcessCandidate], SourceProbeResult]:
    script = r"""
$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
  $_.Name -ieq 'ChatGPT.exe' -or $_.Name -ieq 'Codex.exe'
} | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath)
ConvertTo-Json -InputObject $processes -Compress
"""
    parsed, error = _run_powershell_json_with_error(script)
    if error:
        return [], SourceProbeResult("running-process-powershell", PROBE_FAIL, (), error)
    candidates = _rows_to_process_candidates(parsed)
    errors = [candidate.error for candidate in candidates if candidate.error]
    return candidates, SourceProbeResult(
        "running-process-powershell",
        PROBE_PASS,
        tuple(candidate.label() for candidate in candidates),
        "; ".join(errors) or None,
    )


def select_running_process(candidates: Iterable[RunningProcessCandidate]) -> RunningProcessCandidate | None:
    """Prefer a package path, then ChatGPT.exe, while retaining all candidates."""
    usable = [candidate for candidate in candidates if candidate.executable is not None]
    if not usable:
        return None
    return max(
        usable,
        key=lambda candidate: (
            int("\\windowsapps\\" in str(candidate.executable).casefold()),
            int(candidate.name.casefold() == "chatgpt.exe"),
            str(candidate.executable).casefold(),
        ),
    )


def is_windowsapps_path(path: Path) -> bool:
    return any(part.casefold() == "windowsapps" for part in path.resolve(strict=False).parts)


def path_is_within(path: Path, root: Path) -> bool:
    """Compare Windows paths without trusting case-sensitive string equality."""
    try:
        candidate = os.path.abspath(os.fspath(path))
        parent = os.path.abspath(os.fspath(root))
        return os.path.normcase(os.path.commonpath((candidate, parent))) == os.path.normcase(parent)
    except (OSError, ValueError):
        return False


def read_pe_machine(path: Path) -> int | None:
    """Read the PE COFF machine field without modifying the candidate."""
    try:
        with path.open("rb") as handle:
            header = handle.read(0x1000)
            if len(header) < 0x40 or header[:2] != b"MZ":
                return None
            pe_offset = int.from_bytes(header[0x3C:0x40], "little")
            if pe_offset < 0x40 or pe_offset + 6 > len(header):
                handle.seek(pe_offset)
                pe_header = handle.read(6)
            else:
                pe_header = header[pe_offset : pe_offset + 6]
    except (OSError, ValueError):
        return None
    if pe_header[:4] != b"PE\0\0":
        return None
    return int.from_bytes(pe_header[4:6], "little")


def is_native_windows_executable(path: Path) -> bool:
    """Validate the PE header and machine type before considering a candidate."""
    return path.is_file() and not path.is_symlink() and read_pe_machine(path) in WINDOWS_NATIVE_MACHINES


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_file_version(path: Path) -> str:
    """Read the PE FileVersion, falling back to ProductVersion."""
    versions = read_file_versions(path)
    return versions.get("FileVersion") or versions.get("ProductVersion") or "unknown"


def read_file_versions(path: Path) -> dict[str, str]:
    """Read both PE version fields through PowerShell when available."""
    script = (
        f"$i=(Get-Item -LiteralPath {_powershell_quote(str(path))}).VersionInfo; "
        "[pscustomobject]@{FileVersion=$i.FileVersion;ProductVersion=$i.ProductVersion} "
        "| ConvertTo-Json -Compress"
    )
    try:
        parsed = _run_powershell_json(script)
    except (OSError, subprocess.SubprocessError):
        return {}
    if isinstance(parsed, dict):
        return {
            key: value.strip()
            for key in ("FileVersion", "ProductVersion")
            if isinstance(value := parsed.get(key), str) and value.strip()
        }
    return {}


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


def _manifest_declares_executable(package_root: Path, executable: Path) -> bool:
    manifest = package_root / "AppxManifest.xml"
    try:
        with manifest.open("rb") as handle:
            root = ET.parse(handle).getroot()
        relative = executable.resolve(strict=False).relative_to(package_root.resolve(strict=False))
    except (OSError, ET.ParseError, ValueError):
        return False
    expected = relative.as_posix().casefold()
    return any(
        isinstance(value, str)
        and value.replace("\\", "/").casefold() == expected
        for element in root.iter()
        if _local_name(element.tag) == "Application"
        for value in (element.attrib.get("Executable"),)
    )


def inventory_desktop_executables(source: DesktopSource) -> tuple[DesktopExecutableCandidate, ...]:
    """Inspect only app-root shell candidates, never resources\\codex.exe."""
    try:
        from .fuses import SENTINEL, read_fuses
        from .integrity import read_pe_integrity_resources
    except ImportError:
        from fuses import SENTINEL, read_fuses
        from integrity import read_pe_integrity_resources

    inventory: list[DesktopExecutableCandidate] = []
    for name in DESKTOP_EXECUTABLE_NAMES:
        path = source.app_dir / name
        relative = path.relative_to(source.source_root).as_posix().replace("/", "\\")
        if not path.is_file():
            inventory.append(
                DesktopExecutableCandidate(
                    path=path,
                    relative_path=relative,
                    present=False,
                    file_size=None,
                    file_version=None,
                    product_version=None,
                    authenticode=AuthenticodeMetadata("NOT PRESENT", None),
                    pe_machine=None,
                    appx_manifest_declared=_manifest_declares_executable(source.source_root, path),
                    fuse_wire_present=False,
                    fuse=None,
                    fuse_error=None,
                    integrity_resource_present=False,
                    integrity_resources=(),
                    integrity_error=None,
                )
            )
            continue

        versions = read_file_versions(path)
        try:
            file_size = path.stat().st_size
        except OSError:
            file_size = None
        try:
            data = path.read_bytes()
        except OSError as error:
            data = b""
            fuse_error = _safe_error(error)
        else:
            fuse_error = None
        fuse_wire_present = SENTINEL in data
        fuse_data: dict[str, object] | None = None
        if fuse_wire_present:
            try:
                snapshot = read_fuses(path)
                fuse_data = {
                    "schema_version": snapshot.schema_version,
                    "count": snapshot.count,
                    "fuses": list(snapshot.fuses),
                    "offset": snapshot.offset,
                }
            except (OSError, RuntimeError) as error:
                fuse_error = _safe_error(error)
        integrity_resources: tuple[dict[str, object], ...] = ()
        integrity_error: str | None = None
        try:
            result = read_pe_integrity_resources(path)
            values = result.get("resources")
            if not isinstance(values, list):
                raise RuntimeError("PE integrity helper returned an invalid resource list")
            integrity_resources = tuple(value for value in values if isinstance(value, dict))
        except (OSError, RuntimeError) as error:
            integrity_error = _safe_error(error)
        inventory.append(
            DesktopExecutableCandidate(
                path=path,
                relative_path=relative,
                present=True,
                file_size=file_size,
                file_version=versions.get("FileVersion"),
                product_version=versions.get("ProductVersion"),
                authenticode=read_authenticode(path),
                pe_machine=read_pe_machine(path),
                appx_manifest_declared=_manifest_declares_executable(source.source_root, path),
                fuse_wire_present=fuse_wire_present,
                fuse=fuse_data,
                fuse_error=fuse_error,
                integrity_resource_present=bool(integrity_resources),
                integrity_resources=integrity_resources,
                integrity_error=integrity_error,
            )
        )
    return tuple(inventory)


def select_authoritative_desktop_candidate(
    source: DesktopSource,
    candidates: Iterable[DesktopExecutableCandidate],
) -> DesktopExecutableCandidate:
    """Select the shell for this source without letting a diagnostic sibling veto it."""
    present = [candidate for candidate in candidates if candidate.present]
    if not present:
        raise RuntimeError("no root-level Windows Desktop shell is present")

    by_relative = {
        candidate.relative_path.replace("/", "\\").casefold(): candidate
        for candidate in present
    }
    if (
        source.package.name.casefold() == EXACT_26_820_PACKAGE_NAME.casefold()
        and source.package.version == EXACT_26_820_PACKAGE_VERSION
    ):
        exact = by_relative.get(r"app\chatgpt.exe")
        if exact is None:
            raise RuntimeError(
                "exact OpenAI.Codex 26.820.7780.0 source has no app\\ChatGPT.exe shell"
            )
        if not exact.appx_manifest_declared:
            raise RuntimeError(
                "exact OpenAI.Codex 26.820.7780.0 source does not declare app\\ChatGPT.exe in AppxManifest.xml"
            )
        return exact

    manifest_candidates = [candidate for candidate in present if candidate.appx_manifest_declared]
    if len(manifest_candidates) == 1:
        return manifest_candidates[0]

    source_relative = source.executable.resolve(strict=False).relative_to(
        source.source_root.resolve(strict=False)
    ).as_posix().replace("/", "\\").casefold()
    selected = by_relative.get(source_relative)
    if selected is not None:
        return selected
    if len(present) == 1:
        return present[0]
    raise RuntimeError(
        "multiple Desktop shells are present but no compatibility-specific manifest executable was proven"
    )


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


def _metadata_from_package_name(package_root: Path) -> PackageMetadata:
    name = package_root.name
    match = re.match(
        r"^(?P<name>.+)_(?P<version>\d+(?:\.\d+){1,3})_(?P<architecture>[^_]+)__(?P<publisher>[^_]+)$",
        name,
    )
    if match is None:
        return PackageMetadata(package_full_name=name, install_location=package_root)
    return PackageMetadata(
        name=match.group("name"),
        package_full_name=name,
        version=match.group("version"),
        install_location=package_root,
        architecture=match.group("architecture").upper(),
        publisher=match.group("publisher"),
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_appx_manifest_metadata(package_root: Path) -> tuple[PackageMetadata | None, str | None]:
    """Read AppxManifest.xml directly, without enumerating its parent directory."""
    manifest = package_root / "AppxManifest.xml"
    try:
        with manifest.open("rb") as handle:
            root = ET.parse(handle).getroot()
    except (OSError, ET.ParseError) as error:
        return None, _safe_error(error)
    identity = next((element for element in root.iter() if _local_name(element.tag) == "Identity"), None)
    if identity is None:
        return None, "AppxManifest.xml has no Identity element"
    fallback = _metadata_from_package_name(package_root)
    return (
        PackageMetadata(
            name=str(identity.attrib.get("Name") or fallback.name),
            package_full_name=fallback.package_full_name,
            version=str(identity.attrib.get("Version") or fallback.version),
            install_location=package_root,
            architecture=str(identity.attrib.get("ProcessorArchitecture") or fallback.architecture).upper(),
            status=fallback.status,
            publisher=str(identity.attrib.get("Publisher") or fallback.publisher),
        ),
        None,
    )


def read_appx_manifest_aumids(package_root: Path, package: PackageMetadata) -> tuple[str, ...]:
    """Derive package AUMIDs from manifest Application ids when StartApps is empty."""
    manifest = package_root / "AppxManifest.xml"
    try:
        with manifest.open("rb") as handle:
            root = ET.parse(handle).getroot()
    except (OSError, ET.ParseError):
        return ()
    package_name_fallback = _metadata_from_package_name(package_root)
    package_full_name = package.package_full_name
    if package_full_name in {"", "unknown"}:
        package_full_name = package_name_fallback.package_full_name
    publisher_id = package_full_name.rsplit("__", 1)[-1]
    if not publisher_id or publisher_id == package_full_name:
        return ()
    package_name = package.name if package.name not in {"", "unknown"} else package_name_fallback.name
    prefix = f"{package_name}_{publisher_id}"
    return tuple(
        sorted(
            {
                f"{prefix}!{element.attrib['Id']}"
                for element in root.iter()
                if _local_name(element.tag) == "Application" and element.attrib.get("Id")
            },
            key=str.casefold,
        )
    )


def package_metadata_from_root(package_root: Path) -> PackageMetadata:
    fallback = _metadata_from_package_name(package_root)
    metadata, _ = read_appx_manifest_metadata(package_root)
    return metadata or fallback


def _normalize_manifest_path(value: str) -> Path:
    normalized = value.replace("\\", "/")
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"absolute AppX block-map path is not allowed: {value!r}")
    parts: list[str] = []
    for part in normalized.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"parent traversal in AppX block-map path is not allowed: {value!r}")
        parts.append(part)
    if not parts:
        raise ValueError(f"empty AppX block-map path is not allowed: {value!r}")
    return Path(*parts)


def parse_appx_block_map(path: Path) -> tuple[Path, ...]:
    """Return validated package-relative file names from AppxBlockMap.xml."""
    try:
        with path.open("rb") as handle:
            root = ET.parse(handle).getroot()
    except (OSError, ET.ParseError) as error:
        raise RuntimeError(f"could not read AppxBlockMap.xml: {_safe_error(error)}") from error
    paths: set[Path] = set()
    for element in root.iter():
        if _local_name(element.tag) != "File":
            continue
        name = element.attrib.get("Name")
        if not isinstance(name, str):
            raise RuntimeError("AppxBlockMap.xml contains a file without a Name")
        try:
            paths.add(_normalize_manifest_path(name))
        except ValueError as error:
            raise RuntimeError(str(error)) from error
    if not paths:
        raise RuntimeError("AppxBlockMap.xml contains no file entries")
    return tuple(sorted(paths, key=lambda item: item.as_posix().casefold()))


def _direct_read_probe(method: str, path: Path) -> SourceProbeResult:
    try:
        with path.open("rb") as handle:
            handle.read(1)
    except OSError as error:
        return SourceProbeResult(method, PROBE_FAIL, (str(path),), _safe_error(error))
    return SourceProbeResult(method, PROBE_PASS, (str(path),))


def source_access_probes(source: DesktopSource) -> list[SourceProbeResult]:
    package_root = source.source_root
    try:
        list(package_root.iterdir())
        enumeration = SourceProbeResult("directory-enumeration", PROBE_PASS, (str(package_root),))
    except OSError as error:
        enumeration = SourceProbeResult("directory-enumeration", PROBE_FAIL, (str(package_root),), _safe_error(error))
    executable_label = f"direct-{source.executable.name}-read"
    return [
        enumeration,
        _direct_read_probe(executable_label, source.executable),
        _direct_read_probe("direct-app.asar-read", source.app_asar),
        _direct_read_probe("direct-AppxManifest.xml-read", package_root / "AppxManifest.xml"),
        _direct_read_probe("direct-AppxBlockMap.xml-read", package_root / "AppxBlockMap.xml"),
    ]


def _executable_paths_from_root(root: Path) -> tuple[Path, ...]:
    """Generate known paths without enumerating the source directory."""
    root = root.expanduser().resolve(strict=False)
    if root.suffix.casefold() == ".exe":
        return (root,)
    if root.name.casefold() == "resources":
        root = root.parent
    app_dirs = (root,) if root.name.casefold() == "app" else (root / "app", root)
    paths: list[Path] = []
    for app_dir in app_dirs:
        for name in DESKTOP_EXECUTABLE_NAMES:
            candidate = app_dir / name
            if candidate not in paths:
                paths.append(candidate)
    return tuple(paths)


def _require_direct_file(path: Path, label: str) -> None:
    try:
        with path.open("rb") as handle:
            handle.read(1)
    except OSError as error:
        raise RuntimeError(f"{label} is not directly readable at {path}: {_safe_error(error)}") from error


def desktop_source_from_executable(
    executable: Path,
    *,
    package: PackageMetadata | None = None,
    source_kind: str = "running-process",
) -> DesktopSource:
    """Construct a source from a known executable path without parent enumeration."""
    executable = executable.expanduser().resolve(strict=False)
    if executable.name.casefold() not in {name.casefold() for name in DESKTOP_EXECUTABLE_NAMES}:
        raise RuntimeError(f"unsupported Windows Desktop executable name: {executable.name}")
    app_dir = executable.parent
    package_root = app_dir.parent if app_dir.name.casefold() == "app" else app_dir
    resources_dir = app_dir / "resources"
    app_asar = resources_dir / "app.asar"
    _require_direct_file(executable, "Desktop executable")
    _require_direct_file(app_asar, "Desktop app.asar")
    selected_package = package or package_metadata_from_root(package_root)
    return DesktopSource(
        source_root=package_root,
        app_dir=app_dir,
        executable=executable,
        resources_dir=resources_dir,
        app_asar=app_asar,
        package=selected_package,
        source_kind=source_kind,
        file_version=read_file_version(executable),
    )


def _source_layout(root: Path, package: PackageMetadata, source_kind: str) -> DesktopSource | None:
    for executable in _executable_paths_from_root(root):
        try:
            return desktop_source_from_executable(executable, package=package, source_kind=source_kind)
        except RuntimeError:
            continue
    return None


def _source_from_process_candidates(
    candidates: Iterable[RunningProcessCandidate],
) -> DesktopSource | None:
    selected = select_running_process(candidates)
    if selected is None or selected.executable is None:
        return None
    try:
        return desktop_source_from_executable(selected.executable, source_kind="running-process")
    except RuntimeError:
        return None


def discover_desktop_source(
    explicit: Path | None = None,
    *,
    activate_source: bool = False,
) -> tuple[DesktopSource | None, SourceDiagnostics]:
    """Discover a source and retain every non-sensitive mechanism result."""
    del activate_source  # Activation is intentionally not the default in Phase 2A.
    diagnostics = SourceDiagnostics()
    if explicit is not None:
        explicit = explicit.expanduser().resolve(strict=False)
        try:
            explicit_package_root = explicit.parent if explicit.name.casefold() == "app" else explicit
            explicit_package = package_metadata_from_root(explicit_package_root)
            source = (
                desktop_source_from_executable(explicit, source_kind="explicit")
                if explicit.suffix.casefold() == ".exe"
                else _source_layout(explicit, explicit_package, "explicit")
            )
        except RuntimeError as error:
            source = None
            diagnostics.add(SourceProbeResult("explicit-source", PROBE_FAIL, (str(explicit),), _safe_error(error)))
        else:
            diagnostics.add(SourceProbeResult("explicit-source", PROBE_PASS, (str(source.source_root),)))
        if source is not None:
            diagnostics.selected_source = source
            diagnostics.access = source_access_probes(source)
        return source, diagnostics

    aumids, aumid_probe = query_start_apps_with_probe()
    diagnostics.aumids = aumids
    diagnostics.selected_aumid = aumids[0] if len(aumids) == 1 else None
    diagnostics.add(aumid_probe)

    native_processes, native_probe = discover_running_processes_native()
    diagnostics.add(native_probe)
    process_candidates = list(native_processes)
    source = _source_from_process_candidates(process_candidates)

    if source is None:
        fallback_processes, fallback_probe = query_running_processes_powershell()
        diagnostics.add(fallback_probe)
        process_candidates.extend(fallback_processes)
        source = _source_from_process_candidates(fallback_processes)
    else:
        diagnostics.add(
            SourceProbeResult(
                "running-process-powershell",
                PROBE_NOT_AVAILABLE,
                (),
                "not attempted because native process discovery yielded a readable source",
            )
        )

    packages, package_probe = query_appx_packages_with_probe()
    diagnostics.add(package_probe)
    if source is None:
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
            source = _source_layout(package.install_location, package, "appx")
            if source is not None:
                break

    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    conventional = (
        local / "Programs" / "ChatGPT",
        local / "Programs" / "Codex",
        local / "OpenAI" / "ChatGPT",
        local / "OpenAI" / "Codex",
    )
    if source is None:
        for root in conventional:
            source = _source_layout(root, PackageMetadata(install_location=root), "conventional")
            if source is not None:
                break
    diagnostics.add(
        SourceProbeResult(
            "conventional-paths",
            PROBE_PASS if source is not None and source.source_kind == "conventional" else PROBE_FAIL,
            tuple(str(path) for path in conventional),
            None if source is not None else "no directly readable ChatGPT.exe/app.asar pair found",
        )
    )

    if source is not None:
        diagnostics.manifest_aumids = list(read_appx_manifest_aumids(source.source_root, source.package))
        package_prefix = f"{source.package.name}_".casefold()
        matching_registered = [
            aumid
            for aumid in diagnostics.aumids
            if aumid.casefold().startswith(package_prefix)
        ]
        if matching_registered:
            diagnostics.selected_aumid = matching_registered[0]
        elif diagnostics.manifest_aumids and diagnostics.selected_aumid is None:
            diagnostics.selected_aumid = diagnostics.manifest_aumids[0]
            diagnostics.add(
                SourceProbeResult(
                    "AppxManifest-AUMID-fallback",
                    PROBE_PASS,
                    tuple(diagnostics.manifest_aumids),
                    "Get-StartApps had no matching package identity; AUMID derived from package identity and manifest Application id",
                )
            )
        diagnostics.selected_source = source
        diagnostics.access = source_access_probes(source)
        return source, diagnostics

    if diagnostics.aumids and not process_candidates:
        diagnostics.add(
            SourceProbeResult(
                "registered-app-follow-up",
                PROBE_FAIL,
                tuple(diagnostics.aumids),
                "AUMID exists but no ChatGPT.exe/Codex.exe process is running; launch the official app manually and rerun discovery",
            )
        )
    elif process_candidates:
        diagnostics.add(
            SourceProbeResult(
                "running-process-source-layout",
                PROBE_FAIL,
                tuple(candidate.label() for candidate in process_candidates),
                "running process was found, but its known executable path did not expose a directly readable app.asar",
            )
        )
    return None, diagnostics


def format_source_diagnostics(diagnostics: SourceDiagnostics) -> str:
    lines = ["Phase 2A Windows Desktop source diagnostics"]
    lines.append("registered AUMID: " + (", ".join(diagnostics.aumids) if diagnostics.aumids else "none"))
    if diagnostics.manifest_aumids:
        lines.append("manifest-derived AUMID: " + ", ".join(diagnostics.manifest_aumids))
    for probe in diagnostics.probes:
        lines.append(f"- {probe.method}: {probe.status}")
        if probe.candidates:
            lines.append("  candidates: " + "; ".join(probe.candidates))
        if probe.error:
            lines.append("  error: " + probe.error)
    source = diagnostics.selected_source
    if source is None:
        lines.append("selected ChatGPT.exe: none")
    else:
        lines.extend(
            [
                f"selected {source.executable.name}: {source.executable}",
                f"package root: {source.source_root}",
                f"package metadata: {json.dumps(package_to_dict(source.package), sort_keys=True)}",
            ]
        )
    lines.append("direct-read results:")
    for probe in diagnostics.access:
        detail = f" ({probe.error})" if probe.error else ""
        lines.append(f"- {probe.method}: {probe.status}{detail}")
    return "\n".join(lines)


def locate_desktop_source(explicit: Path | None = None) -> DesktopSource:
    source, diagnostics = discover_desktop_source(explicit)
    if source is not None:
        return source
    raise SourceDiscoveryError(format_source_diagnostics(diagnostics), diagnostics)


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
