"""Bounded startup smoke for an unmodified mirrored Windows Desktop shell."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

try:
    from .discovery import (
        DesktopSource,
        RealCodexCandidate,
        discover_process_snapshot_native,
        enumerate_windows_for_processes,
        is_windowsapps_path,
        process_tree_pids,
        terminate_process_tree,
    )
    from .mirror import mirror_desktop_source, verify_desktop_mirror
except ImportError:
    from discovery import (
        DesktopSource,
        RealCodexCandidate,
        discover_process_snapshot_native,
        enumerate_windows_for_processes,
        is_windowsapps_path,
        process_tree_pids,
        terminate_process_tree,
    )
    from mirror import mirror_desktop_source, verify_desktop_mirror


_IDENTITY_PATTERNS = (
    r"package identity",
    r"appx",
    r"0x80073",
    r"side[- ]by[- ]side",
    r"activation context",
    r"register(?:ed|ing)?",
    r"windowsapps",
    r"failed to set up updater",
    r"initializewindowsupdater",
    r"bootstrap failed to start the main app",
)
_SINGLE_INSTANCE_PATTERNS = (
    r"single instance",
    r"already running",
    r"another instance",
    r"second-instance",
    r"requestsingleinstancelock",
)
_MISSING_DLL_PATTERNS = (r"dll", r"vcruntime", r"msvcp", r"module could not be found")
_RESOURCE_PATTERNS = (r"asar", r"resource", r"cannot find module", r"entry point")
_FATAL_PATTERNS = (r"fatal", r"uncaught", r"exception", r"crash", r"failed")


def _tail(path: Path, limit: int = 24_000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return f"<log read failed: {error}>"
    return text[-limit:]


def _matching_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    rows: list[str] = []
    for line in text.splitlines():
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
            rows.append(line[:1_000])
    return rows[-50:]


def _snapshot_rows(root_pid: int) -> tuple[list[dict[str, object]], tuple[int, ...]]:
    snapshot = discover_process_snapshot_native()
    pids = process_tree_pids(root_pid, snapshot)
    wanted = set(pids)
    rows = [candidate.to_dict() for candidate in snapshot if candidate.pid in wanted]
    return rows, pids


def _official_instance_present() -> bool:
    for candidate in discover_process_snapshot_native():
        if candidate.executable is not None and is_windowsapps_path(candidate.executable):
            if candidate.name.casefold() in {"chatgpt.exe", "codex.exe"}:
                return True
    return False


def run_unmodified_mirror_smoke(
    source: DesktopSource,
    real: RealCodexCandidate,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Mirror, launch, observe, and clean up without patching any mirrored file."""
    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "reason": "unmodified Windows Desktop smoke is Windows-only",
            "manual_operation_required": False,
        }
    started = time.monotonic()
    official_instance = _official_instance_present()
    with tempfile.TemporaryDirectory(prefix="codex-router-phase2a2-smoke-") as temporary:
        root = Path(temporary)
        mirror_root = root / "app"
        user_data = root / "User Data"
        log_path = root / "startup.log"
        mirror_report = mirror_desktop_source(source, mirror_root)
        verify_desktop_mirror(source.app_dir, mirror_root)
        user_data.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update(
            {
                "CODEX_CLI_PATH": str(real.path),
                "CODEX_MUX_DESKTOP_USER_DATA": str(user_data),
                "ELECTRON_ENABLE_LOGGING": "1",
                "ELECTRON_ENABLE_STACK_DUMPING": "1",
            }
        )
        command = [str(mirror_root / source.executable.name), f"--user-data-dir={user_data}"]
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=mirror_root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                )
            except (OSError, subprocess.SubprocessError) as error:
                return {
                    "status": "FAIL",
                    "reason": f"could not launch mirrored ChatGPT.exe: {error}",
                    "mirror": mirror_report.to_dict(),
                    "manual_operation_required": False,
                }

            observations: list[dict[str, object]] = []
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                time.sleep(0.25)
                rows, pids = _snapshot_rows(process.pid)
                windows = enumerate_windows_for_processes(pids)
                observations.append(
                    {
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "return_code": process.poll(),
                        "processes": rows,
                        "windows": windows,
                    }
                )
                if process.poll() is not None:
                    break
            return_code = process.poll()
            final_snapshot = discover_process_snapshot_native()
            final_pids = process_tree_pids(process.pid, final_snapshot)
            final_processes = [
                candidate.to_dict()
                for candidate in final_snapshot
                if candidate.pid in set(final_pids)
            ]
            final_windows = enumerate_windows_for_processes(final_pids)
            still_running = return_code is None
            # The root may exit while a helper remains alive. Always derive the
            # cleanup set from the root PID and the final parent snapshot so no
            # created child is left behind and no unrelated process is touched.
            cleanup = terminate_process_tree(process.pid, final_snapshot)
            log_text = _tail(log_path)

        identity_errors = _matching_lines(log_text, _IDENTITY_PATTERNS)
        single_instance_errors = _matching_lines(log_text, _SINGLE_INSTANCE_PATTERNS)
        missing_dll_errors = _matching_lines(log_text, _MISSING_DLL_PATTERNS)
        resource_errors = _matching_lines(log_text, _RESOURCE_PATTERNS)
        fatal_errors = _matching_lines(log_text, _FATAL_PATTERNS)
        if still_running:
            status = "PASS"
            reason = "mirrored ChatGPT.exe remained healthy for the bounded startup interval"
            manual_required = False
        elif identity_errors:
            status = "BLOCKED_PACKAGE_IDENTITY"
            reason = "the mirrored shell reported a package-registration or Windows identity failure"
            manual_required = False
        elif official_instance and (single_instance_errors or return_code in {0, 1}):
            status = "BLOCKED_SINGLE_INSTANCE_LOCK"
            reason = (
                "the mirrored shell exited while an official WindowsApps ChatGPT/Codex instance was running; "
                "single-instance locking is the leading cause"
            )
            manual_required = True
        else:
            status = "FAIL"
            reason = f"mirrored ChatGPT.exe exited before the startup interval (code={return_code})"
            manual_required = False
        return {
            "status": status,
            "reason": reason,
            "command": command,
            "source_executable": str(source.executable),
            "real_codex": str(real.path),
            "official_instance_present_before_launch": official_instance,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "return_code": return_code,
            "mirror": mirror_report.to_dict(),
            "process_observations": observations[-20:],
            "final_processes": final_processes,
            "final_windows": final_windows,
            "cleanup": cleanup,
            "errors": {
                "package_identity": identity_errors,
                "single_instance": single_instance_errors,
                "missing_dll": missing_dll_errors,
                "resource": resource_errors,
                "fatal": fatal_errors,
                "stdout_stderr_tail": log_text,
            },
            "manual_operation_required": manual_required,
        }
