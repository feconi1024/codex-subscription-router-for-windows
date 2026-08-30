"""Bounded Windows Desktop launch probes with fail-closed cleanup."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator
import urllib.error
import urllib.request

try:
    from .discovery import (
        DesktopExecutableCandidate,
        DesktopSource,
        RealCodexCandidate,
        RunningProcessCandidate,
        attributable_process_pids,
        discover_process_snapshot_native,
        enumerate_windows_for_processes,
        is_native_windows_executable,
        is_windowsapps_path,
        path_is_within,
        select_authoritative_desktop_candidate,
        sha256_file,
        terminate_attributed_processes,
    )
    from .acl import audit_acl_scope, prepare_windows_electron_payload_acl
    from .host_context import detect_windows_host_context, run_localappdata_canary
    from .mirror import mirror_desktop_source, verify_desktop_mirror
except ImportError:
    from discovery import (
        DesktopExecutableCandidate,
        DesktopSource,
        RealCodexCandidate,
        RunningProcessCandidate,
        attributable_process_pids,
        discover_process_snapshot_native,
        enumerate_windows_for_processes,
        is_native_windows_executable,
        is_windowsapps_path,
        path_is_within,
        select_authoritative_desktop_candidate,
        sha256_file,
        terminate_attributed_processes,
    )
    from acl import audit_acl_scope, prepare_windows_electron_payload_acl
    from host_context import detect_windows_host_context, run_localappdata_canary
    from mirror import mirror_desktop_source, verify_desktop_mirror


BLOCKED_UPDATER_IDENTITY = "BLOCKED_UPDATER_IDENTITY"
BLOCKED_OTHER_PACKAGE_IDENTITY = "BLOCKED_OTHER_PACKAGE_IDENTITY"
BLOCKED_SINGLE_INSTANCE_LOCK = "BLOCKED_SINGLE_INSTANCE_LOCK"
BLOCKED_RESOURCE = "BLOCKED_RESOURCE"
BLOCKED_NATIVE_MODULE = "BLOCKED_NATIVE_MODULE"
BLOCKED_CHROMIUM_SANDBOX = "BLOCKED_CHROMIUM_SANDBOX"
CRASHED = "CRASHED"
PASS = "PASS"
NOT_PRESENT = "NOT PRESENT"

GPU_SANDBOX_CONFIRMED = "GPU_SANDBOX_CONFIRMED"
LOCAL_APP_ACL_FIX_CONFIRMED = "LOCAL_APP_ACL_FIX_CONFIRMED"
WINDOWS_26200_GPU_SANDBOX_REGRESSION = "WINDOWS_26200_GPU_SANDBOX_REGRESSION"
APP_CONTAINER_ACCESS_FIX_CONFIRMED = "APP_CONTAINER_ACCESS_FIX_CONFIRMED"
BROADER_CHROMIUM_SANDBOX_BLOCKED = "BROADER_CHROMIUM_SANDBOX_BLOCKED"
PATCHED_SHELL_PASS = "PATCHED_SHELL_PASS"
PATCHED_SHELL_BLOCKED = "PATCHED_SHELL_BLOCKED"
DEVELOPMENT_ONLY_SANDBOX_BYPASS = "DEVELOPMENT_ONLY_SANDBOX_BYPASS"

PHASE2A4_FULL_PASS = "FULL PHASE 2A.4 PASS"
PHASE2A4_LOCAL_ACL_FIX_CONFIRMED = "PHASE 2A.4 LOCAL ACL FIX CONFIRMED"
PHASE2A4_APP_CONTAINER_ACCESS_FIX_CONFIRMED = "PHASE 2A.4 APP CONTAINER ACCESS FIX CONFIRMED"
PHASE2A4_WINDOWS_GPU_SANDBOX_REGRESSION = "PHASE 2A.4 WINDOWS GPU SANDBOX REGRESSION"
PHASE2A4_BROADER_CHROMIUM_SANDBOX_BLOCKED = "PHASE 2A.4 BROADER CHROMIUM SANDBOX BLOCKED"
PHASE2A4_PATCHED_SHELL_BLOCKED = "PHASE 2A.4 PATCHED SHELL BLOCKED"
PHASE2A4_FAIL = "PHASE 2A.4 FAIL"

PHASE2A5_FULL_PASS = "FULL PHASE 2A.5 PASS"
PHASE2A5_HOST_CONTEXT_BLOCKED = "PHASE 2A.5 HOST CONTEXT BLOCKED"
PHASE2A5_FILESYSTEM_VIRTUALIZED = "PHASE 2A.5 FILESYSTEM VIRTUALIZED"
PHASE2A5_DIRECT_HOST_PASS = "PHASE 2A.5 DIRECT HOST PASS"
PHASE2A5_ACL_FIX_CONFIRMED = "PHASE 2A.5 ACL FIX CONFIRMED"
PHASE2A5_GPU_SANDBOX_REGRESSION = "PHASE 2A.5 GPU SANDBOX REGRESSION"
PHASE2A5_PATCHED_SHELL_BLOCKED = "PHASE 2A.5 PATCHED SHELL BLOCKED"
PHASE2A5_FAIL = "PHASE 2A.5 FAIL"

DIRECT_LAUNCH_PASS = "DIRECT_LAUNCH_PASS"
DIRECT_LAUNCH_IDENTITY_BLOCKED = "DIRECT_LAUNCH_IDENTITY_BLOCKED"
DIRECT_LAUNCH_FAIL = "DIRECT_LAUNCH_FAIL"

MINIMAL_BOOTSTRAP_PASS = "MINIMAL_BOOTSTRAP_PASS"
MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED = "MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED"
MINIMAL_BOOTSTRAP_FAIL = "MINIMAL_BOOTSTRAP_FAIL"

DESKTOP_AUTH_BOOT_AUTHENTICATED = "DESKTOP_AUTH_BOOT_AUTHENTICATED"
ROUTER_DESKTOP_AUTH_NOT_PERSISTED = "ROUTER_DESKTOP_AUTH_NOT_PERSISTED"
ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD = "ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD"


# These are intentionally narrow. In particular, a path containing
# ``WindowsApps`` is evidence about provenance, not evidence that activation
# or package identity failed.
_UPDATER_IDENTITY_PATTERNS = (
    r"failed to set up updater",
    r"process package id is missing",
    r"initializewindowsupdater",
)
_OTHER_PACKAGE_IDENTITY_PATTERNS = (
    r"package identity",
    r"(?:appx|appx package).{0,100}(?:identity|activation|register)",
    r"(?:identity|activation|register).{0,100}(?:appx|appx package)",
    r"0x80073[0-9a-f]+",
    r"side[- ]by[- ]side",
    r"activation context",
    r"failed to (?:register|activate) (?:the )?(?:package|application)",
)
_SINGLE_INSTANCE_PATTERNS = (
    r"single instance",
    r"already running",
    r"another instance",
    r"second-instance",
    r"requestsingleinstancelock",
    r"request single instance lock",
)
_MISSING_DLL_PATTERNS = (
    r"(?:dll|\.node).{0,100}(?:not found|could not be found|missing)",
    r"(?:not found|could not be found|missing).{0,100}(?:dll|\.node)",
    r"the code execution cannot proceed",
    r"failed to load native module",
    r"could not load native module",
)
_RESOURCE_PATTERNS = (
    r"(?:not found|missing|cannot|could not|failed|unable|error).{0,100}resources[\\/]app\.asar",
    r"resources[\\/]app\.asar.{0,100}(?:not found|missing|cannot|could not|failed|unable|error)",
    r"(?:not found|missing|cannot|could not|failed|unable|error).{0,100}(?:app\.asar|asar)",
    r"(?:app\.asar|asar).{0,100}(?:not found|missing|cannot|could not|failed|unable|error)",
    r"cannot find module",
    r"entry point.{0,100}(?:not found|could not)",
    r"failed to open (?:asar|resource)",
)
_CRASH_PATTERNS = (
    r"\bfatal\b",
    r"uncaught",
    r"\bexception\b",
    r"crash",
    r"breakpoint",
    r"0x80000003",
)
_GPU_SANDBOX_PATTERNS = (
    r"gpu process exited unexpectedly",
    r"gpu process isn't usable",
    r"gpu_process_host",
    r"gpu process.{0,100}(?:0x80000003|-2147483645)",
    r"(?:0x80000003|-2147483645).{0,100}gpu",
)
_GPU_ATTEMPT_PATTERNS = (
    r"launch(?:ing|ed)? .{0,60}gpu process",
    r"gpu process.{0,60}(?:launch|start|create|exit)",
    r"gpu_process_host",
)
_GPU_EXIT_CODE_PATTERN = re.compile(
    r"(?:exit(?:_code| code)?|status|code)\s*[:=]\s*(0x[0-9a-f]+|-?\d+)",
    re.IGNORECASE,
)
_PROBE_TERMINATION_EXIT_CODE = "49374"  # 0xC0DE used only for attributed cleanup.
_RENDERER_FAILURE_PATTERNS = (
    r"renderer.{0,100}(?:exited|crash|failed|failure|sandbox|not usable|unexpected)",
    r"(?:exited|crash|failed|failure|sandbox|not usable|unexpected).{0,100}renderer",
)
_PACKAGED_PATTERNS = (
    r"packaged",
    r"ispackaged",
    r"is packaged",
)
_ENABLE_UPDATER_PATTERNS = (
    r"enableupdater\s*[:=]\s*(true|false)",
    r"enable updater\s*[:=]\s*(true|false)",
)
_APP_SERVER_PATTERNS = (
    r"app-server",
    r"app server",
    r"app_server",
)
_ABSOLUTE_PATH_PATTERN = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\"'<>\r\n]+")


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


def _all_matching_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    return [
        line[:1_000]
        for line in text.splitlines()
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns)
    ]


def _chromium_sandbox_evidence(log_text: str) -> dict[str, object]:
    """Extract GPU/renderer child evidence without relying on localized text."""
    gpu_lines = _all_matching_lines(log_text, _GPU_SANDBOX_PATTERNS)
    attempt_lines = _all_matching_lines(log_text, _GPU_ATTEMPT_PATTERNS)
    renderer_failure_lines = _all_matching_lines(log_text, _RENDERER_FAILURE_PATTERNS)
    exit_codes: list[str] = []
    for line in log_text.splitlines():
        lowered = line.casefold()
        if "gpu" not in lowered and "gpu_process_host" not in lowered:
            continue
        for match in _GPU_EXIT_CODE_PATTERN.finditer(line):
            value = match.group(1)
            if value not in exit_codes:
                exit_codes.append(value)
        if ("0x80000003" in lowered or "-2147483645" in lowered) and not exit_codes:
            value = "0x80000003" if "0x80000003" in lowered else "-2147483645"
            exit_codes.append(value)
    if gpu_lines and not exit_codes:
        for value in ("0x80000003", "-2147483645"):
            if value.casefold() in log_text.casefold():
                exit_codes.append(value)
    attempt_count = len(attempt_lines)
    if gpu_lines and attempt_count == 0:
        # The fatal line itself proves that Chromium attempted at least one
        # GPU child, even if this Electron build omitted launch diagnostics.
        attempt_count = 1
    fatal_line = next(
        (
            line
            for line in reversed(gpu_lines)
            if re.search(r"(?:fatal|isn't usable|exited unexpectedly|0x80000003|-2147483645)", line, re.IGNORECASE)
        ),
        gpu_lines[-1] if gpu_lines else None,
    )
    return {
        "evidence": bool(gpu_lines),
        "gpu_child_launch_attempt_count": attempt_count,
        "gpu_child_exit_codes": exit_codes,
        "renderer_child_process_failure_observed": bool(renderer_failure_lines),
        "fatal_line": fatal_line,
        "raw_relevant_lines": {
            "gpu": gpu_lines[-50:],
            "gpu_attempts": attempt_lines[-50:],
            "renderer_failure": renderer_failure_lines[-50:],
        },
    }


def classify_probe_output(
    log_text: str,
    *,
    still_running: bool,
    return_code: int | None,
    visible_window_count: int = 0,
) -> dict[str, object]:
    """Classify one probe and preserve the exact lines that caused a block."""
    updater_lines = _matching_lines(log_text, _UPDATER_IDENTITY_PATTERNS)
    other_identity_lines = _matching_lines(log_text, _OTHER_PACKAGE_IDENTITY_PATTERNS)
    single_instance_lines = _matching_lines(log_text, _SINGLE_INSTANCE_PATTERNS)
    native_module_lines = _matching_lines(log_text, _MISSING_DLL_PATTERNS)
    resource_lines = _matching_lines(log_text, _RESOURCE_PATTERNS)
    crash_lines = _matching_lines(log_text, _CRASH_PATTERNS)
    chromium_sandbox = _chromium_sandbox_evidence(log_text)
    cleanup_artifact_only = (
        still_running
        and chromium_sandbox["evidence"] is True
        and chromium_sandbox["gpu_child_exit_codes"]
        and set(chromium_sandbox["gpu_child_exit_codes"]) == {_PROBE_TERMINATION_EXIT_CODE}
        and not re.search(r"gpu process isn't usable|0x80000003|-2147483645", log_text, re.IGNORECASE)
    )
    if cleanup_artifact_only:
        chromium_sandbox["evidence"] = False
        chromium_sandbox["cleanup_artifact_only"] = True

    # A stable process or a visible window without fatal evidence is the only
    # positive result. Identity errors are considered before generic crashes so
    # the report remains actionable.
    if chromium_sandbox["evidence"]:
        status = BLOCKED_CHROMIUM_SANDBOX
        reason = "Chromium GPU/renderer child evidence indicates a Windows sandbox startup failure"
    elif still_running or (
        visible_window_count > 0
        and not crash_lines
        and not updater_lines
        and not other_identity_lines
    ):
        status = PASS
        reason = "shell remained running or exposed a window without fatal launch evidence"
    elif updater_lines:
        status = BLOCKED_UPDATER_IDENTITY
        reason = "the packaged updater initializer requires an unavailable package identity"
    elif other_identity_lines:
        status = BLOCKED_OTHER_PACKAGE_IDENTITY
        reason = "the packaged shell reported a non-updater package activation/identity failure"
    elif single_instance_lines:
        status = BLOCKED_SINGLE_INSTANCE_LOCK
        reason = "the shell reported an existing or conflicting instance"
    elif native_module_lines:
        status = BLOCKED_NATIVE_MODULE
        reason = "a native module or DLL could not be loaded"
    elif resource_lines:
        status = BLOCKED_RESOURCE
        reason = "the shell could not locate or open a packaged ASAR/resource"
    else:
        status = CRASHED
        reason = f"the shell exited before a healthy window/startup interval (code={return_code})"

    return {
        "status": status,
        "reason": reason,
        "relevant_log_lines": {
            "updater_identity": updater_lines,
            "other_package_identity": other_identity_lines,
            "single_instance": single_instance_lines,
            "native_module": native_module_lines,
            "resource": resource_lines,
            "crash": crash_lines,
            "chromium_sandbox": chromium_sandbox["raw_relevant_lines"],
        },
        "chromium_sandbox": chromium_sandbox,
    }


def _snapshot_rows(
    pids: Iterable[int],
    snapshot: Iterable[RunningProcessCandidate],
) -> list[dict[str, object]]:
    wanted = set(int(pid) for pid in pids)
    return [candidate.to_dict() for candidate in snapshot if candidate.pid in wanted]


def _official_instance_present() -> bool:
    for candidate in discover_process_snapshot_native():
        if candidate.executable is not None and is_windowsapps_path(candidate.executable):
            if candidate.name.casefold() in {"chatgpt.exe", "codex.exe"}:
                return True
    return False


def _validated_real_codex(real: RealCodexCandidate) -> tuple[bool, str | None]:
    if not real.path.is_file():
        return False, "validated native codex.exe is not present"
    if is_windowsapps_path(real.path):
        return False, "refusing a WindowsApps codex.exe as the probe CLI"
    if not real.valid_native and not is_native_windows_executable(real.path):
        return False, "codex.exe is not a validated native Windows executable"
    return True, None


def _profile_path_evidence(
    log_text: str,
    *,
    user_data: Path,
    codex_home: Path,
    mux_home: Path | None = None,
    real_codex: Path,
) -> dict[str, object]:
    allowed = tuple(path for path in (user_data, codex_home, mux_home, real_codex.parent) if path is not None)
    production_markers = (
        r"\\\.codex(?:\\|$)",
        r"\\appdata\\roaming\\codex(?:\\|$)",
        r"\\appdata\\local\\openai\\codex(?:\\|$)",
    )
    outside: list[str] = []
    seen: set[str] = set()
    for raw in _ABSOLUTE_PATH_PATTERN.findall(log_text):
        candidate = Path(raw.rstrip(".,;)]}"))
        if not any(re.search(pattern, str(candidate), re.IGNORECASE) for pattern in production_markers):
            continue
        if any(path_is_within(candidate, root) for root in allowed):
            continue
        key = str(candidate).casefold()
        if key not in seen:
            seen.add(key)
            outside.append(str(candidate))
    return {
        "allowed_roots": [str(path) for path in allowed],
        "outside_profile_paths": outside[:50],
        "outside_profile_touch_detected": bool(outside),
    }


def _flag_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    return _matching_lines(text, patterns)


def _mirror_candidate_path(mirror_root: Path, candidate: DesktopExecutableCandidate) -> Path:
    relative = candidate.relative_path.replace("/", "\\")
    parts = [part for part in relative.split("\\") if part]
    # Inventory paths are package-relative (app\\ChatGPT.exe), while a
    # Desktop mirror is rooted at the source app directory itself.
    if parts and parts[0].casefold() == "app":
        parts = parts[1:]
    return mirror_root.joinpath(*parts)


@contextmanager
def _probe_profile_root(
    workspace_root: Path,
    profile_root: Path | None,
) -> Iterator[Path]:
    """Use disposable profiles, optionally in a final-layout-equivalent root."""
    if profile_root is None:
        with tempfile.TemporaryDirectory(prefix="codex-router-probe-") as temporary:
            yield Path(temporary)
        return

    root = profile_root.expanduser().resolve(strict=False)
    workspace = workspace_root.expanduser().resolve(strict=False)
    if not path_is_within(root, workspace):
        raise RuntimeError("probe profile root must remain inside the Router smoke root")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("User Data", "codex-home"):
        path = root / name
        if path.is_symlink():
            raise RuntimeError(f"refusing to use a symlinked isolated profile path: {path}")
        if path.exists():
            if not path_is_within(path, root):
                raise RuntimeError(f"isolated profile path escaped the Router smoke root: {path}")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        path.mkdir(parents=True, exist_ok=True)
    yield root


def _probe_candidate(
    mirror_root: Path,
    workspace_root: Path,
    real: RealCodexCandidate,
    candidate: DesktopExecutableCandidate,
    *,
    timeout_seconds: float,
    baseline: tuple[RunningProcessCandidate, ...] | None = None,
    extra_arguments: Iterable[str] = (),
    profile_root: Path | None = None,
) -> dict[str, object]:
    """Launch one candidate with an isolated profile and attributed cleanup."""
    if os.name != "nt":
        return {
            "candidate": candidate.relative_path,
            "source_path": str(candidate.path),
            "status": "NOT AVAILABLE",
            "reason": "native Windows Desktop launch probes are Windows-only",
            "manual_operation_required": False,
        }

    executable = _mirror_candidate_path(mirror_root, candidate)
    valid_real, real_error = _validated_real_codex(real)
    if not valid_real:
        return {
            "candidate": candidate.relative_path,
            "source_path": str(candidate.path),
            "mirrored_path": str(executable),
            "status": CRASHED,
            "reason": real_error,
            "manual_operation_required": False,
        }
    if not executable.is_file():
        return {
            "candidate": candidate.relative_path,
            "source_path": str(candidate.path),
            "mirrored_path": str(executable),
            "status": NOT_PRESENT,
            "reason": "candidate was present in source inventory but not in the mirror",
            "manual_operation_required": False,
        }

    extra_arguments = tuple(str(argument) for argument in extra_arguments)
    with _probe_profile_root(workspace_root, profile_root) as probe_root:
        user_data = probe_root / "User Data"
        codex_home = probe_root / "codex-home"
        log_path = probe_root / "startup.log"
        user_data.mkdir(parents=True, exist_ok=True)
        codex_home.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_CLI_PATH": str(real.path),
                "CODEX_ELECTRON_USER_DATA_PATH": str(user_data),
                "CODEX_MUX_DESKTOP_USER_DATA": str(user_data),
                "CODEX_HOME": str(codex_home),
                "CODEX_SPARKLE_ENABLED": "false",
                "ELECTRON_ENABLE_LOGGING": "1",
                "ELECTRON_ENABLE_STACK_DUMPING": "1",
            }
        )
        command = [str(executable), *extra_arguments, f"--user-data-dir={user_data}"]
        baseline_rows = tuple(baseline) if baseline is not None else tuple(discover_process_snapshot_native())
        baseline_pids = {row.pid for row in baseline_rows}
        attributed: set[int] = set()
        observations: list[dict[str, object]] = []
        official_instance = _official_instance_present()
        process: subprocess.Popen[bytes] | None = None
        launch_error: str | None = None
        started = time.monotonic()
        with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=mirror_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                )
            except (OSError, subprocess.SubprocessError) as error:
                launch_error = str(error)

            return_code: int | None = None
            if process is not None:
                deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < deadline:
                    time.sleep(0.25)
                    snapshot = discover_process_snapshot_native()
                    current = attributable_process_pids(
                        process.pid,
                        baseline_pids,
                        snapshot,
                        mirror_root,
                        seed_pids=attributed,
                        additional_executable_paths=(real.path,),
                    )
                    attributed.update(current)
                    windows = enumerate_windows_for_processes(current)
                    observations.append(
                        {
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "return_code": process.poll(),
                            "processes": _snapshot_rows(current, snapshot),
                            "windows": windows,
                        }
                    )
                    if process.poll() is not None:
                        break
                return_code = process.poll()
                final_snapshot = discover_process_snapshot_native()
                final_attributed = attributable_process_pids(
                    process.pid,
                    baseline_pids,
                    final_snapshot,
                    mirror_root,
                    seed_pids=attributed,
                    additional_executable_paths=(real.path,),
                )
                attributed.update(final_attributed)
                final_windows = enumerate_windows_for_processes(sorted(attributed))
                final_processes = _snapshot_rows(attributed, final_snapshot)
                still_running = return_code is None
                cleanup = terminate_attributed_processes(
                    attributed,
                    final_snapshot,
                    mirror_root,
                    root_pid=process.pid,
                    allowed_executable_paths=(real.path,),
                )
                # The root is known from Popen and is already part of the
                # attributed set. If its snapshot disappeared after the last
                # poll, use the handle-backed Popen operation only for that
                # root; descendants remain governed by the native attribution
                # set above.
                if still_running:
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                        cleanup.setdefault("terminated_by_popen", []).append(process.pid)
                    except (OSError, subprocess.SubprocessError) as error:
                        cleanup.setdefault("errors", []).append(f"root cleanup: {error}")
            else:
                final_processes = []
                final_windows = []
                still_running = False
                cleanup = {"tracked": [], "requested": [], "terminated": [], "errors": []}
                return_code = None

        log_text = _tail(log_path)
        classification = (
            classify_probe_output(
                log_text,
                still_running=still_running,
                return_code=return_code,
                visible_window_count=len(final_windows),
            )
            if launch_error is None
            else {
                "status": CRASHED,
                "reason": f"could not launch mirrored shell: {launch_error}",
                "relevant_log_lines": {},
            }
        )
        relevant = classification.get("relevant_log_lines", {})
        if not isinstance(relevant, dict):
            relevant = {}
        isolation = _profile_path_evidence(
            log_text,
            user_data=user_data,
            codex_home=codex_home,
            real_codex=real.path,
        )
        isolation.update(
            {
                "user_data": str(user_data),
                "codex_home": str(codex_home),
                "code_cli_path": str(real.path),
                "sparkle_enabled": False,
                "argument_user_data_dir": str(user_data),
                "contract_valid": all(
                    environment.get(key) == value
                    for key, value in {
                        "CODEX_CLI_PATH": str(real.path),
                        "CODEX_ELECTRON_USER_DATA_PATH": str(user_data),
                        "CODEX_HOME": str(codex_home),
                        "CODEX_SPARKLE_ENABLED": "false",
                    }.items()
                ),
            }
        )
        return {
            "candidate": candidate.relative_path,
            "source_path": str(candidate.path),
            "mirrored_path": str(executable),
            "status": classification["status"],
            "reason": classification["reason"],
            "command": command,
            "diagnostic_arguments": list(extra_arguments),
            "working_directory": str(mirror_root),
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "return_code": return_code,
            "still_running_at_timeout": still_running,
            "official_windowsapps_instance_present_before_launch": official_instance,
            "process_observations": observations[-20:],
            "final_processes": final_processes,
            "final_windows": final_windows,
            "cleanup": cleanup,
            "flags": {
                "packaged": _flag_lines(log_text, _PACKAGED_PATTERNS),
                "enable_updater": _flag_lines(log_text, _ENABLE_UPDATER_PATTERNS),
                "app_server": _flag_lines(log_text, _APP_SERVER_PATTERNS),
                "native_module": relevant.get("native_module", []),
                "resource": relevant.get("resource", []),
                "single_instance": relevant.get("single_instance", []),
                "package_identity": (
                    list(relevant.get("updater_identity", []))
                    + list(relevant.get("other_package_identity", []))
                ),
                "chromium_sandbox": relevant.get("chromium_sandbox", []),
            },
            "relevant_log_lines": relevant,
            "chromium_sandbox": classification.get("chromium_sandbox", {}),
            "log_tail": log_text,
            "profile_isolation": isolation,
            "manual_operation_required": False,
        }


def _http_json_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 0.75,
) -> tuple[int | None, object | None, str | None]:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code), None, str(error)
    except (OSError, ValueError, urllib.error.URLError) as error:
        return None, None, str(error)
    try:
        return status, json.loads(raw.decode("utf-8", errors="replace")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return status, None, str(error)


def _process_path_matches(row: RunningProcessCandidate, expected: Path) -> bool:
    return (
        row.executable is not None
        and row.executable.expanduser().resolve(strict=False)
        == expected.expanduser().resolve(strict=False)
    )


def _has_windows_short_path_component(path: Path) -> bool:
    return any(re.search(r"~\d(?:$|\.)", part) for part in path.parts)


def _path_comparison_key(path: Path) -> str:
    # Windows runners may return an 8.3 alias from GetTempPathW while
    # Path.resolve() returns the long spelling. Normalize that benign alias,
    # but keep the raw spelling for ordinary paths so AppContainer
    # virtualization remains visible as a real path change.
    if os.name == "nt" and _has_windows_short_path_component(path):
        try:
            return str(path.resolve(strict=True)).casefold()
        except OSError:
            pass
    return str(path).casefold()


def native_evidence_is_usable(cleanup_status: dict[str, object]) -> bool:
    """Return true only after a non-virtual root has been successfully removed."""

    return (
        cleanup_status.get("path_virtualized") is False
        and cleanup_status.get("removed") is True
    )


def validation_profile_root(local_appdata: Path | None = None) -> Path:
    """Return the Router-owned persistent Desktop validation profile root."""
    return validation_profile_layout(local_appdata).root


@dataclass(frozen=True)
class ValidationProfileLayout:
    """The persistent state boundary and the rebuildable shell location."""

    root: Path
    user_data: Path
    codex_home: Path
    mux_home: Path
    patched_shell: Path

    def to_dict(self, *, exists: bool | None = None, preserved: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "root": str(self.root),
            "user_data": str(self.user_data),
            "codex_home": str(self.codex_home),
            "mux_home": str(self.mux_home),
            "patched_shell": str(self.patched_shell),
            "persistent": True,
            "preserved": preserved,
        }
        if exists is not None:
            result["exists"] = exists
        return result


def validation_profile_layout(
    local_appdata: Path | None = None,
    profile_root: Path | None = None,
) -> ValidationProfileLayout:
    """Resolve every persistent path under the Router-owned profile boundary."""

    if local_appdata is None:
        local_appdata_value = os.environ.get("LOCALAPPDATA")
        local_appdata = (
            Path(local_appdata_value).expanduser()
            if local_appdata_value
            else Path.home() / "AppData" / "Local"
        )
    owner_root = (local_appdata.expanduser() / "Codex Subscription Router").resolve(strict=False)
    expected_root = (owner_root / VALIDATION_PROFILE_DIRNAME).resolve(strict=False)
    requested_root = profile_root.expanduser() if profile_root is not None else expected_root
    root = requested_root.resolve(strict=False)
    if is_windowsapps_path(root):
        raise RuntimeError("the Router validation profile must be outside WindowsApps")
    if root != expected_root:
        raise RuntimeError(
            "the persistent Router validation profile must remain under "
            "%LOCALAPPDATA%\\Codex Subscription Router\\_validation-profile"
        )
    layout = ValidationProfileLayout(
        root=root,
        user_data=root / VALIDATION_USER_DATA_DIRNAME,
        codex_home=root / VALIDATION_CODEX_HOME_DIRNAME,
        mux_home=root / VALIDATION_MUX_HOME_DIRNAME,
        patched_shell=root / VALIDATION_PATCHED_SHELL_DIRNAME,
    )
    for name, path in (
        ("User Data", layout.user_data),
        ("CODEX_HOME", layout.codex_home),
        ("CODEX_MUX_HOME", layout.mux_home),
        ("patched-shell", layout.patched_shell),
    ):
        if is_windowsapps_path(path) or not path_is_within(path, layout.root):
            raise RuntimeError(f"persistent {name} escaped the Router validation profile")
    return layout


ROUTER_RENDERER_NOT_LOADED = "ROUTER_RENDERER_NOT_LOADED"
ROUTER_RENDERER_RUNTIME_ERROR = "ROUTER_RENDERER_RUNTIME_ERROR"
ROUTER_UI_NOT_READY = "ROUTER_UI_NOT_READY"
ROUTER_DESKTOP_AUTH_REQUIRED = "ROUTER_DESKTOP_AUTH_REQUIRED"
ROUTER_DESKTOP_AUTH_UNKNOWN = "ROUTER_DESKTOP_AUTH_UNKNOWN"
ROUTER_PROFILE_CONTROLLER_NOT_READY = "ROUTER_PROFILE_CONTROLLER_NOT_READY"
ROUTER_PROFILE_ACTIVATION_FAILED = "ROUTER_PROFILE_ACTIVATION_FAILED"
ROUTER_MENU_NOT_INJECTED_AFTER_OPEN = "ROUTER_MENU_NOT_INJECTED_AFTER_OPEN"
ROUTER_MENU_NOT_INJECTED = "ROUTER_MENU_NOT_INJECTED"
ROUTER_MENU_NOT_MOUNTED = "ROUTER_MENU_NOT_MOUNTED"
ROUTER_MENU_ACCOUNTS_LOADING = "ROUTER_MENU_ACCOUNTS_LOADING"
ROUTER_MENU_ACCOUNTS_LOAD_FAILED = "ROUTER_MENU_ACCOUNTS_LOAD_FAILED"
DESKTOP_AUTH_PREPARED = "DESKTOP_AUTH_PREPARED"
VALIDATION_PROFILE_DIRNAME = "_validation-profile"
VALIDATION_USER_DATA_DIRNAME = "User Data"
VALIDATION_CODEX_HOME_DIRNAME = "codex-home"
VALIDATION_MUX_HOME_DIRNAME = "mux-home"
VALIDATION_PATCHED_SHELL_DIRNAME = "patched-shell"
AUTH_PERSISTENCE_QUIESCENCE_SECONDS = 2.0

_DESKTOP_AUTH_STATES = {"AUTHENTICATED", "AUTH_REQUIRED", "UNKNOWN"}


def _desktop_auth_evidence(ui_body: object) -> dict[str, object]:
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    raw = debug.get("desktop_auth") if isinstance(debug, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    state = raw.get("state")
    return {"state": state if isinstance(state, str) and state in _DESKTOP_AUTH_STATES else "UNKNOWN"}


def _renderer_runtime_evidence(ui_body: object) -> dict[str, object] | None:
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    raw = debug.get("renderer_runtime") if isinstance(debug, dict) else None
    if not isinstance(raw, dict):
        return None
    output: dict[str, object] = {}
    ready_state = raw.get("readyState")
    if isinstance(ready_state, str) and ready_state in {"loading", "interactive", "complete", "unknown"}:
        output["ready_state"] = ready_state
    for source_key, target_key in (
        ("rootPresent", "root_present"),
        ("composerPresent", "composer_present"),
        ("profileControllerReady", "profile_controller_ready"),
    ):
        value = raw.get(source_key)
        if isinstance(value, bool):
            output[target_key] = value
    for source_key, target_key in (
        ("rootChildCount", "root_child_count"),
        ("bodyChildCount", "body_child_count"),
        ("buttonCount", "button_count"),
        ("visibleInteractiveCount", "visible_interactive_count"),
        ("runtimeErrorCount", "runtime_error_count"),
    ):
        value = raw.get(source_key)
        if type(value) is int and value >= 0:
            output[target_key] = value
    last_error = raw.get("lastSafeRuntimeError")
    if isinstance(last_error, dict):
        output["last_safe_runtime_error"] = {
            key: last_error[key]
            for key in ("kind", "name", "source_asset", "line", "column")
            if isinstance(last_error.get(key), (str, int)) or last_error.get(key) is None
        }
    return output


def _profile_controller_evidence(ui_body: object) -> dict[str, bool]:
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    raw = debug.get("profile_controller") if isinstance(debug, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    return {
        "ready": raw.get("ready") is True,
        "activation_attempted": raw.get("activationAttempted") is True,
        "activation_succeeded": raw.get("activationSucceeded") is True,
    }


def _runtime_error_evidence(ui_body: object) -> list[dict[str, object]]:
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    raw = debug.get("runtime_errors") if isinstance(debug, dict) else None
    if not isinstance(raw, list):
        return []
    output: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                key: item[key]
                for key in ("kind", "name", "source_asset", "line", "column", "reason", "exit_code")
                if isinstance(item.get(key), (str, int)) or item.get(key) is None
            }
        )
    return output[-20:]


def _router_account_menu_evidence(ui_body: object) -> dict[str, object]:
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    router = debug.get("router") if isinstance(debug, dict) else None
    router = router if isinstance(router, dict) else {}
    account_count = router.get("accountCount")
    if type(account_count) is not int or account_count < 0:
        account_count = 0
    return {
        "renderer_loaded": router.get("rendererPatchLoaded") is True,
        "desktop_auth": _desktop_auth_evidence(ui_body),
        "renderer_runtime": _renderer_runtime_evidence(ui_body),
        "profile_controller": _profile_controller_evidence(ui_body),
        "runtime_errors": _runtime_error_evidence(ui_body),
        "injected": router.get("accountMenuInjected") is True,
        "mounted": router.get("accountMenuMounted") is True,
        "accounts_loaded": router.get("accountsLoaded") is True,
        "account_count": account_count,
        "request_failed": router.get("requestFailed") is True,
    }


def router_account_menu_gate(
    ui_body: object,
    *,
    mounting_expected: bool = True,
    activation_attempted: bool = False,
    activation_succeeded: bool = False,
) -> dict[str, object]:
    """Evaluate only Router-owned account-menu runtime evidence.

    The native profile trigger is deliberately excluded. It is an upstream
    implementation detail and is not a stable indication that the Router
    component was injected, mounted, or able to load account state.
    """
    evidence = _router_account_menu_evidence(ui_body)
    runtime = evidence["renderer_runtime"]
    controller = evidence["profile_controller"]
    auth = evidence["desktop_auth"]["state"]
    if isinstance(runtime, dict):
        runtime_error_count = runtime.get("runtime_error_count", len(evidence["runtime_errors"]))
        if not evidence["renderer_loaded"]:
            status = ROUTER_RENDERER_NOT_LOADED
        elif (type(runtime_error_count) is int and runtime_error_count > 0) or evidence["runtime_errors"]:
            status = ROUTER_RENDERER_RUNTIME_ERROR
        elif runtime.get("ready_state") in {"loading", "interactive"} or runtime.get("root_present") is False:
            status = ROUTER_UI_NOT_READY
        elif auth == "AUTH_REQUIRED":
            status = ROUTER_DESKTOP_AUTH_REQUIRED
        elif auth == "UNKNOWN":
            status = ROUTER_DESKTOP_AUTH_UNKNOWN
        elif not controller["ready"]:
            status = ROUTER_PROFILE_CONTROLLER_NOT_READY
        elif activation_attempted and not activation_succeeded:
            status = ROUTER_PROFILE_ACTIVATION_FAILED
        elif activation_attempted and not evidence["injected"]:
            status = ROUTER_MENU_NOT_INJECTED_AFTER_OPEN
        elif not evidence["injected"]:
            status = ROUTER_MENU_NOT_INJECTED
        elif mounting_expected and not evidence["mounted"]:
            status = ROUTER_MENU_NOT_MOUNTED
        elif evidence["request_failed"]:
            status = ROUTER_MENU_ACCOUNTS_LOAD_FAILED
        elif mounting_expected and not evidence["accounts_loaded"]:
            status = ROUTER_MENU_ACCOUNTS_LOADING
        else:
            status = PASS
        return {**evidence, "activation_attempted": activation_attempted, "activation_succeeded": activation_succeeded, "status": status, "pass": status == PASS}
    if not evidence["renderer_loaded"]:
        status = ROUTER_RENDERER_NOT_LOADED
    elif auth == "AUTH_REQUIRED":
        status = ROUTER_DESKTOP_AUTH_REQUIRED
    elif auth == "UNKNOWN":
        status = ROUTER_DESKTOP_AUTH_UNKNOWN
    elif not controller["ready"]:
        status = ROUTER_PROFILE_CONTROLLER_NOT_READY
    elif activation_attempted and not activation_succeeded:
        status = ROUTER_PROFILE_ACTIVATION_FAILED
    elif activation_attempted and not evidence["injected"]:
        status = ROUTER_MENU_NOT_INJECTED_AFTER_OPEN
    elif not evidence["injected"]:
        status = ROUTER_MENU_NOT_INJECTED
    elif mounting_expected and not evidence["mounted"]:
        status = ROUTER_MENU_NOT_MOUNTED
    elif evidence["request_failed"]:
        status = ROUTER_MENU_ACCOUNTS_LOAD_FAILED
    elif mounting_expected and not evidence["accounts_loaded"]:
        status = ROUTER_MENU_ACCOUNTS_LOADING
    else:
        status = PASS
    return {**evidence, "activation_attempted": activation_attempted, "activation_succeeded": activation_succeeded, "status": status, "pass": status == PASS}


def _native_profile_trigger_diagnostic(ui_body: object) -> str:
    """Report the upstream profile trigger without using it as a gate."""
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    buttons = debug.get("buttons") if isinstance(debug, dict) else None
    if isinstance(buttons, list) and any(
        isinstance(button, dict)
        and button.get("ariaLabel") == "Open profile menu"
        for button in buttons
    ):
        return "OBSERVED"
    return "UNKNOWN / NOT OBSERVED"


def build_production_gate(
    *,
    launcher_running: bool,
    chatgpt_classification: bool,
    mux_health: bool,
    ui_bridge: bool,
    router_account_menu: bool,
    mux_process: bool,
    real_codex_process: bool,
    production_sandbox: bool,
    cleanup: bool,
) -> dict[str, object]:
    checks = {
        "launcher_running": bool(launcher_running),
        "chatgpt_classification": bool(chatgpt_classification),
        "mux_health": bool(mux_health),
        "ui_bridge": bool(ui_bridge),
        "router_account_menu": bool(router_account_menu),
        "mux_process": bool(mux_process),
        "real_codex_process": bool(real_codex_process),
        "production_sandbox": bool(production_sandbox),
        "cleanup": bool(cleanup),
    }
    return {
        "pass": all(checks.values()),
        "failed": [key for key, value in checks.items() if not value],
        "checks": checks,
    }


def run_patched_shell_smoke(
    installation_root: Path,
    real: RealCodexCandidate,
    *,
    timeout_seconds: float = 20.0,
    disposable_root: bool = False,
    diagnostic_arguments: Iterable[str] = (),
    development_only: bool = False,
    user_data_override: Path | None = None,
    codex_home_override: Path | None = None,
    mux_home_override: Path | None = None,
    preserve_user_data: bool = False,
    auth_required: bool = False,
    authentication_preparation: bool = False,
    fail_if_auth_required: bool = False,
    validation_profile_root_override: Path | None = None,
    validation_profile_local_appdata: Path | None = None,
) -> dict[str, object]:
    """Launch a built Router and verify the production path contract.

    This probe never logs in, sends account mutations, or removes an
    installation. ``disposable_root`` is explicit so callers cannot
    accidentally point the probe at a user's existing Router installation.
    Persistent authenticated validation must provide the complete
    ``ValidationProfileLayout`` boundary through the three override paths.
    """
    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "reason": "the patched-shell smoke is Windows-only",
            "manual_operation_required": False,
        }
    diagnostic_arguments = tuple(str(argument) for argument in diagnostic_arguments)
    allowed_diagnostic_arguments = {
        "--disable-gpu-sandbox",
        "--no-sandbox",
    }
    if diagnostic_arguments and (
        not development_only
        or any(argument.casefold() not in allowed_diagnostic_arguments for argument in diagnostic_arguments)
    ):
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "sandbox diagnostic arguments require an explicit development-only disposable smoke",
            "diagnostic_arguments": list(diagnostic_arguments),
            "manual_operation_required": True,
        }
    root = installation_root.expanduser().resolve(strict=False)
    persistent_requested = any(
        value is not None
        for value in (
            user_data_override,
            codex_home_override,
            mux_home_override,
            validation_profile_root_override,
        )
    )
    if not disposable_root and not persistent_requested:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "patched-shell smoke requires an explicitly disposable Router root or an explicit validation profile",
            "installation_root": str(root),
            "manual_operation_required": True,
        }
    if is_windowsapps_path(root):
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "refusing to launch a patched shell from WindowsApps",
            "installation_root": str(root),
            "manual_operation_required": True,
        }

    launcher = root / "Codex Subscription Router.exe"
    app_root = root / "app"
    profile_layout: ValidationProfileLayout | None = None
    if persistent_requested:
        try:
            profile_layout = validation_profile_layout(
                local_appdata=(
                    validation_profile_local_appdata
                    if validation_profile_local_appdata is not None
                    else (
                        validation_profile_root_override.expanduser().resolve(strict=False).parent.parent
                        if validation_profile_root_override is not None
                        else None
                    )
                ),
                profile_root=(
                    validation_profile_root_override
                    if validation_profile_root_override is not None
                    else None
                )
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": f"persistent validation profile was rejected: {error}",
                "installation_root": str(root),
                "manual_operation_required": True,
            }
        if root != profile_layout.patched_shell:
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "persistent patched-shell smoke must launch the profile's patched-shell directory",
                "installation_root": str(root),
                "validation_profile": profile_layout.to_dict(),
                "manual_operation_required": True,
            }
        if not preserve_user_data:
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "persistent validation state requires explicit preservation",
                "installation_root": str(root),
                "validation_profile": profile_layout.to_dict(),
                "manual_operation_required": True,
            }
        overrides = {
            "User Data": user_data_override,
            "CODEX_HOME": codex_home_override,
            "CODEX_MUX_HOME": mux_home_override,
        }
        expected_paths = {
            "User Data": profile_layout.user_data,
            "CODEX_HOME": profile_layout.codex_home,
            "CODEX_MUX_HOME": profile_layout.mux_home,
        }
        for name, override in overrides.items():
            if override is not None and override.expanduser().resolve(strict=False) != expected_paths[name]:
                return {
                    "status": PATCHED_SHELL_BLOCKED,
                    "reason": f"persistent {name} override must equal its Router-owned validation profile path",
                    "installation_root": str(root),
                    "validation_profile": profile_layout.to_dict(),
                    "manual_operation_required": True,
                }
        if auth_required and any(override is None for override in overrides.values()):
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "authenticated Desktop validation requires explicit User Data, CODEX_HOME, and CODEX_MUX_HOME overrides",
                "installation_root": str(root),
                "validation_profile": profile_layout.to_dict(),
                "manual_operation_required": True,
            }
        user_data = expected_paths["User Data"]
        codex_home = expected_paths["CODEX_HOME"]
        mux_home = expected_paths["CODEX_MUX_HOME"]
        for name, path in expected_paths.items():
            if is_windowsapps_path(path) or not path_is_within(path, profile_layout.root):
                return {
                    "status": PATCHED_SHELL_BLOCKED,
                    "reason": f"persistent {name} escaped the Router-owned validation profile",
                    "installation_root": str(root),
                    "validation_profile": profile_layout.to_dict(),
                    "manual_operation_required": True,
                }
            if path.is_symlink():
                return {
                    "status": PATCHED_SHELL_BLOCKED,
                    "reason": f"refusing a symlinked persistent {name} path",
                    "installation_root": str(root),
                    "validation_profile": profile_layout.to_dict(),
                    "manual_operation_required": True,
                }
            path.mkdir(parents=True, exist_ok=True)
    else:
        user_data = root / VALIDATION_USER_DATA_DIRNAME
        codex_home = root / VALIDATION_CODEX_HOME_DIRNAME
        runtime = root / "runtime"
        mux_home = runtime / ".codex-mux"
    if auth_required and not persistent_requested:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "authenticated Desktop validation requires the persistent Router validation profile",
            "installation_root": str(root),
            "manual_operation_required": True,
        }
    if persistent_requested:
        runtime = root / "runtime"
        forbidden_state_paths = (
            root / VALIDATION_USER_DATA_DIRNAME,
            root / VALIDATION_CODEX_HOME_DIRNAME,
            runtime / ".codex-mux",
        )
        if any(path.exists() for path in forbidden_state_paths):
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "persistent Router state must remain outside patched-shell",
                "installation_root": str(root),
                "validation_profile": profile_layout.to_dict() if profile_layout is not None else None,
                "manual_operation_required": True,
            }
    mux = runtime / "codex-mux.exe"
    staged_real = runtime / "codex.real.exe"
    control_token = mux_home / "control-token"
    required = (
        ("launcher", launcher),
        ("app", app_root),
        ("user_data", user_data),
        ("codex_home", codex_home),
        ("mux", mux),
        ("real_codex", staged_real),
        ("control_token", control_token),
    )
    missing = []
    for name, path in required:
        if path.exists():
            continue
        try:
            display = str(path.relative_to(root))
        except ValueError:
            display = str(path)
        missing.append(f"{name}={display}")
    if missing:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": f"Router layout is incomplete: {', '.join(missing)}",
            "installation_root": str(root),
            "manual_operation_required": False,
        }
    if any(
        path.is_symlink()
        for path in (root, launcher, app_root, user_data, codex_home, runtime, mux, staged_real, mux_home, control_token)
    ):
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "refusing symlinked Router smoke paths",
            "installation_root": str(root),
            "manual_operation_required": True,
        }
    valid_real, real_error = _validated_real_codex(real)
    if not valid_real:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": real_error,
            "installation_root": str(root),
            "manual_operation_required": False,
        }

    try:
        token = control_token.read_text(encoding="utf-8").strip()
    except OSError as error:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": f"could not read Router control-token: {error}",
            "installation_root": str(root),
            "manual_operation_required": False,
        }
    if re.fullmatch(r"[0-9a-f]{64}", token) is None:
        return {
            "status": PATCHED_SHELL_BLOCKED,
            "reason": "Router control-token is not a valid 32-byte hexadecimal token",
            "installation_root": str(root),
            "manual_operation_required": False,
        }

    environment = os.environ.copy()
    environment.update(
        {
            "CODEX_CLI_PATH": str(mux),
            "CODEX_MUX_REAL_CODEX": str(staged_real),
            "CODEX_MUX_HOME": str(mux_home),
            "CODEX_ELECTRON_USER_DATA_PATH": str(user_data),
            "CODEX_MUX_DESKTOP_USER_DATA": str(user_data),
            "CODEX_HOME": str(codex_home),
            "CODEX_SPARKLE_ENABLED": "false",
            "CODEX_MUX_UI_TESTS": "1",
            "CODEX_MUX_CONTROL_TOKEN": token,
            "ELECTRON_ENABLE_LOGGING": "1",
            "ELECTRON_ENABLE_STACK_DUMPING": "1",
        }
    )
    if profile_layout is not None:
        environment["CODEX_MUX_PERSISTENT_PROFILE_ROOT"] = str(profile_layout.root)
    else:
        environment.pop("CODEX_MUX_PERSISTENT_PROFILE_ROOT", None)
    # The patched renderer has the repository control port compiled into its
    # request URLs. Diagnostic arguments are accepted only for the explicit,
    # disposable development-only escape hatch.
    command = [str(launcher), *diagnostic_arguments]
    baseline_rows = tuple(discover_process_snapshot_native())
    baseline_pids = {row.pid for row in baseline_rows}
    attributed: set[int] = set()
    observations: list[dict[str, object]] = []
    launch_error: str | None = None
    process: subprocess.Popen[bytes] | None = None
    started = time.monotonic()
    temporary_log_path: Path | None = None
    if user_data_override is not None:
        log_handle_fd, temporary_log_name = tempfile.mkstemp(prefix="codex-router-patched-shell-", suffix=".log")
        os.close(log_handle_fd)
        log_path = Path(temporary_log_name)
        temporary_log_path = log_path
    else:
        log_path = root / "patched-shell-smoke.log"
    with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
        try:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except (OSError, subprocess.SubprocessError) as error:
            launch_error = str(error)

        health_status: int | None = None
        health_body: object | None = None
        health_error: str | None = None
        ui_status: int | None = None
        ui_body: object | None = None
        ui_error: str | None = None
        launcher_observed_running = False
        router_account_menu = router_account_menu_gate({})
        activation_attempted = False
        activation_succeeded = False
        authentication_confirmed = False
        authentication_confirmed_at: float | None = None
        graceful_shutdown_attempted = False
        graceful_shutdown_requested = False
        graceful_shutdown_succeeded = False
        graceful_shutdown_status = "NOT_REQUIRED"
        graceful_shutdown_error: str | None = None
        mux_process_observed = False
        real_codex_process_observed = False
        deadline = time.monotonic() + timeout_seconds
        while process is not None and time.monotonic() < deadline:
            snapshot = discover_process_snapshot_native()
            current = attributable_process_pids(
                process.pid,
                baseline_pids,
                snapshot,
                root,
                seed_pids=attributed,
                additional_executable_paths=(staged_real, mux),
            )
            attributed.update(current)
            launcher_observed_running = launcher_observed_running or process.poll() is None
            windows = enumerate_windows_for_processes(current)
            rows = _snapshot_rows(current, snapshot)
            observations.append(
                {
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "return_code": process.poll(),
                    "processes": rows,
                    "windows": windows,
                }
            )
            if health_status != 200:
                health_status, health_body, health_error = _http_json_get(
                    "http://127.0.0.1:48123/v1/health"
                )
            if ui_status != 200 or not router_account_menu["pass"]:
                ui_status, ui_body, ui_error = _http_json_get(
                    "http://127.0.0.1:48124/v1/test/app-state?debug=1",
                    headers={"x-codex-mux-token": token},
                )
            router_account_menu = router_account_menu_gate(
                ui_body,
                activation_attempted=activation_attempted,
                activation_succeeded=activation_succeeded,
            )
            if (
                fail_if_auth_required
                and authentication_preparation
                and auth_required
                and router_account_menu.get("status") == ROUTER_DESKTOP_AUTH_REQUIRED
            ):
                break
            desktop_auth = router_account_menu.get("desktop_auth")
            if isinstance(desktop_auth, dict) and desktop_auth.get("state") == "AUTHENTICATED":
                authentication_confirmed = True
                authentication_confirmed_at = authentication_confirmed_at or time.monotonic()
            if (
                not authentication_preparation
                and authentication_confirmed
                and router_account_menu.get("profile_controller", {}).get("ready") is True
                and not activation_attempted
                and ui_status == 200
            ):
                action_url = "http://127.0.0.1:48124/v1/test/app-state?action=profile-router-open&debug=1&delayMs=400"
                action_status, action_body, action_error = _http_json_get(
                    action_url,
                    headers={"x-codex-mux-token": token},
                )
                activation_attempted = True
                activation_succeeded = action_status == 200 and isinstance(action_body, dict)
                if isinstance(action_body, dict):
                    ui_body = action_body
                    ui_status = action_status
                    ui_error = action_error
                router_account_menu = router_account_menu_gate(
                    ui_body,
                    activation_attempted=activation_attempted,
                    activation_succeeded=activation_succeeded,
                )
            if (
                authentication_preparation
                and authentication_confirmed
                and authentication_confirmed_at is not None
                and not graceful_shutdown_attempted
                and time.monotonic() - authentication_confirmed_at >= AUTH_PERSISTENCE_QUIESCENCE_SECONDS
                and ui_status == 200
            ):
                graceful_shutdown_attempted = True
                graceful_shutdown_status = "REQUESTED"
                action_url = (
                    "http://127.0.0.1:48124/v1/test/app-state?"
                    "action=desktop-auth-graceful-quit&debug=0&delayMs=0"
                )
                action_status, action_body, action_error = _http_json_get(
                    action_url,
                    headers={"x-codex-mux-token": token},
                )
                if action_status == 200 and isinstance(action_body, dict) and action_body.get("ok") is True:
                    graceful_shutdown_requested = True
                else:
                    graceful_shutdown_status = "FAILED"
                    graceful_shutdown_error = "graceful Desktop shutdown was not accepted"
                    if action_error:
                        graceful_shutdown_error = "graceful Desktop shutdown request failed"
            if graceful_shutdown_requested and process.poll() is not None:
                graceful_shutdown_succeeded = True
                graceful_shutdown_status = "EXITED"
                break
            mux_observed = any(
                _process_path_matches(row, mux)
                for row in snapshot
                if row.pid in attributed
            )
            real_observed = any(
                _process_path_matches(row, staged_real)
                for row in snapshot
                if row.pid in attributed
            )
            mux_process_observed = mux_process_observed or mux_observed
            real_codex_process_observed = real_codex_process_observed or real_observed
            if (
                health_status == 200
                and ui_status == 200
                and router_account_menu["pass"]
                and mux_process_observed
                and real_codex_process_observed
                and (not authentication_preparation or graceful_shutdown_succeeded)
            ):
                break
            if process.poll() is not None:
                break
            time.sleep(0.25)

        return_code = process.poll() if process is not None else None
        if graceful_shutdown_requested and return_code is not None:
            graceful_shutdown_succeeded = True
            graceful_shutdown_status = "EXITED"
        final_snapshot = discover_process_snapshot_native()
        if process is not None:
            attributed.update(
                attributable_process_pids(
                    process.pid,
                    baseline_pids,
                    final_snapshot,
                    root,
                    seed_pids=attributed,
                    additional_executable_paths=(staged_real, mux),
                )
            )
        final_processes = _snapshot_rows(attributed, final_snapshot)
        final_windows = enumerate_windows_for_processes(sorted(attributed))
        still_running = process is not None and return_code is None
        timeout_reached = still_running and time.monotonic() >= deadline
        process_still_running_at_timeout = timeout_reached
        harness_requested_termination = False
        cleanup = terminate_attributed_processes(
            attributed,
            final_snapshot,
            root,
            root_pid=process.pid if process is not None else None,
            allowed_executable_paths=(staged_real, mux),
        )
        if still_running and process is not None:
            harness_requested_termination = True
            try:
                process.terminate()
                process.wait(timeout=5)
                cleanup.setdefault("terminated_by_popen", []).append(process.pid)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup.setdefault("errors", []).append(f"root cleanup: {error}")

        if authentication_preparation and graceful_shutdown_attempted and not graceful_shutdown_succeeded:
            graceful_shutdown_status = "FORCED_CLEANUP" if harness_requested_termination else "FAILED"

    log_text = _tail(log_path)
    if temporary_log_path is not None:
        try:
            temporary_log_path.unlink()
        except OSError:
            pass
    classification = (
        classify_probe_output(
            log_text,
            still_running=still_running,
            return_code=return_code,
            visible_window_count=len(final_windows),
        )
        if launch_error is None
        else {"status": CRASHED, "reason": f"could not launch patched shell: {launch_error}", "relevant_log_lines": {}}
    )
    debug = ui_body.get("debug") if isinstance(ui_body, dict) else None
    router_account_menu = router_account_menu_gate(
        ui_body,
        activation_attempted=activation_attempted,
        activation_succeeded=activation_succeeded,
    )
    native_profile_trigger_observed = _native_profile_trigger_diagnostic(ui_body)
    mux_observed = any(
        _process_path_matches(row, mux)
        for row in final_snapshot
        if row.pid in attributed
    ) or any(
        isinstance(item.get("executable"), str)
        and Path(str(item["executable"])).name.casefold() == "codex-mux.exe"
        for item in final_processes
    )
    real_observed = any(
        _process_path_matches(row, staged_real)
        for row in final_snapshot
        if row.pid in attributed
    ) or any(
        isinstance(item.get("executable"), str)
        and Path(str(item["executable"])).resolve(strict=False)
        == staged_real.resolve(strict=False)
        for item in final_processes
    )
    mux_process_observed = mux_process_observed or mux_observed
    real_codex_process_observed = real_codex_process_observed or real_observed
    health_pass = health_status == 200 and isinstance(health_body, dict) and health_body.get("ok") is True
    ui_bridge_pass = ui_status == 200 and isinstance(ui_body, dict)
    production_flags_present = any(
        argument.casefold() in {"--no-sandbox", "--disable-gpu-sandbox"}
        or argument.casefold().startswith("--no-sandbox=")
        or argument.casefold().startswith("--disable-gpu-sandbox=")
        for argument in command
    )
    production_gate = build_production_gate(
        launcher_running=launch_error is None and launcher_observed_running,
        chatgpt_classification=classification.get("status") == PASS,
        mux_health=health_pass,
        ui_bridge=ui_bridge_pass,
        router_account_menu=router_account_menu["pass"],
        mux_process=mux_process_observed,
        real_codex_process=real_codex_process_observed,
        production_sandbox=not production_flags_present,
        cleanup=not cleanup.get("errors"),
    )
    required_pass = bool(production_gate["pass"])
    if authentication_preparation:
        required_pass = (
            authentication_confirmed
            and graceful_shutdown_succeeded
            and not cleanup.get("errors")
        )
    if development_only and not required_pass:
        required_pass = all(
            value
            for key, value in production_gate["checks"].items()
            if key != "production_sandbox"
        )
    status = (
        DESKTOP_AUTH_BOOT_AUTHENTICATED
        if authentication_preparation and required_pass
        else ROUTER_DESKTOP_AUTH_REQUIRED
        if auth_required and router_account_menu.get("status") == ROUTER_DESKTOP_AUTH_REQUIRED
        else DEVELOPMENT_ONLY_SANDBOX_BYPASS
        if required_pass and development_only
        else PATCHED_SHELL_PASS
        if required_pass
        else PATCHED_SHELL_BLOCKED
    )
    return {
        "status": status,
        "reason": (
            "persistent Desktop boot reached authenticated renderer state and exited gracefully"
            if authentication_preparation and required_pass
            else "the persistent Desktop validation profile requires normal interactive ChatGPT login"
            if auth_required and router_account_menu.get("status") == ROUTER_DESKTOP_AUTH_REQUIRED
            else "development-only sandbox bypass showed the patched Router launcher, UI bridge, mux health, account menu, and mux-to-real-codex chain"
            if required_pass and development_only
            else "patched Router launcher, ChatGPT UI bridge, mux health, account menu, and mux-to-real-codex chain passed"
            if required_pass
            else "patched Router shell did not satisfy every bounded production-path gate"
        ),
        "installation_root": str(root),
        "command": command,
        "diagnostic_arguments": list(diagnostic_arguments),
        "development_only": development_only,
        "production_ready": required_pass and not development_only,
        "production_sandbox_flags_present": production_flags_present,
        "launcher_observed_running": launcher_observed_running,
        "launcher_return_code": return_code,
        "desktop_auth": router_account_menu.get("desktop_auth"),
        "renderer_runtime": router_account_menu.get("renderer_runtime"),
        "profile_controller": {
            **router_account_menu.get("profile_controller", {}),
            "activation_attempted": activation_attempted,
            "activation_succeeded": activation_succeeded,
        },
        "runtime_errors": router_account_menu.get("runtime_errors", []),
        "validation_profile": (
            profile_layout.to_dict(
                exists=all(
                    path.is_dir()
                    for path in (
                        profile_layout.user_data,
                        profile_layout.codex_home,
                        profile_layout.mux_home,
                    )
                ),
                preserved=True,
            )
            if profile_layout is not None
            else None
        ),
        "graceful_shutdown": {
            "attempted": graceful_shutdown_attempted,
            "requested": graceful_shutdown_requested,
            "succeeded": graceful_shutdown_succeeded,
            "status": graceful_shutdown_status,
            "quiescence_seconds": AUTH_PERSISTENCE_QUIESCENCE_SECONDS,
            "error": graceful_shutdown_error,
        },
        "termination": {
            "harness_timeout_reached": timeout_reached,
            "harness_requested_termination": harness_requested_termination,
            "process_exited_before_cleanup": return_code is not None,
            "process_return_code": return_code,
            "process_still_running_at_timeout": process_still_running_at_timeout,
        },
        "chatgpt_classification": classification,
        "native_profile_trigger_observed": native_profile_trigger_observed,
        "router_account_menu": router_account_menu,
        "production_gate": production_gate,
        "health": {
            "pass": health_pass,
            "status_code": health_status,
            "body": health_body,
            "error": health_error,
        },
        "ui_bridge": {
            "pass": ui_bridge_pass,
            "status_code": ui_status,
            "error": ui_error,
            "debug": debug,
        },
        "mux_process_observed": mux_process_observed,
        "real_codex_process_observed": real_codex_process_observed,
        "process_observations": observations[-20:],
        "final_processes": final_processes,
        "final_windows": final_windows,
        "cleanup": cleanup,
        "log_tail": log_text,
        "manual_operation_required": bool(cleanup.get("errors")) or not required_pass or development_only,
    }


def _identity_statuses(results: Iterable[dict[str, object]]) -> bool:
    values = [result.get("status") for result in results if result.get("status") != NOT_PRESENT]
    return bool(values) and all(
        value in {BLOCKED_UPDATER_IDENTITY, BLOCKED_OTHER_PACKAGE_IDENTITY}
        for value in values
    )


def run_launch_probes(
    mirror_root: Path,
    workspace_root: Path,
    real: RealCodexCandidate,
    candidates: Iterable[DesktopExecutableCandidate],
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Probe ChatGPT.exe then Codex.exe in one mirror, sequentially."""
    results: list[dict[str, object]] = []
    for candidate in candidates:
        if not candidate.present:
            results.append(
                {
                    "candidate": candidate.relative_path,
                    "source_path": str(candidate.path),
                    "status": NOT_PRESENT,
                    "reason": "candidate is absent from the official app root",
                    "manual_operation_required": False,
                }
            )
            continue
        result = _probe_candidate(
            mirror_root,
            workspace_root,
            real,
            candidate,
            timeout_seconds=timeout_seconds,
        )
        results.append(result)

    present_results = [result for result in results if result.get("status") != NOT_PRESENT]
    if any(result.get("status") == PASS for result in present_results):
        status = DIRECT_LAUNCH_PASS
        reason = "at least one root-level Desktop shell launched with healthy bounded evidence"
    elif _identity_statuses(present_results):
        status = DIRECT_LAUNCH_IDENTITY_BLOCKED
        reason = "all present root-level Desktop shells were blocked by package identity/activation evidence"
    else:
        status = DIRECT_LAUNCH_FAIL
        reason = "no root-level Desktop shell reached a healthy bounded startup result"
    return {
        "status": status,
        "reason": reason,
        "candidates": results,
        "gate1": {
            "status": status,
            "pass": status == DIRECT_LAUNCH_PASS,
            "identity_blocked": status == DIRECT_LAUNCH_IDENTITY_BLOCKED,
            "minimal_bootstrap_eligible": status == DIRECT_LAUNCH_IDENTITY_BLOCKED,
        },
        "manual_operation_required": any(
            bool(result.get("manual_operation_required")) for result in results
        ),
    }


def run_smoke_launch_matrix(
    source: DesktopSource,
    real: RealCodexCandidate,
    candidates: Iterable[DesktopExecutableCandidate],
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Create one unmodified mirror and run the two root-shell probes."""
    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "reason": "native Windows Desktop launch probes are Windows-only",
            "candidates": [
                {
                    "candidate": candidate.relative_path,
                    "status": NOT_PRESENT if not candidate.present else "NOT AVAILABLE",
                }
                for candidate in candidates
            ],
            "manual_operation_required": False,
        }
    with tempfile.TemporaryDirectory(prefix="codex-router-phase2a3-direct-") as temporary:
        root = Path(temporary)
        mirror_root = root / "app"
        mirror_report = mirror_desktop_source(source, mirror_root)
        verify_desktop_mirror(source.app_dir, mirror_root)
        result = run_launch_probes(
            mirror_root,
            root,
            real,
            candidates,
            timeout_seconds=timeout_seconds,
        )
        result["mirror"] = mirror_report.to_dict()
        result["mirror_root"] = str(mirror_root)
        result["isolation_root"] = str(root)
        return result


def run_unmodified_mirror_smoke(
    source: DesktopSource,
    real: RealCodexCandidate,
    candidates: Iterable[DesktopExecutableCandidate] | None = None,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Backward-compatible entry point for the Phase 2A.3 direct matrix."""
    if candidates is None:
        try:
            from .discovery import inventory_desktop_executables
        except ImportError:
            from discovery import inventory_desktop_executables
        candidates = inventory_desktop_executables(source)
    return run_smoke_launch_matrix(source, real, candidates, timeout_seconds=timeout_seconds)


@contextmanager
def final_layout_smoke_root(
    cleanup_status: dict[str, object] | None = None,
    *,
    parent_name: str = "_smoke",
    prefix: str = "phase2a4-",
    persistent: bool = False,
    persistent_root: Path | None = None,
    persistent_local_appdata: Path | None = None,
) -> Iterator[Path]:
    """Create a disposable root, or preserve the Router auth profile explicitly."""
    if persistent:
        if os.name != "nt":
            raise RuntimeError("persistent Desktop authentication preparation is Windows-only")
        layout = validation_profile_layout(
            local_appdata=persistent_local_appdata,
            profile_root=persistent_root,
        )
        root = layout.root
        if root.is_symlink():
            raise RuntimeError("refusing a symlinked persistent Router validation profile")
        root.mkdir(parents=True, exist_ok=True)
        for path in (layout.user_data, layout.codex_home, layout.mux_home):
            if path.is_symlink():
                raise RuntimeError(f"refusing a symlinked persistent Router state path: {path}")
            path.mkdir(parents=True, exist_ok=True)
        if cleanup_status is not None:
            cleanup_status.update(
                {
                    "requested_path": str(root),
                    "resolved_path": str(root),
                    "path_virtualized": False,
                    "persistent": True,
                    "preserved": True,
                    "removed": False,
                    "error": None,
                    "validation_profile": layout.to_dict(
                        exists=all(path.is_dir() for path in (layout.user_data, layout.codex_home, layout.mux_home))
                    ),
                }
            )
        try:
            yield root
        finally:
            # The authentication profile is intentionally never removed by a
            # smoke context.  Its Chromium session is acquired only by the
            # user's normal interactive login.
            if cleanup_status is not None:
                cleanup_status.update({"preserved": True, "removed": False})
        return

    if os.name != "nt":
        root = Path(tempfile.mkdtemp(prefix=prefix))
        if cleanup_status is not None:
            cleanup_status.update(
                {
                    "requested_path": str(root),
                    "resolved_path": str(root.resolve(strict=True)),
                    "path_virtualized": False,
                }
            )
        try:
            (root / "app").mkdir()
            (root / "User Data").mkdir()
            (root / "codex-home").mkdir()
            yield root
        finally:
            try:
                shutil.rmtree(root)
            except OSError as error:
                if cleanup_status is not None:
                    cleanup_status.update({"removed": False, "error": str(error)})
                shutil.rmtree(root, ignore_errors=True)
            else:
                if cleanup_status is not None:
                    cleanup_status.update({"removed": True, "error": None})
        return

    local_appdata_value = os.environ.get("LOCALAPPDATA")
    if local_appdata_value is None:
        local_appdata_value = str(Path.home() / "AppData" / "Local")
    # Keep this logical path for the contract check. An AppContainer can make
    # ``Path.resolve`` return a package-cache target even though callers asked
    # for the user's real LOCALAPPDATA directory.
    local_appdata = Path(local_appdata_value).expanduser()
    router_smoke_parent = local_appdata / "Codex Subscription Router" / parent_name
    router_smoke_parent.mkdir(parents=True, exist_ok=True)
    requested_root = Path(tempfile.mkdtemp(prefix=prefix, dir=router_smoke_parent))
    root = requested_root.resolve(strict=True)
    if cleanup_status is not None:
        cleanup_status.update(
            {
                "requested_path": str(requested_root),
                "resolved_path": str(root),
                "path_virtualized": _path_comparison_key(requested_root) != _path_comparison_key(root),
            }
        )
    try:
        (root / "app").mkdir()
        (root / "User Data").mkdir()
        (root / "codex-home").mkdir()
        yield root
    finally:
        removed = False
        last_error: OSError | None = None
        for _attempt in range(5):
            try:
                shutil.rmtree(root)
            except OSError as error:
                last_error = error
                time.sleep(0.5)
            else:
                removed = True
                break
        if cleanup_status is not None:
            cleanup_status.update(
                {
                    "removed": removed,
                    "error": str(last_error) if last_error is not None else None,
                    "path": str(root),
                }
            )
        if not removed:
            # This is a best-effort final cleanup only after the exact generated
            # path has failed several times. Never broaden it to a parent.
            shutil.rmtree(root, ignore_errors=True)


def _acl_paths(source: DesktopSource, mirror_root: Path) -> dict[str, Path]:
    return {
        "official_app_directory": source.app_dir,
        "official_chatgpt_executable": source.app_dir / "ChatGPT.exe",
        "local_smoke_app_directory": mirror_root,
        "local_smoke_chatgpt_executable": mirror_root / "ChatGPT.exe",
        "local_smoke_chrome_dll": mirror_root / "chrome.dll",
    }


def _has_chromium_sandbox_evidence(result: dict[str, object] | None) -> bool:
    if not isinstance(result, dict):
        return False
    evidence = result.get("chromium_sandbox")
    return isinstance(evidence, dict) and evidence.get("evidence") is True


def _phase2a4_verdict(
    probe_a: dict[str, object],
    probe_b: dict[str, object],
    probe_c: dict[str, object],
    no_sandbox: dict[str, object] | None,
) -> str:
    a_status = probe_a.get("status")
    b_status = probe_b.get("status")
    c_status = probe_c.get("status")
    if a_status == BLOCKED_CHROMIUM_SANDBOX and b_status == PASS and c_status == PASS:
        return LOCAL_APP_ACL_FIX_CONFIRMED
    if a_status == BLOCKED_CHROMIUM_SANDBOX and b_status == PASS and c_status != PASS:
        return WINDOWS_26200_GPU_SANDBOX_REGRESSION
    if a_status == BLOCKED_CHROMIUM_SANDBOX and b_status != PASS and c_status == PASS:
        return APP_CONTAINER_ACCESS_FIX_CONFIRMED
    if no_sandbox is not None and no_sandbox.get("status") == PASS:
        return BROADER_CHROMIUM_SANDBOX_BLOCKED
    return "PHASE 2A.4 FAIL"


def _phase2a4_display_verdict(verdict: str) -> str:
    return {
        LOCAL_APP_ACL_FIX_CONFIRMED: PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
        WINDOWS_26200_GPU_SANDBOX_REGRESSION: PHASE2A4_WINDOWS_GPU_SANDBOX_REGRESSION,
        APP_CONTAINER_ACCESS_FIX_CONFIRMED: PHASE2A4_APP_CONTAINER_ACCESS_FIX_CONFIRMED,
        BROADER_CHROMIUM_SANDBOX_BLOCKED: PHASE2A4_BROADER_CHROMIUM_SANDBOX_BLOCKED,
        "PHASE 2A.4 FAIL": PHASE2A4_FAIL,
    }.get(verdict, verdict)


def run_phase2a4_sandbox_validation(
    source: DesktopSource,
    real: RealCodexCandidate,
    candidates: Iterable[DesktopExecutableCandidate],
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Run ChatGPT A/B/C sandbox probes in a final-layout-equivalent root."""
    candidates = tuple(candidates)
    if os.name != "nt":
        return {
            "status": PHASE2A4_FAIL,
            "reason": "native Windows sandbox/ACL validation is Windows-only",
            "manual_operation_required": False,
        }
    authoritative = select_authoritative_desktop_candidate(source, candidates)
    authoritative_relative = authoritative.relative_path.replace("/", "\\")
    official_fingerprint = {
        "chatgpt_sha256": str(sha256_file(source.app_dir / "ChatGPT.exe"))
        if (source.app_dir / "ChatGPT.exe").is_file()
        else None,
        "app_asar_sha256": str(sha256_file(source.app_asar)) if source.app_asar.is_file() else None,
    }

    cleanup_status: dict[str, object] = {}
    with final_layout_smoke_root(cleanup_status) as root:
        mirror_root = root / "app"
        mirror_report = mirror_desktop_source(source, mirror_root)
        verify_desktop_mirror(source.app_dir, mirror_root)
        acl_before = audit_acl_scope(_acl_paths(source, mirror_root))

        profile_parent = root / "_probe-profiles"
        profile_parent.mkdir(parents=True, exist_ok=True)

        def run_profile_probe(
            label: str,
            candidate: DesktopExecutableCandidate,
            *extra_arguments: str,
        ) -> dict[str, object]:
            profile = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=profile_parent))
            return _probe_candidate(
                mirror_root,
                root,
                real,
                candidate,
                timeout_seconds=timeout_seconds,
                extra_arguments=extra_arguments,
                profile_root=profile,
            )

        probe_a = _probe_candidate(
            mirror_root,
            root,
            real,
            authoritative,
            timeout_seconds=timeout_seconds,
            profile_root=Path(tempfile.mkdtemp(prefix="normal-", dir=profile_parent)),
        )

        diagnostic_shells: list[dict[str, object]] = []
        for candidate in candidates:
            if candidate.relative_path.replace("/", "\\").casefold() == authoritative_relative.casefold():
                continue
            if not candidate.present:
                continue
            diagnostic_shells.append(run_profile_probe("diagnostic", candidate))

        probe_b = run_profile_probe("disable-gpu-sandbox", authoritative, "--disable-gpu-sandbox")
        acl_remediation = prepare_windows_electron_payload_acl(
            mirror_root,
            router_root=root,
        )
        acl_after = audit_acl_scope(_acl_paths(source, mirror_root))
        probe_c = run_profile_probe("acl-normal", authoritative)
        no_sandbox: dict[str, object] | None = None
        if (
            probe_b.get("status") != PASS
            and probe_c.get("status") != PASS
            and _has_chromium_sandbox_evidence(probe_b)
        ):
            no_sandbox = run_profile_probe("no-sandbox", authoritative, "--no-sandbox")

        verdict = _phase2a4_verdict(probe_a, probe_b, probe_c, no_sandbox)
        display_verdict = _phase2a4_display_verdict(verdict)
        result = {
            "status": display_verdict,
            "reason": "Phase 2A.4 ChatGPT normal/diagnostic/ACL probe sequence completed",
            "authoritative_shell": authoritative.to_dict(),
            "diagnostic_shells": diagnostic_shells,
            "final_layout": {
                "root": str(root),
                "app": str(mirror_root),
                "user_data": str(root / "User Data"),
                "codex_home": str(root / "codex-home"),
                "requested_root": cleanup_status.get("requested_path"),
                "resolved_root": cleanup_status.get("resolved_path"),
                "path_virtualized": cleanup_status.get("path_virtualized", False),
                "root_under_localappdata": str(cleanup_status.get("requested_path", root)).casefold().startswith(
                    str(Path(os.environ.get("LOCALAPPDATA", ""))).casefold()
                ),
            },
            "mirror": mirror_report.to_dict(),
            "acl_before": acl_before,
            "probe_a_normal": probe_a,
            "probe_b_disable_gpu_sandbox": probe_b,
            "acl_remediation": acl_remediation,
            "acl_after": acl_after,
            "probe_c_acl_normal_sandbox": probe_c,
            "probe_d_no_sandbox": no_sandbox,
            "official_source_fingerprint_before": official_fingerprint,
        }

    # Cleanup-dependent evidence is finalized only after the context manager's
    # __exit__/finally has populated the status dictionary.
    official_after = {
        "chatgpt_sha256": str(sha256_file(source.app_dir / "ChatGPT.exe"))
        if (source.app_dir / "ChatGPT.exe").is_file()
        else None,
        "app_asar_sha256": str(sha256_file(source.app_asar)) if source.app_asar.is_file() else None,
    }
    result["official_source_fingerprint_after"] = official_after
    result["official_package_unchanged"] = official_fingerprint == official_after
    result["native_evidence_usable"] = native_evidence_is_usable(cleanup_status)
    result["production_acl_strategy"] = (
        "prepare_windows_electron_payload_acl on <Router root>\\app only"
        if cleanup_status.get("path_virtualized") is False
        and acl_remediation.get("status") == PASS
        else "not proven"
    )
    result["smoke_root_cleanup"] = dict(cleanup_status)
    result["manual_operation_required"] = bool(
        acl_remediation.get("manual_operation_required")
        or cleanup_status.get("path_virtualized") is True
        or cleanup_status.get("removed") is not True
    )
    if cleanup_status.get("path_virtualized") is True:
        result["status"] = PHASE2A4_FAIL
        result["reason"] = (
            "the requested LOCALAPPDATA smoke root was filesystem-virtualized by the host; "
            "final-layout native evidence is not usable"
        )
    if result["status"] == PHASE2A4_LOCAL_ACL_FIX_CONFIRMED:
        result["gpu_sandbox_diagnosis"] = GPU_SANDBOX_CONFIRMED
    return result


def _phase2a5_official_fingerprint(source: DesktopSource) -> dict[str, object]:
    return {
        "chatgpt_sha256": str(sha256_file(source.app_dir / "ChatGPT.exe"))
        if (source.app_dir / "ChatGPT.exe").is_file()
        else None,
        "app_asar_sha256": str(sha256_file(source.app_asar)) if source.app_asar.is_file() else None,
    }


def _phase2a5_not_run(reason: str) -> dict[str, object]:
    return {
        "status": "NOT RUN",
        "reason": reason,
        "manual_operation_required": False,
    }


def run_phase2a5_sandbox_validation(
    source: DesktopSource,
    real: RealCodexCandidate,
    candidates: Iterable[DesktopExecutableCandidate],
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Run causally isolated Phase 2A.5 A/B/C probes in a valid host root.

    The caller must perform the package-identity and physical-LOCALAPPDATA
    preflight first.  Each probe gets a fresh mirror: A is never ACL-mutated,
    B is diagnostic-only, and C is the sole fresh ACL experiment.
    """

    candidates = tuple(candidates)
    if os.name != "nt":
        return {
            "status": PHASE2A5_FAIL,
            "reason": "native Windows sandbox/ACL validation is Windows-only",
            "manual_operation_required": False,
        }
    authoritative = select_authoritative_desktop_candidate(source, candidates)
    authoritative_relative = authoritative.relative_path.replace("/", "\\")
    official_before = _phase2a5_official_fingerprint(source)
    cleanup_status: dict[str, object] = {}
    probe_a: dict[str, object] = _phase2a5_not_run("probe root was not available")
    probe_b: dict[str, object] = _phase2a5_not_run("Probe A did not show the exact Chromium sandbox failure")
    probe_c: dict[str, object] = _phase2a5_not_run("Probe A did not show the exact Chromium sandbox failure")
    acl_before: dict[str, object] = {}
    acl_after: dict[str, object] = {}
    acl_remediation: dict[str, object] = _phase2a5_not_run("Probe C was not required")
    mirror_reports: dict[str, object] = {}
    probe_root_paths: dict[str, object] = {}
    production_acl_strategy = "UNRESOLVED"

    with final_layout_smoke_root(
        cleanup_status,
        parent_name="_host-validation",
        prefix="phase2a5-",
    ) as root:
        if cleanup_status.get("path_virtualized") is not True:
            def create_mirror(label: str) -> tuple[Path, Path, object]:
                workspace = root / label
                workspace.mkdir(parents=True, exist_ok=True)
                mirror_root = workspace / "app"
                report = mirror_desktop_source(source, mirror_root)
                verify_desktop_mirror(source.app_dir, mirror_root)
                mirror_reports[label] = report.to_dict()
                probe_root_paths[label] = {
                    "workspace": str(workspace),
                    "app": str(mirror_root),
                    "user_data": str(workspace / "User Data"),
                    "codex_home": str(workspace / "codex-home"),
                }
                return workspace, mirror_root, report

            def run_probe(
                label: str,
                workspace: Path,
                mirror_root: Path,
                candidate: DesktopExecutableCandidate,
                *extra_arguments: str,
            ) -> dict[str, object]:
                profile_parent = workspace / "_probe-profiles"
                profile_parent.mkdir(parents=True, exist_ok=True)
                profile = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=profile_parent))
                return _probe_candidate(
                    mirror_root,
                    workspace,
                    real,
                    candidate,
                    timeout_seconds=timeout_seconds,
                    extra_arguments=extra_arguments,
                    profile_root=profile,
                )

            workspace_a, mirror_a, _report_a = create_mirror("A")
            acl_before = audit_acl_scope(_acl_paths(source, mirror_a))
            probe_a = run_probe("normal", workspace_a, mirror_a, authoritative)

            if (
                probe_a.get("status") == BLOCKED_CHROMIUM_SANDBOX
                and _has_chromium_sandbox_evidence(probe_a)
            ):
                workspace_b, mirror_b, _report_b = create_mirror("B")
                probe_b = run_probe(
                    "disable-gpu-sandbox",
                    workspace_b,
                    mirror_b,
                    authoritative,
                    "--disable-gpu-sandbox",
                )

                workspace_c, mirror_c, _report_c = create_mirror("C")
                acl_before["probe_c"] = audit_acl_scope(_acl_paths(source, mirror_c))
                acl_remediation = prepare_windows_electron_payload_acl(
                    mirror_c,
                    router_root=workspace_c,
                )
                acl_after = audit_acl_scope(_acl_paths(source, mirror_c))
                probe_c = run_probe("acl-normal", workspace_c, mirror_c, authoritative)
                if (
                    acl_remediation.get("status") == PASS
                    and probe_b.get("status") == PASS
                    and probe_c.get("status") == PASS
                ):
                    production_acl_strategy = "APPCONTAINER_RX"
            elif probe_a.get("status") == PASS:
                production_acl_strategy = "NONE"

            # Keep non-authoritative sibling shells as diagnostics, but never
            # let them change the selected shell or the A/B/C promotion rule.
            diagnostic_shells: list[dict[str, object]] = []
            for candidate in candidates:
                if candidate.relative_path.replace("/", "\\").casefold() == authoritative_relative.casefold():
                    continue
                if not candidate.present:
                    continue
                diagnostic_workspace, diagnostic_mirror, _report = create_mirror(
                    f"diagnostic-{len(diagnostic_shells) + 1}"
                )
                diagnostic_shells.append(
                    run_probe(
                        "diagnostic",
                        diagnostic_workspace,
                        diagnostic_mirror,
                        candidate,
                    )
                )
        else:
            diagnostic_shells = []

    official_after = _phase2a5_official_fingerprint(source)
    native_evidence_usable = native_evidence_is_usable(cleanup_status)
    if cleanup_status.get("path_virtualized") is True:
        status = PHASE2A5_FILESYSTEM_VIRTUALIZED
        reason = (
            "the requested external-host validation root was filesystem-virtualized; "
            "no Phase 2A.5 probe evidence is usable"
        )
    elif not native_evidence_usable:
        status = PHASE2A5_FAIL
        reason = "the external-host validation root did not provide usable cleanup evidence"
    elif probe_a.get("status") == PASS:
        status = PHASE2A5_DIRECT_HOST_PASS
        reason = "the authoritative ChatGPT.exe passed with the normal Chromium sandbox"
    elif (
        probe_a.get("status") == BLOCKED_CHROMIUM_SANDBOX
        and probe_b.get("status") == PASS
        and probe_c.get("status") == PASS
        and acl_remediation.get("status") == PASS
    ):
        status = PHASE2A5_ACL_FIX_CONFIRMED
        reason = "the fresh ACL experiment causally restored the normal-sandbox probe"
    elif (
        probe_a.get("status") == BLOCKED_CHROMIUM_SANDBOX
        and probe_b.get("status") == PASS
    ):
        status = PHASE2A5_GPU_SANDBOX_REGRESSION
        reason = "the development-only GPU sandbox bypass passed while the normal path remained blocked"
    else:
        status = PHASE2A5_FAIL
        reason = "the authoritative normal-sandbox probe did not pass"

    manual_operation_required = bool(
        cleanup_status.get("removed") is not True
        or cleanup_status.get("path_virtualized") is True
        or acl_remediation.get("manual_operation_required")
        or any(
            isinstance(probe, dict) and probe.get("manual_operation_required")
            for probe in (probe_a, probe_b, probe_c)
        )
        or official_before != official_after
    )
    return {
        "status": status,
        "reason": reason,
        "authoritative_shell": authoritative.to_dict(),
        "diagnostic_shells": diagnostic_shells,
        "final_layout": {
            "parent": str(Path(cleanup_status.get("requested_path", "")).parent),
            "root": cleanup_status.get("resolved_path"),
            "requested_root": cleanup_status.get("requested_path"),
            "resolved_root": cleanup_status.get("resolved_path"),
            "path_virtualized": cleanup_status.get("path_virtualized"),
            "probe_roots": probe_root_paths,
        },
        "mirror": mirror_reports,
        "acl_before": acl_before,
        "acl_remediation": acl_remediation,
        "acl_after": acl_after,
        "probe_a_normal": probe_a,
        "probe_b_disable_gpu_sandbox": probe_b,
        "probe_c_acl_normal_sandbox": probe_c,
        "official_source_fingerprint_before": official_before,
        "official_source_fingerprint_after": official_after,
        "official_package_unchanged": official_before == official_after,
        "native_evidence_usable": native_evidence_usable,
        "production_acl_strategy": production_acl_strategy,
        "smoke_root_cleanup": dict(cleanup_status),
        "manual_operation_required": manual_operation_required,
    }
