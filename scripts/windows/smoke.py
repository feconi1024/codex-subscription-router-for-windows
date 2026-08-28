"""Bounded Windows Desktop launch probes with fail-closed cleanup."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

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

DIRECT_LAUNCH_PASS = "DIRECT_LAUNCH_PASS"
DIRECT_LAUNCH_IDENTITY_BLOCKED = "DIRECT_LAUNCH_IDENTITY_BLOCKED"
DIRECT_LAUNCH_FAIL = "DIRECT_LAUNCH_FAIL"

MINIMAL_BOOTSTRAP_PASS = "MINIMAL_BOOTSTRAP_PASS"
MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED = "MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED"
MINIMAL_BOOTSTRAP_FAIL = "MINIMAL_BOOTSTRAP_FAIL"


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
    real_codex: Path,
) -> dict[str, object]:
    allowed = (user_data, codex_home, real_codex.parent)
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
def final_layout_smoke_root() -> Iterator[Path]:
    """Create and remove a Router-owned development root under LOCALAPPDATA."""
    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="codex-router-phase2a4-") as temporary:
            root = Path(temporary)
            (root / "app").mkdir()
            (root / "User Data").mkdir()
            (root / "codex-home").mkdir()
            yield root
        return

    local_appdata_value = os.environ.get("LOCALAPPDATA")
    if local_appdata_value is None:
        local_appdata_value = str(Path.home() / "AppData" / "Local")
    local_appdata = Path(local_appdata_value).expanduser().resolve(strict=False)
    router_smoke_parent = local_appdata / "Codex Subscription Router" / "_smoke"
    router_smoke_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase2a4-", dir=router_smoke_parent) as temporary:
        root = Path(temporary).resolve(strict=True)
        (root / "app").mkdir()
        (root / "User Data").mkdir()
        (root / "codex-home").mkdir()
        yield root


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
            "status": "PHASE 2A.4 FAIL",
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

    with final_layout_smoke_root() as root:
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

        official_after = {
            "chatgpt_sha256": str(sha256_file(source.app_dir / "ChatGPT.exe"))
            if (source.app_dir / "ChatGPT.exe").is_file()
            else None,
            "app_asar_sha256": str(sha256_file(source.app_asar)) if source.app_asar.is_file() else None,
        }
        verdict = _phase2a4_verdict(probe_a, probe_b, probe_c, no_sandbox)
        result = {
            "status": verdict,
            "reason": "Phase 2A.4 ChatGPT normal/diagnostic/ACL probe sequence completed",
            "authoritative_shell": authoritative.to_dict(),
            "diagnostic_shells": diagnostic_shells,
            "final_layout": {
                "root": str(root),
                "app": str(mirror_root),
                "user_data": str(root / "User Data"),
                "codex_home": str(root / "codex-home"),
                "root_under_localappdata": str(root).casefold().startswith(
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
            "official_source_fingerprint_after": official_after,
            "official_package_unchanged": official_fingerprint == official_after,
            "production_acl_strategy": (
                "prepare_windows_electron_payload_acl on <Router root>\\app only"
                if acl_remediation.get("status") == PASS
                else "not proven"
            ),
            "manual_operation_required": bool(acl_remediation.get("manual_operation_required")),
        }
        if verdict == LOCAL_APP_ACL_FIX_CONFIRMED:
            result["gpu_sandbox_diagnosis"] = GPU_SANDBOX_CONFIRMED
        return result
