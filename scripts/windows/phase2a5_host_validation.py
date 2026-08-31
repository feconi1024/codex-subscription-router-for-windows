"""User-started Phase 2A.5 validation from an independently opened host."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

try:
    from ..patch_app_windows import build_windows_desktop, probe_go_toolchain
    from .compatibility import PAYLOAD_ACL_NONE
    from .discovery import (
        RealCodexCandidate,
        discover_desktop_source,
        discover_real_codex,
        format_source_diagnostics,
        inventory_desktop_executables,
        sha256_file,
    )
    from .host_context import detect_windows_host_context, run_localappdata_canary
    from .mirror import (
        PHASE2A5_STORAGE_BLOCKED,
        PackagingBlockedError,
        StorageBlockedError,
        inventory_generated_validation_roots,
        inventory_router_backups,
        is_storage_exhaustion,
    )
    from .smoke import (
        PHASE2A5_ACL_FIX_CONFIRMED,
        PHASE2A5_DIRECT_HOST_PASS,
        PHASE2A5_FILESYSTEM_VIRTUALIZED,
        PHASE2A5_FULL_PASS,
        PHASE2A5_GPU_SANDBOX_REGRESSION,
        PHASE2A5_HOST_CONTEXT_BLOCKED,
        PHASE2A5_PATCHED_SHELL_BLOCKED,
        ROUTER_DESKTOP_AUTH_REQUIRED,
        ROUTER_DESKTOP_AUTH_NOT_PERSISTED,
        ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD,
        DESKTOP_AUTH_BOOT_AUTHENTICATED,
        DESKTOP_AUTH_PREPARED,
        PHASE2A5_FAIL,
        PATCHED_SHELL_PASS,
        final_layout_smoke_root,
        run_patched_shell_smoke,
        run_phase2a5_sandbox_validation,
        validation_profile_layout,
    )
    from .integrity import asar_header_digest
    from .reviewed_sources import (
        REVIEWED_SOURCES_DOCUMENT,
        find_reviewed_source,
        reviewed_source_is_patchable,
    )
except ImportError:
    from patch_app_windows import build_windows_desktop, probe_go_toolchain
    from windows.compatibility import PAYLOAD_ACL_NONE
    from windows.discovery import (
        RealCodexCandidate,
        discover_desktop_source,
        discover_real_codex,
        format_source_diagnostics,
        inventory_desktop_executables,
        sha256_file,
    )
    from windows.host_context import detect_windows_host_context, run_localappdata_canary
    from windows.mirror import (
        PHASE2A5_STORAGE_BLOCKED,
        PackagingBlockedError,
        StorageBlockedError,
        inventory_generated_validation_roots,
        inventory_router_backups,
        is_storage_exhaustion,
    )
    from windows.smoke import (
        PHASE2A5_ACL_FIX_CONFIRMED,
        PHASE2A5_DIRECT_HOST_PASS,
        PHASE2A5_FILESYSTEM_VIRTUALIZED,
        PHASE2A5_FULL_PASS,
        PHASE2A5_GPU_SANDBOX_REGRESSION,
        PHASE2A5_HOST_CONTEXT_BLOCKED,
        PHASE2A5_PATCHED_SHELL_BLOCKED,
        ROUTER_DESKTOP_AUTH_REQUIRED,
        ROUTER_DESKTOP_AUTH_NOT_PERSISTED,
        ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD,
        DESKTOP_AUTH_BOOT_AUTHENTICATED,
        DESKTOP_AUTH_PREPARED,
        PHASE2A5_FAIL,
        PATCHED_SHELL_PASS,
        final_layout_smoke_root,
        run_patched_shell_smoke,
        run_phase2a5_sandbox_validation,
        validation_profile_layout,
    )
    from windows.integrity import asar_header_digest
    from windows.reviewed_sources import (
        REVIEWED_SOURCES_DOCUMENT,
        find_reviewed_source,
        reviewed_source_is_patchable,
    )


DEFAULT_ARTIFACT = Path("docs") / "generated" / "WINDOWS-PHASE2A5-HOST-RESULT.json"
PHASE2A5_SOURCE_REVIEW_REQUIRED = "PHASE 2A.5 SOURCE REVIEW REQUIRED"
PHASE2A5_SOURCE_CHANGED_DURING_VALIDATION = "PHASE 2A.5 SOURCE CHANGED DURING VALIDATION"
PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED = "PATCHED SHELL TOOLCHAIN BLOCKED"
PHASE2A5_DESKTOP_AUTH_REQUIRED = "PHASE 2A.5 DESKTOP AUTH REQUIRED"
PHASE2A5_SOURCE_READ_BLOCKED = "PHASE 2A.5 SOURCE READ BLOCKED"
PHASE2A5_PACKAGE_PROTECTION_BLOCKED = "PHASE 2A.5 PACKAGE PROTECTION BLOCKED"
PHASE2A5_RENDERER_BLOCKED = "PHASE 2A.5 RENDERER BLOCKED"


def _safe_error(error: BaseException | str) -> str:
    value = str(error) if not isinstance(error, str) else error
    value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    return value[:500] or type(error).__name__


def _phase2a5_failure_status(error: BaseException, default: str) -> str:
    """Map typed mirror/renderer failures to stable public gate statuses."""

    message = _safe_error(error).casefold()
    if "phase 2a source read blocked" in message or "source read blocked" in message:
        return PHASE2A5_SOURCE_READ_BLOCKED
    if "phase 2 packaging blocked" in message:
        return PHASE2A5_PACKAGE_PROTECTION_BLOCKED
    if "renderer" in message or "syntax blocked" in message:
        return PHASE2A5_RENDERER_BLOCKED
    return default


def _command_version(command: str, arguments: tuple[str, ...]) -> str:
    executable = shutil.which(command)
    if executable is None:
        return "unavailable"
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return f"unavailable: {_safe_error(error)}"
    output = (result.stdout or "").strip().splitlines()
    return output[0].strip() if output else f"exit code {result.returncode}"


def _go_toolchain_report() -> dict[str, object]:
    """Expose the existing Go probes and verify the selected compiler once."""

    probed = probe_go_toolchain()
    selected = probed.get("selected")
    probes = list(probed.get("probes", [])) if isinstance(probed.get("probes"), list) else []
    usable = False
    if isinstance(selected, str) and selected:
        try:
            version = subprocess.run(
                [selected, "version"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            usable = version.returncode == 0
            probes.append(
                {
                    "probe": "selected go version",
                    "status": "PASS" if usable else "FAIL",
                    "candidate": selected,
                    "error": None if usable else _safe_error(version.stderr or f"exit code {version.returncode}"),
                }
            )
        except (OSError, subprocess.SubprocessError) as error:
            probes.append(
                {
                    "probe": "selected go version",
                    "status": "FAIL",
                    "candidate": selected,
                    "error": _safe_error(error),
                }
            )
    else:
        probes.append(
            {
                "probe": "selected go version",
                "status": "FAIL",
                "candidate": None,
                "error": "no Go executable selected",
            }
        )
    return {
        "selected": selected if isinstance(selected, str) else None,
        "usable": usable,
        "probes": probes,
    }


def collect_startup_runtime(repo_root: Path) -> dict[str, object]:
    """Collect only non-secret startup/runtime identity information."""

    try:
        git_result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo_root}",
                "rev-parse",
                "HEAD",
            ],
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        commit = git_result.stdout.strip() if git_result.returncode == 0 else "unknown"
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    windows_version: dict[str, object] = {"platform": platform.platform()}
    if os.name == "nt":
        try:
            version = sys.getwindowsversion()
            windows_version.update(
                {
                    "major": version.major,
                    "minor": version.minor,
                    "build": version.build,
                    "platform": version.platform,
                    "service_pack": version.service_pack,
                }
            )
        except AttributeError:
            pass
    go_toolchain = _go_toolchain_report()
    return {
        "current_process": {
            "pid": os.getpid(),
            "executable": str(Path(sys.executable).expanduser()),
            "argv0": sys.argv[0] if sys.argv else None,
        },
        "windows": windows_version,
        "repository_commit": commit,
        "python": sys.version.splitlines()[0],
        "node": _command_version("node", ("--version",)),
        "go": _command_version("go", ("version",)),
        "go_toolchain": go_toolchain,
    }


def _print_startup(runtime: dict[str, object], host_context: dict[str, object]) -> None:
    print("Phase 2A.5 external-host validation")
    print(f"Current process: {json.dumps(runtime.get('current_process'), sort_keys=True)}")
    print(f"Package identity: {json.dumps(host_context, sort_keys=True)}")
    print(f"Physical LOCALAPPDATA: pending native canary; requested={host_context.get('LOCALAPPDATA')}")
    print(f"Repository commit: {runtime.get('repository_commit')}")
    print(f"Python: {runtime.get('python')}")
    print(f"Node: {runtime.get('node')}")
    print(f"Go: {runtime.get('go')}")
    print(f"Go toolchain: {json.dumps(runtime.get('go_toolchain'), sort_keys=True)}")


def _source_identity(source: Any) -> dict[str, object]:
    asar_path = Path(source.app_asar)
    executable_path = Path(source.executable)
    try:
        app_asar_header_sha256: str | None = asar_header_digest(asar_path).hash
    except (OSError, RuntimeError, ValueError):
        app_asar_header_sha256 = None
    return {
        "package_name": source.package.name,
        "package": source.package.name,
        "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "architecture": source.package.architecture,
        "package_publisher": source.package.publisher,
        "source_root": str(source.source_root),
        "app_dir": str(source.app_dir),
        "executable": str(source.executable),
        "file_version": source.file_version,
        "app_file_version": source.file_version,
        "chatgpt_exe_sha256": sha256_file(executable_path),
        "executable_sha256": sha256_file(executable_path),
        "app_asar": str(source.app_asar),
        "app_asar_sha256": sha256_file(asar_path),
        "app_asar_header_sha256": app_asar_header_sha256,
        "source_kind": source.source_kind,
    }


def _source_stability(source: Any, initial_identity: Mapping[str, object]) -> dict[str, object]:
    """Re-read source identity and reject replacement/disappearance during validation."""

    try:
        final_identity = _source_identity(source)
    except (OSError, RuntimeError, ValueError) as error:
        return {
            "stable": False,
            "changed_fields": ["source_disappeared_or_unreadable"],
            "initial": dict(initial_identity),
            "final": None,
            "error": _safe_error(error),
        }
    fields = (
        "source_root",
        "package_name",
        "package_version",
        "architecture",
        "app_file_version",
        "executable",
        "chatgpt_exe_sha256",
        "app_asar",
        "app_asar_sha256",
        "app_asar_header_sha256",
    )
    changed_fields = [
        field
        for field in fields
        if initial_identity.get(field) != final_identity.get(field)
    ]
    return {
        "stable": not changed_fields,
        "changed_fields": changed_fields,
        "initial": dict(initial_identity),
        "final": final_identity,
        "error": None,
    }


def _public_button_diagnostics(buttons: object) -> list[dict[str, object]]:
    if not isinstance(buttons, list):
        return []
    output: list[dict[str, object]] = []
    for button in buttons:
        if not isinstance(button, dict):
            continue
        item: dict[str, object] = {}
        for key in ("ariaLabel", "type"):
            value = button.get(key)
            if isinstance(value, str):
                item[key] = value[:200]
        disabled = button.get("disabled")
        if isinstance(disabled, bool):
            item["disabled"] = disabled
        rect = button.get("rect")
        if isinstance(rect, dict):
            safe_rect: dict[str, object] = {}
            for key in ("x", "y", "width", "height"):
                value = rect.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    safe_rect[key] = value
            if safe_rect:
                item["rect"] = safe_rect
        if item:
            output.append(item)
    return output


_PUBLIC_STORAGE_INTEGER_FIELDS = {
    "free_bytes",
    "estimated_required_bytes",
    "planned_mirror_bytes",
    "planned_mirror_file_count",
    "existing_validation_shell_bytes",
    "asar_bytes",
    "asar_extracted_estimate_bytes",
    "asar_working_set_bytes",
    "temporary_repacked_asar_bytes",
    "generated_unpacked_bytes",
    "safety_headroom_bytes",
    "router_backup_count",
    "router_backup_bytes",
    "validation_orphan_count",
    "validation_orphan_bytes",
}
_PUBLIC_STORAGE_BOOLEAN_FIELDS = {
    "pass",
    "capacity_query_ok",
    "existing_destination_size_known",
    "asar_size_known",
    "router_backup_scan_complete",
    "validation_orphan_scan_complete",
}


def _public_mirror_plan(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    strategy = value.get("strategy")
    if isinstance(strategy, str) and strategy in {"walk", "appx-block-map"}:
        output["strategy"] = strategy
    for key in (
        "planned_file_count",
        "planned_mirror_bytes",
        "excluded_file_count",
        "excluded_bytes",
    ):
        item = value.get(key)
        if type(item) is int and 0 <= item <= 2**63 - 1:
            output[key] = item
    warning = value.get("planning_warning")
    if warning == "normal walk unavailable":
        output["planning_warning"] = warning
    return output


def _public_backup_inventory(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("windows_desktop_backup_count", "windows_desktop_backup_bytes", "reparse_points_skipped"):
        item = value.get(key)
        if type(item) is int and 0 <= item <= 2**63 - 1:
            output[key] = item
    if isinstance(value.get("scan_complete"), bool):
        output["scan_complete"] = value["scan_complete"]
    return output


def _public_validation_orphans(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("candidate_count", "candidate_bytes", "reparse_points_skipped"):
        item = value.get(key)
        if type(item) is int and 0 <= item <= 2**63 - 1:
            output[key] = item
    if isinstance(value.get("scan_complete"), bool):
        output["scan_complete"] = value["scan_complete"]
    paths = value.get("candidate_paths")
    if isinstance(paths, list):
        safe_paths: list[str] = []
        for item in paths:
            if not isinstance(item, str) or len(item) > 300:
                continue
            normalized = item.replace("\\", "/")
            if (
                not normalized
                or normalized.startswith("/")
                or re.match(r"^[A-Za-z]:", normalized)
                or any(part in {"", ".", ".."} for part in normalized.split("/"))
                or re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", normalized) is None
            ):
                continue
            safe_paths.append(normalized)
        output["candidate_paths"] = safe_paths[:100]
    return output


def _public_storage_preflight(value: object, *, depth: int = 0) -> dict[str, object]:
    """Expose capacity evidence without exporting arbitrary filesystem paths."""

    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    operation = value.get("operation")
    if isinstance(operation, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", operation):
        output["operation"] = operation
    volume = value.get("volume")
    if isinstance(volume, str) and (
        volume == "/"
        or re.fullmatch(r"[A-Za-z]:", volume) is not None
        or re.fullmatch(r"\\\\[^\\/:]{1,80}\\[^\\/:]{1,80}", volume) is not None
    ):
        output["volume"] = volume
    for key in _PUBLIC_STORAGE_INTEGER_FIELDS:
        item = value.get(key)
        if type(item) is int and 0 <= item <= 2**63 - 1:
            output[key] = item
    for key in _PUBLIC_STORAGE_BOOLEAN_FIELDS:
        item = value.get(key)
        if isinstance(item, bool):
            output[key] = item
    mirror_plan = _public_mirror_plan(value.get("mirror_plan"))
    if mirror_plan:
        output["mirror_plan"] = mirror_plan
    if depth == 0:
        probes = value.get("probes")
        if isinstance(probes, dict):
            safe_probes: dict[str, object] = {}
            for label, probe in list(probes.items())[:50]:
                if not isinstance(label, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", label) is None:
                    continue
                safe_probe = _public_storage_preflight(probe, depth=1)
                if safe_probe:
                    safe_probes[label] = safe_probe
            if safe_probes:
                output["probes"] = safe_probes
    return output


def _public_build_metadata_summary(value: object) -> dict[str, object]:
    """Keep build metadata bounded when copying it into the public artifact."""

    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("destination", "desktop_launch_executable", "payload_acl_strategy", "source_app_asar_sha256"):
        item = value.get(key)
        if isinstance(item, str) and len(item) <= 500:
            output[key] = item
    install_policy = value.get("install_policy")
    if install_policy in {"RECOVERABLE_BACKUP", "EPHEMERAL_ROLLBACK"}:
        output["install_policy"] = install_policy
    storage = _public_storage_preflight(value.get("storage_preflight"))
    if storage:
        output["storage_preflight"] = storage
    mirror_plan = _public_mirror_plan(value.get("mirror_plan"))
    if mirror_plan:
        output["mirror_plan"] = mirror_plan
    syntax = value.get("renderer_syntax_validation")
    if isinstance(syntax, dict):
        safe_syntax: dict[str, object] = {}
        status = syntax.get("status")
        if isinstance(status, str) and status in {"PASS", "BLOCKED"}:
            safe_syntax["status"] = status
        parser = syntax.get("parser")
        if isinstance(parser, str) and parser == "node":
            safe_syntax["parser"] = parser
        version = syntax.get("version")
        if isinstance(version, str) and len(version) <= 50:
            safe_syntax["version"] = version
        validated_assets = syntax.get("validated_assets")
        if isinstance(validated_assets, list):
            safe_syntax["validated_assets"] = [
                item[:200]
                for item in validated_assets
                if isinstance(item, str)
            ][:100]
        if safe_syntax:
            output["renderer_syntax_validation"] = safe_syntax
    return output


_PUBLIC_RUNTIME_ERROR_KINDS = {"error", "unhandledrejection", "render-process-gone"}
_PUBLIC_RUNTIME_ERROR_NAMES = {
    "Error",
    "EvalError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "TypeError",
    "URIError",
}
_PUBLIC_RENDER_PROCESS_REASONS = {
    "clean-exit",
    "abnormal-exit",
    "crashed",
    "killed",
    "oom",
    "launch-failed",
    "unknown",
}


def _public_runtime_error(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    name = value.get("name")
    output: dict[str, object] = {
        "kind": kind if isinstance(kind, str) and kind in _PUBLIC_RUNTIME_ERROR_KINDS else "error",
        "name": name if isinstance(name, str) and name in _PUBLIC_RUNTIME_ERROR_NAMES else "Error",
    }
    source_asset = value.get("source_asset")
    if isinstance(source_asset, str):
        source_asset = source_asset.split("?", 1)[0].split("#", 1)[0]
        source_asset = re.split(r"[\\/]", source_asset)[-1]
        if 0 < len(source_asset) <= 200:
            output["source_asset"] = source_asset
    for key in ("line", "column", "exit_code"):
        item = value.get(key)
        if type(item) is int and item >= 0:
            output[key] = item
    reason = value.get("reason")
    if isinstance(reason, str) and reason in _PUBLIC_RENDER_PROCESS_REASONS:
        output["reason"] = reason
    return output


def _public_desktop_auth(value: object) -> dict[str, str]:
    state = value.get("state") if isinstance(value, dict) else None
    return {"state": state if state in {"AUTHENTICATED", "AUTH_REQUIRED", "UNKNOWN"} else "UNKNOWN"}


def _public_renderer_runtime(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("ready_state", "readyState"):
        item = value.get(key)
        if isinstance(item, str) and item in {"loading", "interactive", "complete", "unknown"}:
            output["ready_state"] = item
            break
    for key in (
        "root_present",
        "rootPresent",
        "composer_present",
        "composerPresent",
        "profile_controller_ready",
        "profileControllerReady",
    ):
        item = value.get(key)
        if isinstance(item, bool):
            output[
                {
                    "rootPresent": "root_present",
                    "composerPresent": "composer_present",
                    "profileControllerReady": "profile_controller_ready",
                }.get(key, key)
            ] = item
    for key in (
        "root_child_count",
        "rootChildCount",
        "body_child_count",
        "bodyChildCount",
        "button_count",
        "buttonCount",
        "visible_interactive_count",
        "visibleInteractiveCount",
        "runtime_error_count",
        "runtimeErrorCount",
    ):
        item = value.get(key)
        if type(item) is int and item >= 0:
            output[
                {
                    "rootChildCount": "root_child_count",
                    "bodyChildCount": "body_child_count",
                    "buttonCount": "button_count",
                    "visibleInteractiveCount": "visible_interactive_count",
                    "runtimeErrorCount": "runtime_error_count",
                }.get(key, key)
            ] = item
    last_error = _public_runtime_error(value.get("last_safe_runtime_error", value.get("lastSafeRuntimeError")))
    if last_error is not None:
        output["last_safe_runtime_error"] = last_error
    return output


def _public_profile_controller(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {
        "ready": value.get("ready") is True,
        "activation_attempted": value.get("activation_attempted", value.get("activationAttempted")) is True,
        "activation_succeeded": value.get("activation_succeeded", value.get("activationSucceeded")) is True,
    }


def _public_windows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        safe: dict[str, object] = {}
        web_contents_id = item.get("webContentsId", item.get("web_contents_id"))
        if type(web_contents_id) is int and web_contents_id >= 0:
            safe["webContentsId"] = web_contents_id
        for key in ("visible", "isLoading", "rendererPatchLoaded", "accountMenuInjected"):
            if isinstance(item.get(key), bool):
                safe[key] = item[key]
        bounds = item.get("bounds")
        if isinstance(bounds, dict):
            safe_bounds = {
                key: bounds[key]
                for key in ("x", "y", "width", "height")
                if isinstance(bounds.get(key), (int, float)) and not isinstance(bounds.get(key), bool)
            }
            if safe_bounds:
                safe["bounds"] = safe_bounds
        url = item.get("url")
        if isinstance(url, dict):
            safe_url: dict[str, str] = {}
            origin = url.get("origin")
            if isinstance(origin, str) and len(origin) <= 500:
                safe_url["origin"] = origin
            pathname = url.get("pathname")
            if isinstance(pathname, str) and len(pathname) <= 500:
                safe_url["pathname"] = pathname.split("?", 1)[0].split("#", 1)[0]
            if safe_url:
                safe["url"] = safe_url
        auth = item.get("desktopAuth", item.get("desktop_auth"))
        if isinstance(auth, str) and auth in {"AUTHENTICATED", "AUTH_REQUIRED", "UNKNOWN"}:
            safe["desktopAuth"] = auth
        output.append(safe)
    return output[:50]


def _public_termination(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in (
        "harness_timeout_reached",
        "harness_requested_termination",
        "process_exited_before_cleanup",
        "process_still_running_at_timeout",
    ):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    return_code = value.get("process_return_code")
    if type(return_code) is int:
        output["process_return_code"] = return_code
    return output


def _public_cleanup(value: object) -> dict[str, object]:
    """Keep cleanup evidence useful without exporting process or token payloads."""

    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in (
        "persistent",
        "preserved",
        "removed",
        "path_virtualized",
    ):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    for key in ("requested_path", "resolved_path", "path"):
        item = value.get(key)
        if isinstance(item, str) and len(item) <= 1000:
            output[key] = item
    for key in ("tracked", "requested", "terminated", "terminated_by_popen"):
        item = value.get(key)
        if isinstance(item, list):
            output[key] = [pid for pid in item if type(pid) is int and pid >= 0][:200]
    errors = value.get("errors")
    if isinstance(errors, list):
        output["error_count"] = len([error for error in errors if isinstance(error, str)])
    observed = value.get("external_processes_observed")
    if isinstance(observed, list):
        output["external_processes_observed"] = [
            {
                "name": item["name"][:100],
                "cleanup_required": False,
            }
            for item in observed
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and item.get("cleanup_required") is False
        ][:50]
    return output


_PUBLIC_GRACEFUL_SHUTDOWN_STATUSES = {
    "NOT_REQUIRED",
    "REQUESTED",
    "EXITED",
    "FAILED",
    "FORCED_CLEANUP",
}


def _public_graceful_shutdown(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("attempted", "requested", "succeeded"):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    status = value.get("status")
    if isinstance(status, str) and status in _PUBLIC_GRACEFUL_SHUTDOWN_STATUSES:
        output["status"] = status
    quiescence = value.get("quiescence_seconds")
    if isinstance(quiescence, (int, float)) and not isinstance(quiescence, bool) and 0 <= quiescence <= 60:
        output["quiescence_seconds"] = quiescence
    error = value.get("error")
    if isinstance(error, str) and len(error) <= 500:
        output["error"] = error
    return output


_PUBLIC_AUTH_PERSISTENCE_STATUSES = {
    "NOT_RUN",
    "AUTH_REQUIRED",
    "UNKNOWN",
    "AUTHENTICATED",
    "AUTHENTICATED_BUT_GRACEFUL_SHUTDOWN_FAILED",
    "FAILED",
}


def _public_auth_persistence(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("initial_login", "restart_check", "post_rebuild_check"):
        stage = value.get(key)
        if not isinstance(stage, dict):
            continue
        safe_stage: dict[str, object] = {}
        status = stage.get("status")
        if isinstance(status, str) and status in _PUBLIC_AUTH_PERSISTENCE_STATUSES:
            safe_stage["status"] = status
        graceful = stage.get("graceful_shutdown")
        if isinstance(graceful, str) and graceful in {"PASS", "FAILED", "NOT_RUN"}:
            safe_stage["graceful_shutdown"] = graceful
        if safe_stage:
            output[key] = safe_stage
    return output


def _public_validation_profile(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, object] = {}
    for key in ("root", "user_data", "codex_home", "mux_home", "patched_shell"):
        item = value.get(key)
        if isinstance(item, str) and len(item) <= 1000:
            output[key] = item
    for key in ("persistent", "preserved", "authenticated", "exists"):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    return output


def _public_probe(result: object) -> object:
    if not isinstance(result, dict):
        return result
    allowed = (
        "status",
        "reason",
        "candidate",
        "source_path",
        "mirrored_path",
        "diagnostic_arguments",
        "return_code",
        "still_running_at_timeout",
        "manual_operation_required",
        "graceful_shutdown",
        "profile_isolation",
        "chromium_sandbox",
        "production_sandbox_flags_present",
        "production_ready",
        "launcher_observed_running",
        "launcher_return_code",
        "health",
        "ui_bridge",
        "mux_process_observed",
        "real_codex_process_observed",
        "installation_root",
        "command",
        "development_only",
        "build_metadata_summary",
        "go_toolchain",
        "storage_preflight",
        "mirror_plan",
        "backup_inventory",
        "validation_orphans",
    )
    output = {key: result[key] for key in allowed if key in result}
    if "build_metadata_summary" in result:
        output["build_metadata_summary"] = _public_build_metadata_summary(
            result.get("build_metadata_summary")
        )
    if "storage_preflight" in result:
        output["storage_preflight"] = _public_storage_preflight(result.get("storage_preflight"))
    if "mirror_plan" in result:
        output["mirror_plan"] = _public_mirror_plan(result.get("mirror_plan"))
    if "backup_inventory" in result:
        output["backup_inventory"] = _public_backup_inventory(result.get("backup_inventory"))
    if "validation_orphans" in result:
        output["validation_orphans"] = _public_validation_orphans(result.get("validation_orphans"))
    if "desktop_auth" in result:
        output["desktop_auth"] = _public_desktop_auth(result.get("desktop_auth"))
    if "renderer_runtime" in result:
        output["renderer_runtime"] = _public_renderer_runtime(result.get("renderer_runtime"))
    if "profile_controller" in result:
        output["profile_controller"] = _public_profile_controller(result.get("profile_controller"))
    if "runtime_errors" in result:
        raw_errors = result.get("runtime_errors")
        output["runtime_errors"] = [
            safe
            for safe in (_public_runtime_error(item) for item in (raw_errors if isinstance(raw_errors, list) else []))
            if safe is not None
        ][-20:]
    if "termination" in result:
        output["termination"] = _public_termination(result.get("termination"))
    if "cleanup" in result:
        output["cleanup"] = _public_cleanup(result.get("cleanup"))
    if "smoke_root_cleanup" in result:
        output["smoke_root_cleanup"] = _public_cleanup(result.get("smoke_root_cleanup"))
    if "graceful_shutdown" in result:
        output["graceful_shutdown"] = _public_graceful_shutdown(result.get("graceful_shutdown"))
    if "windows" in result:
        output["windows"] = _public_windows(result.get("windows"))
    if "validation_profile" in result:
        output["validation_profile"] = _public_validation_profile(result.get("validation_profile"))
    profile = result.get("profile_isolation")
    if isinstance(profile, dict):
        output["profile_isolation"] = {
            key: profile.get(key)
            for key in (
                "allowed_roots",
                "outside_profile_paths",
                "outside_profile_touch_detected",
                "user_data",
                "codex_home",
                "mux_home",
                "code_cli_path",
                "sparkle_enabled",
                "argument_user_data_dir",
                "contract_valid",
            )
            if key in profile
        }
    flags = result.get("flags")
    if isinstance(flags, dict):
        output["flags_observed"] = {
            key: bool(value)
            for key, value in flags.items()
            if key in {"packaged", "enable_updater", "app_server", "native_module", "resource", "single_instance", "package_identity", "chromium_sandbox"}
        }
    health = result.get("health")
    if isinstance(health, dict):
        output["health"] = {
            key: health.get(key)
            for key in ("pass", "status_code")
            if key in health
        }
    classification = result.get("chatgpt_classification")
    if isinstance(classification, dict):
        output["chatgpt_classification"] = {
            key: classification.get(key)
            for key in ("status", "reason")
            if isinstance(classification.get(key), str)
        }
    router_account_menu = result.get("router_account_menu")
    if isinstance(router_account_menu, dict):
        safe_router_menu: dict[str, object] = {}
        for key in (
            "renderer_loaded",
            "activation_attempted",
            "activation_succeeded",
            "injected",
            "mounted",
            "accounts_loaded",
            "request_failed",
            "pass",
        ):
            value = router_account_menu.get(key)
            if isinstance(value, bool):
                safe_router_menu[key] = value
        account_count = router_account_menu.get("account_count")
        if type(account_count) is int and account_count >= 0:
            safe_router_menu["account_count"] = account_count
        status = router_account_menu.get("status")
        if isinstance(status, str) and status in {
            "PASS",
            "ROUTER_RENDERER_RUNTIME_ERROR",
            "ROUTER_UI_NOT_READY",
            "ROUTER_DESKTOP_AUTH_REQUIRED",
            "ROUTER_DESKTOP_AUTH_NOT_PERSISTED",
            "ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD",
            "ROUTER_DESKTOP_AUTH_UNKNOWN",
            "ROUTER_PROFILE_CONTROLLER_NOT_READY",
            "ROUTER_PROFILE_ACTIVATION_FAILED",
            "ROUTER_MENU_NOT_INJECTED_AFTER_OPEN",
            "ROUTER_MENU_NOT_INJECTED",
            "ROUTER_MENU_NOT_MOUNTED",
            "ROUTER_MENU_ACCOUNTS_LOADING",
            "ROUTER_MENU_ACCOUNTS_LOAD_FAILED",
            "ROUTER_RENDERER_NOT_LOADED",
        }:
            safe_router_menu["status"] = status
        if "desktop_auth" in router_account_menu:
            safe_router_menu["desktop_auth"] = _public_desktop_auth(router_account_menu.get("desktop_auth"))
        if "renderer_runtime" in router_account_menu:
            safe_router_menu["renderer_runtime"] = _public_renderer_runtime(router_account_menu.get("renderer_runtime"))
        if "profile_controller" in router_account_menu:
            safe_router_menu["profile_controller"] = _public_profile_controller(router_account_menu.get("profile_controller"))
        if "runtime_errors" in router_account_menu:
            raw_errors = router_account_menu.get("runtime_errors")
            safe_router_menu["runtime_errors"] = [
                safe
                for safe in (_public_runtime_error(item) for item in (raw_errors if isinstance(raw_errors, list) else []))
                if safe is not None
            ][-20:]
        output["router_account_menu"] = safe_router_menu
    production_gate = result.get("production_gate")
    if isinstance(production_gate, dict):
        gate_keys = (
            "launcher_running",
            "chatgpt_classification",
            "mux_health",
            "ui_bridge",
            "router_account_menu",
            "mux_process",
            "real_codex_process",
            "production_sandbox",
            "cleanup",
        )
        checks = production_gate.get("checks")
        safe_checks: dict[str, bool] = {}
        if isinstance(checks, dict):
            for key in gate_keys:
                value = checks.get(key)
                if isinstance(value, bool):
                    safe_checks[key] = value
        failed = production_gate.get("failed")
        safe_failed = (
            [value for value in failed if value in gate_keys]
            if isinstance(failed, list)
            else [key for key in gate_keys if safe_checks.get(key) is False]
        )
        output["production_gate"] = {
            "pass": production_gate.get("pass") is True,
            "failed": safe_failed,
            "checks": safe_checks,
        }
    native_profile = result.get("native_profile_trigger_observed")
    if isinstance(native_profile, str):
        output["native_profile_trigger_observed"] = native_profile[:100]
    ui_bridge = result.get("ui_bridge")
    if isinstance(ui_bridge, dict):
        output["ui_bridge"] = {
            key: ui_bridge.get(key)
            for key in ("pass", "status_code")
            if key in ui_bridge
        }
        router_gate_failed = (
            isinstance(router_account_menu, dict)
            and router_account_menu.get("pass") is not True
        )
        production_gate_failed = (
            isinstance(production_gate, dict)
            and production_gate.get("pass") is not True
        )
        if router_gate_failed or production_gate_failed:
            debug = ui_bridge.get("debug")
            buttons = debug.get("buttons") if isinstance(debug, dict) else None
            output["ui_bridge"]["native_button_diagnostics"] = _public_button_diagnostics(buttons)
    sandbox = output.get("chromium_sandbox")
    if isinstance(sandbox, dict):
        output["chromium_sandbox"] = {
            key: sandbox.get(key)
            for key in (
                "evidence",
                "gpu_child_launch_attempt_count",
                "gpu_child_exit_codes",
                "renderer_child_process_failure_observed",
                "fatal_line",
                "cleanup_artifact_only",
            )
            if key in sandbox
        }
    return output


def _public_sandbox(result: dict[str, object]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key in (
        "status",
        "reason",
        "authoritative_shell",
        "final_layout",
        "mirror",
        "acl_before",
        "acl_remediation",
        "acl_after",
        "official_source_fingerprint_before",
        "official_source_fingerprint_after",
        "official_package_unchanged",
        "native_evidence_usable",
        "production_acl_strategy",
        "manual_operation_required",
    ):
        if key in result:
            output[key] = result[key]
    if "smoke_root_cleanup" in result:
        output["smoke_root_cleanup"] = _public_cleanup(result.get("smoke_root_cleanup"))
    if "storage_preflight" in result:
        output["storage_preflight"] = _public_storage_preflight(result.get("storage_preflight"))
    if "mirror_plan" in result:
        output["mirror_plan"] = _public_mirror_plan(result.get("mirror_plan"))
    if "backup_inventory" in result:
        output["backup_inventory"] = _public_backup_inventory(result.get("backup_inventory"))
    if "validation_orphans" in result:
        output["validation_orphans"] = _public_validation_orphans(result.get("validation_orphans"))
    for key in ("probe_a_normal", "probe_b_disable_gpu_sandbox", "probe_c_acl_normal_sandbox"):
        if key in result:
            output[key] = _public_probe(result[key])
    output["diagnostic_shells"] = [_public_probe(item) for item in result.get("diagnostic_shells", [])]
    return output


def _resolve_validation_profile_root(
    local_appdata: Path,
    override: Path | None = None,
) -> Path:
    """Resolve the single persistent profile boundary with shared path rules."""

    return validation_profile_layout(local_appdata, override).root


def _validation_profile_summary(root: Path, local_appdata: Path | None = None) -> dict[str, object]:
    layout = validation_profile_layout(local_appdata, root)
    return layout.to_dict(
        exists=all(
            path.is_dir()
            for path in (layout.user_data, layout.codex_home, layout.mux_home)
        ),
        preserved=True,
    )


def _persistent_profile_state_is_intact(layout: object) -> bool:
    if not hasattr(layout, "root"):
        return False
    paths = (
        layout.root,
        layout.user_data,
        layout.codex_home,
        layout.mux_home,
    )
    try:
        return all(path.is_dir() and not path.is_symlink() for path in paths)
    except OSError:
        return False


def _run_external_patched_shell(
    source: Any,
    selected_real: RealCodexCandidate,
    *,
    acl_strategy: str,
    timeout_seconds: float,
    reviewed_source: Mapping[str, object] | None = None,
    go_toolchain: Mapping[str, object] | None = None,
    validation_profile_root: Path | None = None,
    local_appdata: Path | None = None,
) -> dict[str, object]:
    """Build and smoke either a disposable shell or the persistent auth shell."""

    if go_toolchain is not None and go_toolchain.get("usable") is not True:
        return {
            "status": PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED,
            "reason": "Go toolchain is unavailable after all configured probes",
            "go_toolchain": dict(go_toolchain),
            "smoke_root_cleanup": {"not_started": True},
            "manual_operation_required": False,
        }

    persistent = validation_profile_root is not None
    persistent_local_appdata = local_appdata
    profile_layout = None
    if persistent:
        try:
            if persistent_local_appdata is None:
                persistent_local_appdata = (
                    validation_profile_root.expanduser().resolve(strict=False).parent.parent
                )
            profile_layout = validation_profile_layout(
                persistent_local_appdata,
                validation_profile_root,
            )
        except (OSError, RuntimeError, ValueError) as error:
            return {
                "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                "reason": f"persistent validation profile was rejected: {_safe_error(error)}",
                "manual_operation_required": True,
            }
    cleanup: dict[str, object] = {}
    result: dict[str, object]
    try:
        with final_layout_smoke_root(
            cleanup,
            parent_name="_host-validation",
            prefix="phase2a5-patched-",
            persistent=persistent,
            persistent_root=validation_profile_root,
            persistent_local_appdata=persistent_local_appdata,
        ) as root:
            if cleanup.get("path_virtualized") is True:
                result = {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "the disposable patched-shell root was filesystem-virtualized",
                    "manual_operation_required": True,
                }
            else:
                destination = profile_layout.patched_shell if profile_layout is not None else root / "patched-shell"
                metadata = build_windows_desktop(
                    source,
                    selected_real,
                    destination,
                    force=persistent,
                    allow_untested_source=False,
                    reviewed_source=reviewed_source,
                    payload_acl_strategy=acl_strategy,
                    mux_home_override=(profile_layout.mux_home if profile_layout is not None else None),
                    validation_profile_local_appdata=persistent_local_appdata,
                )
                result = run_patched_shell_smoke(
                    destination,
                    selected_real,
                    timeout_seconds=timeout_seconds,
                    disposable_root=not persistent,
                    user_data_override=(profile_layout.user_data if profile_layout is not None else None),
                    codex_home_override=(profile_layout.codex_home if profile_layout is not None else None),
                    mux_home_override=(profile_layout.mux_home if profile_layout is not None else None),
                    preserve_user_data=persistent,
                    auth_required=persistent,
                    validation_profile_root_override=root if persistent else None,
                    validation_profile_local_appdata=persistent_local_appdata,
                )
                result["build_metadata_summary"] = {
                    "destination": str(destination),
                    "desktop_launch_executable": metadata.get("desktop_launch_executable"),
                    "payload_acl_strategy": metadata.get("payload_acl_strategy"),
                    "source_app_asar_sha256": metadata.get("source_app_asar_sha256"),
                    "renderer_syntax_validation": metadata.get("renderer_syntax_validation"),
                    "storage_preflight": metadata.get("storage_preflight"),
                    "install_policy": metadata.get("install_policy"),
                    "mirror_plan": metadata.get("mirror_plan"),
                }
    except StorageBlockedError as error:
        result = {
            "status": PHASE2A5_STORAGE_BLOCKED,
            "reason": _safe_error(error),
            "storage_preflight": getattr(error, "evidence", {}),
            "manual_operation_required": True,
        }
    except OSError as error:
        if is_storage_exhaustion(error):
            result = {
                "status": PHASE2A5_STORAGE_BLOCKED,
                "reason": f"{PHASE2A5_STORAGE_BLOCKED}: {_safe_error(error)}",
                "storage_preflight": {},
                "manual_operation_required": True,
            }
        else:
            result = {
                "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                "reason": _safe_error(error),
                "manual_operation_required": True,
            }
    except (PackagingBlockedError, RuntimeError, subprocess.SubprocessError) as error:
        result = {
            "status": _phase2a5_failure_status(error, PHASE2A5_PATCHED_SHELL_BLOCKED),
            "reason": _safe_error(error),
            "manual_operation_required": True,
        }

    # Do not return a cleanup-dependent result from inside the context manager.
    result["smoke_root_cleanup"] = dict(cleanup)
    if not persistent and cleanup.get("removed") is not True:
        result["status"] = PHASE2A5_PATCHED_SHELL_BLOCKED
        result["reason"] = "the disposable patched-shell root was not cleaned up successfully"
        result["manual_operation_required"] = True
    if persistent:
        if profile_layout is not None:
            result["validation_profile"] = profile_layout.to_dict(
                exists=_persistent_profile_state_is_intact(profile_layout),
                preserved=cleanup.get("preserved") is True,
            )
            result["validation_profile"]["authenticated"] = (
                isinstance(result.get("desktop_auth"), dict)
                and result["desktop_auth"].get("state") == "AUTHENTICATED"
            )
            if not _persistent_profile_state_is_intact(profile_layout):
                result["status"] = PHASE2A5_PATCHED_SHELL_BLOCKED
                result["reason"] = "persistent Router state roots were not preserved outside patched-shell"
                result["manual_operation_required"] = True
    return result


def _auth_state_from_boot(boot: object) -> str:
    if not isinstance(boot, dict):
        return "UNKNOWN"
    auth = boot.get("desktop_auth")
    state = auth.get("state") if isinstance(auth, dict) else None
    return state if state in {"AUTHENTICATED", "AUTH_REQUIRED", "UNKNOWN"} else "UNKNOWN"


def _auth_boot_succeeded(boot: object) -> bool:
    if not isinstance(boot, dict):
        return False
    return (
        _auth_state_from_boot(boot) == "AUTHENTICATED"
        and isinstance(boot.get("graceful_shutdown"), dict)
        and boot["graceful_shutdown"].get("succeeded") is True
    )


def _auth_persistence_stage(boot: object) -> dict[str, str]:
    state = _auth_state_from_boot(boot)
    graceful = (
        boot.get("graceful_shutdown")
        if isinstance(boot, dict) and isinstance(boot.get("graceful_shutdown"), dict)
        else {}
    )
    if state == "AUTHENTICATED" and graceful.get("succeeded") is True:
        status = "AUTHENTICATED"
        graceful_status = "PASS"
    elif state == "AUTHENTICATED":
        status = "AUTHENTICATED_BUT_GRACEFUL_SHUTDOWN_FAILED"
        graceful_status = "FAILED"
    elif state == "AUTH_REQUIRED":
        status = "AUTH_REQUIRED"
        graceful_status = "NOT_RUN"
    else:
        status = "UNKNOWN" if isinstance(boot, dict) else "FAILED"
        graceful_status = "NOT_RUN"
    return {"status": status, "graceful_shutdown": graceful_status}


def prepare_desktop_auth(
    *,
    repo_root: Path,
    source_override: Path | None = None,
    real_override: Path | None = None,
    timeout_seconds: float = 900.0,
    artifact_path: Path | None = None,
    validation_profile: Path | None = None,
) -> dict[str, object]:
    """Prepare persistent Desktop authentication and prove it survives restart/rebuild."""

    repo_root = repo_root.expanduser().resolve(strict=False)
    runtime = collect_startup_runtime(repo_root)
    host_context = detect_windows_host_context()
    _print_startup(runtime, host_context)
    result: dict[str, object] = {
        "schema_version": 1,
        "status": PHASE2A5_FAIL,
        "reason": None,
        "runtime": runtime,
        "host_context": host_context,
        "physical_localappdata": None,
        "source_identity": None,
        "source_review": None,
        "source_diagnostics": None,
        "go_toolchain": runtime.get("go_toolchain"),
        "real_codex": None,
        "patched_shell": None,
        "validation_profile": None,
        "auth_boots": [],
        "auth_persistence": {
            "initial_login": {"status": "NOT_RUN", "graceful_shutdown": "NOT_RUN"},
            "restart_check": {"status": "NOT_RUN", "graceful_shutdown": "NOT_RUN"},
            "post_rebuild_check": {"status": "NOT_RUN", "graceful_shutdown": "NOT_RUN"},
        },
        "rebuild": None,
        "storage_preflight": None,
        "backup_inventory": None,
        "validation_orphans": None,
        "mirror_plan": None,
        "manual_operation_required": True,
    }

    def finish() -> dict[str, object]:
        if artifact_path is not None:
            write_artifact(artifact_path, result)
        return result

    if host_context.get("has_package_identity") is not False:
        result.update(
            {
                "status": PHASE2A5_HOST_CONTEXT_BLOCKED,
                "reason": "Desktop authentication preparation must be started independently from an unpackaged Windows process",
            }
        )
        return finish()

    raw_local_appdata = host_context.get("LOCALAPPDATA")
    canary = run_localappdata_canary(
        Path(raw_local_appdata) if isinstance(raw_local_appdata, str) and raw_local_appdata else None
    )
    result["physical_localappdata"] = canary
    print(f"Physical LOCALAPPDATA: {json.dumps(canary, sort_keys=True)}")
    if canary.get("filesystem_virtualized") is not False:
        result.update(
            {
                "status": (
                    PHASE2A5_FILESYSTEM_VIRTUALIZED
                    if canary.get("filesystem_virtualized") is True
                    else PHASE2A5_HOST_CONTEXT_BLOCKED
                ),
                "reason": (
                    "LOCALAPPDATA canary resolved into a package-cache location"
                    if canary.get("filesystem_virtualized") is True
                    else "physical LOCALAPPDATA behavior could not be proven"
                ),
            }
        )
        return finish()

    try:
        source, diagnostics = discover_desktop_source(source_override)
        result["source_diagnostics"] = diagnostics.to_dict()
        if source is None:
            result.update({"status": PHASE2A5_FAIL, "reason": format_source_diagnostics(diagnostics)})
            return finish()

        identity = _source_identity(source)
        result["source_identity"] = identity
        reviewed_source = find_reviewed_source(identity)
        reviewed_ok, reviewed_reason = reviewed_source_is_patchable(identity, reviewed_source)
        shell_path = str(source.executable).replace("/", "\\").casefold()
        if not shell_path.endswith("\\app\\chatgpt.exe"):
            reviewed_ok = False
            reviewed_reason = "discovered source does not end in app\\ChatGPT.exe"
        result["source_review"] = {
            "registry": str(REVIEWED_SOURCES_DOCUMENT),
            "status": "PATCHABLE" if reviewed_ok else "SOURCE REVIEW REQUIRED",
            "reason": reviewed_reason,
            "record": reviewed_source,
        }
        if not reviewed_ok:
            result.update(
                {
                    "status": PHASE2A5_SOURCE_REVIEW_REQUIRED,
                    "reason": f"{PHASE2A5_SOURCE_REVIEW_REQUIRED}: {reviewed_reason}",
                    "manual_operation_required": False,
                }
            )
            return finish()

        selected_real, real_candidates = discover_real_codex(real_override)
        result["real_codex"] = {
            "selected": {
                "path": str(selected_real.path),
                "version": selected_real.version,
                "sha256": selected_real.sha256,
                "authenticode": {
                    "status": selected_real.authenticode.status,
                    "signer": selected_real.authenticode.signer,
                },
            },
            "candidates": [str(candidate.path) for candidate in real_candidates],
        }
        local_appdata = Path(raw_local_appdata) if isinstance(raw_local_appdata, str) and raw_local_appdata else Path.home() / "AppData" / "Local"
        layout = validation_profile_layout(local_appdata, validation_profile)
        layout.root.mkdir(parents=True, exist_ok=True)
        for path in (layout.user_data, layout.codex_home, layout.mux_home):
            if path.is_symlink():
                raise RuntimeError(f"refusing a symlinked persistent Router state path: {path}")
            path.mkdir(parents=True, exist_ok=True)
        result["validation_profile"] = layout.to_dict(
            exists=_persistent_profile_state_is_intact(layout),
            preserved=True,
        )
        result["backup_inventory"] = inventory_router_backups()
        result["validation_orphans"] = inventory_generated_validation_roots(
            local_appdata,
            layout.root,
        )

        destination = layout.patched_shell

        def build_profile() -> dict[str, object]:
            metadata = build_windows_desktop(
                source,
                selected_real,
                destination,
                force=True,
                allow_untested_source=False,
                reviewed_source=reviewed_source,
                payload_acl_strategy=PAYLOAD_ACL_NONE,
                mux_home_override=layout.mux_home,
                validation_profile_local_appdata=local_appdata,
            )
            return {
                "destination": str(destination),
                "force": True,
                "desktop_launch_executable": metadata.get("desktop_launch_executable"),
                "payload_acl_strategy": metadata.get("payload_acl_strategy"),
                "source_app_asar_sha256": metadata.get("source_app_asar_sha256"),
                "renderer_syntax_validation": metadata.get("renderer_syntax_validation"),
                "storage_preflight": metadata.get("storage_preflight"),
                "install_policy": metadata.get("install_policy"),
                "mirror_plan": metadata.get("mirror_plan"),
            }

        def boot(*, fail_if_auth_required: bool) -> dict[str, object]:
            return run_patched_shell_smoke(
                destination,
                selected_real,
                timeout_seconds=max(float(timeout_seconds), 60.0),
                disposable_root=False,
                user_data_override=layout.user_data,
                codex_home_override=layout.codex_home,
                mux_home_override=layout.mux_home,
                preserve_user_data=True,
                auth_required=True,
                authentication_preparation=True,
                fail_if_auth_required=fail_if_auth_required,
                validation_profile_root_override=layout.root,
                validation_profile_local_appdata=local_appdata,
            )

        initial_build = build_profile()
        first_boot = boot(fail_if_auth_required=False)
        first_boot["build_metadata_summary"] = _public_build_metadata_summary(initial_build)
        result["auth_boots"].append(first_boot)
        result["patched_shell"] = first_boot
        result["auth_persistence"]["initial_login"] = _auth_persistence_stage(first_boot)
        if _auth_state_from_boot(first_boot) != "AUTHENTICATED":
            result.update(
                {
                    "status": ROUTER_DESKTOP_AUTH_REQUIRED,
                    "reason": "complete normal ChatGPT login in the persistent Router validation window",
                    "manual_operation_required": True,
                }
            )
            return finish()
        if not _auth_boot_succeeded(first_boot) or not _persistent_profile_state_is_intact(layout):
            result.update(
                {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "initial authenticated Desktop boot did not finish with graceful shutdown and preserved state",
                    "manual_operation_required": True,
                }
            )
            return finish()

        second_boot = boot(fail_if_auth_required=True)
        result["auth_boots"].append(second_boot)
        result["patched_shell"] = second_boot
        result["auth_persistence"]["restart_check"] = _auth_persistence_stage(second_boot)
        if _auth_state_from_boot(second_boot) != "AUTHENTICATED":
            result.update(
                {
                    "status": ROUTER_DESKTOP_AUTH_NOT_PERSISTED,
                    "reason": "Desktop authentication was not available on the second boot without manual interaction",
                    "manual_operation_required": True,
                }
            )
            return finish()
        if not _auth_boot_succeeded(second_boot) or not _persistent_profile_state_is_intact(layout):
            result.update(
                {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "second authenticated Desktop boot did not finish with graceful shutdown and preserved state",
                    "manual_operation_required": True,
                }
            )
            return finish()

        rebuild = build_profile()
        result["rebuild"] = _public_build_metadata_summary(rebuild)
        if not _persistent_profile_state_is_intact(layout):
            result.update(
                {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "persistent Router state roots were not preserved across the forced patched-shell rebuild",
                    "manual_operation_required": True,
                }
            )
            return finish()

        third_boot = boot(fail_if_auth_required=True)
        result["auth_boots"].append(third_boot)
        result["patched_shell"] = third_boot
        result["auth_persistence"]["post_rebuild_check"] = _auth_persistence_stage(third_boot)
        if _auth_state_from_boot(third_boot) != "AUTHENTICATED":
            result.update(
                {
                    "status": ROUTER_DESKTOP_AUTH_LOST_AFTER_REBUILD,
                    "reason": "Desktop authentication was lost after rebuilding patched-shell",
                    "manual_operation_required": True,
                }
            )
            return finish()
        if not _auth_boot_succeeded(third_boot) or not _persistent_profile_state_is_intact(layout):
            result.update(
                {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "post-rebuild authenticated Desktop boot did not finish with graceful shutdown and preserved state",
                    "manual_operation_required": True,
                }
            )
            return finish()

        result.update(
            {
                "status": DESKTOP_AUTH_PREPARED,
                "reason": "Desktop authentication survived restart and forced patched-shell rebuild",
                "validation_profile": layout.to_dict(
                    exists=_persistent_profile_state_is_intact(layout),
                    preserved=True,
                ),
                "manual_operation_required": False,
            }
        )
    except StorageBlockedError as error:
        result.update(
            {
                "status": PHASE2A5_STORAGE_BLOCKED,
                "reason": _safe_error(error),
                "storage_preflight": getattr(error, "evidence", {}),
                "manual_operation_required": True,
            }
        )
    except OSError as error:
        if is_storage_exhaustion(error):
            result.update(
                {
                    "status": PHASE2A5_STORAGE_BLOCKED,
                    "reason": f"{PHASE2A5_STORAGE_BLOCKED}: {_safe_error(error)}",
                    "storage_preflight": {},
                    "manual_operation_required": True,
                }
            )
        else:
            result.update({"status": PHASE2A5_FAIL, "reason": _safe_error(error), "manual_operation_required": True})
    except (PackagingBlockedError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(
            {
                "status": _phase2a5_failure_status(error, PHASE2A5_FAIL),
                "reason": _safe_error(error),
                "manual_operation_required": True,
            }
        )
    return finish()


def _artifact_result(result: dict[str, object]) -> dict[str, object]:
    """Remove logs and UI/process payloads before writing the diagnostic artifact."""

    output: dict[str, object] = {}
    for key in (
        "schema_version",
        "status",
        "reason",
        "runtime",
        "host_context",
        "physical_localappdata",
        "source_identity",
        "source_review",
        "source_stability",
        "source_diagnostics",
        "go_toolchain",
        "real_codex",
        "sandbox_validation",
        "acl_strategy_verdict",
        "patched_shell",
        "validation_profile",
        "storage_preflight",
        "backup_inventory",
        "validation_orphans",
        "mirror_plan",
        "auth_boots",
        "auth_persistence",
        "rebuild",
        "mux_chain",
        "ci",
        "phase2b_ready",
        "manual_operation_required",
    ):
        if key not in result:
            continue
        if key == "sandbox_validation" and isinstance(result[key], dict):
            output[key] = _public_sandbox(result[key])
        elif key == "patched_shell":
            output[key] = _public_probe(result[key])
        elif key == "validation_profile":
            output[key] = _public_validation_profile(result[key])
        elif key == "auth_boots":
            output[key] = [_public_probe(item) for item in result[key] if isinstance(item, dict)]
        elif key == "auth_persistence":
            output[key] = _public_auth_persistence(result[key])
        elif key == "rebuild":
            output[key] = _public_build_metadata_summary(result[key])
        elif key == "storage_preflight":
            output[key] = _public_storage_preflight(result[key])
        elif key == "backup_inventory":
            output[key] = _public_backup_inventory(result[key])
        elif key == "validation_orphans":
            output[key] = _public_validation_orphans(result[key])
        elif key == "mirror_plan":
            output[key] = _public_mirror_plan(result[key])
        else:
            output[key] = result[key]
    return output


def write_artifact(path: Path, result: dict[str, object]) -> None:
    path = path.expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_artifact_result(result), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def run_phase2a5_host_validation(
    *,
    repo_root: Path,
    source_override: Path | None = None,
    real_override: Path | None = None,
    timeout_seconds: float = 20.0,
    artifact_path: Path | None = None,
    ci_verified: bool = False,
    validation_profile: Path | None = None,
) -> dict[str, object]:
    """Run Phase 2A.5, stopping before mutation when the host is not valid."""

    repo_root = repo_root.expanduser().resolve(strict=False)
    runtime = collect_startup_runtime(repo_root)
    host_context = detect_windows_host_context()
    _print_startup(runtime, host_context)
    result: dict[str, object] = {
        "schema_version": 1,
        "status": PHASE2A5_FAIL,
        "reason": None,
        "runtime": runtime,
        "host_context": host_context,
        "physical_localappdata": None,
        "validation_profile": None,
        "storage_preflight": None,
        "backup_inventory": None,
        "validation_orphans": None,
        "mirror_plan": None,
        "source_identity": None,
        "source_review": None,
        "source_stability": None,
        "source_diagnostics": None,
        "go_toolchain": runtime.get("go_toolchain"),
        "real_codex": None,
        "sandbox_validation": None,
        "acl_strategy_verdict": "UNRESOLVED",
        "patched_shell": None,
        "mux_chain": None,
        "ci": {
            "status": "NOT RUN",
            "required_jobs": ["checks", "windows-go-core"],
        },
        "phase2b_ready": False,
        "manual_operation_required": False,
    }
    source_for_stability: Any | None = None
    initial_source_identity: dict[str, object] | None = None
    reviewed_source: dict[str, object] | None = None

    if host_context.get("has_package_identity") is not False:
        result.update(
            {
                "status": PHASE2A5_HOST_CONTEXT_BLOCKED,
                "reason": (
                    "native validation must be started independently from an unpackaged Windows process"
                ),
            }
        )
        if artifact_path is not None:
            write_artifact(artifact_path, result)
        return result

    raw_local_appdata = host_context.get("LOCALAPPDATA")
    canary = run_localappdata_canary(
        Path(raw_local_appdata) if isinstance(raw_local_appdata, str) and raw_local_appdata else None
    )
    result["physical_localappdata"] = canary
    print(f"Physical LOCALAPPDATA: {json.dumps(canary, sort_keys=True)}")
    if canary.get("filesystem_virtualized") is True:
        result.update(
            {
                "status": PHASE2A5_FILESYSTEM_VIRTUALIZED,
                "reason": "LOCALAPPDATA canary resolved into a package-cache location",
            }
        )
        if artifact_path is not None:
            write_artifact(artifact_path, result)
        return result
    if canary.get("filesystem_virtualized") is not False:
        result.update(
            {
                "status": PHASE2A5_HOST_CONTEXT_BLOCKED,
                "reason": "physical LOCALAPPDATA behavior could not be proven",
            }
        )
        if artifact_path is not None:
            write_artifact(artifact_path, result)
        return result

    raw_local_appdata = host_context.get("LOCALAPPDATA")
    local_appdata = (
        Path(raw_local_appdata)
        if isinstance(raw_local_appdata, str) and raw_local_appdata
        else Path.home() / "AppData" / "Local"
    )
    try:
        profile_root = _resolve_validation_profile_root(local_appdata, validation_profile)
    except (OSError, RuntimeError, ValueError) as error:
        result.update(
            {
                "status": PHASE2A5_FAIL,
                "reason": _safe_error(error),
                "manual_operation_required": True,
            }
        )
        if artifact_path is not None:
            write_artifact(artifact_path, result)
        return result
    result["validation_profile"] = _validation_profile_summary(profile_root, local_appdata)
    result["backup_inventory"] = inventory_router_backups()
    result["validation_orphans"] = inventory_generated_validation_roots(
        local_appdata,
        profile_root,
    )

    try:
        source, diagnostics = discover_desktop_source(source_override)
        if source is None:
            result.update(
                {
                    "status": PHASE2A5_FAIL,
                    "reason": format_source_diagnostics(diagnostics),
                    "source_diagnostics": diagnostics.to_dict(),
                    "manual_operation_required": False,
                }
            )
        else:
            result["source_diagnostics"] = diagnostics.to_dict()
            identity = _source_identity(source)
            source_for_stability = source
            initial_source_identity = identity
            result["source_identity"] = identity
            reviewed_source = find_reviewed_source(identity)
            reviewed_ok, reviewed_reason = reviewed_source_is_patchable(identity, reviewed_source)
            shell_path = str(source.executable).replace("/", "\\").casefold()
            if not shell_path.endswith("\\app\\chatgpt.exe"):
                reviewed_ok = False
                reviewed_reason = "discovered source does not end in app\\ChatGPT.exe"
            result["source_review"] = {
                "registry": str(REVIEWED_SOURCES_DOCUMENT),
                "status": "PATCHABLE" if reviewed_ok else "SOURCE REVIEW REQUIRED",
                "reason": reviewed_reason,
                "record": reviewed_source,
            }
            if not reviewed_ok:
                result.update(
                    {
                        "status": PHASE2A5_SOURCE_REVIEW_REQUIRED,
                        "reason": f"{PHASE2A5_SOURCE_REVIEW_REQUIRED}: {reviewed_reason}",
                        "manual_operation_required": False,
                    }
                )
            else:
                selected_real, real_candidates = discover_real_codex(real_override)
                # Keep the selected candidate object intact.  Candidate ordering is
                # evidence, not a substitute for the selected result.
                result["real_codex"] = {
                    "selected": {
                        "path": str(selected_real.path),
                        "version": selected_real.version,
                        "sha256": selected_real.sha256,
                        "authenticode": {
                            "status": selected_real.authenticode.status,
                            "signer": selected_real.authenticode.signer,
                        },
                    },
                    "candidates": [str(candidate.path) for candidate in real_candidates],
                }
                desktop_candidates = inventory_desktop_executables(source)
                sandbox = run_phase2a5_sandbox_validation(
                    source,
                    selected_real,
                    desktop_candidates,
                    timeout_seconds=timeout_seconds,
                )
                result["sandbox_validation"] = sandbox
                result["acl_strategy_verdict"] = sandbox.get("production_acl_strategy", "UNRESOLVED")
                if (
                    sandbox.get("status") == PHASE2A5_DIRECT_HOST_PASS
                    and sandbox.get("native_evidence_usable") is True
                    and sandbox.get("production_acl_strategy") == PAYLOAD_ACL_NONE
                ):
                    patched = _run_external_patched_shell(
                        source,
                        selected_real,
                        acl_strategy=PAYLOAD_ACL_NONE,
                        timeout_seconds=timeout_seconds,
                        reviewed_source=reviewed_source,
                        go_toolchain=(
                            runtime.get("go_toolchain")
                            if isinstance(runtime.get("go_toolchain"), Mapping)
                            else None
                        ),
                        validation_profile_root=profile_root,
                        local_appdata=local_appdata,
                    )
                    result["patched_shell"] = patched
                    result["mux_chain"] = {
                        "launcher": "Codex Subscription Router.exe",
                        "desktop": "app\\ChatGPT.exe",
                        "code_cli_path": "runtime\\codex-mux.exe",
                        "mux": "runtime\\codex-mux.exe",
                        "real_codex": "runtime\\codex.real.exe",
                        "observed_mux": patched.get("mux_process_observed"),
                        "observed_real_codex": patched.get("real_codex_process_observed"),
                    }
                    patched_cleanup = patched.get("smoke_root_cleanup")
                    patched_cleanup_ok = (
                        isinstance(patched_cleanup, dict)
                        and (
                            patched_cleanup.get("removed") is True
                            or patched_cleanup.get("persistent") is True
                            and patched_cleanup.get("preserved") is True
                        )
                    )
                    if (
                        patched.get("status") == PATCHED_SHELL_PASS
                        and patched_cleanup_ok
                        and sandbox.get("official_package_unchanged") is True
                    ):
                        if ci_verified:
                            result["status"] = PHASE2A5_FULL_PASS
                            result["reason"] = (
                                "external normal-sandbox, patched-shell, cleanup, official-source, "
                                "and reviewed CI gates passed"
                            )
                            result["ci"] = {
                                "status": "VERIFIED_BY_OPERATOR",
                                "required_jobs": ["checks", "windows-go-core"],
                            }
                            result["phase2b_ready"] = True
                        else:
                            # CI is checked separately on the commit recorded in
                            # the artifact.  Do not claim the aggregate PASS before
                            # that review is complete.
                            result["status"] = PHASE2A5_DIRECT_HOST_PASS
                            result["reason"] = (
                                "external normal-sandbox and patched-shell probes passed; "
                                "GitHub checks remain to be confirmed before aggregate PASS"
                            )
                            result["phase2b_ready"] = False
                    elif patched.get("status") == ROUTER_DESKTOP_AUTH_REQUIRED:
                        result["status"] = PHASE2A5_DESKTOP_AUTH_REQUIRED
                        result["reason"] = (
                            "the persistent Router Desktop validation profile requires normal interactive ChatGPT login"
                        )
                    elif patched.get("status") == PHASE2A5_STORAGE_BLOCKED:
                        result["status"] = PHASE2A5_STORAGE_BLOCKED
                        result["reason"] = patched.get("reason")
                        result["storage_preflight"] = patched.get("storage_preflight")
                        result["manual_operation_required"] = True
                    elif patched.get("status") == PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED:
                        result["status"] = PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED
                        result["reason"] = patched.get("reason")
                    else:
                        result["status"] = PHASE2A5_PATCHED_SHELL_BLOCKED
                        result["reason"] = "the external normal-sandbox probe passed but the patched shell was blocked"
                else:
                    result["status"] = sandbox.get("status", PHASE2A5_FAIL)
                    result["reason"] = sandbox.get("reason")
                result["manual_operation_required"] = bool(
                    result.get("manual_operation_required")
                    or sandbox.get("manual_operation_required")
                    or (
                        isinstance(result.get("patched_shell"), dict)
                        and result["patched_shell"].get("manual_operation_required")
                    )
                )
    except StorageBlockedError as error:
        result.update(
            {
                "status": PHASE2A5_STORAGE_BLOCKED,
                "reason": _safe_error(error),
                "storage_preflight": getattr(error, "evidence", {}),
                "manual_operation_required": True,
            }
        )
    except OSError as error:
        if is_storage_exhaustion(error):
            result.update(
                {
                    "status": PHASE2A5_STORAGE_BLOCKED,
                    "reason": f"{PHASE2A5_STORAGE_BLOCKED}: {_safe_error(error)}",
                    "storage_preflight": {},
                    "manual_operation_required": True,
                }
            )
        else:
            result.update(
                {
                    "status": PHASE2A5_FAIL,
                    "reason": _safe_error(error),
                    "manual_operation_required": False,
                }
            )
    except (PackagingBlockedError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(
            {
                "status": _phase2a5_failure_status(error, PHASE2A5_FAIL),
                "reason": _safe_error(error),
                "manual_operation_required": False,
            }
        )

    if source_for_stability is not None and initial_source_identity is not None:
        source_review = result.get("source_review")
        if isinstance(source_review, dict) and source_review.get("status") == "PATCHABLE":
            stability = _source_stability(source_for_stability, initial_source_identity)
            result["source_stability"] = stability
            if stability.get("stable") is not True:
                result.update(
                    {
                        "status": PHASE2A5_SOURCE_CHANGED_DURING_VALIDATION,
                        "reason": (
                            f"{PHASE2A5_SOURCE_CHANGED_DURING_VALIDATION}: "
                            f"{stability.get('changed_fields') or stability.get('error')}"
                        ),
                        "real_codex": None,
                        "sandbox_validation": None,
                        "acl_strategy_verdict": "UNRESOLVED",
                        "patched_shell": None,
                        "mux_chain": None,
                        "phase2b_ready": False,
                        "manual_operation_required": False,
                    }
                )

    if artifact_path is not None:
        write_artifact(artifact_path, result)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path, help="exact Windows package root/app directory override")
    parser.add_argument("--real-codex", type=Path, help="explicit validated native per-user codex.exe")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument(
        "--prepare-desktop-auth",
        action="store_true",
        help="build and foreground-launch the persistent Router validation profile for manual Desktop login",
    )
    parser.add_argument(
        "--validation-profile",
        type=Path,
        help="Router-owned persistent validation-profile override; never use the official Desktop profile",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARTIFACT,
        help="ignored machine-readable result artifact path",
    )
    parser.add_argument(
        "--ci-verified",
        action="store_true",
        help="claim aggregate PASS only after manually confirming checks and windows-go-core for this commit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.prepare_desktop_auth:
        result = prepare_desktop_auth(
            repo_root=args.repo_root,
            source_override=args.source,
            real_override=args.real_codex,
            timeout_seconds=max(args.timeout_seconds, 60.0),
            artifact_path=args.output,
            validation_profile=args.validation_profile,
        )
        if result.get("manual_operation_required"):
            if result.get("status") == PHASE2A5_STORAGE_BLOCKED:
                print(
                    "Manual operation required: inspect/free space on the reported validation "
                    "volume and review Router-owned backups/orphan roots; persistent auth state "
                    "must be preserved."
                )
            elif result.get("status") == ROUTER_DESKTOP_AUTH_REQUIRED:
                print(
                    "Manual operation required: complete normal ChatGPT login in the opened "
                    "Router validation window; credentials are never read by this workflow."
                )
            else:
                print(
                    "Manual operation required: inspect the persistent desktop-auth result "
                    "and resolve the reported state before retrying; credentials are never "
                    "read by this workflow."
                )
        print(f"Phase 2A.5 Desktop authentication preparation: {result.get('status')}")
        print(json.dumps(_artifact_result(result), indent=2, ensure_ascii=False))
        return 0 if result.get("status") == DESKTOP_AUTH_PREPARED else 1
    result = run_phase2a5_host_validation(
        repo_root=args.repo_root,
        source_override=args.source,
        real_override=args.real_codex,
        timeout_seconds=args.timeout_seconds,
        artifact_path=args.output,
        ci_verified=args.ci_verified,
        validation_profile=args.validation_profile,
    )
    if result.get("manual_operation_required"):
        if result.get("status") == PHASE2A5_STORAGE_BLOCKED:
            print(
                "Manual operation required: inspect/free space on the reported validation "
                "volume and review Router-owned backups/orphan roots; do not delete WindowsApps."
            )
        else:
            print(
                "Manual operation required: start this runner from an independently opened "
                "Windows Terminal/PowerShell process; no official WindowsApps path was modified."
            )
    print(f"Phase 2A.5 verdict: {result.get('status')}")
    print(json.dumps(_artifact_result(result), indent=2, ensure_ascii=False))
    if result.get("status") in {
        PHASE2A5_FULL_PASS,
        PHASE2A5_HOST_CONTEXT_BLOCKED,
        PHASE2A5_FILESYSTEM_VIRTUALIZED,
        PHASE2A5_DIRECT_HOST_PASS,
        PHASE2A5_ACL_FIX_CONFIRMED,
        PHASE2A5_GPU_SANDBOX_REGRESSION,
        PHASE2A5_SOURCE_REVIEW_REQUIRED,
        PHASE2A5_DESKTOP_AUTH_REQUIRED,
    }:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
