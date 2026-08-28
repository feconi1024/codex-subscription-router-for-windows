"""User-started Phase 2A.5 validation from an independently opened host."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from ..patch_app_windows import build_windows_desktop
    from .compatibility import PAYLOAD_ACL_NONE
    from .discovery import (
        EXACT_26_820_PACKAGE_NAME,
        EXACT_26_820_PACKAGE_VERSION,
        RealCodexCandidate,
        discover_desktop_source,
        discover_real_codex,
        format_source_diagnostics,
        inventory_desktop_executables,
        sha256_file,
    )
    from .host_context import detect_windows_host_context, run_localappdata_canary
    from .mirror import PackagingBlockedError
    from .smoke import (
        PHASE2A5_ACL_FIX_CONFIRMED,
        PHASE2A5_DIRECT_HOST_PASS,
        PHASE2A5_FILESYSTEM_VIRTUALIZED,
        PHASE2A5_FULL_PASS,
        PHASE2A5_GPU_SANDBOX_REGRESSION,
        PHASE2A5_HOST_CONTEXT_BLOCKED,
        PHASE2A5_PATCHED_SHELL_BLOCKED,
        PHASE2A5_FAIL,
        PATCHED_SHELL_PASS,
        final_layout_smoke_root,
        run_patched_shell_smoke,
        run_phase2a5_sandbox_validation,
    )
except ImportError:
    from patch_app_windows import build_windows_desktop
    from windows.compatibility import PAYLOAD_ACL_NONE
    from windows.discovery import (
        EXACT_26_820_PACKAGE_NAME,
        EXACT_26_820_PACKAGE_VERSION,
        RealCodexCandidate,
        discover_desktop_source,
        discover_real_codex,
        format_source_diagnostics,
        inventory_desktop_executables,
        sha256_file,
    )
    from windows.host_context import detect_windows_host_context, run_localappdata_canary
    from windows.mirror import PackagingBlockedError
    from windows.smoke import (
        PHASE2A5_ACL_FIX_CONFIRMED,
        PHASE2A5_DIRECT_HOST_PASS,
        PHASE2A5_FILESYSTEM_VIRTUALIZED,
        PHASE2A5_FULL_PASS,
        PHASE2A5_GPU_SANDBOX_REGRESSION,
        PHASE2A5_HOST_CONTEXT_BLOCKED,
        PHASE2A5_PATCHED_SHELL_BLOCKED,
        PHASE2A5_FAIL,
        PATCHED_SHELL_PASS,
        final_layout_smoke_root,
        run_patched_shell_smoke,
        run_phase2a5_sandbox_validation,
    )


EXPECTED_APP_ASAR_SHA256 = "5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2"
DEFAULT_ARTIFACT = Path("docs") / "generated" / "WINDOWS-PHASE2A5-HOST-RESULT.json"


def _safe_error(error: BaseException | str) -> str:
    value = str(error) if not isinstance(error, str) else error
    value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    return value[:500] or type(error).__name__


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


def _source_identity(source: Any) -> dict[str, object]:
    return {
        "package_name": source.package.name,
        "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "architecture": source.package.architecture,
        "source_root": str(source.source_root),
        "app_dir": str(source.app_dir),
        "executable": str(source.executable),
        "file_version": source.file_version,
        "app_asar": str(source.app_asar),
        "app_asar_sha256": sha256_file(source.app_asar),
        "source_kind": source.source_kind,
    }


def _validate_reviewed_source(source: Any) -> dict[str, object]:
    identity = _source_identity(source)
    if (
        identity["package_name"] != EXACT_26_820_PACKAGE_NAME
        or identity["package_version"] != EXACT_26_820_PACKAGE_VERSION
    ):
        raise RuntimeError(
            "Phase 2A.5 requires the reviewed OpenAI.Codex 26.820.7780.0 source"
        )
    if identity["app_asar_sha256"] != EXPECTED_APP_ASAR_SHA256:
        raise RuntimeError(
            "Phase 2A.5 source app.asar hash does not match the reviewed 26.820 source"
        )
    if str(identity["executable"]).replace("/", "\\").casefold().split("\\")[-2:] != ["app", "chatgpt.exe"]:
        raise RuntimeError("Phase 2A.5 requires app\\ChatGPT.exe as the authoritative shell")
    return identity


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
        "cleanup",
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
        "smoke_root_cleanup",
    )
    output = {key: result[key] for key in allowed if key in result}
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
    ui_bridge = result.get("ui_bridge")
    if isinstance(ui_bridge, dict):
        output["ui_bridge"] = {
            key: ui_bridge.get(key)
            for key in ("pass", "status_code", "account_menu_rendered")
            if key in ui_bridge
        }
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
        "smoke_root_cleanup",
        "manual_operation_required",
    ):
        if key in result:
            output[key] = result[key]
    for key in ("probe_a_normal", "probe_b_disable_gpu_sandbox", "probe_c_acl_normal_sandbox"):
        if key in result:
            output[key] = _public_probe(result[key])
    output["diagnostic_shells"] = [_public_probe(item) for item in result.get("diagnostic_shells", [])]
    return output


def _run_external_patched_shell(
    source: Any,
    selected_real: RealCodexCandidate,
    *,
    acl_strategy: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Build and smoke one disposable Router shell, finalizing cleanup afterward."""

    cleanup: dict[str, object] = {}
    result: dict[str, object]
    try:
        with final_layout_smoke_root(
            cleanup,
            parent_name="_host-validation",
            prefix="phase2a5-patched-",
        ) as root:
            if cleanup.get("path_virtualized") is True:
                result = {
                    "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
                    "reason": "the disposable patched-shell root was filesystem-virtualized",
                    "manual_operation_required": True,
                }
            else:
                destination = root / "patched-shell"
                metadata = build_windows_desktop(
                    source,
                    selected_real,
                    destination,
                    force=False,
                    allow_untested_source=True,
                    payload_acl_strategy=acl_strategy,
                )
                result = run_patched_shell_smoke(
                    destination,
                    selected_real,
                    timeout_seconds=timeout_seconds,
                    disposable_root=True,
                )
                result["build_metadata_summary"] = {
                    "destination": str(destination),
                    "desktop_launch_executable": metadata.get("desktop_launch_executable"),
                    "payload_acl_strategy": metadata.get("payload_acl_strategy"),
                    "source_app_asar_sha256": metadata.get("source_app_asar_sha256"),
                }
    except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        result = {
            "status": PHASE2A5_PATCHED_SHELL_BLOCKED,
            "reason": _safe_error(error),
            "manual_operation_required": True,
        }

    # Do not return a cleanup-dependent result from inside the context manager.
    result["smoke_root_cleanup"] = dict(cleanup)
    if cleanup.get("removed") is not True:
        result["status"] = PHASE2A5_PATCHED_SHELL_BLOCKED
        result["reason"] = "the disposable patched-shell root was not cleaned up successfully"
        result["manual_operation_required"] = True
    return result


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
        "source_diagnostics",
        "real_codex",
        "sandbox_validation",
        "acl_strategy_verdict",
        "patched_shell",
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
        "source_identity": None,
        "source_diagnostics": None,
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
            result["source_identity"] = _validate_reviewed_source(source)
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
                if (
                    patched.get("status") == PATCHED_SHELL_PASS
                    and isinstance(patched.get("smoke_root_cleanup"), dict)
                    and patched["smoke_root_cleanup"].get("removed") is True
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
    except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(
            {
                "status": PHASE2A5_FAIL,
                "reason": _safe_error(error),
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
    result = run_phase2a5_host_validation(
        repo_root=args.repo_root,
        source_override=args.source,
        real_override=args.real_codex,
        timeout_seconds=args.timeout_seconds,
        artifact_path=args.output,
        ci_verified=args.ci_verified,
    )
    if result.get("manual_operation_required"):
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
    }:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
