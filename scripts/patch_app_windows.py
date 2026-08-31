#!/usr/bin/env python3
"""Build a writable Windows Desktop MVP without modifying the official install."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Mapping

try:
    from .patch_common import (
        PROJECT_ROOT,
        audit_renderer_anchors,
        compare_renderer_contract,
        detect_renderer_contract,
        ensure_asar_tool,
        load_or_create_token,
       patch_renderer,
       select_renderer_contract,
       validate_patched_javascript_syntax,
    )
    from .windows.bootstrap import BootstrapPatchReport, audit_bootstrap, patch_bootstrap
    from .windows.compatibility import (
        PAYLOAD_ACL_APPCONTAINER_RX,
        PAYLOAD_ACL_NONE,
        PAYLOAD_ACL_STRATEGIES,
        PAYLOAD_ACL_UNRESOLVED,
        find_matching_record,
        load_compatibility_records,
    )
    from .windows.discovery import (
        DesktopExecutableCandidate,
        DesktopSource,
        RealCodexCandidate,
        SourceDiagnostics,
        discover_desktop_source,
        copy_byte_identical,
        discover_real_codex,
        format_source_diagnostics,
        locate_desktop_source,
        package_to_dict,
        parse_appx_block_map,
        read_authenticode,
        read_file_version,
        read_file_versions,
        sha256_file,
        source_access_probes,
        is_windowsapps_path,
        inventory_desktop_executables,
        select_authoritative_desktop_candidate,
    )
    from .windows.fuses import FuseSnapshot
    from .windows.acl import prepare_windows_electron_payload_acl, validate_router_app_root
    from .windows.integrity import (
        apply_windows_asar_integrity,
        asar_header_digest,
        resolve_windows_asar_integrity,
        scan_fuse_carriers,
    )
    from .windows.smoke import (
        BLOCKED_OTHER_PACKAGE_IDENTITY,
        BLOCKED_UPDATER_IDENTITY,
        DEVELOPMENT_ONLY_SANDBOX_BYPASS,
        DIRECT_LAUNCH_IDENTITY_BLOCKED,
        DIRECT_LAUNCH_PASS,
        MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED,
        MINIMAL_BOOTSTRAP_PASS,
        PATCHED_SHELL_BLOCKED,
        PATCHED_SHELL_PASS,
        PHASE2A4_APP_CONTAINER_ACCESS_FIX_CONFIRMED,
        PHASE2A4_FAIL,
        PHASE2A4_FULL_PASS,
        PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
        PHASE2A4_PATCHED_SHELL_BLOCKED,
        PHASE2A4_WINDOWS_GPU_SANDBOX_REGRESSION,
        final_layout_smoke_root,
        run_launch_probes,
        run_patched_shell_smoke,
        run_phase2a4_sandbox_validation,
        run_smoke_launch_matrix,
        run_unmodified_mirror_smoke,
        validation_profile_layout,
    )
    from .windows.mirror import (
        PHASE2A5_STORAGE_BLOCKED,
        PackagingBlockedError,
        StorageBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_desktop_source,
        plan_mirror_source,
        require_storage_capacity,
        storage_preflight,
        verify_desktop_mirror,
        is_storage_exhaustion,
    )
    from .windows.reviewed_sources import find_reviewed_source, reviewed_source_is_patchable
except ImportError:
    from patch_common import (
        PROJECT_ROOT,
        audit_renderer_anchors,
        compare_renderer_contract,
        detect_renderer_contract,
        ensure_asar_tool,
        load_or_create_token,
       patch_renderer,
       select_renderer_contract,
       validate_patched_javascript_syntax,
    )
    from windows.bootstrap import BootstrapPatchReport, audit_bootstrap, patch_bootstrap
    from windows.compatibility import (
        PAYLOAD_ACL_APPCONTAINER_RX,
        PAYLOAD_ACL_NONE,
        PAYLOAD_ACL_STRATEGIES,
        PAYLOAD_ACL_UNRESOLVED,
        find_matching_record,
        load_compatibility_records,
    )
    from windows.discovery import (
        DesktopExecutableCandidate,
        DesktopSource,
        RealCodexCandidate,
        SourceDiagnostics,
        discover_desktop_source,
        copy_byte_identical,
        discover_real_codex,
        format_source_diagnostics,
        locate_desktop_source,
        package_to_dict,
        parse_appx_block_map,
        read_authenticode,
        read_file_version,
        read_file_versions,
        sha256_file,
        source_access_probes,
        is_windowsapps_path,
        inventory_desktop_executables,
        select_authoritative_desktop_candidate,
    )
    from windows.fuses import FuseSnapshot
    from windows.acl import prepare_windows_electron_payload_acl, validate_router_app_root
    from windows.integrity import (
        apply_windows_asar_integrity,
        asar_header_digest,
        resolve_windows_asar_integrity,
        scan_fuse_carriers,
    )
    from windows.smoke import (
        BLOCKED_OTHER_PACKAGE_IDENTITY,
        BLOCKED_UPDATER_IDENTITY,
        DEVELOPMENT_ONLY_SANDBOX_BYPASS,
        DIRECT_LAUNCH_IDENTITY_BLOCKED,
        DIRECT_LAUNCH_PASS,
        MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED,
        MINIMAL_BOOTSTRAP_PASS,
        PATCHED_SHELL_BLOCKED,
        PATCHED_SHELL_PASS,
        PHASE2A4_APP_CONTAINER_ACCESS_FIX_CONFIRMED,
        PHASE2A4_FAIL,
        PHASE2A4_FULL_PASS,
        PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
        PHASE2A4_PATCHED_SHELL_BLOCKED,
        PHASE2A4_WINDOWS_GPU_SANDBOX_REGRESSION,
        final_layout_smoke_root,
        run_launch_probes,
        run_patched_shell_smoke,
        run_phase2a4_sandbox_validation,
        run_smoke_launch_matrix,
        run_unmodified_mirror_smoke,
        validation_profile_layout,
    )
    from windows.mirror import (
        PHASE2A5_STORAGE_BLOCKED,
        PackagingBlockedError,
        StorageBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_desktop_source,
        plan_mirror_source,
        require_storage_capacity,
        storage_preflight,
        verify_desktop_mirror,
        is_storage_exhaustion,
    )
    from windows.reviewed_sources import find_reviewed_source, reviewed_source_is_patchable


PROJECT_VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
DEFAULT_DESTINATION = Path(
    os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
) / "Codex Subscription Router"
COMPATIBILITY_DOCUMENT = PROJECT_ROOT / "docs" / "WINDOWS-COMPATIBILITY.md"
PHASE2A5_SOURCE_REVIEW_PASS = "FULL PHASE 2A.5 SOURCE REVIEW PASS"
PHASE2A5_RENDERER_ADAPTATION_REQUIRED = "PHASE 2A.5 RENDERER ADAPTATION REQUIRED"
PHASE2A5_BOOTSTRAP_BLOCKED = "PHASE 2A.5 BOOTSTRAP BLOCKED"
PHASE2A5_INTEGRITY_BLOCKED = "PHASE 2A.5 INTEGRITY BLOCKED"
PHASE2A5_FAIL = "PHASE 2A.5 FAIL"
PHASE2A5_SOURCE_CHANGED_DURING_REVIEW = "PHASE 2A.5 SOURCE CHANGED DURING REVIEW"

# Keep the old Python names as compatibility aliases for callers that imported
# them during the earlier source-refresh round.  The values and all user-facing
# output remain explicitly in the Phase 2A.5 vocabulary.
PHASE2A6_SOURCE_REVIEW_PASS = PHASE2A5_SOURCE_REVIEW_PASS
PHASE2A6_RENDERER_ADAPTATION_REQUIRED = PHASE2A5_RENDERER_ADAPTATION_REQUIRED
PHASE2A6_BOOTSTRAP_BLOCKED = PHASE2A5_BOOTSTRAP_BLOCKED
PHASE2A6_INTEGRITY_BLOCKED = PHASE2A5_INTEGRITY_BLOCKED
PHASE2A6_FAIL = PHASE2A5_FAIL


class InstallPolicy(str, Enum):
    """Choose whether a replacement keeps or discards the old validation shell."""

    RECOVERABLE_BACKUP = "RECOVERABLE_BACKUP"
    EPHEMERAL_ROLLBACK = "EPHEMERAL_ROLLBACK"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    parser.add_argument("--source", type=Path, help="Windows package root/app directory override")
    parser.add_argument("--real-codex", type=Path, help="explicit native per-user codex.exe override")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument(
        "--diagnose-source",
        action="store_true",
        help="read-only source discovery diagnostics; never stages or patches files",
    )
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="read-only real Desktop executable, ASAR, fuse, and renderer audit",
    )
    parser.add_argument(
        "--mirror-dry-run",
        action="store_true",
        help="mirror the unmodified Desktop shell into a temporary writable directory",
    )
    parser.add_argument(
        "--smoke-unmodified-mirror",
        action="store_true",
        help="launch an unmodified temporary Desktop mirror for bounded startup evidence",
    )
    parser.add_argument(
        "--smoke-launch-matrix",
        action="store_true",
        help="run the sequential ChatGPT.exe/Codex.exe direct-launch matrix and identity-gated minimal fallback",
    )
    parser.add_argument(
        "--smoke-sandbox-acl",
        "--smoke-phase2a4",
        dest="smoke_sandbox_acl",
        action="store_true",
        help="run Phase 2A.4 Chromium sandbox diagnostics, local app ACL remediation, and post-ACL probe",
    )
    parser.add_argument(
        "--payload-acl-strategy",
        choices=PAYLOAD_ACL_STRATEGIES,
        default=None,
        help=(
            "select the Router app-tree ACL strategy explicitly; the default "
            "UNRESOLVED strategy never mutates ACLs"
        ),
    )
    parser.add_argument(
        "--launch-executable",
        help="validated root shell relative path from launch metadata, for example app\\ChatGPT.exe",
    )
    parser.add_argument(
        "--bootstrap-user-data-patch",
        action="store_true",
        default=None,
        help="force the legacy source userData bootstrap patch (otherwise the Phase 2A.2 default applies)",
    )
    parser.add_argument(
        "--bootstrap-disable-updater",
        action="store_true",
        default=None,
        help="force removal of the copied updater initializer (otherwise the Phase 2A.2 default applies)",
    )
    parser.add_argument(
        "--diagnostics-json",
        type=Path,
        help="write source diagnostics (and audit/mirror evidence when selected) to JSON",
    )
    parser.add_argument("--force", action="store_true", help="move a previous local build to a recoverable backup")
    parser.add_argument(
        "--allow-untested-source",
        action="store_true",
        help="allow an unknown package/version/app.asar hash after exact anchor validation",
    )
    return parser.parse_args()


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def output(command: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def _powershell_executable() -> str | None:
    return shutil.which("pwsh.exe") or shutil.which("powershell.exe") or shutil.which("pwsh")


def _go_probe_command(command: list[str]) -> tuple[list[str], str | None]:
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return [], str(error)
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if result.returncode != 0 and not lines:
        return [], (result.stderr or f"exit code {result.returncode}").strip().splitlines()[0]
    return lines, None


def probe_go_toolchain() -> dict[str, object]:
    """Probe Go without installing it or changing the process/global PATH."""
    attempts: list[dict[str, object]] = []
    candidates: list[Path] = []

    path_go = shutil.which("go")
    attempts.append({"probe": "PATH/shutil.which(go)", "status": "PASS" if path_go else "FAIL"})
    if path_go:
        candidates.append(Path(path_go))

    where_executable = shutil.which("where.exe") or shutil.which("where")
    if where_executable:
        paths, error = _go_probe_command([where_executable, "go"])
        attempts.append({"probe": "where.exe go", "status": "PASS" if paths else "FAIL", "error": error})
        candidates.extend(Path(path) for path in paths)
    else:
        attempts.append({"probe": "where.exe go", "status": "NOT AVAILABLE", "error": "where.exe unavailable"})

    known_paths = (Path(r"C:\Program Files\Go\bin\go.exe"), Path(r"C:\Go\bin\go.exe"))
    for known in known_paths:
        exists = known.is_file()
        attempts.append({"probe": f"Test-Path {known}", "status": "PASS" if exists else "FAIL", "candidate": str(known)})
        if exists:
            candidates.append(known)

    powershell = _powershell_executable()
    registry_candidates: list[str] = []
    if powershell:
        command_script = r"""
$paths = @(Get-Command go -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
ConvertTo-Json -InputObject $paths -Compress
"""
        command_output, command_error = _go_probe_command(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command_script]
        )
        command_paths: list[str] = []
        if command_output and command_error is None:
            try:
                parsed = json.loads(command_output[-1])
            except json.JSONDecodeError:
                parsed = []
            parsed_values = parsed if isinstance(parsed, list) else [parsed]
            command_paths = [
                item for item in parsed_values
                if isinstance(item, str) and item.strip()
            ]
        attempts.append(
            {
                "probe": "Get-Command go -All",
                "status": "PASS" if command_paths else "FAIL",
                "error": command_error,
            }
        )
        candidates.extend(Path(path) for path in command_paths)
        registry_script = r"""
$keys = @('HKLM:\SOFTWARE\GoProgrammingLanguage','HKLM:\SOFTWARE\WOW6432Node\GoProgrammingLanguage')
$values = foreach ($key in $keys) {
  Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty InstallLocation -ErrorAction SilentlyContinue
}
ConvertTo-Json -InputObject @($values) -Compress
"""
        raw, error = _go_probe_command([powershell, "-NoProfile", "-NonInteractive", "-Command", registry_script])
        if raw and error is None:
            try:
                parsed = json.loads(raw[-1])
            except json.JSONDecodeError:
                parsed = []
            registry_candidates = parsed if isinstance(parsed, list) else [parsed]
            registry_candidates = [item for item in registry_candidates if isinstance(item, str) and item]
        attempts.append({"probe": "Go installation registry", "status": "PASS" if registry_candidates else "FAIL", "error": error})
        candidates.extend(Path(item) / "bin" / "go.exe" for item in registry_candidates)
    else:
        attempts.append({"probe": "Go installation registry", "status": "NOT AVAILABLE", "error": "PowerShell unavailable"})

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.expanduser().resolve(strict=False)
        key = str(resolved).casefold()
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        unique.append(resolved)
    selected = unique[0] if unique else None
    return {
        "selected": str(selected) if selected else None,
        "candidates": [str(path) for path in unique],
        "probes": attempts,
    }


def go_executable_or_raise() -> Path:
    result = probe_go_toolchain()
    selected = result.get("selected")
    if isinstance(selected, str) and selected:
        return Path(selected)
    raise RuntimeError(f"required Go toolchain not found; probes: {json.dumps(result['probes'], sort_keys=True)}")


def build_go_binary(package: str, destination: Path, go_executable: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            str(go_executable),
            "build",
            "-trimpath",
            "-ldflags=-s -w",
            "-o",
            str(destination),
            package,
        ],
        cwd=PROJECT_ROOT,
    )


def print_anchor_audit(audit: list[object]) -> None:
    print("Renderer anchor audit:")
    for item in audit:
        print(
            f"  {item.name}: {item.status}; asset={item.asset}; "
            f"matched={item.matched or '-'}; count={item.count}"
        )


def _fuse_summary(snapshot: FuseSnapshot | None, error: str | None = None) -> dict[str, object]:
    if snapshot is None:
        return {"status": "NOT PRESENT" if error is None else "UNAVAILABLE", "error": error}
    required = (
        "RunAsNode",
        "EnableCookieEncryption",
        "EnableNodeOptionsEnvironmentVariable",
        "EnableNodeCliInspectArguments",
        "EnableEmbeddedAsarIntegrityValidation",
        "OnlyLoadAppFromAsar",
    )
    return {
        "schema_version": snapshot.schema_version,
        "count": snapshot.count,
        "fuses": list(snapshot.fuses),
        "named": {
            name: snapshot.fuses[index]
            for name, index in {
                "RunAsNode": 0,
                "EnableCookieEncryption": 1,
                "EnableNodeOptionsEnvironmentVariable": 2,
                "EnableNodeCliInspectArguments": 3,
                "EnableEmbeddedAsarIntegrityValidation": 4,
                "OnlyLoadAppFromAsar": 5,
            }.items()
            if index < snapshot.count and name in required
        },
    }


def _audit_has_failure(audit: list[object]) -> bool:
    return any(
        item.status in {"MISSING", "SEMANTICALLY_CHANGED", "CHANGED", "AMBIGUOUS"}
        for item in audit
    )


def _phase2a5_verdict(
    *,
    renderer_variant: str,
    renderer_audit_pass: bool,
    bootstrap_pass: bool,
    integrity_resolved: bool,
    reviewed_source_pass: bool,
    authoritative_shell_proven: bool,
) -> str:
    if not renderer_audit_pass or renderer_variant == "UNRESOLVED":
        return PHASE2A5_RENDERER_ADAPTATION_REQUIRED
    if not bootstrap_pass:
        return PHASE2A5_BOOTSTRAP_BLOCKED
    if not integrity_resolved:
        return PHASE2A5_INTEGRITY_BLOCKED
    if not reviewed_source_pass or not authoritative_shell_proven:
        return PHASE2A5_FAIL
    return PHASE2A5_SOURCE_REVIEW_PASS


def _phase2a6_verdict(**kwargs: object) -> str:
    """Compatibility wrapper for callers from the earlier source-refresh round."""

    return _phase2a5_verdict(**kwargs)


def _bounded_audit_error(error: BaseException) -> str:
    message = " ".join(str(error).replace("\r", " ").replace("\n", " ").split())
    return message[:300] or type(error).__name__


def _source_review_identity(source: DesktopSource) -> dict[str, object]:
    """Capture the immutable source fields used by the Phase 2A.5 gate."""

    versions = read_file_versions(source.executable)
    return {
        "source_root": str(source.source_root.resolve(strict=False)),
        "executable": str(source.executable.resolve(strict=False)),
        "app_asar": str(source.app_asar.resolve(strict=False)),
        "package_name": source.package.name,
        "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "architecture": source.package.architecture,
        "app_file_version": versions.get("FileVersion") or source.file_version,
        "product_version": versions.get("ProductVersion") or "unknown",
        "chatgpt_exe_sha256": sha256_file(source.executable),
        "app_asar_sha256": sha256_file(source.app_asar),
        "app_asar_header_sha256": asar_header_digest(source.app_asar).hash,
    }


def _source_stability_result(
    initial: Mapping[str, object],
    final: Mapping[str, object],
    *,
    recheck_error: str | None = None,
) -> dict[str, object]:
    fields = (
        "source_root",
        "executable",
        "app_asar",
        "package_name",
        "package_full_name",
        "package_version",
        "architecture",
        "app_file_version",
        "product_version",
        "chatgpt_exe_sha256",
        "app_asar_sha256",
        "app_asar_header_sha256",
    )
    changed_fields = [field for field in fields if initial.get(field) != final.get(field)]
    stable = not changed_fields and recheck_error is None
    result: dict[str, object] = {
        "status": "STABLE" if stable else "CHANGED",
        "stable": stable,
        "checked_fields": list(fields),
        "changed_fields": changed_fields,
        "initial": dict(initial),
        "final": dict(final),
    }
    if recheck_error is not None:
        result["recheck_error"] = recheck_error
    return result


def _real_codex_review() -> dict[str, object]:
    """Re-discover the current per-user native Codex only after source review."""

    try:
        selected, candidates = discover_real_codex()
    except (OSError, RuntimeError) as error:
        return {
            "status": "UNAVAILABLE",
            "candidate_count": 0,
            "error": _bounded_audit_error(error),
        }
    return {
        "status": "PASS",
        "candidate_count": len(candidates),
        "selected": {
            "path": str(selected.path),
            "version": selected.version,
            "sha256": selected.sha256,
            "authenticode": {
                "status": selected.authenticode.status,
                "signer": selected.authenticode.signer,
            },
        },
    }


def _carrier_paths_from_scan(mirrored_root: Path, fuse_scan: dict[str, object]) -> tuple[Path, ...]:
    values = fuse_scan.get("carriers")
    if not isinstance(values, list):
        return ()
    paths: list[Path] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        relative = value.get("relative")
        if isinstance(relative, str) and relative:
            paths.append(mirrored_root / Path(relative.replace("/", "\\")))
    return tuple(paths)


def audit_windows_source(source: DesktopSource) -> dict[str, object]:
    """Audit the real source without changing its executable or ASAR."""
    asar = ensure_asar_tool()
    frozen_identity = _source_review_identity(source)
    source_hash = str(frozen_identity["app_asar_sha256"])
    source_header_hash = str(frozen_identity["app_asar_header_sha256"])
    signature = read_authenticode(source.executable)
    block_map_path = source.source_root / "AppxBlockMap.xml"
    try:
        block_map_files = [path.as_posix() for path in parse_appx_block_map(block_map_path)]
        block_map_error = None
    except RuntimeError as error:
        block_map_files = []
        block_map_error = str(error)
    with tempfile.TemporaryDirectory(prefix="codex-router-phase2a-audit-") as temporary:
        temporary_root = Path(temporary)
        mirror_root = temporary_root / "mirror" / "app"
        mirror_report = mirror_desktop_source(source, mirror_root)
        verify_desktop_mirror(source.app_dir, mirror_root)
        fuse_scan = scan_fuse_carriers(mirror_root)
        carrier_paths = _carrier_paths_from_scan(mirror_root, fuse_scan)
        integrity_plan = resolve_windows_asar_integrity(
            source.executable,
            carrier_paths=carrier_paths,
        )
        executable_inventory = inventory_desktop_executables(source)
        extracted = temporary_root / "asar"
        run([str(asar), "extract", str(source.app_asar), str(extracted)])
        initial_bundles = list((extracted / "webview" / "assets").glob("app-initial-*.js"))
        reviewed_source = find_reviewed_source(frozen_identity)
        renderer_variant_id = "UNRESOLVED"
        try:
            if len(initial_bundles) != 1:
                raise RuntimeError(f"expected one initial renderer bundle, found {len(initial_bundles)}")
            bundle_text = initial_bundles[0].read_text(encoding="utf-8")
            reviewed_contract = (
                reviewed_source.get("renderer_variant")
                if isinstance(reviewed_source, Mapping)
                else None
            )
            selected_contract = (
                select_renderer_contract(bundle_text, reviewed_contract)
                if isinstance(reviewed_contract, str) and reviewed_contract
                else detect_renderer_contract(bundle_text)
            )
            renderer_variant_id = selected_contract.variant_id
        except (RuntimeError, ValueError):
            renderer_variant_id = "UNRESOLVED"
        try:
            renderer_audit = audit_renderer_anchors(
                extracted,
                renderer_variant=(renderer_variant_id if renderer_variant_id != "UNRESOLVED" else None),
                package_name=source.package.name,
                package_version=source.package.version,
                app_asar_sha256=source_hash,
            )
            renderer_audit_error = None
        except (RuntimeError, ValueError) as error:
            renderer_audit = []
            renderer_audit_error = _bounded_audit_error(error)
        renderer_comparison = compare_renderer_contract(
            extracted,
            reference_variant=(
                "windows-26.825" if renderer_variant_id == "windows-26.825" else "windows-26.820"
            ),
            observed_variant=(renderer_variant_id if renderer_variant_id != "UNRESOLVED" else None),
        )
        bootstrap_audit = audit_bootstrap(extracted, PROJECT_ROOT)
    try:
        final_identity = _source_review_identity(source)
        stability_error = None
    except (OSError, RuntimeError, ValueError) as error:
        final_identity = {"capture_status": "UNAVAILABLE"}
        stability_error = _bounded_audit_error(error)
    source_stability = _source_stability_result(
        frozen_identity,
        final_identity,
        recheck_error=stability_error,
    )
    fuse_summary = _fuse_summary(integrity_plan.fuse, integrity_plan.fuse_error)
    audited_file_version = str(frozen_identity["app_file_version"])
    product_version = str(frozen_identity["product_version"])
    source_identity = dict(frozen_identity)
    reviewed_source = find_reviewed_source(source_identity)
    reviewed_source_pass, reviewed_source_reason = reviewed_source_is_patchable(
        source_identity,
        reviewed_source,
    )
    authoritative_shell_proven = any(
        candidate.relative_path.replace("/", "\\").casefold() == "app\\chatgpt.exe"
        and candidate.present is True
        and candidate.appx_manifest_declared is True
        for candidate in executable_inventory
    )
    if not authoritative_shell_proven:
        reviewed_source_pass = False
        reviewed_source_reason = "app\\ChatGPT.exe was not proven as the present AppX-declared shell"
    comparison_statuses = renderer_comparison.get("surface_status")
    comparison_failed = isinstance(comparison_statuses, list) and any(
        isinstance(item, Mapping)
        and item.get("status") in {"MISSING", "CHANGED", "AMBIGUOUS"}
        for item in comparison_statuses
    )
    renderer_variant_pass = (
        renderer_variant_id != "UNRESOLVED"
        and renderer_audit_error is None
        and not _audit_has_failure(renderer_audit)
        and not comparison_failed
    )
    phase2a5_verdict = _phase2a5_verdict(
        renderer_variant=renderer_variant_id,
        renderer_audit_pass=renderer_variant_pass,
        bootstrap_pass=bool(bootstrap_audit.get("audit_pass")),
        integrity_resolved=integrity_plan.resolved,
        reviewed_source_pass=reviewed_source_pass,
        authoritative_shell_proven=authoritative_shell_proven,
    )
    if source_stability["status"] != "STABLE":
        phase2a5_verdict = PHASE2A5_SOURCE_CHANGED_DURING_REVIEW
        reviewed_source_pass = False
        reviewed_source_reason = "source identity changed or could not be re-read after the read-only audit"
    real_codex_review = (
        _real_codex_review()
        if (
            source_stability["status"] == "STABLE"
            and reviewed_source_pass
            and renderer_variant_pass
            and bool(bootstrap_audit.get("audit_pass"))
            and integrity_plan.resolved
            and authoritative_shell_proven
        )
        else {
            "status": "NOT RUN",
            "reason": "real Codex discovery is deferred until the exact source review gate passes",
        }
    )
    return {
        "source_identity": source_identity,
        "source_stability": source_stability,
        "source": {
            "package": package_to_dict(source.package),
            "source_kind": source.source_kind,
            "source_root": str(source.source_root),
            "app_dir": str(source.app_dir),
            "executable": str(source.executable),
            "file_version": audited_file_version,
            "product_version": product_version,
            "authenticode": {"status": signature.status, "signer": signature.signer},
            "chatgpt_exe_sha256": frozen_identity["chatgpt_exe_sha256"],
            "app_asar": str(source.app_asar),
            "app_asar_sha256": source_hash,
            "app_asar_header_sha256": source_header_hash,
        },
        "access": [probe.to_dict() for probe in source_access_probes(source)],
        "appx_block_map": {
            "path": str(block_map_path),
            "file_count": len(block_map_files),
            "error": block_map_error,
        },
        "windows_asar_integrity": integrity_plan.to_dict(),
        "fuse_carriers": fuse_scan,
        "desktop_executables": [candidate.to_dict() for candidate in executable_inventory],
        "bootstrap_audit": bootstrap_audit,
        "mirror": mirror_report.to_dict(),
        "renderer_anchor_audit": [
            {
                "name": item.name,
                "asset": item.asset,
                "status": item.status,
                "matched": item.matched,
                "count": item.count,
            }
            for item in renderer_audit
        ],
        "renderer_variant": renderer_variant_id,
        "renderer_contract_comparison": renderer_comparison,
        "renderer_audit_error": renderer_audit_error,
        "real_codex_review": real_codex_review,
        "electron_fuses": fuse_summary,
        "renderer_audit_pass": renderer_variant_pass,
        "fuse_audit_pass": True,
        "reviewed_source": {
            "status": "PATCHABLE" if reviewed_source_pass else "SOURCE REVIEW REQUIRED",
            "reason": reviewed_source_reason,
            "record": reviewed_source,
        },
        "authoritative_shell_proven": authoritative_shell_proven,
        "phase2a5_verdict": phase2a5_verdict,
        "phase2a6_verdict": phase2a5_verdict,
        "audit_pass": phase2a5_verdict == PHASE2A5_SOURCE_REVIEW_PASS,
    }


def _write_json(path: Path | None, payload: dict[str, object]) -> None:
    if path is None:
        return
    path = path.expanduser().resolve(strict=False)
    if is_windowsapps_path(path):
        raise RuntimeError("refusing to write diagnostics inside protected WindowsApps")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _print_access_matrix(probes: list[dict[str, object]]) -> None:
    print("Direct-read/access results:")
    for probe in probes:
        detail = f"; error={probe['error']}" if probe.get("error") else ""
        print(f"  {probe['method']}: {probe['status']}{detail}")


def _run_source_diagnostics(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is not None:
        diagnostics.selected_source = source
    payload = diagnostics.to_dict()
    _write_json(args.diagnostics_json, payload)
    print(format_source_diagnostics(diagnostics))
    return 0 if source is not None else 1


def _run_source_audit(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is None:
        payload = diagnostics.to_dict()
        _write_json(args.diagnostics_json, payload)
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        return 1
    try:
        audit = audit_windows_source(source)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        payload = diagnostics.to_dict()
        payload["audit_error"] = str(error)
        _write_json(args.diagnostics_json, payload)
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        print(f"Phase 2A audit failed: {error}", file=sys.stderr)
        return 1
    payload = diagnostics.to_dict()
    payload["audit"] = audit
    _write_json(args.diagnostics_json, payload)
    print(format_source_diagnostics(diagnostics))
    print(f"Source app.asar SHA-256: {audit['source']['app_asar_sha256']}")
    print(f"ChatGPT.exe SHA-256: {audit['source']['chatgpt_exe_sha256']}")
    print(f"ChatGPT.exe FileVersion: {audit['source']['file_version']}")
    print(f"ChatGPT.exe ProductVersion: {audit['source']['product_version']}")
    print(f"Authenticode: {audit['source']['authenticode']}")
    print(f"ASAR header SHA-256: {audit['source']['app_asar_header_sha256']}")
    print(f"Renderer variant: {audit['renderer_variant']}")
    print(f"Phase 2A.5 verdict: {audit['phase2a5_verdict']}")
    print(f"AppxBlockMap files: {audit['appx_block_map']['file_count']}")
    print(f"Electron fuses: {json.dumps(audit['electron_fuses'], sort_keys=True)}")
    print(f"Windows ASAR integrity: {json.dumps(audit['windows_asar_integrity'], sort_keys=True)}")
    print("Desktop executable candidates:")
    for candidate in audit["desktop_executables"]:
        print(
            f"  {candidate['relative_path']}: "
            f"{'present' if candidate['present'] else 'NOT PRESENT'}; "
            f"machine={candidate.get('pe_machine_hex')}; "
            f"fuse={candidate.get('fuse_wire_present')}; "
            f"integrity_resource={candidate.get('integrity_resource_present')}"
        )
    print(
        "Fuse carrier scan: "
        f"{audit['fuse_carriers']['carrier_count']} carrier(s), "
        f"{len(audit['fuse_carriers']['scanned_files'])} file(s) scanned"
    )
    print(f"Bootstrap audit: {json.dumps(audit['bootstrap_audit'], sort_keys=True)}")
    print_anchor_audit([type("AuditItem", (), item) for item in audit["renderer_anchor_audit"]])
    _print_access_matrix(audit["access"])
    return 0 if audit["audit_pass"] else 1


def _direct_profile_contract_proven(direct: dict[str, object]) -> bool:
    values = direct.get("candidates")
    if not isinstance(values, list):
        return False
    present = [value for value in values if isinstance(value, dict) and value.get("status") != "NOT PRESENT"]
    if not present:
        return False
    for value in present:
        isolation = value.get("profile_isolation")
        if not isinstance(isolation, dict) or isolation.get("contract_valid") is not True:
            return False
    return True


def _direct_updater_identity_seen(direct: dict[str, object]) -> bool:
    values = direct.get("candidates")
    if not isinstance(values, list):
        return False
    for value in values:
        if not isinstance(value, dict):
            continue
        if value.get("status") == BLOCKED_UPDATER_IDENTITY:
            return True
        relevant = value.get("relevant_log_lines")
        if isinstance(relevant, dict) and relevant.get("updater_identity"):
            return True
    return False


def _minimal_bootstrap_smoke(
    source: DesktopSource,
    real: RealCodexCandidate,
    candidates: tuple[DesktopExecutableCandidate, ...],
    direct: dict[str, object],
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Run Gate 2 with only the minimum proven bootstrap change."""
    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "reason": "minimal Windows bootstrap validation is Windows-only",
            "renderer_patch_applied": False,
            "manual_operation_required": False,
        }
    disable_updater = _direct_updater_identity_seen(direct)
    patch_user_data = not _direct_profile_contract_proven(direct)
    with tempfile.TemporaryDirectory(prefix="codex-router-phase2a3-minimal-") as temporary:
        root = Path(temporary)
        mirror_root = root / "app"
        mirror_report = mirror_desktop_source(source, mirror_root)
        verify_desktop_mirror(source.app_dir, mirror_root)
        fuse_scan = scan_fuse_carriers(mirror_root)
        carrier_paths = _carrier_paths_from_scan(mirror_root, fuse_scan)
        staged_source = mirror_root / source.executable.name
        integrity_plan = resolve_windows_asar_integrity(
            staged_source,
            carrier_paths=carrier_paths,
        )
        asar = ensure_asar_tool()
        extracted = root / "asar"
        run([str(asar), "extract", str(mirror_root / "resources" / "app.asar"), str(extracted)])
        bootstrap_report = patch_bootstrap(
            extracted,
            PROJECT_ROOT,
            patch_user_data=patch_user_data,
            disable_updater=disable_updater,
            inject_ui_test_bridge=False,
        )
        renderer_syntax_validation = validate_patched_javascript_syntax(
            [bootstrap_report.bootstrap, bootstrap_report.main],
            root=extracted,
        )
        unpacked_source = mirror_root / "resources" / "app.asar.unpacked"
        unpack_directories = derive_unpack_directories(unpacked_source)
        unpack_files = derive_unpack_files(unpacked_source)
        repacked_asar = root / "app.asar"
        listing = pack_asar(asar, extracted, repacked_asar, unpack_directories, unpack_files)
        verify_asar_listing(
            listing,
            unpacked_source,
            unpack_directories,
            unpack_files,
            require_ui_test_bridge=False,
        )
        shutil.copy2(repacked_asar, mirror_root / "resources" / "app.asar")
        generated_unpacked = root / "app.asar.unpacked"
        if generated_unpacked.is_dir():
            copy_unpacked_tree(generated_unpacked, mirror_root / "resources" / "app.asar.unpacked")
        integrity_result = apply_windows_asar_integrity(
            staged_source,
            mirror_root / "resources" / "app.asar",
            integrity_plan,
        )
        launch = run_launch_probes(
            mirror_root,
            root,
            real,
            candidates,
            timeout_seconds=timeout_seconds,
        )
        launch_status = launch.get("status")
        if launch_status == DIRECT_LAUNCH_PASS:
            status = MINIMAL_BOOTSTRAP_PASS
            reason = "minimum bootstrap mirror reached a healthy bounded startup result"
        elif launch_status == DIRECT_LAUNCH_IDENTITY_BLOCKED:
            status = MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED
            reason = "minimum bootstrap mirror remained blocked by package identity/activation evidence"
        else:
            status = "MINIMAL_BOOTSTRAP_FAIL"
            reason = "minimum bootstrap mirror did not reach a healthy bounded startup result"
        return {
            "status": status,
            "reason": reason,
            "renderer_patch_applied": False,
            "ui_test_bridge_injected": False,
            "minimum_modifications": {
                "patch_user_data": patch_user_data,
                "disable_updater": disable_updater,
                "environment_switch_used_first": True,
            },
            "bootstrap": {
                "bootstrap_bundle": bootstrap_report.bootstrap.name,
                "main_bundle": bootstrap_report.main.name,
                "profile_anchor": bootstrap_report.profile_anchor,
                "user_data_patched": bootstrap_report.user_data_patched,
                "updater_disabled": bootstrap_report.updater_disabled,
                "strategy": bootstrap_report.strategy,
            },
            "renderer_syntax_validation": renderer_syntax_validation,
            "integrity": integrity_result,
            "fuse_carriers": fuse_scan,
            "mirror": mirror_report.to_dict(),
            "launch": launch,
            "manual_operation_required": bool(launch.get("manual_operation_required")),
        }


def _run_smoke_launch_matrix(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is None:
        _write_json(args.diagnostics_json, diagnostics.to_dict())
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        return 1
    try:
        real, candidates = discover_real_codex(args.real_codex)
        desktop_candidates = inventory_desktop_executables(source)
        direct = run_smoke_launch_matrix(source, real, desktop_candidates)
        result: dict[str, object] = {
            "status": direct.get("status"),
            "reason": direct.get("reason"),
            "direct_launch": direct,
            "desktop_executables": [candidate.to_dict() for candidate in desktop_candidates],
        }
        if direct.get("status") == DIRECT_LAUNCH_IDENTITY_BLOCKED:
            minimal = _minimal_bootstrap_smoke(
                source,
                real,
                desktop_candidates,
                direct,
            )
            result["minimal_bootstrap"] = minimal
            if minimal.get("status") in {MINIMAL_BOOTSTRAP_PASS, MINIMAL_BOOTSTRAP_IDENTITY_BLOCKED}:
                result["status"] = minimal.get("status")
        smoke = result
    except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        smoke = {
            "status": "DIRECT_LAUNCH_IDENTITY_BLOCKED" if "identity" in str(error).casefold() else "DIRECT_LAUNCH_FAIL",
            "reason": str(error),
            "manual_operation_required": False,
        }
        candidates = []
    payload = diagnostics.to_dict()
    payload["phase2a3_launch"] = smoke
    if candidates:
        payload["real_codex_candidates"] = [str(candidate.path) for candidate in candidates]
    _write_json(args.diagnostics_json, payload)
    print(f"Phase 2A.3 launch matrix: {smoke.get('status')}")
    print(f"Reason: {smoke.get('reason')}")
    if smoke.get("manual_operation_required"):
        print(
            "Manual operation required: inspect the reported attributed process set before rerunning. "
            "The probe did not close any official WindowsApps process."
        )
    print(json.dumps(smoke, indent=2))
    return 0 if smoke.get("status") in {DIRECT_LAUNCH_PASS, MINIMAL_BOOTSTRAP_PASS} else 1


def _run_sandbox_acl_smoke(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is None:
        _write_json(args.diagnostics_json, diagnostics.to_dict())
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        return 1
    candidates: list[RealCodexCandidate] = []
    selected_real: RealCodexCandidate | None = None
    try:
        selected_real, candidates = discover_real_codex(args.real_codex)
        desktop_candidates = inventory_desktop_executables(source)
        smoke = run_phase2a4_sandbox_validation(source, selected_real, desktop_candidates)
    except PermissionError as error:
        smoke = {
            "status": PHASE2A4_FAIL,
            "reason": f"permission denied while preparing the Router-owned smoke root: {error}",
            "manual_operation_required": True,
        }
        candidates = []
    except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        smoke = {
            "status": PHASE2A4_FAIL,
            "reason": str(error),
            "manual_operation_required": True if isinstance(error, PermissionError) else False,
        }
        candidates = []

    def run_disposable_patched_shell(
        diagnostic_arguments: tuple[str, ...] = (),
        *,
        development_only: bool = False,
    ) -> dict[str, object]:
        patched_cleanup: dict[str, object] = {}
        try:
            with final_layout_smoke_root(patched_cleanup) as smoke_root:
                if patched_cleanup.get("path_virtualized") is True:
                    patched = {
                        "status": PATCHED_SHELL_BLOCKED,
                        "reason": "the disposable patched-shell root was filesystem-virtualized by the host",
                        "installation_root": str(smoke_root),
                        "manual_operation_required": True,
                    }
                else:
                    patched_destination = smoke_root / "patched-install"
                    metadata = build_windows_desktop(
                        source,
                        selected_real,
                        patched_destination,
                        force=False,
                        allow_untested_source=args.allow_untested_source,
                        launch_executable=args.launch_executable,
                        bootstrap_user_data_patch=args.bootstrap_user_data_patch,
                        bootstrap_disable_updater=args.bootstrap_disable_updater,
                        payload_acl_strategy=getattr(args, "payload_acl_strategy", None),
                    )
                    patched = run_patched_shell_smoke(
                        patched_destination,
                        selected_real,
                        disposable_root=True,
                        diagnostic_arguments=diagnostic_arguments,
                        development_only=development_only,
                    )
                    patched["build_metadata_summary"] = {
                        "destination": str(patched_destination),
                        "desktop_launch_executable": metadata.get("desktop_launch_executable"),
                        "payload_acl_strategy": metadata.get("payload_acl_strategy"),
                        "renderer_syntax_validation": metadata.get("renderer_syntax_validation"),
                    }
            # Cleanup-dependent result fields are attached only after the
            # final-layout context has completed its __exit__/finally block.
            patched["smoke_root_cleanup"] = dict(patched_cleanup)
            if patched_cleanup.get("removed") is not True:
                patched["status"] = PATCHED_SHELL_BLOCKED
                patched["reason"] = (
                    "the disposable patched-shell root was not cleaned up successfully"
                )
                patched["manual_operation_required"] = True
            return patched
        except PermissionError as error:
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": f"permission denied during disposable patched-shell validation: {error}",
                "smoke_root_cleanup": patched_cleanup,
                "manual_operation_required": True,
            }
        except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            return {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": str(error),
                "smoke_root_cleanup": patched_cleanup,
                "manual_operation_required": True,
            }

    # A full patched-shell check is meaningful only after a normal-sandbox
    # ChatGPT probe passes in a real, non-virtualized final-layout root. Build
    # into a disposable sibling that is removed with the smoke root; never
    # replace the user's configured destination from this diagnostic mode.
    probe_c = smoke.get("probe_c_acl_normal_sandbox")
    probe_b = smoke.get("probe_b_disable_gpu_sandbox")
    if smoke.get("native_evidence_usable") is True and isinstance(probe_c, dict) and probe_c.get("status") == "PASS":
        if not candidates:
            smoke["patched_shell"] = {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "the validated real Codex candidate is unavailable for the patched-shell probe",
                "manual_operation_required": True,
            }
            smoke["status"] = PHASE2A4_PATCHED_SHELL_BLOCKED
            smoke["manual_operation_required"] = True
        else:
            smoke["patched_shell"] = run_disposable_patched_shell()
            patched_shell = smoke.get("patched_shell")
            patched_cleanup = patched_shell.get("smoke_root_cleanup") if isinstance(patched_shell, dict) else None
            if (
                not isinstance(patched_shell, dict)
                or patched_shell.get("status") != PATCHED_SHELL_PASS
                or not isinstance(patched_cleanup, dict)
                or patched_cleanup.get("removed") is not True
            ):
                smoke["status"] = PHASE2A4_PATCHED_SHELL_BLOCKED
                smoke["manual_operation_required"] = True
            else:
                smoke["status"] = PHASE2A4_FULL_PASS
                smoke["reason"] = "normal-sandbox probes and the disposable patched Router shell passed"
                smoke["manual_operation_required"] = False
    elif (
        smoke.get("native_evidence_usable") is True
        and isinstance(probe_b, dict)
        and probe_b.get("status") == "PASS"
        and isinstance(probe_c, dict)
        and probe_c.get("status") != "PASS"
    ):
        # This is the sole development-only escape hatch. It answers whether
        # the rest of the patched shell is functional when Chromium's GPU
        # sandbox switch is the remaining blocker; it can never become a
        # production-pass verdict or alter generated launch metadata.
        if not candidates:
            development_probe = {
                "status": PATCHED_SHELL_BLOCKED,
                "reason": "the validated real Codex candidate is unavailable for the development-only probe",
                "manual_operation_required": True,
            }
        else:
            development_probe = run_disposable_patched_shell(
                ("--disable-gpu-sandbox",),
                development_only=True,
            )
        smoke["development_only_patched_shell"] = development_probe
        development_cleanup = development_probe.get("smoke_root_cleanup")
        if (
            development_probe.get("status") == DEVELOPMENT_ONLY_SANDBOX_BYPASS
            and isinstance(development_cleanup, dict)
            and development_cleanup.get("removed") is True
        ):
            smoke["status"] = PHASE2A4_WINDOWS_GPU_SANDBOX_REGRESSION
            smoke["reason"] = (
                "the one disposable development-only sandbox bypass smoke passed; "
                "the normal-sandbox production path remains blocked"
            )
        else:
            smoke["status"] = PHASE2A4_PATCHED_SHELL_BLOCKED
            smoke["reason"] = "the development-only sandbox bypass smoke was blocked"
        smoke["manual_operation_required"] = True
    payload = diagnostics.to_dict()
    payload["phase2a4_sandbox"] = smoke
    if candidates:
        payload["real_codex_candidates"] = [str(candidate.path) for candidate in candidates]
    _write_json(args.diagnostics_json, payload)
    print(f"Phase 2A.4 sandbox/ACL validation: {smoke.get('status')}")
    print(f"Reason: {smoke.get('reason')}")
    if smoke.get("manual_operation_required"):
        print(
            "Manual operation required: native evidence or the Router-owned disposable "
            "root could not be validated; no official WindowsApps path was modified."
        )
    for label in ("probe_a_normal", "probe_b_disable_gpu_sandbox", "probe_c_acl_normal_sandbox"):
        probe = smoke.get(label)
        if isinstance(probe, dict):
            print(f"{label}: {probe.get('status')}")
    patched_shell = smoke.get("patched_shell")
    if isinstance(patched_shell, dict):
        print(f"patched_shell: {patched_shell.get('status')}")
    development_patched_shell = smoke.get("development_only_patched_shell")
    if isinstance(development_patched_shell, dict):
        print(f"development_only_patched_shell: {development_patched_shell.get('status')}")
    print(json.dumps(smoke, indent=2))
    return 0 if smoke.get("status") in {
        PHASE2A4_FULL_PASS,
        PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
        PHASE2A4_APP_CONTAINER_ACCESS_FIX_CONFIRMED,
    } else 1


def _run_unmodified_mirror_smoke(args: argparse.Namespace) -> int:
    return _run_smoke_launch_matrix(args)


def _run_mirror_dry_run(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is None:
        _write_json(args.diagnostics_json, diagnostics.to_dict())
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="codex-router-phase2a-mirror-") as temporary:
        destination = Path(temporary) / "app"
        try:
            mirror = mirror_desktop_source(source, destination)
            verify_desktop_mirror(source.app_dir, destination)
        except (PackagingBlockedError, OSError, RuntimeError) as error:
            print(f"Phase 2A mirror dry run failed: {error}", file=sys.stderr)
            return 1
        payload = diagnostics.to_dict()
        payload["mirror"] = mirror.to_dict()
        payload["mirror"]["destination"] = str(destination)
        _write_json(args.diagnostics_json, payload)
        print(f"Mirror strategy: {mirror.strategy}")
        print(f"Mirror copied files: {len(mirror.copied)}")
        print(f"Optional protected files skipped: {len(mirror.excluded)}")
        print(f"Required-file failures: {len(mirror.required_failures)}")
        print(f"Temporary mirror verified: {destination}")
    return 0


def _asar_unpack_pattern(unpack_directories: tuple[str, ...]) -> str | None:
    if not unpack_directories:
        return None
    if len(unpack_directories) == 1:
        return unpack_directories[0]
    return "{" + ",".join(unpack_directories) + "}"


def pack_asar(
    asar: Path,
    extracted: Path,
    destination: Path,
    unpack_directories: tuple[str, ...],
    unpack_files: tuple[str, ...] = (),
) -> str:
    command = [str(asar), "pack"]
    file_pattern = _asar_unpack_pattern(unpack_files)
    if file_pattern is not None:
        command.extend(("--unpack", file_pattern))
    pattern = _asar_unpack_pattern(unpack_directories)
    if pattern is not None:
        command.extend(("--unpack-dir", pattern))
    command.extend((str(extracted), str(destination)))
    run(command)
    return output([str(asar), "list", "--is-pack", str(destination)])


def verify_asar_listing(
    listing: str,
    unpacked_source: Path,
    unpack_directories: tuple[str, ...],
    unpack_files: tuple[str, ...] = (),
    *,
    require_ui_test_bridge: bool = True,
) -> None:
    normalized_listing = listing.replace("\\", "/")
    if require_ui_test_bridge and "ui-test-bridge.cjs" not in normalized_listing:
        raise RuntimeError("repacked ASAR is missing the injected UI test bridge")
    native_files = [
        path.relative_to(unpacked_source).as_posix()
        for path in unpacked_source.rglob("*")
        if path.is_file() and path.suffix.casefold() in {".node", ".dll", ".exe"}
    ] if unpacked_source.is_dir() else []
    for relative in native_files:
        if any(part.casefold() in {"codex", "codex.exe", "cua_node", "cua_node.exe"} for part in Path(relative).parts):
            continue
        if f"unpack : /{relative}" not in normalized_listing:
            raise RuntimeError(f"native ASAR module was not kept unpacked: {relative}")
    for directory in unpack_directories:
        if f"unpack : /{directory}" not in normalized_listing:
            raise RuntimeError(f"derived ASAR unpack root was not preserved: {directory}")
    for file in unpack_files:
        if f"unpack : /{file}" not in normalized_listing:
            raise RuntimeError(f"root ASAR unpacked file was not preserved: {file}")


def _patched_javascript_assets(
    extracted: Path,
    bootstrap_report: BootstrapPatchReport,
) -> list[Path]:
    """Enumerate every JavaScript asset touched by the Router patch."""

    assets = extracted / "webview" / "assets"
    paths = [bootstrap_report.bootstrap, bootstrap_report.main]
    if bootstrap_report.ui_test_bridge is not None:
        paths.append(bootstrap_report.ui_test_bridge)
    for pattern in (
        "app-initial-*.js",
        "profile-*.js",
        "plugins-page-*.js",
        "plugins-settings-*.js",
        "local-conversation-thread-*.js",
    ):
        paths.extend(sorted(assets.glob(pattern)))
    return paths


def _metadata(
    source: DesktopSource,
    real: RealCodexCandidate,
    destination: Path,
    launch_executable: str,
    bootstrap_report: BootstrapPatchReport,
    audit: list[object],
    integrity_result: dict[str, object],
    fuse_scan: dict[str, object],
    mirror_report: object,
    payload_acl: dict[str, object],
    renderer_syntax_validation: Mapping[str, object],
) -> dict[str, object]:
    return {
        "platform": "windows",
        "architecture": source.package.architecture,
        "package_name": source.package.name,
        "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "package_publisher": source.package.publisher,
        "package_architecture": source.package.architecture,
        "source_kind": source.source_kind,
        "source_root": str(source.source_root),
        "source_app_executable": str(source.executable),
        "source_app_file_version": source.file_version,
        "desktop_launch_executable": launch_executable,
        "launch_metadata": "launch.json",
        "launch_selection_basis": (
            f"exact {source.package.name} {source.package.version} AppxManifest executable"
            if source.package.name.casefold() == "openai.codex"
            else "compatibility-specific AppxManifest executable or validated legacy shell"
        ),
        "profile_isolation_strategy": "CODEX_ELECTRON_USER_DATA_PATH plus --user-data-dir",
        "updater_strategy": (
            "bootstrap-removal plus CODEX_SPARKLE_ENABLED=false"
            if bootstrap_report.updater_disabled
            else "CODEX_SPARKLE_ENABLED=false"
        ),
        "source_app_asar_sha256": sha256_file(source.app_asar),
        "source_app_asar_header_sha256": asar_header_digest(source.app_asar).hash,
        "bootstrap_patch": {
            "bootstrap_bundle": bootstrap_report.bootstrap.name,
            "main_bundle": bootstrap_report.main.name,
            "profile_anchor": bootstrap_report.profile_anchor,
            "user_data_patched": bootstrap_report.user_data_patched,
            "updater_disabled": bootstrap_report.updater_disabled,
            "strategy": bootstrap_report.strategy,
            "ui_test_bridge": (
                bootstrap_report.ui_test_bridge.name
                if bootstrap_report.ui_test_bridge is not None
                else None
            ),
        },
        "real_codex_source": str(real.path),
        "real_codex_version": real.version,
        "real_codex_sha256": real.sha256,
        "real_codex_authenticode": {
            "status": real.authenticode.status,
            "signer": real.authenticode.signer,
        },
        "staged_layout": {
            "root": str(destination),
            "launcher": str(destination / "Codex Subscription Router.exe"),
            "desktop": str(destination / "app"),
            "mux": str(destination / "runtime" / "codex-mux.exe"),
            "real_codex": str(destination / "runtime" / "codex.real.exe"),
            "user_data": str(destination / "User Data"),
        },
        "renderer_anchor_audit": [
            {
                "name": item.name,
                "asset": item.asset,
                "status": item.status,
                "matched": item.matched,
                "count": item.count,
            }
            for item in audit
        ],
        "windows_asar_integrity": integrity_result,
        "payload_acl": payload_acl,
        "payload_acl_strategy": payload_acl.get("strategy", PAYLOAD_ACL_UNRESOLVED),
        "payload_acl_scope": "Router-owned app tree only; runtime, User Data, and control token excluded",
        "renderer_syntax_validation": dict(renderer_syntax_validation),
        "fuse_carriers": fuse_scan,
        "actual_fuse_carrier_relative_paths": fuse_scan.get("carrier_relative_paths", []),
        "mirror": {
            "strategy": mirror_report.strategy,
            "copied_count": len(mirror_report.copied),
            "planned_file_count": mirror_report.planned_file_count,
            "planned_mirror_bytes": mirror_report.planned_mirror_bytes,
            "excluded": mirror_report.excluded,
            "excluded_bytes": mirror_report.excluded_bytes,
            "copy_failures": mirror_report.copy_failures,
            "required_failures": mirror_report.required_failures,
        },
        "computer_use": "out of scope; no Windows Computer Use patch was applied",
    }


def _same_router_destination_directory(
    destination_parent: Path,
    router_root: Path,
    resolved_destination_parent: Path,
    resolved_router_root: Path,
) -> bool:
    """Return whether the rollback directory and Router root are the same path."""

    for left, right in (
        (destination_parent, router_root),
        (resolved_destination_parent, resolved_router_root),
    ):
        try:
            if os.path.normcase(os.path.abspath(os.fspath(left))) == os.path.normcase(
                os.path.abspath(os.fspath(right))
            ):
                return True
        except (OSError, ValueError):
            continue
    try:
        return os.path.samefile(destination_parent, router_root)
    except (OSError, ValueError):
        return False


def _atomic_install(
    staged: Path,
    destination: Path,
    force: bool,
    *,
    policy: InstallPolicy = InstallPolicy.RECOVERABLE_BACKUP,
    router_root: Path | None = None,
) -> Path | None:
    """Atomically install a build with an explicit rollback/retention policy."""

    try:
        policy = InstallPolicy(policy)
    except ValueError as error:
        raise RuntimeError(f"unknown Windows Desktop install policy: {policy}") from error
    if policy == InstallPolicy.EPHEMERAL_ROLLBACK:
        if router_root is None:
            raise RuntimeError("ephemeral rollback requires an explicit Router-owned root")
        # The destination must be an immediate child of the supplied Router-owned
        # root. Compare the lexical paths first, then resolved paths and samefile;
        # Windows runners can expose the same temporary directory through path
        # aliases that make direct Path equality unreliable.
        destination_parent = destination.parent.expanduser()
        router_root = router_root.expanduser()
        resolved_destination_parent = destination_parent.resolve(strict=False)
        resolved_router_root = router_root.resolve(strict=False)
        if (
            is_windowsapps_path(resolved_destination_parent)
            or is_windowsapps_path(resolved_router_root)
            or not _same_router_destination_directory(
                destination_parent,
                router_root,
                resolved_destination_parent,
                resolved_router_root,
            )
        ):
            raise RuntimeError("ephemeral rollback must remain in the Router-owned destination directory")
    if destination.exists() and not force:
        raise RuntimeError(f"destination exists: {destination} (pass --force to replace it)")
    backup: Path | None = None
    rollback: Path | None = None
    if destination.exists():
        if policy == InstallPolicy.RECOVERABLE_BACKUP:
            backup_root = Path(os.environ.get("USERPROFILE", Path.home())) / ".codex-mux" / "backups"
            backup_root.mkdir(parents=True, exist_ok=True)
            backup = backup_root / f"windows-desktop-{time.strftime('%Y%m%d-%H%M%S')}"
            suffix = 1
            while backup.exists():
                backup = backup_root / f"windows-desktop-{time.strftime('%Y%m%d-%H%M%S')}-{suffix}"
                suffix += 1
            backup.parent.mkdir(parents=True, exist_ok=True)
            destination.rename(backup)
        else:
            for _attempt in range(10):
                candidate = destination_parent / (
                    f".codex-router-windows-{destination.name}-rollback-"
                    f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{uuid.uuid4().hex}"
                )
                if not candidate.exists():
                    rollback = candidate
                    break
            if rollback is None:
                raise RuntimeError("could not allocate a unique ephemeral rollback path")
            destination.rename(rollback)
    try:
        staged.rename(destination)
    except OSError as install_error:
        if rollback is not None and not destination.exists() and rollback.exists():
            try:
                rollback.rename(destination)
            except OSError as restore_error:
                raise RuntimeError(
                    "validation shell replacement failed and the previous shell could not be restored"
                ) from restore_error
        elif backup is not None and not destination.exists() and backup.exists():
            try:
                backup.rename(destination)
            except OSError as restore_error:
                raise RuntimeError(
                    "Desktop replacement failed and the previous build could not be restored"
                ) from restore_error
        raise install_error
    if rollback is not None:
        try:
            shutil.rmtree(rollback)
        except OSError as error:
            raise RuntimeError(
                "validation shell installed but its ephemeral rollback could not be removed"
            ) from error
    return backup


def _resolve_launch_executable(
    source: DesktopSource,
    requested: str | None,
) -> tuple[str, DesktopExecutableCandidate]:
    inventory = inventory_desktop_executables(source)
    if not requested or not requested.strip():
        selected = select_authoritative_desktop_candidate(source, inventory)
        return selected.relative_path.replace("/", "\\"), selected
    normalized = requested.replace("/", "\\").strip("\\").casefold()
    if normalized in {"chatgpt.exe", "codex.exe"}:
        normalized = f"app\\{normalized}"
    if normalized not in {"app\\chatgpt.exe", "app\\codex.exe"}:
        raise RuntimeError(
            "--launch-executable must identify a root-level app\\ChatGPT.exe or app\\Codex.exe"
        )
    for candidate in inventory:
        if candidate.relative_path.replace("/", "\\").casefold() == normalized:
            if not candidate.present:
                raise RuntimeError(f"selected Desktop shell is not present: {candidate.relative_path}")
            return candidate.relative_path.replace("/", "\\"), candidate
    raise RuntimeError(f"selected Desktop shell was not found in source inventory: {requested}")


_STAGED_LAUNCH_EXECUTABLES = {
    r"app\chatgpt.exe": "ChatGPT.exe",
    r"app\codex.exe": "Codex.exe",
}


def resolve_staged_launch_path(staged_root: Path, launch_executable: str) -> Path:
    """Resolve installation-root-relative launch metadata inside a staged tree."""

    if not isinstance(launch_executable, str) or not launch_executable:
        raise RuntimeError(
            "desktop launch executable must be exactly app\\ChatGPT.exe or app\\Codex.exe"
        )
    normalized = launch_executable.replace("/", "\\")
    windows_path = PureWindowsPath(normalized)
    if (
        windows_path.anchor
        or windows_path.drive
        or any(part in {".", ".."} for part in windows_path.parts)
    ):
        raise RuntimeError(
            "desktop launch executable must be a relative app\\ChatGPT.exe or app\\Codex.exe path"
        )
    executable_name = _STAGED_LAUNCH_EXECUTABLES.get(normalized.casefold())
    if executable_name is None:
        raise RuntimeError(
            "desktop launch executable must be exactly app\\ChatGPT.exe or app\\Codex.exe"
        )
    return staged_root / "app" / executable_name


def validate_staged_layout(required_layout: Mapping[str, Path]) -> dict[str, object]:
    """Validate a staged install and identify every missing required file."""

    missing = [
        (name, path)
        for name, path in required_layout.items()
        if not path.is_file()
    ]
    if missing:
        details = "; ".join(f"missing {name}={path}" for name, path in missing)
        raise RuntimeError(f"staged Windows Desktop layout is incomplete; {details}")
    return {
        "status": "PASS",
        "required_files": {name: str(path) for name, path in required_layout.items()},
    }


def _payload_acl_for_strategy(
    staged_app: Path,
    *,
    router_root: Path,
    strategy: str,
) -> dict[str, object]:
    """Apply only an explicitly requested diagnostic ACL strategy."""

    normalized = strategy.strip().upper()
    if normalized not in PAYLOAD_ACL_STRATEGIES:
        raise RuntimeError(
            f"unknown payload ACL strategy {strategy!r}; expected one of {', '.join(PAYLOAD_ACL_STRATEGIES)}"
        )
    root, target = validate_router_app_root(staged_app, router_root)
    base: dict[str, object] = {
        "strategy": normalized,
        "router_root": str(root),
        "target": str(target),
        "scope": str(target),
        "applied": False,
        "official_paths_touched": False,
        "runtime_user_data_scope": "excluded",
    }
    if normalized == PAYLOAD_ACL_APPCONTAINER_RX:
        result = prepare_windows_electron_payload_acl(target, router_root=root)
        result["strategy"] = normalized
        result["applied"] = result.get("status") == "PASS"
        return result
    if normalized == PAYLOAD_ACL_NONE:
        base.update(
            {
                "status": "PASS",
                "verified": True,
                "reason": "no payload ACL mutation was requested",
            }
        )
    else:
        base.update(
            {
                "status": PAYLOAD_ACL_UNRESOLVED,
                "verified": False,
                "reason": (
                    "out-of-package native validation has not established a payload ACL requirement; "
                    "no mutation was performed"
                ),
            }
        )
    return base


def build_windows_desktop(
    source: DesktopSource,
    real: RealCodexCandidate,
    destination: Path,
    *,
    force: bool,
    allow_untested_source: bool,
    reviewed_source: Mapping[str, object] | None = None,
    launch_executable: str | None = None,
    bootstrap_user_data_patch: bool | None = None,
    bootstrap_disable_updater: bool | None = None,
    payload_acl_strategy: str | None = None,
    mux_home_override: Path | None = None,
    validation_profile_local_appdata: Path | None = None,
) -> dict[str, object]:
    destination = destination.expanduser().resolve(strict=False)
    if (
        destination == source.source_root
        or destination == source.app_dir
        or destination.is_relative_to(source.source_root)
    ):
        raise RuntimeError("destination must be separate from the official source")
    selected_launch_executable, _selected_candidate = _resolve_launch_executable(source, launch_executable)
    # Phase 2A.3 proved the environment and argument isolation contract and
    # CODEX_SPARKLE_ENABLED=false without a bootstrap mutation. Keep the full
    # shell minimal unless a caller explicitly requests a reviewed legacy patch.
    patch_user_data = False if bootstrap_user_data_patch is None else bootstrap_user_data_patch
    disable_updater = False if bootstrap_disable_updater is None else bootstrap_disable_updater
    selected_payload_acl_strategy = (
        payload_acl_strategy.strip().upper()
        if payload_acl_strategy is not None
        else PAYLOAD_ACL_UNRESOLVED
    )
    if selected_payload_acl_strategy not in PAYLOAD_ACL_STRATEGIES:
        raise RuntimeError(
            "--payload-acl-strategy must be one of "
            + ", ".join(PAYLOAD_ACL_STRATEGIES)
        )
    records = load_compatibility_records(COMPATIBILITY_DOCUMENT)
    source_hash = sha256_file(source.app_asar)
    source_header_hash = asar_header_digest(source.app_asar).hash
    source_identity = {
        "package_name": source.package.name,
       "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "architecture": source.package.architecture,
        "app_file_version": source.file_version,
        "app_asar_sha256": source_hash,
        "app_asar_header_sha256": source_header_hash,
    }
    reviewed_record = (
        reviewed_source
        if reviewed_source is not None
        else find_reviewed_source(source_identity)
    )
    reviewed_ok, reviewed_reason = reviewed_source_is_patchable(source_identity, reviewed_record)
    matching = find_matching_record(
        records,
        package_name=source.package.name,
        package_version=source.package.version,
        app_file_version=source.file_version,
        app_asar_sha256=source_hash,
    )
    if not reviewed_ok and not allow_untested_source:
        compatibility_note = (
            "no legacy compatibility record matched either"
            if matching is None
            else "a legacy compatibility record is insufficient without an exact reviewed-source record"
        )
        raise RuntimeError(
            "unknown Windows ChatGPT source: reviewed-source gate failed: "
            f"{reviewed_reason}; {compatibility_note}; "
            "pass --allow-untested-source only for a deliberate generic test build"
        )
    go_executable = go_executable_or_raise()
    asar = ensure_asar_tool()
    persistent_mux_home = (
        mux_home_override.expanduser().resolve(strict=False)
        if mux_home_override is not None
        else None
    )
    if persistent_mux_home is not None:
        if validation_profile_local_appdata is not None:
            profile_local_appdata_path = validation_profile_local_appdata
        else:
            profile_local_appdata = os.environ.get("LOCALAPPDATA")
            profile_local_appdata_path = (
                Path(profile_local_appdata)
                if profile_local_appdata
                else persistent_mux_home.parent.parent.parent
            )
        try:
            profile_layout = validation_profile_layout(
                profile_local_appdata_path,
                persistent_mux_home.parent,
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError(f"persistent CODEX_MUX_HOME is outside the Router validation profile: {error}") from error
        if persistent_mux_home != profile_layout.mux_home:
            raise RuntimeError("persistent CODEX_MUX_HOME must be the validation profile's mux-home directory")
        if any(path.is_symlink() for path in (profile_layout.root, profile_layout.user_data, profile_layout.codex_home, persistent_mux_home)):
            raise RuntimeError("persistent Router validation state cannot use symlinked paths")
        if persistent_mux_home == destination or persistent_mux_home.is_relative_to(destination):
            raise RuntimeError("persistent CODEX_MUX_HOME must remain outside patched-shell")
        persistent_mux_home.mkdir(parents=True, exist_ok=True)
    token: str
    mirror_plan = plan_mirror_source(source)
    storage_check = storage_preflight(
        mirror_plan,
        destination,
        operation=(
            "validation-patched-shell-build"
            if persistent_mux_home is not None
            else "patched-shell-build"
        ),
        current_destination=destination if destination.exists() else None,
        asar_path=source.app_asar,
        validation_profile_root=(profile_layout.root if persistent_mux_home is not None else None),
        local_appdata=validation_profile_local_appdata,
    )
    require_storage_capacity(storage_check)
    token = load_or_create_token(persistent_mux_home)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: patched-shell destination could not be created",
                evidence=storage_check,
            ) from error
        raise
    with tempfile.TemporaryDirectory(prefix=".codex-router-windows-", dir=destination.parent) as temporary:
        temporary_root = Path(temporary)
        staged = temporary_root / destination.name
        staged_app = staged / "app"
        staged_resources = staged_app / "resources"
        staged_runtime = staged / "runtime"
        extracted = temporary_root / "asar"
        staged.mkdir(parents=True, exist_ok=True)
        try:
            mirror_report = mirror_desktop_source(source, staged_app, plan=mirror_plan)
        except StorageBlockedError as error:
            error.evidence = {**storage_check, **getattr(error, "evidence", {})}
            raise
        verify_desktop_mirror(source.app_dir, staged_app)
        payload_acl = _payload_acl_for_strategy(
            staged_app,
            router_root=staged,
            strategy=selected_payload_acl_strategy,
        )
        if (
            os.name == "nt"
            and selected_payload_acl_strategy == PAYLOAD_ACL_APPCONTAINER_RX
            and payload_acl.get("status") != "PASS"
        ):
            raise RuntimeError(
                "explicit payload ACL strategy APPCONTAINER_RX was not verified: "
                f"{payload_acl.get('reason', 'staged app payload ACL was not verified')}"
            )
        fuse_scan = scan_fuse_carriers(staged_app)
        staged_source_executable = staged_app / source.executable.name
        carrier_paths = _carrier_paths_from_scan(staged_app, fuse_scan)
        integrity_plan = resolve_windows_asar_integrity(
            staged_source_executable,
            carrier_paths=carrier_paths,
        )
        if not integrity_plan.resolved:
            raise RuntimeError(
                "PHASE 2A.3 INTEGRITY BLOCKED: "
                f"{integrity_plan.state}: {integrity_plan.reason}"
            )
        staged_source_hash = sha256_file(staged_source_executable)
        source_executable_hash = sha256_file(source.executable)
        if staged_source_hash != source_executable_hash:
            raise RuntimeError("staged desktop executable changed while mirroring")

        run([str(asar), "extract", str(staged_resources / "app.asar"), str(extracted)])
        audit = audit_renderer_anchors(
            extracted,
            renderer_variant=(
                str(reviewed_record["renderer_variant"])
                if reviewed_ok and isinstance(reviewed_record, Mapping)
                else None
            ),
            package_name=source.package.name,
            package_version=source.package.version,
            app_asar_sha256=source_hash,
        )
        print_anchor_audit(audit)
        failed = [
            item
            for item in audit
            if item.status in {"MISSING", "SEMANTICALLY_CHANGED", "CHANGED", "AMBIGUOUS"}
        ]
        if failed:
            raise RuntimeError("Windows renderer anchor audit failed; no loose replacement was attempted")
        if reviewed_ok:
            renderer_bundles = list((extracted / "webview" / "assets").glob("app-initial-*.js"))
            if len(renderer_bundles) != 1:
                raise RuntimeError("reviewed-source renderer variant could not be resolved uniquely")
            reviewed_contract_id = reviewed_record.get("renderer_variant")
            if not isinstance(reviewed_contract_id, str) or not reviewed_contract_id:
                raise RuntimeError("reviewed-source renderer contract ID is missing")
            selected_renderer_variant = select_renderer_contract(
                renderer_bundles[0].read_text(encoding="utf-8"),
                reviewed_contract_id,
            )
            if reviewed_contract_id != selected_renderer_variant.variant_id:
                raise RuntimeError(
                    "reviewed-source renderer variant does not match the exact extracted renderer: "
                    f"{reviewed_contract_id} != {selected_renderer_variant.variant_id}"
                )
        bootstrap_report = patch_bootstrap(
            extracted,
            PROJECT_ROOT,
            patch_user_data=patch_user_data,
            disable_updater=disable_updater,
            inject_ui_test_bridge=True,
        )
        patch_renderer(
            extracted,
            token,
            renderer_variant=(
                str(reviewed_record["renderer_variant"])
                if reviewed_ok and isinstance(reviewed_record, Mapping)
                else None
            ),
            package_name=source.package.name,
            package_version=source.package.version,
            app_asar_sha256=source_hash,
        )
        renderer_syntax_validation = validate_patched_javascript_syntax(
            _patched_javascript_assets(extracted, bootstrap_report),
            root=extracted,
        )
        unpacked_source = staged_resources / "app.asar.unpacked"
        unpack_directories = derive_unpack_directories(unpacked_source)
        unpack_files = derive_unpack_files(unpacked_source)
        repacked_asar = temporary_root / "app.asar"
        listing = pack_asar(asar, extracted, repacked_asar, unpack_directories, unpack_files)
        verify_asar_listing(listing, unpacked_source, unpack_directories, unpack_files)
        try:
            shutil.copy2(repacked_asar, staged_resources / "app.asar")
        except OSError as error:
            if is_storage_exhaustion(error):
                raise StorageBlockedError(
                    f"{PHASE2A5_STORAGE_BLOCKED}: repacked app.asar could not be staged",
                    evidence=storage_check,
                ) from error
            raise
        integrity_result = apply_windows_asar_integrity(
            staged_source_executable,
            staged_resources / "app.asar",
            integrity_plan,
        )
        generated_unpacked = temporary_root / "app.asar.unpacked"
        if generated_unpacked.is_dir():
            try:
                copy_unpacked_tree(generated_unpacked, staged_resources / "app.asar.unpacked")
            except StorageBlockedError as error:
                error.evidence = {**storage_check, **getattr(error, "evidence", {})}
                raise

        staged_runtime.mkdir(parents=True, exist_ok=True)
        staged_mux_home = None
        if persistent_mux_home is None:
            staged_mux_home = staged_runtime / ".codex-mux"
            staged_mux_home.mkdir(parents=True, exist_ok=True)
            # Disposable builds keep their token beside the runtime. Persistent
            # builds keep the complete mux home outside patched-shell instead.
            staged_control_token = staged_mux_home / "control-token"
            staged_control_token.write_text(token + "\n", encoding="utf-8")
            try:
                staged_control_token.chmod(0o600)
            except OSError:
                pass
        else:
            staged_control_token = persistent_mux_home / "control-token"
        mux = staged_runtime / "codex-mux.exe"
        staged_real = staged_runtime / "codex.real.exe"
        launcher = staged / "Codex Subscription Router.exe"
        build_go_binary("./cmd/codex-mux", mux, go_executable)
        build_go_binary("./cmd/codex-router-launcher", launcher, go_executable)
        copy_byte_identical(real.path, staged_real)

        if persistent_mux_home is None:
            (staged / "User Data").mkdir(parents=True, exist_ok=True)
            (staged / "codex-home").mkdir(parents=True, exist_ok=True)
        launch_config = {
            "schema_version": 1,
            "desktop_launch_executable": selected_launch_executable,
            "selection_basis": "Phase 2A.4 compatibility-specific authoritative shell selection",
            "source_relative_candidates": [
                "app\\ChatGPT.exe",
                "app\\Codex.exe",
            ],
        }
        (staged / "launch.json").write_text(json.dumps(launch_config, indent=2) + "\n", encoding="utf-8")
        metadata = _metadata(
            source,
            real,
            destination,
            selected_launch_executable,
            bootstrap_report,
            audit,
            integrity_result,
            fuse_scan,
            mirror_report,
            payload_acl,
            renderer_syntax_validation,
        )
        metadata["reviewed_source"] = dict(reviewed_record) if reviewed_ok else None
        metadata["reviewed_source_gate"] = {
            "status": "PATCHABLE" if reviewed_ok else "GENERIC_TEST_ESCAPE_HATCH",
            "reason": reviewed_reason,
        }
        metadata["storage_preflight"] = storage_check
        metadata["mirror_plan"] = mirror_plan.to_dict()
        install_policy = (
            InstallPolicy.EPHEMERAL_ROLLBACK
            if persistent_mux_home is not None
            else InstallPolicy.RECOVERABLE_BACKUP
        )
        metadata["install_policy"] = install_policy.value
        metadata["state_boundary"] = {
            "persistent": persistent_mux_home is not None,
            "user_data": (
                str(persistent_mux_home.parent / "User Data")
                if persistent_mux_home is not None
                else str(staged / "User Data")
            ),
            "codex_home": (
                str(persistent_mux_home.parent / "codex-home")
                if persistent_mux_home is not None
                else str(staged / "codex-home")
            ),
            "mux_home": str(persistent_mux_home or staged_mux_home),
            "persistent_state_outside_patched_shell": persistent_mux_home is not None,
        }
        if persistent_mux_home is not None:
            metadata["staged_layout"]["user_data"] = None
        (staged / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        # The launcher owns the environment contract; this static check keeps the
        # generated layout honest without starting the official UI in Round 1.
        selected_staged_desktop = resolve_staged_launch_path(staged, selected_launch_executable)
        required_layout = {
            "launcher": launcher,
            "mux": mux,
            "real_codex": staged_real,
            "selected_desktop": selected_staged_desktop,
            "source_desktop": staged_source_executable,
            "app_asar": staged_resources / "app.asar",
            "launch_metadata": staged / "launch.json",
            "control_token": staged_control_token,
        }
        validate_staged_layout(required_layout)
        backup = _atomic_install(
            staged,
            destination,
            force,
            policy=install_policy,
            router_root=(profile_layout.root if persistent_mux_home is not None else None),
        )
    print(f"Windows Desktop staged at {destination}")
    if backup is not None:
        print(f"Previous local build moved to {backup}")
    return metadata


def main() -> int:
    args = parse_args()
    try:
        selected_modes = sum(
            bool(value)
            for value in (
                args.diagnose_source,
                args.audit_only,
                args.mirror_dry_run,
                args.smoke_unmodified_mirror,
                args.smoke_launch_matrix,
                args.smoke_sandbox_acl,
            )
        )
        if selected_modes > 1:
            raise RuntimeError(
                "choose only one of --diagnose-source, --audit-only, --mirror-dry-run, "
                "or --smoke-unmodified-mirror/--smoke-launch-matrix/--smoke-sandbox-acl"
            )
        if args.diagnose_source:
            return _run_source_diagnostics(args)
        if args.audit_only:
            return _run_source_audit(args)
        if args.mirror_dry_run:
            return _run_mirror_dry_run(args)
        if args.smoke_unmodified_mirror:
            return _run_unmodified_mirror_smoke(args)
        if args.smoke_launch_matrix:
            return _run_smoke_launch_matrix(args)
        if args.smoke_sandbox_acl:
            return _run_sandbox_acl_smoke(args)
        source = locate_desktop_source(args.source)
        real, candidates = discover_real_codex(args.real_codex)
        print(f"Windows source: {source.source_root}")
        print(f"Desktop executable: {source.executable} ({source.file_version})")
        print(f"app.asar SHA-256: {sha256_file(source.app_asar)}")
        print(f"Real Codex: {real.path} ({real.version}, {real.sha256})")
        if len(candidates) > 1:
            print(f"Real Codex candidates considered: {len(candidates)}")
        build_windows_desktop(
            source,
            real,
            args.destination,
            force=args.force,
            allow_untested_source=args.allow_untested_source,
            launch_executable=args.launch_executable,
            bootstrap_user_data_patch=args.bootstrap_user_data_patch,
            bootstrap_disable_updater=args.bootstrap_disable_updater,
            payload_acl_strategy=args.payload_acl_strategy,
        )
    except StorageBlockedError as error:
        print(f"{PHASE2A5_STORAGE_BLOCKED}: {error}", file=sys.stderr)
        return 1
    except (PackagingBlockedError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Windows patch failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
