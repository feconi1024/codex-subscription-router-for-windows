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
from pathlib import Path

try:
    from .patch_common import (
        PROJECT_ROOT,
        audit_renderer_anchors,
        ensure_asar_tool,
        load_or_create_token,
        patch_renderer,
        select_renderer_variant,
    )
    from .windows.bootstrap import BootstrapPatchReport, audit_bootstrap, patch_bootstrap
    from .windows.compatibility import find_matching_record, load_compatibility_records
    from .windows.discovery import (
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
    )
    from .windows.fuses import FuseSnapshot
    from .windows.integrity import (
        apply_windows_asar_integrity,
        asar_header_digest,
        resolve_windows_asar_integrity,
        scan_fuse_carriers,
    )
    from .windows.smoke import run_unmodified_mirror_smoke
    from .windows.mirror import (
        MirrorReport,
        PackagingBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_desktop_source,
        verify_desktop_mirror,
    )
except ImportError:
    from patch_common import (
        PROJECT_ROOT,
        audit_renderer_anchors,
        ensure_asar_tool,
        load_or_create_token,
        patch_renderer,
        select_renderer_variant,
    )
    from windows.bootstrap import BootstrapPatchReport, audit_bootstrap, patch_bootstrap
    from windows.compatibility import find_matching_record, load_compatibility_records
    from windows.discovery import (
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
    )
    from windows.fuses import FuseSnapshot
    from windows.integrity import (
        apply_windows_asar_integrity,
        asar_header_digest,
        resolve_windows_asar_integrity,
        scan_fuse_carriers,
    )
    from windows.smoke import run_unmodified_mirror_smoke
    from windows.mirror import (
        MirrorReport,
        PackagingBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_desktop_source,
        verify_desktop_mirror,
    )


PROJECT_VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
DEFAULT_DESTINATION = Path(
    os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
) / "Codex Subscription Router"
COMPATIBILITY_DOCUMENT = PROJECT_ROOT / "docs" / "WINDOWS-COMPATIBILITY.md"


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
    return any(item.status in {"MISSING", "SEMANTICALLY_CHANGED", "AMBIGUOUS"} for item in audit)


def audit_windows_source(source: DesktopSource) -> dict[str, object]:
    """Audit the real source without changing its executable or ASAR."""
    asar = ensure_asar_tool()
    versions = read_file_versions(source.executable)
    source_hash = sha256_file(source.app_asar)
    source_header = asar_header_digest(source.app_asar)
    signature = read_authenticode(source.executable)
    integrity_plan = resolve_windows_asar_integrity(source.executable)
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
        extracted = temporary_root / "asar"
        run([str(asar), "extract", str(source.app_asar), str(extracted)])
        initial_bundles = list((extracted / "webview" / "assets").glob("app-initial-*.js"))
        try:
            if len(initial_bundles) != 1:
                raise RuntimeError(f"expected one initial renderer bundle, found {len(initial_bundles)}")
            renderer_variant_id = select_renderer_variant(
                initial_bundles[0].read_text(encoding="utf-8"),
                package_name=source.package.name,
                package_version=source.package.version,
                app_asar_sha256=source_hash,
            ).variant_id
        except RuntimeError:
            renderer_variant_id = "UNRESOLVED"
        renderer_audit = audit_renderer_anchors(
            extracted,
            package_name=source.package.name,
            package_version=source.package.version,
            app_asar_sha256=source_hash,
        )
        bootstrap_audit = audit_bootstrap(extracted, PROJECT_ROOT)
    fuse_summary = _fuse_summary(integrity_plan.fuse, integrity_plan.fuse_error)
    return {
        "source": {
            "package": package_to_dict(source.package),
            "source_kind": source.source_kind,
            "source_root": str(source.source_root),
            "app_dir": str(source.app_dir),
            "executable": str(source.executable),
            "file_version": versions.get("FileVersion") or source.file_version,
            "product_version": versions.get("ProductVersion") or "unknown",
            "authenticode": {"status": signature.status, "signer": signature.signer},
            "app_asar": str(source.app_asar),
            "app_asar_sha256": source_hash,
            "app_asar_header_sha256": source_header.hash,
        },
        "access": [probe.to_dict() for probe in source_access_probes(source)],
        "appx_block_map": {
            "path": str(block_map_path),
            "file_count": len(block_map_files),
            "error": block_map_error,
        },
        "windows_asar_integrity": integrity_plan.to_dict(),
        "fuse_carriers": fuse_scan,
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
        "electron_fuses": fuse_summary,
        "renderer_audit_pass": not _audit_has_failure(renderer_audit),
        "fuse_audit_pass": True,
        "audit_pass": (
            renderer_variant_id != "UNRESOLVED"
            and not _audit_has_failure(renderer_audit)
            and bool(bootstrap_audit.get("audit_pass"))
            and integrity_plan.resolved
        ),
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
    print(f"ChatGPT.exe FileVersion: {audit['source']['file_version']}")
    print(f"ChatGPT.exe ProductVersion: {audit['source']['product_version']}")
    print(f"Authenticode: {audit['source']['authenticode']}")
    print(f"ASAR header SHA-256: {audit['source']['app_asar_header_sha256']}")
    print(f"Renderer variant: {audit['renderer_variant']}")
    print(f"AppxBlockMap files: {audit['appx_block_map']['file_count']}")
    print(f"Electron fuses: {json.dumps(audit['electron_fuses'], sort_keys=True)}")
    print(f"Windows ASAR integrity: {json.dumps(audit['windows_asar_integrity'], sort_keys=True)}")
    print(
        "Fuse carrier scan: "
        f"{audit['fuse_carriers']['carrier_count']} carrier(s), "
        f"{len(audit['fuse_carriers']['scanned_files'])} file(s) scanned"
    )
    print(f"Bootstrap audit: {json.dumps(audit['bootstrap_audit'], sort_keys=True)}")
    print_anchor_audit([type("AuditItem", (), item) for item in audit["renderer_anchor_audit"]])
    _print_access_matrix(audit["access"])
    return 0 if audit["audit_pass"] else 1


def _run_unmodified_mirror_smoke(args: argparse.Namespace) -> int:
    source, diagnostics = discover_desktop_source(args.source)
    if source is None:
        _write_json(args.diagnostics_json, diagnostics.to_dict())
        print(format_source_diagnostics(diagnostics), file=sys.stderr)
        return 1
    try:
        real, candidates = discover_real_codex(args.real_codex)
        smoke = run_unmodified_mirror_smoke(source, real)
    except (PackagingBlockedError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        smoke = {
            "status": "BLOCKED_PACKAGE_IDENTITY" if "identity" in str(error).casefold() else "FAIL",
            "reason": str(error),
            "manual_operation_required": False,
        }
        candidates = []
    payload = diagnostics.to_dict()
    payload["smoke_unmodified_mirror"] = smoke
    if candidates:
        payload["real_codex_candidates"] = [str(candidate.path) for candidate in candidates]
    _write_json(args.diagnostics_json, payload)
    print(f"Unmodified mirror smoke: {smoke.get('status')}")
    print(f"Reason: {smoke.get('reason')}")
    if smoke.get("manual_operation_required"):
        print(
            "Manual operation required: close the official ChatGPT/Codex Desktop instance, "
            "then rerun --smoke-unmodified-mirror. The test did not close it."
        )
    print(json.dumps(smoke, indent=2))
    return 0 if smoke.get("status") == "PASS" else 1


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
) -> None:
    normalized_listing = listing.replace("\\", "/")
    if "ui-test-bridge.cjs" not in normalized_listing:
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


def _metadata(
    source: DesktopSource,
    real: RealCodexCandidate,
    destination: Path,
    bootstrap_report: BootstrapPatchReport,
    audit: list[object],
    integrity_result: dict[str, object],
    fuse_scan: dict[str, object],
    mirror_report: object,
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
        "source_app_asar_sha256": sha256_file(source.app_asar),
        "source_app_asar_header_sha256": asar_header_digest(source.app_asar).hash,
        "bootstrap_patch": {
            "bootstrap_bundle": bootstrap_report.bootstrap.name,
            "main_bundle": bootstrap_report.main.name,
            "profile_anchor": bootstrap_report.profile_anchor,
            "updater_disabled": bootstrap_report.updater_disabled,
            "ui_test_bridge": bootstrap_report.ui_test_bridge.name,
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
        "fuse_carriers": fuse_scan,
        "mirror": {
            "strategy": mirror_report.strategy,
            "copied_count": len(mirror_report.copied),
            "excluded": mirror_report.excluded,
            "copy_failures": mirror_report.copy_failures,
            "required_failures": mirror_report.required_failures,
        },
        "computer_use": "out of scope; no Windows Computer Use patch was applied",
    }


def _atomic_install(staged: Path, destination: Path, force: bool) -> Path | None:
    if destination.exists() and not force:
        raise RuntimeError(f"destination exists: {destination} (pass --force to replace it)")
    backup: Path | None = None
    if destination.exists():
        backup_root = Path(os.environ.get("USERPROFILE", Path.home())) / ".codex-mux" / "backups"
        backup_root.mkdir(parents=True, exist_ok=True)
        backup = backup_root / f"windows-desktop-{time.strftime('%Y%m%d-%H%M%S')}"
        suffix = 1
        while backup.exists():
            backup = backup_root / f"windows-desktop-{time.strftime('%Y%m%d-%H%M%S')}-{suffix}"
            suffix += 1
        backup.parent.mkdir(parents=True, exist_ok=True)
        destination.rename(backup)
    try:
        staged.rename(destination)
    except OSError:
        if backup is not None and not destination.exists() and backup.exists():
            backup.rename(destination)
        raise
    return backup


def build_windows_desktop(
    source: DesktopSource,
    real: RealCodexCandidate,
    destination: Path,
    *,
    force: bool,
    allow_untested_source: bool,
) -> dict[str, object]:
    destination = destination.expanduser().resolve(strict=False)
    if (
        destination == source.source_root
        or destination == source.app_dir
        or destination.is_relative_to(source.source_root)
    ):
        raise RuntimeError("destination must be separate from the official source")
    records = load_compatibility_records(COMPATIBILITY_DOCUMENT)
    source_hash = sha256_file(source.app_asar)
    integrity_plan = resolve_windows_asar_integrity(source.executable)
    if not integrity_plan.resolved:
        raise RuntimeError(
            "PHASE 2A.2 INTEGRITY BLOCKED: "
            f"{integrity_plan.state}: {integrity_plan.reason}"
        )
    matching = find_matching_record(
        records,
        package_name=source.package.name,
        package_version=source.package.version,
        app_file_version=source.file_version,
        app_asar_sha256=source_hash,
    )
    if matching is None and not allow_untested_source:
        raise RuntimeError(
            "unknown Windows ChatGPT source: package/version/app.asar is not in "
            f"{COMPATIBILITY_DOCUMENT}; pass --allow-untested-source only after reviewing the anchor audit"
        )
    go_executable = go_executable_or_raise()
    asar = ensure_asar_tool()
    token = load_or_create_token()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".codex-router-windows-", dir=destination.parent) as temporary:
        temporary_root = Path(temporary)
        staged = temporary_root / destination.name
        staged_app = staged / "app"
        staged_resources = staged_app / "resources"
        staged_runtime = staged / "runtime"
        extracted = temporary_root / "asar"
        staged.mkdir(parents=True, exist_ok=True)
        mirror_report = mirror_desktop_source(source, staged_app)
        verify_desktop_mirror(source.app_dir, staged_app)
        fuse_scan = scan_fuse_carriers(staged_app)
        staged_source_executable = staged_app / source.executable.name
        staged_source_hash = sha256_file(staged_source_executable)
        source_executable_hash = sha256_file(source.executable)
        if staged_source_hash != source_executable_hash:
            raise RuntimeError("staged desktop executable changed while mirroring")

        run([str(asar), "extract", str(staged_resources / "app.asar"), str(extracted)])
        audit = audit_renderer_anchors(
            extracted,
            package_name=source.package.name,
            package_version=source.package.version,
            app_asar_sha256=source_hash,
        )
        print_anchor_audit(audit)
        failed = [
            item
            for item in audit
            if item.status in {"MISSING", "SEMANTICALLY_CHANGED", "AMBIGUOUS"}
        ]
        if failed:
            raise RuntimeError("Windows renderer anchor audit failed; no loose replacement was attempted")
        bootstrap_report = patch_bootstrap(extracted, PROJECT_ROOT)
        patch_renderer(
            extracted,
            token,
            package_name=source.package.name,
            package_version=source.package.version,
            app_asar_sha256=source_hash,
        )
        unpacked_source = staged_resources / "app.asar.unpacked"
        unpack_directories = derive_unpack_directories(unpacked_source)
        unpack_files = derive_unpack_files(unpacked_source)
        repacked_asar = temporary_root / "app.asar"
        listing = pack_asar(asar, extracted, repacked_asar, unpack_directories, unpack_files)
        verify_asar_listing(listing, unpacked_source, unpack_directories, unpack_files)
        shutil.copy2(repacked_asar, staged_resources / "app.asar")
        integrity_result = apply_windows_asar_integrity(
            staged_source_executable,
            staged_resources / "app.asar",
            integrity_plan,
        )
        generated_unpacked = temporary_root / "app.asar.unpacked"
        if generated_unpacked.is_dir():
            copy_unpacked_tree(generated_unpacked, staged_resources / "app.asar.unpacked")

        staged_runtime.mkdir(parents=True, exist_ok=True)
        mux = staged_runtime / "codex-mux.exe"
        staged_real = staged_runtime / "codex.real.exe"
        launcher = staged / "Codex Subscription Router.exe"
        build_go_binary("./cmd/codex-mux", mux, go_executable)
        build_go_binary("./cmd/codex-router-launcher", launcher, go_executable)
        copy_byte_identical(real.path, staged_real)

        (staged / "User Data").mkdir(parents=True, exist_ok=True)
        metadata = _metadata(
            source,
            real,
            destination,
            bootstrap_report,
            audit,
            integrity_result,
            fuse_scan,
            mirror_report,
        )
        (staged / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        # The launcher owns the environment contract; this static check keeps the
        # generated layout honest without starting the official UI in Round 1.
        if not all(
            path.is_file()
            for path in (launcher, mux, staged_real, staged_source_executable, staged_resources / "app.asar")
        ):
            raise RuntimeError("staged Windows Desktop layout is incomplete")
        backup = _atomic_install(staged, destination, force)
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
            )
        )
        if selected_modes > 1:
            raise RuntimeError(
                "choose only one of --diagnose-source, --audit-only, --mirror-dry-run, "
                "or --smoke-unmodified-mirror"
            )
        if args.diagnose_source:
            return _run_source_diagnostics(args)
        if args.audit_only:
            return _run_source_audit(args)
        if args.mirror_dry_run:
            return _run_mirror_dry_run(args)
        if args.smoke_unmodified_mirror:
            return _run_unmodified_mirror_smoke(args)
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
        )
    except (PackagingBlockedError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Windows patch failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
