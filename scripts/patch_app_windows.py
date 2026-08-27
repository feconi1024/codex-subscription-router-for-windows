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
    )
    from .windows.bootstrap import BootstrapPatchReport, patch_bootstrap
    from .windows.compatibility import find_matching_record, load_compatibility_records
    from .windows.discovery import (
        DesktopSource,
        RealCodexCandidate,
        copy_byte_identical,
        discover_real_codex,
        locate_desktop_source,
        sha256_file,
    )
    from .windows.fuses import disable_asar_integrity_validation
    from .windows.mirror import (
        PackagingBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_directory,
        verify_desktop_mirror,
    )
except ImportError:
    from patch_common import (
        PROJECT_ROOT,
        audit_renderer_anchors,
        ensure_asar_tool,
        load_or_create_token,
        patch_renderer,
    )
    from windows.bootstrap import BootstrapPatchReport, patch_bootstrap
    from windows.compatibility import find_matching_record, load_compatibility_records
    from windows.discovery import (
        DesktopSource,
        RealCodexCandidate,
        copy_byte_identical,
        discover_real_codex,
        locate_desktop_source,
        sha256_file,
    )
    from windows.fuses import disable_asar_integrity_validation
    from windows.mirror import (
        PackagingBlockedError,
        copy_unpacked_tree,
        derive_unpack_directories,
        derive_unpack_files,
        mirror_directory,
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


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required tool not found: {name}")


def build_go_binary(package: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "go",
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
    fuse_before: object,
    fuse_after: object,
    mirror_report: object,
) -> dict[str, object]:
    return {
        "platform": "windows",
        "architecture": source.package.architecture,
        "package_name": source.package.name,
        "package_full_name": source.package.package_full_name,
        "package_version": source.package.version,
        "source_kind": source.source_kind,
        "source_root": str(source.source_root),
        "source_app_executable": str(source.executable),
        "source_app_file_version": source.file_version,
        "source_app_asar_sha256": sha256_file(source.app_asar),
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
        "electron_fuses_before": {
            "schema_version": fuse_before.schema_version,
            "count": fuse_before.count,
            "fuses": list(fuse_before.fuses),
        },
        "electron_fuses_after": {
            "schema_version": fuse_after.schema_version,
            "count": fuse_after.count,
            "fuses": list(fuse_after.fuses),
        },
        "mirror": {
            "copied_count": len(mirror_report.copied),
            "excluded": mirror_report.excluded,
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
    for tool in ("go",):
        require_tool(tool)
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
        mirror_report = mirror_directory(source.app_dir, staged_app)
        verify_desktop_mirror(source.app_dir, staged_app)
        staged_source_hash = sha256_file(staged / source.executable.name)
        source_executable_hash = sha256_file(source.executable)
        if staged_source_hash != source_executable_hash:
            raise RuntimeError("staged desktop executable changed while mirroring")

        run([str(asar), "extract", str(staged_resources / "app.asar"), str(extracted)])
        audit = audit_renderer_anchors(extracted)
        print_anchor_audit(audit)
        failed = [item for item in audit if item.status in {"NO LONGER PRESENT", "AMBIGUOUS"}]
        if failed:
            raise RuntimeError("Windows renderer anchor audit failed; no loose replacement was attempted")
        bootstrap_report = patch_bootstrap(extracted, PROJECT_ROOT)
        patch_renderer(extracted, token)
        unpacked_source = staged_resources / "app.asar.unpacked"
        unpack_directories = derive_unpack_directories(unpacked_source)
        unpack_files = derive_unpack_files(unpacked_source)
        repacked_asar = temporary_root / "app.asar"
        listing = pack_asar(asar, extracted, repacked_asar, unpack_directories, unpack_files)
        verify_asar_listing(listing, unpacked_source, unpack_directories, unpack_files)
        shutil.copy2(repacked_asar, staged_resources / "app.asar")
        generated_unpacked = temporary_root / "app.asar.unpacked"
        if generated_unpacked.is_dir():
            copy_unpacked_tree(generated_unpacked, staged_resources / "app.asar.unpacked")

        staged_runtime.mkdir(parents=True, exist_ok=True)
        mux = staged_runtime / "codex-mux.exe"
        staged_real = staged_runtime / "codex.real.exe"
        launcher = staged / "Codex Subscription Router.exe"
        build_go_binary("./cmd/codex-mux", mux)
        build_go_binary("./cmd/codex-router-launcher", launcher)
        copy_byte_identical(real.path, staged_real)

        fuse_backup = temporary_root / f"{source.executable.name}.before-fuse-change"
        fuse_before, fuse_after = disable_asar_integrity_validation(
            staged_app / source.executable.name,
            fuse_backup,
        )
        try:
            fuse_backup.unlink()
        except FileNotFoundError:
            pass
        (staged / "User Data").mkdir(parents=True, exist_ok=True)
        metadata = _metadata(
            source,
            real,
            destination,
            bootstrap_report,
            audit,
            fuse_before,
            fuse_after,
            mirror_report,
        )
        (staged / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        # The launcher owns the environment contract; this static check keeps the
        # generated layout honest without starting the official UI in Round 1.
        if not all(
            path.is_file()
            for path in (launcher, mux, staged_real, staged_app / source.executable.name, staged_resources / "app.asar")
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
