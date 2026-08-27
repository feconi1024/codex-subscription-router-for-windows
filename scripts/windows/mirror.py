"""Controlled, non-privileged mirroring of the Windows desktop shell."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


PROTECTED_COMPONENTS = {
    "codex",
    "codex.exe",
    "cua_node",
    "cua_node.exe",
    "computer-use",
    "computer_use",
    "codex computer use",
    "codex computer use.exe",
}


class PackagingBlockedError(RuntimeError):
    """A required source file could not be copied without bypassing protection."""


@dataclass
class MirrorReport:
    copied: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)


def _relative_parts(relative: Path) -> tuple[str, ...]:
    return tuple(part.casefold() for part in relative.parts)


def should_exclude(relative: Path) -> bool:
    """Exclude only bundled Codex/Computer Use runtime components."""
    parts = _relative_parts(relative)
    if not parts:
        return False
    # A legacy desktop package may itself be launched as app\\Codex.exe. Keep
    # that shell executable; only bundled resources are excluded.
    if len(parts) == 1 and parts[0] in {"codex.exe", "chatgpt.exe"}:
        return False
    if any(part in PROTECTED_COMPONENTS for part in parts):
        return True
    if parts[0] == "resources" and len(parts) > 1 and parts[1] in PROTECTED_COMPONENTS:
        return True
    return False


def mirror_directory(source: Path, destination: Path) -> MirrorReport:
    """Copy a desktop app tree while preserving ordinary assets and failing closed."""
    source = source.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve(strict=False)
    if source == destination:
        raise RuntimeError("desktop mirror source and destination must differ")
    if destination.is_relative_to(source):
        raise RuntimeError("desktop mirror destination cannot be inside the source")
    report = MirrorReport()
    destination.mkdir(parents=True, exist_ok=True)
    def on_walk_error(error: OSError) -> None:
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: source tree could not be read safely: {error}"
        ) from error

    for current, directories, files in os.walk(
        source,
        topdown=True,
        onerror=on_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        relative_root = current_path.relative_to(source)
        kept_directories: list[str] = []
        for name in directories:
            relative = relative_root / name
            if should_exclude(relative):
                report.excluded.append(relative.as_posix())
            elif (current_path / name).is_symlink():
                raise PackagingBlockedError(
                    f"PHASE 2 PACKAGING BLOCKED: required symlink cannot be mirrored safely: {relative}"
                )
            else:
                kept_directories.append(name)
        directories[:] = kept_directories
        target_root = destination / relative_root
        target_root.mkdir(parents=True, exist_ok=True)
        for name in files:
            relative = relative_root / name
            if should_exclude(relative):
                report.excluded.append(relative.as_posix())
                continue
            source_file = current_path / name
            target_file = destination / relative
            if source_file.is_symlink():
                raise PackagingBlockedError(
                    f"PHASE 2 PACKAGING BLOCKED: required symlink cannot be mirrored safely: {relative}"
                )
            try:
                shutil.copy2(source_file, target_file)
            except (OSError, shutil.Error) as error:
                raise PackagingBlockedError(
                    f"PHASE 2 PACKAGING BLOCKED: required file could not be copied "
                    f"without bypassing package protection: {relative}: {error}"
                ) from error
            report.copied.append(relative.as_posix())
    return report


def verify_desktop_mirror(source_root: Path, mirrored_root: Path) -> None:
    """Ensure the controlled mirror contains the shell files required for startup."""
    source_root = source_root.expanduser().resolve(strict=True)
    mirrored_root = mirrored_root.expanduser().resolve(strict=True)
    source_executable = next(
        (
            source_root / name
            for name in ("ChatGPT.exe", "Codex.exe")
            if (source_root / name).is_file()
        ),
        None,
    )
    if source_executable is None:
        raise RuntimeError("desktop source has no ChatGPT.exe or legacy Codex.exe")
    target_executable = mirrored_root / source_executable.name
    if not target_executable.is_file():
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: staged desktop executable is missing: {target_executable}"
        )
    if not (mirrored_root / "resources" / "app.asar").is_file():
        raise PackagingBlockedError(
            "PHASE 2 PACKAGING BLOCKED: staged resources\\app.asar is missing"
        )


def derive_unpack_directories(unpacked_root: Path) -> tuple[str, ...]:
    """Derive ASAR unpack roots from the source's actual unpacked tree."""
    if not unpacked_root.is_dir():
        return ()
    roots: set[str] = set()
    try:
        candidates = list(unpacked_root.rglob("*"))
    except OSError as error:
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: ASAR unpacked tree could not be audited: {error}"
        ) from error
    for candidate in candidates:
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(unpacked_root)
        if relative.parts and relative.parent != Path("."):
            # Every file already present in app.asar.unpacked is intentionally
            # kept outside the archive. A top-level root preserves the exact
            # source layout without relying on a hard-coded native-module list.
            roots.add(relative.parts[0])
    return tuple(sorted(roots))


def derive_unpack_files(unpacked_root: Path) -> tuple[str, ...]:
    """Return files at the unpacked-tree root for ASAR's file glob."""
    if not unpacked_root.is_dir():
        return ()
    try:
        candidates = list(unpacked_root.iterdir())
    except OSError as error:
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: ASAR unpacked tree could not be audited: {error}"
        ) from error
    return tuple(
        sorted(
            candidate.name
            for candidate in candidates
            if candidate.is_file()
        )
    )


def copy_unpacked_tree(source: Path, destination: Path) -> None:
    """Copy the generated ASAR unpacked output, if the source actually has one."""
    if not source.is_dir():
        return
    if destination.exists():
        shutil.rmtree(destination)
    try:
        # Apply the same protected-component and symlink policy to files
        # generated from the archive as to files mirrored from the package.
        mirror_directory(source, destination)
    except (OSError, shutil.Error) as error:
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: ASAR native dependency tree could not be staged: {error}"
        ) from error
