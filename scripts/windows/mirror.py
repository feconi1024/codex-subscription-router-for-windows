"""Controlled, non-privileged mirroring of the Windows desktop shell."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

try:
    from .discovery import parse_appx_block_map
except ImportError:
    from discovery import parse_appx_block_map


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
REQUIRED_DESKTOP_SHELL = "REQUIRED_DESKTOP_SHELL"
OPTIONAL_PHASE2_RUNTIME = "OPTIONAL_PHASE2_RUNTIME"
UNKNOWN_REQUIRED = "UNKNOWN_REQUIRED"
DESKTOP_EXECUTABLE_NAMES = {"chatgpt.exe", "codex.exe"}
KNOWN_REQUIRED_ROOT_FILES = {
    "resources.pak",
    "icudtl.dat",
    "snapshot_blob.bin",
    "v8_context_snapshot.bin",
}


class PackagingBlockedError(RuntimeError):
    """A required source file could not be copied without bypassing protection."""


class DirectoryEnumerationBlockedError(PackagingBlockedError):
    """The package tree could not be enumerated, so block-map fallback may apply."""


@dataclass
class MirrorReport:
    strategy: str = "walk"
    copied: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    copy_failures: list[str] = field(default_factory=list)
    required_failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy": self.strategy,
            "copied": list(self.copied),
            "excluded": list(self.excluded),
            "copy_failures": list(self.copy_failures),
            "required_failures": list(self.required_failures),
        }


def _relative_parts(relative: Path) -> tuple[str, ...]:
    return tuple(part.casefold() for part in relative.parts)


def should_exclude(relative: Path) -> bool:
    """Exclude only bundled Codex/Computer Use runtime components."""
    parts = _relative_parts(relative)
    if len(parts) < 2 or parts[0] != "resources":
        # A legacy desktop package may itself be launched as app\\Codex.exe.
        return False
    return parts[1] in PROTECTED_COMPONENTS


def classify_source_path(relative: Path) -> str:
    parts = _relative_parts(relative)
    if should_exclude(relative):
        return OPTIONAL_PHASE2_RUNTIME
    if len(parts) == 1 and parts[0] in DESKTOP_EXECUTABLE_NAMES:
        return REQUIRED_DESKTOP_SHELL
    if len(parts) == 1 and parts[0] in KNOWN_REQUIRED_ROOT_FILES:
        return REQUIRED_DESKTOP_SHELL
    if parts and parts[0] == "locales":
        return REQUIRED_DESKTOP_SHELL
    if len(parts) >= 2 and parts[0] == "resources" and parts[1] == "app.asar":
        return REQUIRED_DESKTOP_SHELL
    return UNKNOWN_REQUIRED


def _record_optional_skip(report: MirrorReport, relative: Path, error: OSError | None = None) -> None:
    value = relative.as_posix()
    report.excluded.append(value)
    if error is not None:
        report.copy_failures.append(f"{value}: {error}")


def _copy_one(
    source_file: Path,
    target_file: Path,
    relative: Path,
    report: MirrorReport,
) -> None:
    classification = classify_source_path(relative)
    if classification == OPTIONAL_PHASE2_RUNTIME:
        _record_optional_skip(report, relative)
        return
    if source_file.is_symlink():
        error = f"required symlink cannot be mirrored safely: {relative}"
        report.required_failures.append(error)
        raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: {error}")
    try:
        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target_file)
    except (OSError, shutil.Error) as error:
        if classification == OPTIONAL_PHASE2_RUNTIME:
            _record_optional_skip(report, relative, error)
            return
        report.required_failures.append(f"{relative}: {error}")
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: required file could not be copied "
            f"without bypassing package protection: {relative}: {error}"
        ) from error
    report.copied.append(relative.as_posix())


def mirror_directory(source: Path, destination: Path) -> MirrorReport:
    """Copy a desktop app tree while preserving ordinary assets and failing closed."""
    source = source.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve(strict=False)
    if source == destination:
        raise RuntimeError("desktop mirror source and destination must differ")
    if destination.is_relative_to(source):
        raise RuntimeError("desktop mirror destination cannot be inside the source")
    report = MirrorReport(strategy="walk")
    destination.mkdir(parents=True, exist_ok=True)

    def on_walk_error(error: OSError) -> None:
        raise DirectoryEnumerationBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: source tree could not be enumerated safely: {error}"
        ) from error

    walker = os.walk(source, topdown=True, onerror=on_walk_error, followlinks=False)
    while True:
        try:
            current, directories, files = next(walker)
        except StopIteration:
            break
        except DirectoryEnumerationBlockedError:
            raise
        except OSError as error:
            raise DirectoryEnumerationBlockedError(
                f"PHASE 2 PACKAGING BLOCKED: source tree could not be enumerated safely: {error}"
            ) from error
        current_path = Path(current)
        relative_root = current_path.relative_to(source)
        kept_directories: list[str] = []
        for name in directories:
            relative = relative_root / name
            if should_exclude(relative):
                report.excluded.append(relative.as_posix())
            elif (current_path / name).is_symlink():
                error = f"required symlink cannot be mirrored safely: {relative}"
                report.required_failures.append(error)
                raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: {error}")
            else:
                kept_directories.append(name)
        directories[:] = kept_directories
        target_root = destination / relative_root
        try:
            target_root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: mirror destination is not writable: {error}") from error
        for name in files:
            relative = relative_root / name
            _copy_one(current_path / name, destination / relative, relative, report)
    return report


def _package_relative_to_app(package_root: Path, app_dir: Path, relative: Path) -> Path | None:
    package_root = package_root.expanduser().resolve(strict=False)
    app_dir = app_dir.expanduser().resolve(strict=False)
    try:
        app_prefix = app_dir.relative_to(package_root)
    except ValueError as error:
        raise PackagingBlockedError("source app directory is outside its package root") from error
    if len(relative.parts) < len(app_prefix.parts):
        return None
    if tuple(part.casefold() for part in relative.parts[: len(app_prefix.parts)]) != tuple(
        part.casefold() for part in app_prefix.parts
    ):
        return None
    return Path(*relative.parts[len(app_prefix.parts) :])


def mirror_from_block_map(
    package_root: Path,
    app_dir: Path,
    destination: Path,
    block_map: Path | None = None,
) -> MirrorReport:
    """Mirror app files by direct known paths listed in AppxBlockMap.xml."""
    package_root = package_root.expanduser().resolve(strict=True)
    app_dir = app_dir.expanduser().resolve(strict=False)
    destination = destination.expanduser().resolve(strict=False)
    block_map = block_map or (package_root / "AppxBlockMap.xml")
    entries = parse_appx_block_map(block_map)
    report = MirrorReport(strategy="appx-block-map")
    destination.mkdir(parents=True, exist_ok=True)
    package_root_resolved = package_root.resolve(strict=False)
    selected = 0
    for package_relative in entries:
        relative = _package_relative_to_app(package_root, app_dir, package_relative)
        if relative is None or not relative.parts:
            continue
        selected += 1
        source_file = package_root.joinpath(*package_relative.parts)
        if not source_file.resolve(strict=False).is_relative_to(package_root_resolved):
            raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: block-map path escaped package root: {package_relative}")
        _copy_one(source_file, destination / relative, relative, report)
    if selected == 0:
        raise PackagingBlockedError("PHASE 2 PACKAGING BLOCKED: AppxBlockMap.xml contains no app files")
    return report


def mirror_desktop_source(source: object, destination: Path) -> MirrorReport:
    """Use normal walking first, then AppxBlockMap direct reads on enumeration denial."""
    app_dir = source.app_dir
    try:
        return mirror_directory(app_dir, destination)
    except DirectoryEnumerationBlockedError as enumeration_error:
        block_map = source.source_root / "AppxBlockMap.xml"
        try:
            report = mirror_from_block_map(source.source_root, app_dir, destination, block_map)
        except (OSError, RuntimeError) as block_map_error:
            raise PackagingBlockedError(
                "PHASE 2A SOURCE READ BLOCKED: directory enumeration failed and "
                f"AppxBlockMap direct mirror was unavailable: {block_map_error}"
            ) from enumeration_error
        report.copy_failures.append(f"normal walk unavailable: {enumeration_error}")
        return report


def _direct_exists(path: Path, kind: str) -> bool:
    try:
        if kind == "file":
            with path.open("rb") as handle:
                handle.read(1)
            return True
        return path.is_dir()
    except OSError:
        return False


def verify_desktop_mirror(source_root: Path, mirrored_root: Path) -> None:
    """Ensure a mirror contains the source's required shell files."""
    source_root = source_root.expanduser().resolve(strict=True)
    mirrored_root = mirrored_root.expanduser().resolve(strict=True)
    source_executable = next(
        (
            source_root / name
            for name in ("ChatGPT.exe", "Codex.exe")
            if _direct_exists(source_root / name, "file")
        ),
        None,
    )
    if source_executable is None:
        raise RuntimeError("desktop source has no directly readable ChatGPT.exe or legacy Codex.exe")
    target_executable = mirrored_root / source_executable.name
    if not target_executable.is_file():
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: staged desktop executable is missing: {target_executable}"
        )
    if not (mirrored_root / "resources" / "app.asar").is_file():
        raise PackagingBlockedError(
            "PHASE 2 PACKAGING BLOCKED: staged resources\\app.asar is missing"
        )
    for name in KNOWN_REQUIRED_ROOT_FILES:
        source_file = source_root / name
        if _direct_exists(source_file, "file") and not (mirrored_root / name).is_file():
            raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: required Electron asset is missing: {name}")
    source_locales = source_root / "locales"
    if _direct_exists(source_locales, "dir") and not (mirrored_root / "locales").is_dir():
        raise PackagingBlockedError("PHASE 2 PACKAGING BLOCKED: required Electron locales directory is missing")


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
    return tuple(sorted(candidate.name for candidate in candidates if candidate.is_file()))


def copy_unpacked_tree(source: Path, destination: Path) -> None:
    """Copy the generated ASAR unpacked output, if the source actually has one."""
    if not source.is_dir():
        return
    if destination.exists():
        shutil.rmtree(destination)
    try:
        mirror_directory(source, destination)
    except (OSError, shutil.Error) as error:
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: ASAR native dependency tree could not be staged: {error}"
        ) from error
