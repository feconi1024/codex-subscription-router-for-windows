"""Controlled, non-privileged mirroring of the Windows desktop shell."""

from __future__ import annotations

import errno
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
PHASE2A5_STORAGE_BLOCKED = "PHASE 2A.5 STORAGE BLOCKED"
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
WINDOWS_DISK_FULL_WINERRORS = frozenset({39, 112})
MIN_STORAGE_HEADROOM_BYTES = 64 * 1024 * 1024
MAX_STORAGE_HEADROOM_BYTES = 512 * 1024 * 1024
ASAR_EXTRACTED_SIZE_MULTIPLIER = 2


class PackagingBlockedError(RuntimeError):
    """A required source file could not be copied without bypassing protection."""


class DirectoryEnumerationBlockedError(PackagingBlockedError):
    """The package tree could not be enumerated, so block-map fallback may apply."""


class StorageBlockedError(RuntimeError):
    """The operation was stopped because the destination volume lacks capacity."""

    def __init__(self, message: str, *, evidence: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.evidence = dict(evidence or {})


class MirrorIOError(RuntimeError):
    """A required mirror operation failed for a reason other than access or capacity."""


@dataclass(frozen=True)
class MirrorEntry:
    """One source file that the mirror policy plans to copy."""

    source: Path
    relative: Path
    size_bytes: int
    classification: str


@dataclass
class MirrorPlan:
    """The single classification inventory shared by preflight and mirroring."""

    strategy: str = "walk"
    files: tuple[MirrorEntry, ...] = ()
    excluded: tuple[str, ...] = ()
    excluded_bytes: int = 0
    planning_warning: str | None = None

    @property
    def required_bytes(self) -> int:
        return sum(entry.size_bytes for entry in self.files)

    @property
    def unpacked_bytes(self) -> int:
        return sum(
            entry.size_bytes
            for entry in self.files
            if len(entry.relative.parts) >= 3
            and tuple(part.casefold() for part in entry.relative.parts[:2])
            == ("resources", "app.asar.unpacked")
        )

    @property
    def app_asar_bytes(self) -> int:
        return sum(
            entry.size_bytes
            for entry in self.files
            if tuple(part.casefold() for part in entry.relative.parts)
            == ("resources", "app.asar")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy": self.strategy,
            "planned_file_count": len(self.files),
            "planned_mirror_bytes": self.required_bytes,
            "excluded_file_count": len(self.excluded),
            "excluded_bytes": self.excluded_bytes,
            "planning_warning": self.planning_warning,
        }


@dataclass
class MirrorReport:
    strategy: str = "walk"
    copied: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    copy_failures: list[str] = field(default_factory=list)
    required_failures: list[str] = field(default_factory=list)
    planned_file_count: int = 0
    planned_mirror_bytes: int = 0
    excluded_bytes: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy": self.strategy,
            "copied": list(self.copied),
            "excluded": list(self.excluded),
            "copy_failures": list(self.copy_failures),
            "required_failures": list(self.required_failures),
            "planned_file_count": self.planned_file_count,
            "planned_mirror_bytes": self.planned_mirror_bytes,
            "excluded_bytes": self.excluded_bytes,
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


def is_storage_exhaustion(error: BaseException) -> bool:
    """Recognize Python and Win32 disk-full errors without parsing package paths."""

    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, OSError):
            if current.errno == errno.ENOSPC:
                return True
            winerror = getattr(current, "winerror", None)
            if isinstance(winerror, int) and winerror in WINDOWS_DISK_FULL_WINERRORS:
                return True
        current = current.__cause__ or current.__context__
    return False


def _is_access_denied(error: BaseException) -> bool:
    if isinstance(error, PermissionError):
        return True
    if isinstance(error, OSError):
        if error.errno in {errno.EACCES, errno.EPERM}:
            return True
        winerror = getattr(error, "winerror", None)
        if isinstance(winerror, int) and winerror in {5, 32}:
            return True
    message = str(error).casefold()
    return "access denied" in message or "permission denied" in message


def _required_copy_error(
    relative: Path,
    error: BaseException,
    report: MirrorReport,
) -> None:
    """Raise a stable error class while retaining the original exception as cause."""

    relative_text = relative.as_posix()
    if is_storage_exhaustion(error):
        failure = f"storage exhausted while copying required file: {relative_text}"
        report.required_failures.append(failure)
        raise StorageBlockedError(
            f"{PHASE2A5_STORAGE_BLOCKED}: {failure}",
            evidence={"operation": "mirror_copy", "failed_relative": relative_text},
        ) from error
    if _is_access_denied(error):
        failure = f"required file copy access denied: {relative_text}"
        report.required_failures.append(failure)
        raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: {failure}") from error
    failure = f"required file copy I/O failure ({type(error).__name__}): {relative_text}"
    report.required_failures.append(failure)
    raise MirrorIOError(f"PHASE 2 PACKAGING I/O BLOCKED: {failure}") from error


def _source_file_size(source_file: Path, relative: Path) -> int:
    try:
        return max(0, int(source_file.stat().st_size))
    except OSError as error:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: could not inspect required file {relative.as_posix()}"
            ) from error
        if _is_access_denied(error):
            raise PackagingBlockedError(
                f"PHASE 2 PACKAGING BLOCKED: could not inspect required file {relative.as_posix()}"
            ) from error
        raise MirrorIOError(
            f"PHASE 2 SOURCE READ BLOCKED: could not inspect required file {relative.as_posix()}"
        ) from error


def _record_optional_skip(report: MirrorReport, relative: Path, error: OSError | None = None) -> None:
    value = relative.as_posix()
    report.excluded.append(value)
    if error is not None:
        report.copy_failures.append(f"{value}: optional runtime copy skipped ({type(error).__name__})")


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
        _required_copy_error(relative, error, report)
    report.copied.append(relative.as_posix())


def plan_mirror_directory(source: Path) -> MirrorPlan:
    """Plan the exact files the walking mirror will copy, without writing output."""

    source = source.expanduser().resolve(strict=True)
    entries: list[MirrorEntry] = []
    excluded: list[str] = []
    excluded_bytes = 0

    def on_walk_error(error: OSError) -> None:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: source mirror planning could not enumerate the source"
            ) from error
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
            if is_storage_exhaustion(error):
                raise StorageBlockedError(
                    f"{PHASE2A5_STORAGE_BLOCKED}: source mirror planning could not enumerate the source"
                ) from error
            raise DirectoryEnumerationBlockedError(
                f"PHASE 2 PACKAGING BLOCKED: source tree could not be enumerated safely: {error}"
            ) from error
        current_path = Path(current)
        relative_root = current_path.relative_to(source)
        kept_directories: list[str] = []
        for name in directories:
            relative = relative_root / name
            if should_exclude(relative):
                excluded.append(relative.as_posix())
            elif (current_path / name).is_symlink():
                error = f"required symlink cannot be mirrored safely: {relative}"
                raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: {error}")
            else:
                kept_directories.append(name)
        directories[:] = kept_directories
        for name in files:
            relative = relative_root / name
            source_file = current_path / name
            classification = classify_source_path(relative)
            if classification == OPTIONAL_PHASE2_RUNTIME:
                excluded.append(relative.as_posix())
                if not source_file.is_symlink():
                    try:
                        excluded_bytes += _source_file_size(source_file, relative)
                    except (PackagingBlockedError, MirrorIOError, StorageBlockedError):
                        # Optional content is not part of the required capacity
                        # estimate; a failure to inspect it must not weaken the
                        # required-file safety gate.
                        pass
                continue
            if source_file.is_symlink():
                error = f"required symlink cannot be mirrored safely: {relative}"
                raise PackagingBlockedError(f"PHASE 2 PACKAGING BLOCKED: {error}")
            entries.append(
                MirrorEntry(
                    source=source_file,
                    relative=relative,
                    size_bytes=_source_file_size(source_file, relative),
                    classification=classification,
                )
            )
    return MirrorPlan(
        strategy="walk",
        files=tuple(entries),
        excluded=tuple(excluded),
        excluded_bytes=excluded_bytes,
    )


def plan_mirror_from_block_map(
    package_root: Path,
    app_dir: Path,
    block_map: Path | None = None,
) -> MirrorPlan:
    """Plan a direct block-map mirror when package enumeration is denied."""

    package_root = package_root.expanduser().resolve(strict=True)
    app_dir = app_dir.expanduser().resolve(strict=False)
    block_map = block_map or (package_root / "AppxBlockMap.xml")
    entries = parse_appx_block_map(block_map)
    planned: list[MirrorEntry] = []
    excluded: list[str] = []
    excluded_bytes = 0
    selected = 0
    for package_relative in entries:
        relative = _package_relative_to_app(package_root, app_dir, package_relative)
        if relative is None or not relative.parts:
            continue
        selected += 1
        source_file = package_root.joinpath(*package_relative.parts)
        if not source_file.resolve(strict=False).is_relative_to(package_root):
            raise PackagingBlockedError(
                f"PHASE 2 PACKAGING BLOCKED: block-map path escaped package root: {package_relative}"
            )
        classification = classify_source_path(relative)
        if classification == OPTIONAL_PHASE2_RUNTIME:
            excluded.append(relative.as_posix())
            if not source_file.is_symlink():
                try:
                    excluded_bytes += _source_file_size(source_file, relative)
                except (PackagingBlockedError, MirrorIOError, StorageBlockedError):
                    pass
            continue
        if source_file.is_symlink():
            raise PackagingBlockedError(
                f"PHASE 2 PACKAGING BLOCKED: required symlink cannot be mirrored safely: {relative}"
            )
        planned.append(
            MirrorEntry(
                source=source_file,
                relative=relative,
                size_bytes=_source_file_size(source_file, relative),
                classification=classification,
            )
        )
    if selected == 0:
        raise PackagingBlockedError("PHASE 2 PACKAGING BLOCKED: AppxBlockMap.xml contains no app files")
    return MirrorPlan(
        strategy="appx-block-map",
        files=tuple(planned),
        excluded=tuple(excluded),
        excluded_bytes=excluded_bytes,
    )


def plan_mirror_source(source: object) -> MirrorPlan:
    """Plan a source using the same walk/block-map fallback as the real mirror."""

    try:
        return plan_mirror_directory(source.app_dir)
    except DirectoryEnumerationBlockedError as enumeration_error:
        try:
            plan = plan_mirror_from_block_map(
                source.source_root,
                source.app_dir,
                source.source_root / "AppxBlockMap.xml",
            )
        except StorageBlockedError:
            raise
        except (OSError, RuntimeError, MirrorIOError) as block_map_error:
            raise PackagingBlockedError(
                "PHASE 2A SOURCE READ BLOCKED: directory enumeration failed and "
                f"AppxBlockMap direct mirror was unavailable: {block_map_error}"
            ) from enumeration_error
        plan.planning_warning = f"normal walk unavailable: {type(enumeration_error).__name__}"
        return plan


def _execute_mirror_plan(plan: MirrorPlan, destination: Path) -> MirrorReport:
    destination = destination.expanduser().resolve(strict=False)
    report = MirrorReport(
        strategy=plan.strategy,
        excluded=list(plan.excluded),
        planned_file_count=len(plan.files),
        planned_mirror_bytes=plan.required_bytes,
        excluded_bytes=plan.excluded_bytes,
    )
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: mirror destination could not be created"
            ) from error
        if _is_access_denied(error):
            raise PackagingBlockedError(
                "PHASE 2 PACKAGING BLOCKED: mirror destination is not writable"
            ) from error
        raise MirrorIOError("PHASE 2 PACKAGING I/O BLOCKED: mirror destination could not be created") from error
    for entry in plan.files:
        _copy_one(entry.source, destination / entry.relative, entry.relative, report)
    if plan.planning_warning:
        report.copy_failures.append(plan.planning_warning)
    return report


def mirror_directory(source: Path, destination: Path) -> MirrorReport:
    """Copy a desktop app tree while preserving ordinary assets and failing closed."""

    source = source.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve(strict=False)
    if source == destination:
        raise RuntimeError("desktop mirror source and destination must differ")
    if destination.is_relative_to(source):
        raise RuntimeError("desktop mirror destination cannot be inside the source")
    return _execute_mirror_plan(plan_mirror_directory(source), destination)


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
    return _execute_mirror_plan(
        plan_mirror_from_block_map(package_root, app_dir, block_map),
        destination,
    )


def mirror_desktop_source(
    source: object,
    destination: Path,
    *,
    plan: MirrorPlan | None = None,
) -> MirrorReport:
    """Use normal walking first, then AppxBlockMap direct reads on enumeration denial."""
    if plan is not None:
        return _execute_mirror_plan(plan, destination)
    app_dir = source.app_dir
    try:
        return mirror_directory(app_dir, destination)
    except DirectoryEnumerationBlockedError as enumeration_error:
        block_map = source.source_root / "AppxBlockMap.xml"
        try:
            report = mirror_from_block_map(source.source_root, app_dir, destination, block_map)
        except StorageBlockedError:
            raise
        except (OSError, RuntimeError) as block_map_error:
            raise PackagingBlockedError(
                "PHASE 2A SOURCE READ BLOCKED: directory enumeration failed and "
                f"AppxBlockMap direct mirror was unavailable: {block_map_error}"
            ) from enumeration_error
        report.copy_failures.append(f"normal walk unavailable: {enumeration_error}")
        return report


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def _tree_size(path: Path) -> tuple[int, bool]:
    """Return a non-following tree size and whether the scan was complete."""

    # Do not resolve the final component here: resolving would follow a
    # junction/symlink before _is_reparse_point() can reject it.  The inventory
    # callers pass absolute Router-owned roots, so abspath is sufficient for a
    # stable scan without changing link semantics.
    path = Path(os.path.abspath(os.fspath(path.expanduser())))
    if not path.exists():
        return 0, True
    if _is_reparse_point(path):
        return 0, False
    if path.is_file():
        try:
            return max(0, int(path.stat().st_size)), True
        except OSError:
            return 0, False

    total = 0
    complete = True

    def on_error(_error: OSError) -> None:
        nonlocal complete
        complete = False

    for current, directories, files in os.walk(path, topdown=True, followlinks=False, onerror=on_error):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            if _is_reparse_point(candidate):
                complete = False
            else:
                kept_directories.append(name)
        directories[:] = kept_directories
        for name in files:
            candidate = current_path / name
            if _is_reparse_point(candidate):
                complete = False
                continue
            try:
                total += max(0, int(candidate.stat().st_size))
            except OSError:
                complete = False
    return total, complete


def _existing_volume_path(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.exists() and candidate.is_file():
        candidate = candidate.parent
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _volume_name(path: Path) -> str:
    anchor = path.anchor
    if anchor:
        return anchor.rstrip("\\/") or anchor
    return str(path)


def _default_userprofile(userprofile: Path | None) -> Path:
    if userprofile is not None:
        return userprofile.expanduser().resolve(strict=False)
    value = os.environ.get("USERPROFILE")
    return (Path(value) if value else Path.home()).expanduser().resolve(strict=False)


def _default_local_appdata(local_appdata: Path | None) -> Path:
    if local_appdata is not None:
        return local_appdata.expanduser().resolve(strict=False)
    value = os.environ.get("LOCALAPPDATA")
    return (
        (Path(value) if value else Path.home() / "AppData" / "Local")
        .expanduser()
        .resolve(strict=False)
    )


def inventory_router_backups(userprofile: Path | None = None) -> dict[str, object]:
    """Inspect only Router-owned windows-desktop backups, never their parents."""

    root = _default_userprofile(userprofile) / ".codex-mux" / "backups"
    result: dict[str, object] = {
        "root": str(root),
        "windows_desktop_backup_count": 0,
        "windows_desktop_backup_bytes": 0,
        "scan_complete": True,
        "reparse_points_skipped": 0,
    }
    if not root.exists():
        return result
    if _is_reparse_point(root):
        result["scan_complete"] = False
        result["reparse_points_skipped"] = 1
        return result
    try:
        entries = tuple(root.iterdir())
    except OSError:
        result["scan_complete"] = False
        return result
    total = 0
    count = 0
    skipped = 0
    complete = True
    for entry in entries:
        if not entry.name.startswith("windows-desktop-") or not entry.is_dir():
            continue
        if _is_reparse_point(entry):
            skipped += 1
            complete = False
            continue
        size, known = _tree_size(entry)
        total += size
        count += 1
        complete = complete and known
    result.update(
        {
            "windows_desktop_backup_count": count,
            "windows_desktop_backup_bytes": total,
            "scan_complete": complete,
            "reparse_points_skipped": skipped,
        }
    )
    return result


def inventory_generated_validation_roots(
    local_appdata: Path | None = None,
    validation_profile_root: Path | None = None,
) -> dict[str, object]:
    """List only positively named Router validation temporary roots."""

    owner = _default_local_appdata(local_appdata) / "Codex Subscription Router"
    specifications: list[tuple[Path, tuple[str, ...]]] = [
        (owner / "_host-validation", ("phase2a5-",)),
        (owner / "_smoke", ("phase2a2-", "phase2a3-", "phase2a4-", "phase2a5-")),
    ]
    if validation_profile_root is not None:
        profile = validation_profile_root.expanduser().resolve(strict=False)
        if profile == owner / "_validation-profile":
            specifications.append((profile, (".codex-router-windows-",)))

    candidates: list[str] = []
    total = 0
    complete = True
    skipped = 0
    for parent, prefixes in specifications:
        if not parent.exists():
            continue
        if _is_reparse_point(parent):
            complete = False
            skipped += 1
            continue
        try:
            entries = tuple(parent.iterdir())
        except OSError:
            complete = False
            continue
        for entry in entries:
            if not entry.name.startswith(prefixes) or not entry.is_dir():
                continue
            if _is_reparse_point(entry):
                complete = False
                skipped += 1
                continue
            size, known = _tree_size(entry)
            total += size
            complete = complete and known
            try:
                candidates.append(entry.relative_to(owner).as_posix())
            except ValueError:
                complete = False
    return {
        "root": str(owner),
        "candidate_count": len(candidates),
        "candidate_bytes": total,
        "candidate_paths": candidates[:100],
        "scan_complete": complete,
        "reparse_points_skipped": skipped,
    }


def _storage_headroom_bytes(base_bytes: int) -> int:
    calculated = max(0, int(base_bytes)) // 10
    return min(MAX_STORAGE_HEADROOM_BYTES, max(MIN_STORAGE_HEADROOM_BYTES, calculated))


def storage_preflight(
    plan: MirrorPlan,
    destination: Path,
    *,
    operation: str,
    current_destination: Path | None = None,
    asar_path: Path | None = None,
    userprofile: Path | None = None,
    local_appdata: Path | None = None,
    validation_profile_root: Path | None = None,
) -> dict[str, object]:
    """Estimate the current operation from the planned mirror and actual volume."""

    destination = destination.expanduser().resolve(strict=False)
    existing_path = (
        current_destination.expanduser().resolve(strict=False)
        if current_destination is not None
        else None
    )
    existing_bytes, existing_known = _tree_size(existing_path) if existing_path is not None else (0, True)
    asar_bytes = 0
    asar_known = True
    if asar_path is not None:
        try:
            asar_bytes = max(0, int(asar_path.expanduser().resolve(strict=True).stat().st_size))
        except OSError:
            asar_known = False

    is_build = operation != "mirror"
    extracted_asar_bytes = asar_bytes * ASAR_EXTRACTED_SIZE_MULTIPLIER if is_build else 0
    temporary_repacked_asar_bytes = asar_bytes if is_build else 0
    generated_unpacked_bytes = plan.unpacked_bytes if is_build else 0
    asar_working_set_bytes = extracted_asar_bytes + generated_unpacked_bytes
    before_headroom = (
        plan.required_bytes
        + existing_bytes
        + asar_working_set_bytes
        + temporary_repacked_asar_bytes
    )
    safety_headroom_bytes = _storage_headroom_bytes(before_headroom)
    estimated_required_bytes = before_headroom + safety_headroom_bytes

    volume_path = _existing_volume_path(destination.parent)
    free_bytes = 0
    capacity_known = True
    try:
        free_bytes = max(0, int(shutil.disk_usage(volume_path).free))
    except OSError:
        capacity_known = False

    backup = inventory_router_backups(userprofile)
    orphans = inventory_generated_validation_roots(local_appdata, validation_profile_root)
    result: dict[str, object] = {
        "operation": operation,
        "volume": _volume_name(volume_path),
        "free_bytes": free_bytes,
        "estimated_required_bytes": estimated_required_bytes,
        "planned_mirror_bytes": plan.required_bytes,
        "planned_mirror_file_count": len(plan.files),
        "existing_validation_shell_bytes": existing_bytes,
        "asar_bytes": asar_bytes,
        "asar_extracted_estimate_bytes": extracted_asar_bytes,
        "asar_working_set_bytes": asar_working_set_bytes,
        "temporary_repacked_asar_bytes": temporary_repacked_asar_bytes,
        "generated_unpacked_bytes": generated_unpacked_bytes,
        "safety_headroom_bytes": safety_headroom_bytes,
        "mirror_plan": plan.to_dict(),
        "router_backup_count": backup["windows_desktop_backup_count"],
        "router_backup_bytes": backup["windows_desktop_backup_bytes"],
        "router_backup_scan_complete": backup["scan_complete"],
        "validation_orphan_count": orphans["candidate_count"],
        "validation_orphan_bytes": orphans["candidate_bytes"],
        "validation_orphan_scan_complete": orphans["scan_complete"],
        "capacity_query_ok": capacity_known,
        "existing_destination_size_known": existing_known,
        "asar_size_known": asar_known,
    }
    result["pass"] = bool(
        capacity_known
        and existing_known
        and asar_known
        and free_bytes >= estimated_required_bytes
    )
    return result


def require_storage_capacity(preflight: dict[str, object]) -> None:
    """Stop before copying when capacity cannot be proven sufficient."""

    if preflight.get("pass") is True:
        return
    operation = str(preflight.get("operation", "operation"))
    free_bytes = int(preflight.get("free_bytes", 0) or 0)
    required_bytes = int(preflight.get("estimated_required_bytes", 0) or 0)
    reason = (
        f"insufficient free space for {operation} "
        f"(free={free_bytes}, required={required_bytes})"
    )
    raise StorageBlockedError(f"{PHASE2A5_STORAGE_BLOCKED}: {reason}", evidence=preflight)


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
    try:
        if destination.exists():
            shutil.rmtree(destination)
    except OSError as error:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: existing ASAR native dependency tree could not be replaced"
            ) from error
        if _is_access_denied(error):
            raise PackagingBlockedError(
                "PHASE 2 PACKAGING BLOCKED: existing ASAR native dependency tree could not be replaced"
            ) from error
        raise MirrorIOError(
            "PHASE 2 PACKAGING I/O BLOCKED: existing ASAR native dependency tree could not be replaced"
        ) from error
    try:
        mirror_directory(source, destination)
    except (OSError, shutil.Error) as error:
        if is_storage_exhaustion(error):
            raise StorageBlockedError(
                f"{PHASE2A5_STORAGE_BLOCKED}: ASAR native dependency tree could not be staged"
            ) from error
        raise PackagingBlockedError(
            f"PHASE 2 PACKAGING BLOCKED: ASAR native dependency tree could not be staged: {error}"
        ) from error
