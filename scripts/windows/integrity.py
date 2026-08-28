"""Windows Electron ASAR-integrity planning and staged PE-resource updates."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from .fuses import SENTINEL, FuseSnapshot, read_fuses
except ImportError:
    from fuses import SENTINEL, FuseSnapshot, read_fuses


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ASAR_INTEGRITY_SCRIPT = Path(__file__).with_name("asar_integrity.mjs")
PE_RESOURCES_SCRIPT = Path(__file__).with_name("pe_resources.mjs")
INTEGRITY_TYPE = "INTEGRITY"
INTEGRITY_ID = "ELECTRONASAR"
EXPECTED_ASAR_RESOURCE = "resources\\app.asar"

RESOURCE_PRESENT_UPDATE_REQUIRED = "RESOURCE_PRESENT_UPDATE_REQUIRED"
RESOURCE_ABSENT_NO_VALIDATION_METADATA = "RESOURCE_ABSENT_NO_VALIDATION_METADATA"
FUSE_PRESENT_RESOURCE_PRESENT = "FUSE_PRESENT_RESOURCE_PRESENT"
FUSE_PRESENT_RESOURCE_MISSING = "FUSE_PRESENT_RESOURCE_MISSING"
FUSE_PRESENT_ASAR_VALIDATION_DISABLED = "FUSE_PRESENT_ASAR_VALIDATION_DISABLED"
UNRESOLVED = "UNRESOLVED"

_OPTIONAL_RUNTIME_NAMES = {
    "codex",
    "codex.exe",
    "cua_node",
    "cua_node.exe",
    "computer-use",
    "computer_use",
    "codex computer use",
    "codex computer use.exe",
}


@dataclass(frozen=True)
class AsarHeaderDigest:
    algorithm: str
    hash: str
    header_size: int
    header_string_length: int

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "hash": self.hash,
            "header_size": self.header_size,
            "header_string_length": self.header_string_length,
        }


@dataclass(frozen=True)
class WindowsAsarIntegrityPlan:
    state: str
    resolved: bool
    reason: str
    fuse: FuseSnapshot | None
    fuse_error: str | None
    resource_present: bool
    resource_entries: tuple[dict[str, object], ...]
    resource_error: str | None
    carrier_paths: tuple[Path, ...] = ()
    carrier_records: tuple[dict[str, object], ...] = ()
    carrier_paths_known: bool = False

    def to_dict(self) -> dict[str, object]:
        fuse: dict[str, object] | None
        if self.fuse is None:
            fuse = None
        else:
            fuse = {
                "schema_version": self.fuse.schema_version,
                "count": self.fuse.count,
                "fuses": list(self.fuse.fuses),
                "offset": self.fuse.offset,
            }
        return {
            "state": self.state,
            "resolved": self.resolved,
            "reason": self.reason,
            "fuse": fuse,
            "fuse_error": self.fuse_error,
            "resource_present": self.resource_present,
            "resource_entries": list(self.resource_entries),
            "resource_error": self.resource_error,
            "carrier_paths_known": self.carrier_paths_known,
            "carrier_paths": [str(path) for path in self.carrier_paths],
            "carrier_relative_paths": [path.name for path in self.carrier_paths],
            "carrier_records": list(self.carrier_records),
        }


def _safe_error(error: BaseException | str) -> str:
    text = str(error) if not isinstance(error, str) else error
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())[:500]


def _node_executable() -> str:
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        raise RuntimeError("Node.js is required for pinned ASAR/PE integrity operations")
    return node


def _run_node_json(
    script: Path,
    arguments: list[str],
    *,
    stdin: str | None = None,
) -> dict[str, object]:
    try:
        result = subprocess.run(
            [_node_executable(), str(script), *arguments],
            input=stdin,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"Node integrity helper failed to start: {_safe_error(error)}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"Node integrity helper failed: {_safe_error(detail)}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Node integrity helper returned invalid JSON: {_safe_error(error)}") from error
    if not isinstance(parsed, dict):
        raise RuntimeError("Node integrity helper returned a non-object result")
    return parsed


def asar_header_digest(asar: Path) -> AsarHeaderDigest:
    result = _run_node_json(ASAR_INTEGRITY_SCRIPT, [str(asar)])
    try:
        return AsarHeaderDigest(
            algorithm=str(result["algorithm"]),
            hash=str(result["hash"]),
            header_size=int(result["header_size"]),
            header_string_length=int(result["header_string_length"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"ASAR integrity helper returned incomplete metadata: {_safe_error(error)}") from error


def read_pe_integrity_resources(executable: Path) -> dict[str, object]:
    return _run_node_json(PE_RESOURCES_SCRIPT, ["read", str(executable)])


def _matching_resource_entries(resources: dict[str, object]) -> list[dict[str, object]]:
    values = resources.get("resources")
    if not isinstance(values, list):
        raise RuntimeError("PE integrity helper returned an invalid resource list")
    return [entry for entry in values if isinstance(entry, dict)]


def _resource_asar_digest(resources: dict[str, object]) -> str | None:
    matches = _matching_resource_entries(resources)
    found: list[str] = []
    for entry in matches:
        parsed = entry.get("parsed")
        if not isinstance(parsed, list):
            raise RuntimeError("INTEGRITY/ELECTRONASAR resource is not valid JSON")
        for item in parsed:
            if not isinstance(item, dict):
                raise RuntimeError("INTEGRITY/ELECTRONASAR JSON contains a non-object entry")
            file_name = str(item.get("file", "")).replace("/", "\\").casefold()
            algorithm = str(item.get("alg", "")).casefold()
            value = item.get("value")
            if file_name != EXPECTED_ASAR_RESOURCE.casefold() or algorithm != "sha256":
                continue
            if not isinstance(value, str) or len(value) != 64:
                raise RuntimeError("INTEGRITY/ELECTRONASAR app.asar SHA-256 value is malformed")
            try:
                int(value, 16)
            except ValueError as error:
                raise RuntimeError("INTEGRITY/ELECTRONASAR app.asar SHA-256 value is not hexadecimal") from error
            found.append(value.casefold())
    if not found:
        raise RuntimeError("INTEGRITY/ELECTRONASAR has no resources\\app.asar SHA-256 entry")
    if len(set(found)) != 1:
        raise RuntimeError("INTEGRITY/ELECTRONASAR contains conflicting app.asar digests")
    return found[0]


def _read_fuse_state(executable: Path) -> tuple[FuseSnapshot | None, str | None, bool]:
    try:
        return read_fuses(executable), None, True
    except (OSError, RuntimeError) as error:
        message = str(error)
        if "fuse sentinel not found" in message:
            return None, None, False
        return None, message, True


def _carrier_paths_from_argument(
    executable: Path,
    carrier_paths: Iterable[Path] | None,
) -> tuple[tuple[Path, ...], bool]:
    if carrier_paths is None:
        return (executable,), False
    return tuple(Path(path) for path in carrier_paths), True


def _carrier_record(
    path: Path,
    fuse: FuseSnapshot | None,
    fuse_error: str | None,
    fuse_wire_present: bool,
    resource_entries: tuple[dict[str, object], ...],
    resource_error: str | None,
) -> dict[str, object]:
    return {
        "path": str(path),
        "relative": path.name,
        "sentinel_found": fuse_wire_present,
        "fuse": (
            {
                "schema_version": fuse.schema_version,
                "count": fuse.count,
                "fuses": list(fuse.fuses),
                "offset": fuse.offset,
                "asar_integrity_validation": (
                    fuse.fuses[4] if fuse.count > 4 else "NOT PRESENT"
                ),
            }
            if fuse is not None
            else None
        ),
        "fuse_error": fuse_error,
        "integrity_resource_present": bool(resource_entries),
        "integrity_resources": list(resource_entries),
        "integrity_error": resource_error,
    }


def resolve_windows_asar_integrity(
    executable: Path,
    *,
    carrier_paths: Iterable[Path] | None = None,
) -> WindowsAsarIntegrityPlan:
    """Resolve validation against the observed Electron fuse carrier set.

    ``carrier_paths=None`` retains the historical single-file API for callers
    that only have one executable. Passing an explicit iterable, including an
    empty iterable, makes the carrier inventory authoritative and prevents a
    manifest executable from silently becoming the integrity carrier.
    """
    paths, paths_known = _carrier_paths_from_argument(executable, carrier_paths)
    carrier_records: list[dict[str, object]] = []
    fuses: list[FuseSnapshot] = []
    fuse_errors: list[str] = []
    resource_entries: list[dict[str, object]] = []
    resource_errors: list[str] = []
    resource_present = False
    for path in paths:
        fuse, fuse_error, fuse_wire_present = _read_fuse_state(path)
        if fuse is not None:
            fuses.append(fuse)
        if fuse_error:
            fuse_errors.append(f"{path}: {fuse_error}")
        entries: tuple[dict[str, object], ...] = ()
        resource_error: str | None = None
        try:
            resource_result = read_pe_integrity_resources(path)
            entries = tuple(_matching_resource_entries(resource_result))
            if entries:
                _resource_asar_digest(resource_result)
                resource_present = True
                resource_entries.extend(entries)
        except (OSError, RuntimeError) as error:
            resource_error = _safe_error(error)
            resource_errors.append(f"{path}: {resource_error}")
        carrier_records.append(
            _carrier_record(
                path,
                fuse,
                fuse_error,
                fuse_wire_present,
                entries,
                resource_error,
            )
        )

    fuse = fuses[0] if fuses else None
    fuse_wire_present = any(record["sentinel_found"] for record in carrier_records)
    asar_validation_enabled = any(fuse.count > 4 and fuse.fuses[4] == "on" for fuse in fuses)
    fuse_error = "; ".join(fuse_errors) or None
    resource_error = "; ".join(resource_errors) or None
    all_errors = fuse_error or resource_error
    common = {
        "fuse": fuse,
        "fuse_error": fuse_error,
        "resource_present": resource_present,
        "resource_entries": tuple(resource_entries),
        "resource_error": resource_error,
        "carrier_paths": paths,
        "carrier_records": tuple(carrier_records),
        "carrier_paths_known": paths_known,
    }
    if all_errors:
        return WindowsAsarIntegrityPlan(
            UNRESOLVED,
            False,
            "fuse or PE resource metadata could not be parsed",
            **common,
        )
    if asar_validation_enabled and resource_present:
        return WindowsAsarIntegrityPlan(
            FUSE_PRESENT_RESOURCE_PRESENT,
            True,
            "the actual Electron fuse carrier enables ASAR validation and carries PE integrity metadata",
            **common,
        )
    if asar_validation_enabled and not resource_present:
        return WindowsAsarIntegrityPlan(
            FUSE_PRESENT_RESOURCE_MISSING,
            False,
            "the actual Electron fuse carrier enables ASAR validation but its PE integrity metadata is missing",
            **common,
        )
    if fuse_wire_present and not asar_validation_enabled:
        return WindowsAsarIntegrityPlan(
            FUSE_PRESENT_ASAR_VALIDATION_DISABLED,
            True,
            "the actual Electron fuse carrier is present but EnableEmbeddedAsarIntegrityValidation is off",
            **common,
        )
    if resource_present:
        return WindowsAsarIntegrityPlan(
            RESOURCE_PRESENT_UPDATE_REQUIRED,
            True,
            "PE ASAR-integrity resource is present and must be updated after repacking",
            **common,
        )
    return WindowsAsarIntegrityPlan(
        RESOURCE_ABSENT_NO_VALIDATION_METADATA,
        True,
        "no Electron fuse wire or PE ASAR-integrity resource was found; launch validation is required",
        **common,
    )


def _ensure_staged_target(executable: Path) -> None:
    if any(part.casefold() == "windowsapps" for part in executable.resolve(strict=False).parts):
        raise RuntimeError("refusing to modify an executable inside WindowsApps")


def apply_windows_asar_integrity(
    executable: Path,
    asar: Path,
    plan: WindowsAsarIntegrityPlan,
) -> dict[str, object]:
    """Update only a staged PE resource, preserving fuse state and source files."""
    if not plan.resolved:
        raise RuntimeError(f"Windows ASAR integrity plan is not buildable: {plan.state}: {plan.reason}")
    digest = asar_header_digest(asar)
    targets = plan.carrier_paths if plan.carrier_paths_known else (executable,)
    targets = tuple(targets)
    if not targets:
        return {
            "plan": plan.to_dict(),
            "asar_header": digest.to_dict(),
            "carriers": [],
            "resource_updated": False,
            "resource_before": None,
            "resource_after": None,
        }
    updated = False
    carrier_results: list[dict[str, object]] = []
    for target in targets:
        _ensure_staged_target(target)
        before = read_pe_integrity_resources(target)
        carrier_updated = False
        if plan.resource_present:
            payload = json.dumps(
                [{"file": EXPECTED_ASAR_RESOURCE, "alg": "sha256", "value": digest.hash}],
                separators=(",", ":"),
            )
            target_entries = tuple(_matching_resource_entries(before))
            if target_entries:
                _run_node_json(PE_RESOURCES_SCRIPT, ["update", str(target)], stdin=payload)
                carrier_updated = True
                updated = True
        after = read_pe_integrity_resources(target)
        if carrier_updated:
            actual = _resource_asar_digest(after)
            if actual != digest.hash:
                raise RuntimeError(
                    f"staged PE INTEGRITY/ELECTRONASAR resource did not read back the new ASAR header digest: {target}"
                )
        carrier_results.append(
            {
                "path": str(target),
                "resource_before": before,
                "resource_after": after,
                "resource_updated": carrier_updated,
            }
        )
    return {
        "plan": plan.to_dict(),
        "asar_header": digest.to_dict(),
        "carriers": carrier_results,
        "resource_before": carrier_results[0]["resource_before"] if carrier_results else None,
        "resource_after": carrier_results[0]["resource_after"] if carrier_results else None,
        "resource_updated": updated,
    }


def _is_optional_runtime(relative: Path) -> bool:
    parts = tuple(part.casefold() for part in relative.parts)
    return len(parts) >= 2 and parts[0] == "resources" and parts[1] in _OPTIONAL_RUNTIME_NAMES


def scan_fuse_carriers(mirrored_root: Path) -> dict[str, object]:
    """Scan every mirrored executable/DLL, excluding optional bundled runtimes."""
    mirrored_root = mirrored_root.expanduser().resolve(strict=True)
    files: list[dict[str, object]] = []
    carriers: list[dict[str, object]] = []
    try:
        candidates = sorted(
            (path for path in mirrored_root.rglob("*") if path.is_file() and path.suffix.casefold() in {".exe", ".dll"}),
            key=lambda path: path.relative_to(mirrored_root).as_posix().casefold(),
        )
    except OSError as error:
        raise RuntimeError(f"could not enumerate mirrored runtime for fuse scan: {_safe_error(error)}") from error
    for path in candidates:
        relative = path.relative_to(mirrored_root)
        if _is_optional_runtime(relative):
            continue
        record: dict[str, object] = {"path": str(path), "relative": relative.as_posix(), "sentinel_found": False}
        try:
            data = path.read_bytes()
            offsets: list[int] = []
            cursor = 0
            while True:
                offset = data.find(SENTINEL, cursor)
                if offset < 0:
                    break
                offsets.append(offset)
                cursor = offset + 1
            record["sentinel_found"] = bool(offsets)
            record["sentinel_offsets"] = offsets
            if offsets:
                carrier = record.copy()
                try:
                    snapshot = read_fuses(path)
                    carrier["fuse"] = {
                        "schema_version": snapshot.schema_version,
                        "count": snapshot.count,
                        "fuses": list(snapshot.fuses),
                        "offset": snapshot.offset,
                        "asar_integrity_validation": (
                            snapshot.fuses[4] if snapshot.count > 4 else "NOT PRESENT"
                        ),
                    }
                except (OSError, RuntimeError) as error:
                    carrier["fuse_error"] = _safe_error(error)
                try:
                    resources = read_pe_integrity_resources(path)
                    entries = _matching_resource_entries(resources)
                    carrier["integrity_resource_present"] = bool(entries)
                    carrier["integrity_resources"] = entries
                except (OSError, RuntimeError) as error:
                    carrier["integrity_resource_present"] = False
                    carrier["integrity_resources"] = []
                    carrier["integrity_error"] = _safe_error(error)
                carriers.append(carrier)
        except OSError as error:
            record["error"] = _safe_error(error)
        files.append(record)
    return {
        "scanned_files": files,
        "carriers": carriers,
        "carrier_count": len(carriers),
        "carrier_relative_paths": [str(carrier["relative"]) for carrier in carriers],
    }
