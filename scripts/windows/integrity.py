"""Windows Electron ASAR-integrity planning and staged PE-resource updates."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    except RuntimeError as error:
        message = str(error)
        if "fuse sentinel not found" in message:
            return None, None, False
        return None, message, True


def resolve_windows_asar_integrity(executable: Path) -> WindowsAsarIntegrityPlan:
    fuse, fuse_error, fuse_wire_present = _read_fuse_state(executable)
    resource_entries: tuple[dict[str, object], ...] = ()
    resource_error: str | None = None
    resource_present = False
    try:
        resource_result = read_pe_integrity_resources(executable)
        resource_entries = tuple(_matching_resource_entries(resource_result))
        resource_present = bool(resource_entries)
        if resource_present:
            _resource_asar_digest(resource_result)
    except (OSError, RuntimeError) as error:
        resource_error = _safe_error(error)

    if fuse_error or resource_error:
        return WindowsAsarIntegrityPlan(
            UNRESOLVED,
            False,
            "fuse or PE resource metadata could not be parsed",
            fuse,
            fuse_error,
            resource_present,
            resource_entries,
            resource_error,
        )
    if fuse_wire_present and resource_present:
        return WindowsAsarIntegrityPlan(
            FUSE_PRESENT_RESOURCE_PRESENT,
            True,
            "Electron fuse metadata and PE ASAR-integrity resource are both present",
            fuse,
            None,
            True,
            resource_entries,
            None,
        )
    if fuse_wire_present and not resource_present:
        return WindowsAsarIntegrityPlan(
            FUSE_PRESENT_RESOURCE_MISSING,
            False,
            "Electron ASAR-integrity fuse is present but INTEGRITY/ELECTRONASAR metadata is missing",
            fuse,
            None,
            False,
            resource_entries,
            None,
        )
    if resource_present:
        return WindowsAsarIntegrityPlan(
            RESOURCE_PRESENT_UPDATE_REQUIRED,
            True,
            "PE ASAR-integrity resource is present and must be updated after repacking",
            None,
            None,
            True,
            resource_entries,
            None,
        )
    return WindowsAsarIntegrityPlan(
        RESOURCE_ABSENT_NO_VALIDATION_METADATA,
        True,
        "No Electron fuse wire or PE ASAR-integrity resource was found; launch validation is required",
        None,
        None,
        False,
        (),
        None,
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
    _ensure_staged_target(executable)
    if not plan.resolved:
        raise RuntimeError(f"Windows ASAR integrity plan is not buildable: {plan.state}: {plan.reason}")
    digest = asar_header_digest(asar)
    before = read_pe_integrity_resources(executable)
    updated = False
    if plan.resource_present:
        payload = json.dumps(
            [{"file": EXPECTED_ASAR_RESOURCE, "alg": "sha256", "value": digest.hash}],
            separators=(",", ":"),
        )
        _run_node_json(PE_RESOURCES_SCRIPT, ["update", str(executable)], stdin=payload)
        updated = True
    after = read_pe_integrity_resources(executable)
    if updated:
        actual = _resource_asar_digest(after)
        if actual != digest.hash:
            raise RuntimeError(
                "staged PE INTEGRITY/ELECTRONASAR resource did not read back the new ASAR header digest"
            )
    return {
        "plan": plan.to_dict(),
        "asar_header": digest.to_dict(),
        "resource_before": before,
        "resource_after": after,
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
                    }
                except (OSError, RuntimeError) as error:
                    carrier["fuse_error"] = _safe_error(error)
                carriers.append(carrier)
        except OSError as error:
            record["error"] = _safe_error(error)
        files.append(record)
    return {"scanned_files": files, "carriers": carriers, "carrier_count": len(carriers)}
