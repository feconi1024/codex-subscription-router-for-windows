"""Minimal Electron fuse reader/writer for staged Windows executables."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSE_INDEX = {
    "RunAsNode": 0,
    "EnableCookieEncryption": 1,
    "EnableNodeOptionsEnvironmentVariable": 2,
    "EnableNodeCliInspectArguments": 3,
    "EnableEmbeddedAsarIntegrityValidation": 4,
    "OnlyLoadAppFromAsar": 5,
    "LoadBrowserProcessSpecificV8Snapshot": 6,
    "GrantFileProtocolExtraPrivileges": 7,
    "ResetAdHocDarwinSignature": 8,
}
FUSE_VALUES = {"off": 0x30, "on": 0x31, "removed": 0x32, "inherit": 0x33}
BYTE_VALUES = {value: key for key, value in FUSE_VALUES.items()}


@dataclass(frozen=True)
class FuseSnapshot:
    schema_version: int
    count: int
    fuses: tuple[str, ...]
    offset: int


def read_fuses(binary: Path) -> FuseSnapshot:
    data = binary.read_bytes()
    sentinel_offset = data.find(SENTINEL)
    if sentinel_offset < 0:
        raise RuntimeError(f"Electron fuse sentinel not found in {binary}")
    header_offset = sentinel_offset + len(SENTINEL)
    if header_offset + 2 > len(data):
        raise RuntimeError(f"truncated Electron fuse header in {binary}")
    schema_version = data[header_offset]
    count = data[header_offset + 1]
    fuse_offset = header_offset + 2
    if schema_version != 1:
        raise RuntimeError(f"unsupported Electron fuse schema version: {schema_version}")
    if count < 1 or count > 32 or fuse_offset + count > len(data):
        raise RuntimeError(f"implausible Electron fuse count: {count}")
    fuses: list[str] = []
    for index in range(count):
        value = BYTE_VALUES.get(data[fuse_offset + index])
        if value is None:
            raise RuntimeError(
                f"unknown Electron fuse byte 0x{data[fuse_offset + index]:02x} at index {index}"
            )
        fuses.append(value)
    return FuseSnapshot(schema_version, count, tuple(fuses), fuse_offset)


def write_fuse(binary: Path, name: str, value: str) -> tuple[str, str]:
    if name not in FUSE_INDEX:
        raise ValueError(f"unknown Electron fuse: {name}")
    if value not in FUSE_VALUES:
        raise ValueError(f"unknown Electron fuse value: {value}")
    snapshot = read_fuses(binary)
    index = FUSE_INDEX[name]
    if index >= snapshot.count:
        raise RuntimeError(
            f"Electron fuse {name} is beyond the binary fuse count ({snapshot.count})"
        )
    previous = snapshot.fuses[index]
    if previous == value:
        return previous, value
    data = bytearray(binary.read_bytes())
    data[snapshot.offset + index] = FUSE_VALUES[value]
    binary.write_bytes(data)
    return previous, value


def disable_asar_integrity_validation(binary: Path, backup: Path) -> tuple[FuseSnapshot, FuseSnapshot]:
    """Back up the staged PE and change only the embedded ASAR-integrity fuse."""
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, backup)
    try:
        before = read_fuses(binary)
        for required in ("EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar"):
            if FUSE_INDEX[required] >= before.count:
                raise RuntimeError(f"staged Electron executable has no {required} fuse")
        index = FUSE_INDEX["EnableEmbeddedAsarIntegrityValidation"]
        if before.fuses[index] == "on":
            write_fuse(binary, "EnableEmbeddedAsarIntegrityValidation", "off")
        after = read_fuses(binary)
        changed = [
            position
            for position, (left, right) in enumerate(zip(before.fuses, after.fuses))
            if left != right
        ]
        if changed != ([index] if before.fuses[index] == "on" else []):
            raise RuntimeError("Electron fuse operation changed an unrelated fuse")
    except Exception:
        shutil.copy2(backup, binary)
        raise
    return before, after
