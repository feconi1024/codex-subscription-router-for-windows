"""Fail-closed compatibility records for Windows desktop sources."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WindowsCompatibilityRecord:
    architecture: str
    package_name: str
    package_version: str
    app_file_version: str
    app_asar_sha256: str
    real_codex_version: str | None
    real_codex_sha256: str | None
    tested_patch_anchors: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "WindowsCompatibilityRecord":
        required = (
            "architecture",
            "package_name",
            "package_version",
            "app_file_version",
            "app_asar_sha256",
            "tested_patch_anchors",
        )
        missing = [key for key in required if not isinstance(value.get(key), str)]
        if missing:
            raise ValueError(f"Windows compatibility record is missing: {', '.join(missing)}")
        digest = value["app_asar_sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("app_asar_sha256 must be a lowercase SHA-256 digest")
        real_digest = value.get("real_codex_sha256")
        if real_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", real_digest):
            raise ValueError("real_codex_sha256 must be a lowercase SHA-256 digest")
        real_version = value.get("real_codex_version")
        if real_version is not None and not isinstance(real_version, str):
            raise ValueError("real_codex_version must be a string or null")
        return cls(
            architecture=value["architecture"],
            package_name=value["package_name"],
            package_version=value["package_version"],
            app_file_version=value["app_file_version"],
            app_asar_sha256=digest,
            real_codex_version=real_version,
            real_codex_sha256=real_digest,
            tested_patch_anchors=value["tested_patch_anchors"],
        )


def load_compatibility_records(path: Path) -> list[WindowsCompatibilityRecord]:
    """Read the JSON record block embedded in the human-readable document."""
    text = path.read_text(encoding="utf-8")
    match = re.search(r"```json\s*(\[.*?\])\s*```", text, re.DOTALL)
    if match is None:
        raise ValueError(f"no JSON compatibility record block found in {path}")
    payload = json.loads(match.group(1))
    if not isinstance(payload, list):
        raise ValueError("Windows compatibility record block must be a JSON array")
    return [WindowsCompatibilityRecord.from_mapping(item) for item in payload]


def find_matching_record(
    records: list[WindowsCompatibilityRecord],
    *,
    package_name: str,
    package_version: str,
    app_file_version: str,
    app_asar_sha256: str,
) -> WindowsCompatibilityRecord | None:
    for record in records:
        if (
            record.package_name == package_name
            and record.package_version == package_version
            and record.app_file_version == app_file_version
            and record.app_asar_sha256 == app_asar_sha256
        ):
            return record
    return None
