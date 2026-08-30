"""Exact read-only-reviewed Windows Desktop source contracts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping


REVIEWED_SOURCES_DOCUMENT = Path(__file__).with_name("reviewed_sources.json")
PATCHABLE_REVIEW_STATUS = "PATCHABLE"

_REQUIRED_FIELDS = (
    "package_name",
    "package_version",
    "architecture",
    "app_file_version",
    "app_asar_sha256",
    "app_asar_header_sha256",
    "renderer_variant",
    "authoritative_shell",
    "bootstrap_strategy",
    "integrity_state",
    "payload_acl_strategy",
    "review_status",
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def load_reviewed_sources(
    path: Path = REVIEWED_SOURCES_DOCUMENT,
) -> list[dict[str, object]]:
    """Load and validate exact source records without probing or mutating a source."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("reviewed source registry must be a JSON array")
    records: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for index, value in enumerate(payload):
        if not isinstance(value, dict):
            raise ValueError(f"reviewed source record {index} must be an object")
        missing = [field for field in _REQUIRED_FIELDS if not isinstance(value.get(field), str)]
        if missing:
            raise ValueError(
                f"reviewed source record {index} is missing: {', '.join(missing)}"
            )
        for field in ("app_asar_sha256", "app_asar_header_sha256"):
            digest = str(value[field])
            if not _SHA256.fullmatch(digest):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        identity = _record_identity(value)
        if identity in seen:
            raise ValueError(f"duplicate reviewed source identity at record {index}")
        seen.add(identity)
        records.append(dict(value))
    return records


def _record_identity(record: Mapping[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(record.get("package_name", "")).casefold(),
        str(record.get("package_version", "")),
        str(record.get("architecture", "")).casefold(),
        str(record.get("app_file_version", "")),
        str(record.get("app_asar_sha256", "")).casefold(),
        str(record.get("app_asar_header_sha256", "")).casefold(),
    )


def _identity_value(identity: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in identity:
            return identity[key]
    return None


def reviewed_source_matches_identity(
    identity: Mapping[str, Any],
    record: Mapping[str, Any],
) -> bool:
    """Require every recorded source fingerprint to match exactly."""

    comparisons = (
        ("package_name", _identity_value(identity, "package_name", "package"), record.get("package_name")),
        ("package_version", _identity_value(identity, "package_version"), record.get("package_version")),
        ("architecture", _identity_value(identity, "architecture"), record.get("architecture")),
        ("app_file_version", _identity_value(identity, "app_file_version", "file_version"), record.get("app_file_version")),
        ("app_asar_sha256", _identity_value(identity, "app_asar_sha256"), record.get("app_asar_sha256")),
        (
            "app_asar_header_sha256",
            _identity_value(identity, "app_asar_header_sha256"),
            record.get("app_asar_header_sha256"),
        ),
    )
    for field, observed, expected in comparisons:
        if observed is None or expected is None:
            return False
        if field in {"package_name", "architecture"}:
            if str(observed).casefold() != str(expected).casefold():
                return False
        elif str(observed).casefold() != str(expected).casefold():
            return False
    return True


def find_reviewed_source(
    identity: Mapping[str, Any],
    records: list[Mapping[str, Any]] | None = None,
    *,
    path: Path = REVIEWED_SOURCES_DOCUMENT,
) -> dict[str, object] | None:
    """Return one exact reviewed record, or ``None`` for a clean compatibility miss."""

    candidates = records if records is not None else load_reviewed_sources(path)
    matches = [
        dict(record)
        for record in candidates
        if reviewed_source_matches_identity(identity, record)
    ]
    if len(matches) > 1:
        raise ValueError("reviewed source registry contains ambiguous exact matches")
    return matches[0] if matches else None


def reviewed_source_is_patchable(
    identity: Mapping[str, Any],
    record: Mapping[str, Any] | None,
) -> tuple[bool, str]:
    """Check the source-review gate used by Phase 2A.5 before any build."""

    if record is None:
        return False, "exact source identity is not present in the reviewed-source registry"
    if not reviewed_source_matches_identity(identity, record):
        return False, "reviewed-source fingerprint does not match the discovered source"
    if record.get("review_status") != PATCHABLE_REVIEW_STATUS:
        return False, f"reviewed-source status is {record.get('review_status')!r}, not PATCHABLE"
    if str(record.get("authoritative_shell", "")).replace("/", "\\").casefold() != "app\\chatgpt.exe":
        return False, "reviewed source does not prove app\\ChatGPT.exe as the authoritative shell"
    return True, "exact source is reviewed and PATCHABLE"
