"""Render documentation from the sole machine-readable source registry."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .reviewed_sources import load_reviewed_sources

DOCUMENT = Path(__file__).resolve().parents[2] / "docs/WINDOWS-COMPATIBILITY.md"


def render() -> str:
    records = load_reviewed_sources()
    rows = ["# Windows compatibility", "", "<!-- Generated: python -m scripts.windows.generate_compatibility -->", "",
            "The exact source registry in `scripts/windows/reviewed_sources.json` is",
            "authoritative. PATCHABLE means the recorded source contracts were reviewed;",
            "it does not imply Phase 3 native or installer acceptance. Unknown source",
            "fingerprints are rejected. Every fingerprint field must match.", "",
            "Phase 2 final acceptance: [WINDOWS-PHASE2-RECOVERY.md](WINDOWS-PHASE2-RECOVERY.md).",
            "Phase 3 progress: [WINDOWS-PHASE3.md](WINDOWS-PHASE3.md).", "",
            "| Package version | Architecture | Review | Renderer |",
            "| --- | --- | --- | --- |"]
    for record in records:
        rows.append(f"| {record['package_version']} | {record['architecture']} | {record['review_status']} | {record['renderer_variant']} |")
    # Retain the historical diagnostic document schema for readers of older
    # tools; these rows are derived, never independently edited or trusted.
    derived = [{key: record[key] for key in ("architecture", "package_name", "package_version", "app_file_version", "app_asar_sha256")} |
               {"real_codex_version": None, "real_codex_sha256": None, "tested_patch_anchors": record["renderer_variant"]} for record in records]
    rows += ["", "## Derived legacy diagnostic records", "", "```json", json.dumps(derived, indent=2), "```", ""]
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = render()
    if args.check:
        if not DOCUMENT.exists() or DOCUMENT.read_text(encoding="utf-8") != result:
            parser.exit(1, "Windows compatibility document is stale; run python -m scripts.windows.generate_compatibility\n")
    else:
        DOCUMENT.write_text(result, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
