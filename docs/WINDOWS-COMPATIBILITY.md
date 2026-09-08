# Windows compatibility

<!-- Generated: python -m scripts.windows.generate_compatibility -->

The exact source registry in `scripts/windows/reviewed_sources.json` is
authoritative. PATCHABLE means the recorded source contracts were reviewed;
it does not imply Phase 3 native or installer acceptance. Unknown source
fingerprints are rejected. Every fingerprint field must match.

Phase 2 final acceptance: [WINDOWS-PHASE2-RECOVERY.md](WINDOWS-PHASE2-RECOVERY.md).
Phase 3 progress: [WINDOWS-PHASE3.md](WINDOWS-PHASE3.md).

| Package version | Architecture | Review | Renderer |
| --- | --- | --- | --- |
| 26.820.7780.0 | X64 | PATCHABLE | windows-26.820 |
| 26.825.5331.0 | X64 | PATCHABLE | windows-26.825 |
| 26.825.6671.0 | X64 | PATCHABLE | windows-26.825 |
| 26.901.4073.0 | X64 | PATCHABLE | windows-26.901 |
| 26.901.5280.0 | X64 | PATCHABLE | windows-26.901 |
| 26.901.6511.0 | X64 | PATCHABLE | windows-26.901 |

## Derived legacy diagnostic records

```json
[
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.820.7780.0",
    "app_file_version": "151.0.7922.170",
    "app_asar_sha256": "5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.820"
  },
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.825.5331.0",
    "app_file_version": "151.0.7922.174",
    "app_asar_sha256": "178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.825"
  },
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.825.6671.0",
    "app_file_version": "151.0.7922.174",
    "app_asar_sha256": "86e791e0eb330a1507057d30e450878f7c958e56e04e718f101ba80549e9baf2",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.825"
  },
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.901.4073.0",
    "app_file_version": "152.0.7977.64",
    "app_asar_sha256": "689a59eccd6b4d38f3ddaf202dac05b7cf5ca9cba93b2703f7aa8a44be90b23e",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.901"
  },
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.901.5280.0",
    "app_file_version": "152.0.7977.64",
    "app_asar_sha256": "6579c4326cccdb508d079ecc878ad4725451b2234370d2ed9d4db53939cf99c7",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.901"
  },
  {
    "architecture": "X64",
    "package_name": "OpenAI.Codex",
    "package_version": "26.901.6511.0",
    "app_file_version": "152.0.7977.83",
    "app_asar_sha256": "e75bae2b8a02f174c7ceeed6d631aaff355e44f8af5c798fa3628089f11d659e",
    "real_codex_version": null,
    "real_codex_sha256": null,
    "tested_patch_anchors": "windows-26.901"
  }
]
```
