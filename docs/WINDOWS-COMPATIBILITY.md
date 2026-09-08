# Windows Desktop compatibility

This file records exact Windows Desktop source material that has been audited,
patched, and launched successfully. A source is not added as supported until
the unmodified mirror gate and the patched-shell gate both pass.

## Current Phase 2A.2 status

The exact installed source is renderer-compatible, but it is not yet a
supported compatibility record because the required unmodified writable-mirror
startup gate is blocked by the Windows package identity/updater requirement.
No patched Desktop package was built or launched after that gate failed.

Do not claim Phase 2 completion or begin Phase 2B from this record.

## Record schema

Add one object to the JSON array only after a manual Windows extraction,
renderer/bootstrap audit, unmodified-mirror startup, patched build, and
patched-shell startup all pass. Never commit the extracted app, patched
`app.asar`, or either executable.

```json
[]
```

Each record must contain:

| Field | Meaning |
| --- | --- |
| `architecture` | AppX architecture such as `X64` or `Arm64` |
| `package_name` | AppX package name |
| `package_version` | AppX package version |
| `app_file_version` | `ChatGPT.exe` or legacy `Codex.exe` file version |
| `app_asar_sha256` | SHA-256 of the unmodified source `resources\\app.asar` |
| `app_asar_header_sha256` | SHA-256 of the UTF-8 ASAR header string, used by Electron integrity metadata |
| `renderer_variant` | Exact reviewed renderer contract selected by metadata and multiple fingerprints |
| `bootstrap_result` | User-data, updater, main-bundle, and bridge audit result |
| `windows_asar_integrity` | Fuse/resource strategy and staged read-back result |
| `real_codex_version` | Selected per-user native `codex.exe --version` output |
| `real_codex_sha256` | SHA-256 of the selected native Codex binary |
| `startup_result` | Unmodified-mirror and patched-shell startup evidence |

## Exact 26.820 source audit

The host currently exposes this exact source identity:

| Item | Observed value |
| --- | --- |
| Package | `OpenAI.Codex` |
| Package version | `26.820.7780.0` |
| Architecture | `X64` |
| Desktop executable | `app\\ChatGPT.exe` |
| ChatGPT.exe File/ProductVersion | `151.0.7922.170` |
| Source app.asar SHA-256 | `5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2` |
| ASAR header SHA-256 | `f00563ffa0028f929484acd0a5545fa866e33f0778f72f1c514d919f8abbc501` |
| Renderer variant | `windows-26.820` |
| Renderer audit | `PASS`; 28 exact anchors, including one current profile-menu open-state hook |
| Bootstrap audit | `PASS`; exact user-data and updater hooks, bridge location; native optional CUA references retained but not injected or enabled |
| Windows ASAR integrity | `RESOURCE_ABSENT_NO_VALIDATION_METADATA`; no fuse wire or `INTEGRITY/ELECTRONASAR` resource; launch validation required |
| Fuse carrier scan | 1 carrier, 28 non-excluded `.exe`/`.dll` files scanned |

The whole-file ASAR hash and ASAR-header hash are intentionally recorded as
different values. The patched strategy updates only a staged PE
`INTEGRITY/ELECTRONASAR` resource when one exists; it never mutates the
official WindowsApps executable.

## Gate result

The required `--smoke-unmodified-mirror` run copied the source to a temporary
writable directory and launched the mirrored `ChatGPT.exe` with isolated user
data and the validated per-user native `codex.exe` in `CODEX_CLI_PATH`.

Result: `BLOCKED_PACKAGE_IDENTITY`.

The process created a `ChatGPT` window and child processes, then exited before
the bounded interval with exit code `2147483651` (`0x80000003`). The log
contained `[sparkle] Failed to set up updater`, a localized package-identity
error, and `Desktop bootstrap failed to start the main app`. GPU initialization
errors were also recorded. The official instance was present, but no
single-instance-lock evidence was found. No official process was terminated,
and no manual operation is required for this result.

Because Gate A failed, there is no patched ASAR integrity read-back result,
patched Router startup result, or supported compatibility record yet.

## Scope boundary

This round does not add account login, two-account routing, chat submission,
failover, sticky ownership, reset consumption, Computer Use, Appshots, or
Phase 2B GUI E2E.
