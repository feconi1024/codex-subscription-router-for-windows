# Windows Desktop compatibility

This file records exact Windows Desktop source material that has been extracted,
audited, patched, and launched. The patcher rejects a package/version/`app.asar`
hash that is not represented below. `--allow-untested-source` is a development
override only; it does not bypass renderer anchor checks, PE fuse checks, or
protected-file exclusions.

No official Windows Desktop source was accessible to the Phase 2 Round 1
automated environment. The installed per-user native Codex binary was validated
in the Phase 1 report, but it is not a desktop source and is intentionally not
listed as a desktop compatibility record.

## Record schema

Add one object to the JSON array after a manual Windows extraction and audit.
Never commit the extracted app, the patched `app.asar`, or either executable.

```json
[]
```

Each record must contain:

| Field | Meaning |
| --- | --- |
| `architecture` | AppX architecture such as `X64` or `Arm64` |
| `package_name` | `Get-AppxPackage` package name |
| `package_version` | AppX package version |
| `app_file_version` | `ChatGPT.exe` or legacy `Codex.exe` file version |
| `app_asar_sha256` | SHA-256 of the unmodified source `resources\\app.asar` |
| `real_codex_version` | Selected per-user native `codex.exe --version` output |
| `real_codex_sha256` | SHA-256 of the selected native Codex binary |
| `tested_patch_anchors` | Human-readable build/anchor identifier |

## Renderer anchor audit

The shared renderer patcher has exact variants for the existing `26.803`-style
symbols and the renamed/lazy-loaded `26.810`/build `6662` symbols from the
upstream compatibility reference. Windows builds are still audited from their
own extracted `app.asar`; the table below describes the supported classifications,
not a claim that either build is Windows-tested.

| Semantic hook | 26.803-style result | 26.810/build 6662 result | Fail-closed condition |
| --- | --- | --- | --- |
| Profile menu | `UNCHANGED` | `RENAMED` | Missing or ambiguous exact function |
| App-server request bridge | `UNCHANGED` | `RENAMED` | Missing or ambiguous exact function |
| Profile statistics request | `UNCHANGED` | `RENAMED` | Missing or ambiguous exact request |
| Usage/reset hooks | `UNCHANGED` | `RENAMED` | Any missing exact query/mutation/header |
| Plugins request mappings | `UNCHANGED` | `RENAMED` wrapper symbols | Any mapping count other than one |
| Profile settings bundle | `UNCHANGED` | `RENAMED` asset/anchors | Missing or ambiguous exact bundle |
| Plugins settings bundle | `UNCHANGED` | `MOVED` to `plugins-page-*.js` | Missing or ambiguous exact bundle |
| Local conversation thread | `UNCHANGED` | `RENAMED` lazy chunk symbol | Missing or ambiguous exact component |

The actual per-build result is written to the generated `metadata.json` under
`renderer_anchor_audit`.

## Windows source layout

The supported source layouts are:

```text
<InstallLocation>\\app\\ChatGPT.exe
<InstallLocation>\\app\\resources\\app.asar
```

and the legacy executable spelling:

```text
<InstallLocation>\\app\\Codex.exe
<InstallLocation>\\app\\resources\\app.asar
```

The official package is read-only input. The patcher never takes ownership of
`WindowsApps`, changes its ACLs, or uses the bundled `resources\\codex.exe` as
the real Codex runtime.

Changing the ASAR-integrity fuse changes the local staged PE and therefore
invalidates the upstream Authenticode signature for that development copy.
This round does not re-sign Windows binaries; production signing is deferred to
Phase 3.
