# Windows Desktop MVP — Phase 2 Round 1

Date: 2026-08-27

This report records the implementation and the local evidence available for
Round 1. It is not a claim that the full Windows Desktop feature set has passed
GUI validation.

## Source discovery

The current-user `Get-AppxPackage` query returned no accessible OpenAI/Codex
desktop package. The following per-user package-data directories were present,
but no usable desktop executable or `app.asar` was accessible from them:

```text
C:\Users\hehao\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0
C:\Users\hehao\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0
```

No WindowsApps ACL, ownership, or protected package file was changed. The
implemented source discovery accepts either of these layouts when the source is
available:

```text
<InstallLocation>\app\ChatGPT.exe
<InstallLocation>\app\resources\app.asar
```

or the legacy `app\Codex.exe` spelling. Consequently, the exact Windows
desktop package version, executable file version, and source `app.asar` hash
remain **not observed** in this round; no placeholder compatibility record was
added.

## Real Codex discovery

The Phase 1 validated per-user native binary remains the expected runtime
source:

| Field | Observed value |
| --- | --- |
| Path | `C:\Users\hehao\AppData\Local\OpenAI\Codex\bin\d0097be4feba73d0\codex.exe` |
| `--version` | `codex-cli 0.150.0-alpha.8` |
| SHA-256 | `09D6723925E724EDF0BBBBC7B9E204526E0FB1462C86BD2A4997311FD5071EBA` |
| Authenticode | `Valid`; signer `OpenAI OpCo, LLC` |

The Windows patcher re-discovers or accepts this binary through
`--real-codex`, validates native PE headers, prefers valid OpenAI signatures,
and verifies the hash before and after copying it to
`runtime\codex.real.exe`. No credentials are inspected.

## Renderer and fuse evidence

No Windows `app.asar` was available for a real audit. The shared patcher was
validated against synthetic fixtures for both the existing 26.803-style
anchors and the renamed/lazy-loaded 26.810/build-6662 variant. The 26.803
fixture classified its hooks as `UNCHANGED`; the 6662 fixture classified the
renamed symbols as `RENAMED` and the plugins asset move as `MOVED`. This is
explicit variant coverage, not a claim of Windows compatibility.

The fuse writer was validated against a synthetic Electron FuseV1 image:

| State | Fuse values (indexes 0–8) |
| --- | --- |
| Before | `off, on, on, on, on, on, on, on, on` |
| After | `off, on, on, on, off, on, on, on, on` |

Only index 4, `EnableEmbeddedAsarIntegrityValidation`, changed. Index 5,
`OnlyLoadAppFromAsar`, and all other fuses remained unchanged. The operation
backs up the local staged executable; the official executable is never
written. Changing the staged PE invalidates its upstream Authenticode
signature. Windows signing is deferred to Phase 3.

## Produced architecture

The native launcher establishes the following contract before starting the
copied Electron shell:

```text
Codex Subscription Router.exe
  -> app\ChatGPT.exe (or legacy app\Codex.exe)
     CODEX_CLI_PATH=runtime\codex-mux.exe
       CODEX_MUX_REAL_CODEX=runtime\codex.real.exe
       CODEX_MUX_DESKTOP_USER_DATA=User Data\
```

`CODEX_HOME` is preserved. User-supplied arguments pass through except an
existing Chromium `--user-data-dir`, which is replaced with the isolated
Router profile. The launcher uses `app\` as the working directory, waits for
the Electron process, and returns its exit code.

The intended writable tree is:

```text
%LOCALAPPDATA%\Codex Subscription Router\
  Codex Subscription Router.exe
  app\
    ChatGPT.exe
    resources\app.asar
    resources\app.asar.unpacked\
  runtime\
    codex-mux.exe
    codex.real.exe
  User Data\
  metadata.json
```

The official source is mirrored into a temporary sibling directory, protected
bundled Codex/Computer Use paths are excluded, ASAR unpack roots are derived
from the staged source tree, and the result is atomically installed. Existing
local builds are moved to `%USERPROFILE%\.codex-mux\backups\` when `--force` is
used.

## Checks run

Passed locally:

```text
python -m unittest discover -s scripts/tests -p "test_*.py" -v  (11/11)
python -m compileall -q scripts
npm run check:js
npm run check:python
git diff --check
```

The Windows CI job retains `go test ./...`, `go vet ./...`, builds
`cmd/codex-mux`, builds `cmd/codex-router-launcher`, and runs the Python helper
checks. A Go toolchain was not available in this local environment, so the new
launcher build was not duplicated locally. The actual desktop staging command
was also not run because the official Windows source was unavailable.

## Round 2 entry conditions

Round 2 should use an accessible exact Windows package and run, after reviewing
the printed anchor audit:

```powershell
npm ci --ignore-scripts
python scripts/patch_app_windows.py `
  --source 'C:\path\to\package' `
  --real-codex "$env:LOCALAPPDATA\OpenAI\Codex\bin\<version>\codex.exe" `
  --allow-untested-source
```

Record the real package/version/file-version/ASAR hash and audit output in
`WINDOWS-COMPATIBILITY.md`, then manually validate launch, account add/login/
logout, profile selection, Plugins/MCP scoping, reset selection, thread
ownership, isolated profile behavior, and normal routing. Do not port or test
Computer Use in this MVP. Do not call this a full Phase 2 pass until that GUI
validation and the real staged-fuse/ASAR checks succeed.
