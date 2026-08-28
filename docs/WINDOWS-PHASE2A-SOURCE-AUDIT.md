# Windows Desktop MVP — Phase 2A source acquisition and compatibility audit

Date: 2026-08-28  
Branch: `codex/windows-desktop-mvp`  
Scope: real Windows Desktop source acquisition, compatibility audit, and an unmodified mirror dry run. Full Phase 2 GUI E2E and Phase 2B were not started.

## Verdict

**PHASE 2A FAIL**

The official Windows package was discovered and read successfully. The mandatory compatibility gates did not pass: the real renderer is a newer/changed build relative to the exact patch variants, and the expected Electron fuse sentinel is absent from the official executable. The implementation therefore remains fail-closed and no patched package was built or launched.

## Root cause

The selected Microsoft Store package is `OpenAI.Codex` `26.820.7780.0`, with `ChatGPT.exe` file/product version `151.0.7922.170`. Its extracted renderer contains exact current counterparts for many existing semantic hooks, but not the byte-level anchors used by the current patch variants. The audit classifies those counterparts as `SEMANTICALLY_CHANGED`; it does not treat broad regex matches as patchable. Two local-conversation-thread hooks are `MISSING`.

The official `ChatGPT.exe` also does not contain the fuse sentinel expected by the current read-only fuse reader. This is recorded as `UNAVAILABLE`, with no attempt to mutate the official executable or its package.

## Source identity and hashes

| Item | Observed value |
| --- | --- |
| Package name | `OpenAI.Codex` |
| Package version | `26.820.7780.0` |
| Architecture | `X64` |
| Publisher | `CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B` |
| Package root | `C:\Program Files\WindowsApps\OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0` |
| App directory | `C:\Program Files\WindowsApps\OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0\app` |
| Selected source executable | `C:\Program Files\WindowsApps\OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe` |
| Source executable length | `4,195,632` bytes |
| File/product version | `151.0.7922.170` |
| Source executable SHA-256 | `BCDC21867D2010005C5957B44794B5E073EB0F08416EC72845227D86A7DC0DFE` |
| Authenticode | `Valid` |
| Signer | `CN="OpenAI OpCo, LLC", O="OpenAI OpCo, LLC", L=San Francisco, S=California, C=US` |
| Source `app.asar` | `C:\Program Files\WindowsApps\OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0\app\resources\app.asar` |
| Source `app.asar` length | `285,134,571` bytes |
| Source `app.asar` SHA-256 | `5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2` |
| Appx block-map entries | `5,280` |

The manifest independently reports `Identity Name=OpenAI.Codex`, `ProcessorArchitecture=x64`, `Version=26.820.7780.0`, `Publisher=CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B`, and application `Id=App`, `Executable=app/ChatGPT.exe`.

The manifest-derived AUMID is `OpenAI.Codex_2p2nqsd0c76g0!App`. `Get-StartApps` completed successfully but did not return a matching registered AUMID on this host, so the diagnostic records the manifest-derived identity rather than trusting a localized display name.

The selected per-user native Codex runtime was also read for metadata, but it is not used as Desktop source material:

| Item | Observed value |
| --- | --- |
| Native runtime | `C:\Users\hehao\AppData\Local\OpenAI\Codex\bin\d0097be4feba73d0\codex.exe` |
| Version | `codex-cli 0.150.0-alpha.8` |
| SHA-256 | `09D6723925E724EDF0BBBBC7B9E204526E0FB1462C86BD2A4997311FD5071EBA` |
| Authenticode | `Valid`, signer `OpenAI OpCo, LLC` |

## Discovery probes

| Method | Status | Candidates/evidence | Non-sensitive error or note |
| --- | --- | --- | --- |
| `Get-StartApps` | `PASS` | No matching registered AUMID | Command succeeded; no matching identity was returned |
| Native running-process Toolhelp32 + query-limited path | `PASS` | Official WindowsApps `ChatGPT.exe` plus per-user/extension `codex.exe` candidates | Some protected `ChatGPT.exe` processes returned Win32 error 5 for path query; a readable official candidate was still selected |
| PowerShell/CIM running-process fallback | `NOT AVAILABLE` | Not attempted | Native probe already yielded a readable source |
| `Get-AppxPackage` | `PASS` | No accessible candidate returned by the package query | Command succeeded; direct process/manifest evidence selected the package |
| Conventional per-user paths | `FAIL` | `AppData\Local\Programs\ChatGPT`, `Programs\Codex`, `Local\OpenAI\ChatGPT`, `Local\OpenAI\Codex` | No supported conventional Desktop layout was found there |
| `AppxManifest.xml` AUMID fallback | `PASS` | `OpenAI.Codex_2p2nqsd0c76g0!App` | Derived from package identity and manifest application id because StartApps had no match |

The native process probe selected the WindowsApps `ChatGPT.exe` candidate, not the extension or per-user native Codex binaries. Source layout was built directly from that known executable path; parent-directory enumeration was not required for selection.

## Direct-read access matrix

| Independent operation | Status | Path/evidence |
| --- | --- | --- |
| Directory enumeration | `PASS` | Package root was enumerated |
| Direct `ChatGPT.exe` read | `PASS` | Exact `app\ChatGPT.exe` path read successfully |
| Direct `app.asar` read | `PASS` | Exact `app\resources\app.asar` path read successfully |
| Direct `AppxManifest.xml` read | `PASS` | Exact package-root manifest read successfully |
| Direct `AppxBlockMap.xml` read | `PASS` | Exact package-root block map read successfully; 5,280 file entries parsed |

All reads were read-only. No ownership, ACL, package registration, or official-file modification operation was performed.

## Real renderer audit

Command used: `python scripts/patch_app_windows.py --audit-only --diagnostics-json <temporary-json-path>`

The audit extracted the real source `app.asar` to a temporary directory and inspected the actual renderer assets. It used exact static signatures and exact asset resolution. `SEMANTICALLY_CHANGED` means an exact current counterpart was observed but the existing patch anchor no longer matches; it is not a patch approval.

| # | Semantic hook | Asset | Result |
| ---: | --- | --- | --- |
| 1 | Renderer CSP | `webview/index.html` | `UNCHANGED` |
| 2 | Native profile menu | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 3 | App-server request bridge | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 4 | Profile statistics request | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 5 | Native usage modal | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 6 | Reset-credit query | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 7 | Reset-credit mutation | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 8 | Usage-window selection | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 9 | Usage sheet header | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 10 | Usage menu slot | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 11 | List-apps RPC mapping | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 12 | List-installed-apps RPC mapping | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 13 | Read-apps RPC mapping | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 14 | Login-MCP-server RPC mapping | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 15 | List-MCP-server-status RPC mapping | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 16 | `listMcpServers` RPC wrapper | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 17 | `mcpServerStatus/list` RPC call | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 18 | Profile-menu open-state hook 1 | `app-initial-wqR9HoXP.js` | `SEMANTICALLY_CHANGED` |
| 19 | Profile-menu open-state hook 2 | `app-initial-wqR9HoXP.js` | `MISSING` |
| 20 | Subscription-depletion alert 1 | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 21 | Subscription-depletion alert 2 | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 22 | Subscription-depletion alert 3 | `app-initial-wqR9HoXP.js` | `UNCHANGED` |
| 23 | Profile avatar | `profile-BR9AXjS1.js` | `SEMANTICALLY_CHANGED` |
| 24 | Profile display name | `profile-BR9AXjS1.js` | `SEMANTICALLY_CHANGED` |
| 25 | Profile username and plan | `profile-BR9AXjS1.js` | `SEMANTICALLY_CHANGED` |
| 26 | Plugins settings content | `plugins-settings-BTCJQ31Y.js` | `UNCHANGED` |
| 27 | Thread-summary source component | `local-conversation-thread-*.js` | `MISSING` |
| 28 | Thread-summary section list | `local-conversation-thread-*.js` | `MISSING` |

The audit result is `renderer_audit_pass=false`. The patcher rejects `MISSING`, `SEMANTICALLY_CHANGED`, and `AMBIGUOUS` hooks, so this source cannot be patched by the existing variants. No broad regex fallback was added.

## Electron fuse audit

The fuse reader was invoked read-only against the actual selected `ChatGPT.exe`. Result:

```text
status: UNAVAILABLE
error: Electron fuse sentinel not found in the official ChatGPT.exe
```

`fuse_audit_pass=false`. No official executable was changed, and no fuse mutation was attempted. Because the fuse gate is mandatory, the source is not eligible for a development build under the current fail-closed policy.

## Unmodified mirror dry run

Command used: `python scripts/patch_app_windows.py --mirror-dry-run --diagnostics-json <temporary-json-path>`

| Field | Result |
| --- | --- |
| Strategy | `walk` |
| Files copied | `1,214` |
| Required copy failures | `0` |
| Other copy failures | `0` |
| Temporary mirror verification | `PASS` |
| Excluded optional protected components | `resources/cua_node`, `resources/codex`, `resources/codex.exe` |
| Official source changed | `NO` |

The shell, `ChatGPT.exe`, `Codex.exe`, and required runtime content remain in the mirror. The optional bundled Codex/Computer Use components are classified as protected optional components and are excluded. If directory enumeration is blocked on another host, the implementation can mirror from the validated Appx block map and rejects traversal paths; required-file failures remain fatal.

## Go/toolchain probe

The host was probed without installing anything:

| Probe | Result |
| --- | --- |
| `PATH` / `shutil.which(go)` | `FAIL` |
| `where.exe go` | `FAIL` — no matching files |
| `Test-Path C:\Program Files\Go\bin\go.exe` | `FAIL` |
| `Test-Path C:\Go\bin\go.exe` | `FAIL` |
| `Get-Command go -All` | `FAIL` |
| Go installation registry keys | `FAIL` |

No automatic Go installation was attempted. Consequently, a local Windows Go build was not run in this round.

## Verification

| Check | Result |
| --- | --- |
| Python unit tests | `21/21 PASS` |
| Python compileall | `PASS` |
| JavaScript syntax checks | `PASS` |
| `npm run check:js` | `PASS` |
| `npm run check:python` | `PASS` |
| `npm run release:check` | `PASS` |
| `git diff --check` | `PASS` |
| Audit-only command | Expected exit 1 because renderer/fuse gates fail; evidence was produced |
| Mirror dry-run command | `PASS` |

The pushed implementation commit is [`785b473`](https://github.com/feconi1024/codex-subscription-router-for-windows/commit/785b473e5b61b9ae79c8d7b881da7f2454c2bbed).

The resulting GitHub Actions run is [`33155946728`](https://github.com/feconi1024/codex-subscription-router-for-windows/actions/runs/33155946728):

| Job | Result | Details |
| --- | --- | --- |
| `checks` | `SUCCESS` | Go tests/vet and syntax/release checks completed |
| `windows-go-core` | `FAILURE` | Hosted job failed during setup before checkout; the public annotation reports that the preserved `actions/setup-go@b7ad1dad31d06c5925ef5d2fc7ad053ef454303e` reference could not be resolved |

The Windows job therefore did not execute its project steps. The workflow change preserved the existing pinned action SHAs as required by the Phase 2A brief. The setup-go pin needs separate CI maintenance before that job can provide Windows-hosted validation.

## Changes in this round

- Added structured source discovery with native running-process selection, AUMID evidence, direct known-layout reads, manifest metadata fallback, and Appx block-map parsing.
- Added fail-closed protected-component classification and block-map-capable mirroring.
- Added `--diagnose-source`, `--audit-only`, and `--mirror-dry-run` modes with optional JSON diagnostics.
- Added exact renderer compatibility classifications and fail-closed handling for semantic drift, missing, and ambiguous hooks.
- Added real-source tests for process selection, AUMID identity, direct reads, block-map traversal safety, mirror fallback, required-file failure, diagnostics, and semantic drift.
- Extended CI push coverage to `main` and `codex/**` while preserving the existing pinned action SHAs and Windows job steps.

`docs/WINDOWS-COMPATIBILITY.md` was intentionally not updated with a supported build/hash record because the mandatory audit did not pass.

## Manual operations and recommendation

No manual operation was required to complete Phase 2A. No account login, GUI chat, reset consumption, package registration, ACL change, or official-file mutation was performed.

Do not begin Phase 2B or full GUI E2E on this source. First select or obtain an exact Desktop build compatible with a reviewed renderer/fuse variant, or implement and review a new narrow variant plus the correct read-only fuse interpretation. Then rerun source acquisition and `--audit-only`; only a `FULL PHASE 2A PASS` should unlock Phase 2B.
