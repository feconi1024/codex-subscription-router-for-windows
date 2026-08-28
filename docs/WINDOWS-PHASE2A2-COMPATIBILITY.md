# Windows Desktop MVP — Phase 2A.2 compatibility adaptation

Date: 2026-08-28  
Branch: `codex/windows-desktop-mvp`

## Verdict

**PHASE 2A.2 UNMODIFIED MIRROR BLOCKED**

The exact Windows source is now covered by a reviewed `windows-26.820`
renderer variant, corrected bootstrap audit, and explicit Windows ASAR
integrity planning. The required unmodified writable-mirror startup gate did
not pass, so the patched Desktop build and patched-shell smoke were not run.

Phase 2B was not started.

## Exact source identity

| Item | Value |
| --- | --- |
| Package | `OpenAI.Codex` |
| Package version | `26.820.7780.0` |
| Architecture | `x64` |
| Desktop executable | `app\\ChatGPT.exe` |
| ChatGPT.exe File/ProductVersion | `151.0.7922.170` |
| Source app.asar SHA-256 | `5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2` |
| ASAR header SHA-256 | `f00563ffa0028f929484acd0a5545fa866e33f0778f72f1c514d919f8abbc501` |

The whole-file ASAR digest and the independently calculated UTF-8 ASAR-header
digest are different by design. The implementation uses the pinned
`@electron/asar` package for the header digest.

## Implementation result

### Renderer

The source selects only when the exact package/hash identity and multiple
renderer fingerprints match. The selected variant is `windows-26.820`.

| Surface | Exact adaptation |
| --- | --- |
| Profile menu | Injects the Router account menu before `Jyl`; aliases are retargeted to the current `p8`/`ibl`/`ds`/`Tz`/`g6s`/`UI`/`DP`/`YI`/`aza` bindings |
| App server | Preserves `qg(scope, hostId) -> forHost(hostId)` unchanged |
| Plugin RPCs | Adds `codexMuxAccountId` only to the five account-scoped plugin parameter objects |
| Usage | Retargets the current reset query/mutation, usage header, usage slot, and usage-window selection |
| Profile page | Adds account avatar selection and hides native profile identity fields until an account is selected |
| Open state | Wraps the one verified `onOpenChange:l` hook; the outside/panel hook remains unchanged |
| Plugins settings | Injects the account scope control at the current `plugins-page-*.js` connected-content slot |
| Thread details | Adds `CodexMuxThreadSubscription` as a sibling section beside the current `tool-sources` section, passing the exact `conversationId` |
| Preserved hooks | CSP, `listMcpServers`, `mcpServerStatus/list`, and all three depletion alerts are left unchanged |

Every listed replacement requires one exact match. A missing, ambiguous, or
semantically changed precondition fails closed.

### Bootstrap

The read-only audit proves one current `userData` hook, one updater initializer
immediately before main startup, the main bundle, and the bridge injection
location. The official Windows main bundle contains platform-conditional
Computer Use references; they are classified as native optional source code,
not injected macOS code. The optional CUA runtime remains excluded from the
mirror and no Computer Use code is added by this project.

### ASAR integrity

The corrected fuse schema uses `0x30`/`0x31`/`0x72`/`0x90`, with
`WasmTrapHandlers` at index 8 and no Darwin-only pseudo-fuse. The mirror scan
covered 28 non-excluded `.exe`/`.dll` files and found one fuse carrier; each
carrier record includes its fuse-read result.

The selected official `ChatGPT.exe` has no readable fuse wire and no
`INTEGRITY/ELECTRONASAR` resource. The explicit plan is therefore
`RESOURCE_ABSENT_NO_VALIDATION_METADATA`, resolved for build planning only with
launch validation required. When a staged resource exists, the patcher updates
only the staged executable, reads it back, and verifies the new ASAR-header
digest.

PE resource inspection uses the pinned `resedit` implementation and never
writes the official WindowsApps executable.

## Unmodified mirror gate

Command:

```powershell
python scripts/patch_app_windows.py --smoke-unmodified-mirror
```

Result: `BLOCKED_PACKAGE_IDENTITY`.

The temporary mirror was writable and launched `ChatGPT.exe`; it created a
`ChatGPT` window and child processes. It exited before the 20-second bound with
code `2147483651` (`0x80000003`). The captured log contained a localized
package-identity error from `[sparkle] Failed to set up updater`, followed by
`Desktop bootstrap failed to start the main app`; GPU initialization errors
were also present. The official instance was observed, but no
single-instance-lock evidence was found. The temporary mirror and isolated
user-data directory were cleaned up, and no official process was terminated.

No manual operation is required for this result. Closing the official app is
not the diagnosed fix because the failure is the copied package's updater/
identity requirement.

## Validation status

| Check | Result |
| --- | --- |
| Python unit tests | `31/31 PASS` |
| Python compileall | `PASS` |
| JavaScript syntax | `PASS` |
| Release metadata | `PASS` |
| `git diff --check` | `PASS` |
| Shell syntax | Not run locally; the available `bash` invocation is access-denied on this host |
| Go tests/vet and mux/launcher build | Not run locally; Go is unavailable; required in Windows Actions |
| Real renderer audit | `PASS` |
| Real bootstrap audit | `PASS` with native optional CUA classification |
| ASAR-integrity strategy | `RESOLVED` as `RESOURCE_ABSENT_NO_VALIDATION_METADATA` |
| Unmodified mirror startup | `BLOCKED_PACKAGE_IDENTITY` |
| Patched build/startup | Not run because Gate A failed |
| CI Windows job | `PASS`; run [33168938990](https://github.com/feconi1024/codex-subscription-router-for-windows/actions/runs/33168938990) executed checkout, pinned Go setup, Go test/vet, Node/dependency install, both native builds, Python compile, and 31 helper tests |

The passing Windows Actions run provides the hosted Go/build evidence. A CI
setup failure before checkout or project steps would not be evidence of a
passing Windows job.

## Manual operations and scope

No account login, chat, reset consumption, package registration, ACL change,
official-file mutation, or broad process termination was performed. Phase 2B
two-account GUI E2E is not ready until a source or launch strategy passes the
unmodified mirror gate and the patched-shell gate.
