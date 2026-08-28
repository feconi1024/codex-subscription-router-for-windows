# Windows Phase 2A.3 Launch Validation

Date: 2026-08-28  
Branch: `codex/windows-desktop-mvp`  
Source package: `OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0`  
Source root: `C:\Program Files\WindowsApps\OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0`

## Verdict

`PHASE 2A.3 FAIL`

Gate 1 reached both app-root Desktop shell candidates in an unmodified temporary mirror, but neither produced a healthy bounded startup result. The observed failures are unrelated to package identity, so Gate 2 was not run. This is intentionally fail-closed: no sparse-package fallback and no patched shell build were attempted.

No manual operation is required. The official WindowsApps installation was read only; no official process was terminated.

## Candidate inventory

The inventory is limited to the package app root. `resources\codex.exe` and other bundled runtimes are not Desktop shell candidates.

| Candidate | Present | Size | File/Product version | Authenticode | PE machine | Manifest | Fuse wire | PE ASAR resource |
| --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: |
| `app\ChatGPT.exe` | yes | 4,195,632 | `151.0.7922.170` / `151.0.7922.170` | Valid, OpenAI OpCo, LLC | `0x8664` | yes | no | no |
| `app\Codex.exe` | yes | 1,105,200 | unavailable / unavailable | Valid, OpenAI OpCo, LLC | `0x8664` | no | no | no |

The source ASAR SHA-256 is `5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2`; its ASAR header SHA-256 is `f00563ffa0028f929484acd0a5545fa866e33f0778f72f1c514d919f8abbc501`.

## Actual fuse carrier and integrity plan

The mirror scan inspected 28 non-excluded `.exe`/`.dll` files and found exactly one fuse carrier:

- relative carrier path: `chrome.dll`
- sentinel offset in the Phase 2A.3 audit mirror: `277172690`
- schema version: `1`
- fuse count: `9`
- all fuse states, by index: `on, off, on, on, off, off, off, on, on`
- relevant states: `EnableEmbeddedAsarIntegrityValidation` (index 4) = `off`; `OnlyLoadAppFromAsar` (index 5) = `off`
- `INTEGRITY/ELECTRONASAR` PE resource: absent
- integrity plan: `FUSE_PRESENT_ASAR_VALIDATION_DISABLED`, resolved

The plan is tied to this actual carrier, not to the manifest-declared `ChatGPT.exe`. Because ASAR validation is fused off and no PE integrity resource exists, repacking would not require a PE resource update for this source. Any future source with a different carrier set must be audited again.

## Gate 1 direct-launch matrix

Both probes used one unmodified temporary mirror and ran sequentially. Each probe created a fresh temporary `User Data` and `codex-home`, set `CODEX_ELECTRON_USER_DATA_PATH`, `CODEX_HOME`, `CODEX_SPARKLE_ENABLED=false`, `CODEX_CLI_PATH` to the validated per-user native `codex.exe`, retained `CODEX_MUX_DESKTOP_USER_DATA` for compatibility, and passed `--user-data-dir=<temporary>\User Data`.

| Candidate | Result | Evidence |
| --- | --- | --- |
| `app\ChatGPT.exe` | `CRASHED` | exit `2147483651` (`0x80000003`); logs reported `enableUpdater=false`, `packaged=true`, then fatal GPU initialization: `GPU process isn't usable. Goodbye.` The only observed window was a system UAC input-indicator overlay, not a healthy app window. |
| `app\Codex.exe` | `CRASHED` | exit `1`; no updater, package-identity, resource, native-module, or single-instance evidence was logged, and no window was observed. |

The matrix recorded PID trees, executable paths, visible windows/titles/classes, exit codes, packaged/updater/app-server flags, and relevant failure lines. Profile contract evidence was valid for both probes, with no outside production `.codex`/Codex profile path observed in the captured logs. Temporary process sets were attributed by mirror path or parent relationship; no official WindowsApps process was included in cleanup.

The `enableUpdater=false` line proves the environment switch is reaching the packaged ChatGPT shell. Since the shell still failed on GPU initialization, this run does not claim a direct-launch pass.

## Gate 2 and patched shell

Gate 2 is reserved for an exact package-identity block after Gate 1. Gate 1 produced unrelated `CRASHED` results, so no minimal bootstrap mutation was applied. Consequently:

- minimal bootstrap result: not run
- renderer patch: not run
- Router UI/mux build: not run
- selected launch executable: none proven
- patched-shell result: not attempted
- `docs/WINDOWS-COMPATIBILITY.md`: intentionally unchanged
- Phase 2B: not started and not ready

The implementation nevertheless includes the guarded Gate 2 path, actual-carrier integrity planner, isolated probe contract, cleanup attribution, and `launch.json`-based launcher selection for a subsequent evidence-backed run.

## Verification

- Python helper tests: 38 passed
- Python compilation: passed
- `git diff --check`: passed
- Go build/test/vet: delegated to the pinned Windows CI job because Go is not installed on this workstation
- official source/package: unchanged by this validation

Implementation files are `scripts/windows/smoke.py`, `scripts/windows/discovery.py`, `scripts/windows/integrity.py`, `scripts/windows/bootstrap.py`, `scripts/patch_app_windows.py`, `cmd/codex-router-launcher/main.go`, and their tests. The pushed implementation round is commit `f0f7f68`; the documentation/evidence follow-up is pending CI verification.
