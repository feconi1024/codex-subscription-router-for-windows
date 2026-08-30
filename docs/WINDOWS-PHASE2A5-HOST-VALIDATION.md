# Windows Phase 2A.5 host validation

Phase 2A.5 separates implementation from native release evidence.  The
implementation is committed on `codex/windows-desktop-mvp`; native A/B/C and
patched-shell evidence is accepted only when the validator is started by the
user from an independently opened Windows Terminal or PowerShell process.

## Implementation and CI evidence

This round adds:

- a `GetCurrentPackageFullName` host-context detector;
- a handle-backed `GetFinalPathNameByHandleW` LOCALAPPDATA canary with a
  conservative `Path.resolve()` fallback;
- fail-closed preflight before source discovery, mirroring, ACL mutation, or
  Electron startup;
- explicit `NONE`, `APPCONTAINER_RX`, and `UNRESOLVED` payload ACL strategies;
- causally isolated Phase 2A.5 A/B/C mirrors;
- cleanup-finalized native evidence and patched-shell results;
- selected `RealCodexCandidate` propagation without candidate-index fallback;
- the user-started `scripts/windows/run_phase2a5_host_validation.ps1` runner;
- the user-started `scripts/windows/prepare_phase2a5_desktop_auth.ps1` persistent
  Desktop-authentication preparation runner;
- an ignored `docs/generated/WINDOWS-PHASE2A5-HOST-RESULT.json` artifact path.

Phase 2A.6 adds a second fail-closed gate before the native probes: the
discovered source must match an exact record in
`scripts/windows/reviewed_sources.json`.  A clean version, architecture,
executable-version, ASAR-hash, or ASAR-header-hash mismatch stops with
`PHASE 2A.5 SOURCE REVIEW REQUIRED`; the identity and source diagnostics are
still retained in the artifact.  The old compatibility markdown remains a
release list and is not widened by this registry refresh.

The existing Phase 2A.4 CI baseline was green before this round.  The current
round must still pass both `checks` and `windows-go-core` before compatibility
promotion.

## Router UI runtime-gate fix

The patched-shell smoke no longer treats the upstream English `Open profile
menu` button as proof that the Router account menu rendered.  Each reviewed
renderer variant now records a Router-owned injection marker at the exact
`usageItems` replacement.  `CodexMuxAccountMenu` records mounted, account-load,
count, and request-failure state using only non-sensitive values, and the UI
test bridge observes that state under `debug.router`.

The public Phase 2A.5 probe artifact now includes sanitized
`chatgpt_classification`, `router_account_menu`, and `production_gate` fields.
When a UI gate fails, it retains only native button aria labels, types, and
geometry; body text, root HTML, image data, account identity, and control
tokens are excluded.  The upstream profile trigger remains diagnostic-only as
`native_profile_trigger_observed`.

Regression coverage proves that Router markers pass without an upstream
profile trigger, an upstream trigger without Router markers fails, each
Router runtime failure has an explicit status, and public artifacts do not
leak identity or token data.

The implementation result for commit
`692796b32cf4e95d67e7fa3488f6e2fe3a8c887d` is:

```text
PHASE 2A.5 ROUTER UI RUNTIME GATE FIX PASS
```

The required `checks` and `windows-go-core` jobs both passed for that exact
commit in GitHub Actions run `33304158356`.  Native compatibility promotion
still requires the independent external-host rerun below.

## Renderer syntax and value-site injection fix

The latest native result identified `ROUTER_MENU_NOT_INJECTED`, so the exact
reviewed Windows 26.825 renderer was checked before changing the patch.  The
source identity was `OpenAI.Codex 26.825.5331.0` with app.asar SHA-256
`178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b`.

The complete bounded audit of `function ZCc` showed that its
`usageItems:h` occurrence is the object-destructuring binding.  The later
profile-menu call computes the native usage value in `wt` and passes it as the
unique object-literal value `usageItems:wt`.  The 26.825 contract now patches
that value site and leaves the destructuring binding unchanged.  The other
reviewed contracts remain value-site hooks: `usageItems:Ct` (legacy 6662),
`usageItems:Ge` (legacy current), and `usageItems:wt` (Windows 26.820).
The patcher fails closed if a configured usage anchor is part of the native
component binding.

The old code was reproduced against the exact source in a disposable
extraction.  The patched `app-initial-DWX_sBmZ.js` failed the syntax-only Node
check at line 9667, column 259 with `Invalid destructuring assignment target`.
The failure report contained only the asset, parser/version, location, and
concise error; it did not print minified source.  A valid 26.825-style fixture
now proves the old replacement fails, the new value-site replacement parses,
and `usageItems:h` remains intact.

Every Router-touched JavaScript asset is now parsed with Node before ASAR
packing.  Renderer `.js` assets are checked through temporary `.mjs`
representations; the CommonJS UI bridge is checked as `.cjs`; no bundle is
executed.  A syntax failure stops the build with
`PHASE 2A.5 RENDERER SYNTAX BLOCKED` and a bounded diagnostic.  The exact
source disposable rebuild after the fix passed Node `v24.15.0` for the
bootstrap/main bundles, UI bridge, initial renderer, profile, plugin, and
conversation-thread assets.

The implementation commit for this fix is
`161ef5e48f39c308704319511ed574c2f7c17046`.  Both required CI jobs,
`checks` and `windows-go-core`, passed for that exact commit in GitHub Actions
run `33307218376`.

The injected helper now sets the independent
`__codexMuxRendererPatchLoaded` marker at the start of renderer execution.
The bridge reports that marker, the account-menu injection/mount/load state,
and safe summaries for every non-destroyed BrowserWindow using only IDs,
visibility, bounds, loading state, sanitized origin/path, and Router flags.
Page body, conversation content, window titles, identities, tokens, and full
query parameters are not exposed.  Runtime classification now distinguishes
`ROUTER_RENDERER_NOT_LOADED` from `ROUTER_MENU_NOT_INJECTED` and the existing
mount/load failures.  The build metadata records a safe
`renderer_syntax_validation` summary.

This is still a code-level fix only.  The independent native rerun below is
required before claiming `FULL PHASE 2A.5 PASS`.

## Patched-shell staging layout fix

The failed native run for commit `646fde9a4dc59de145e8a3faa9a0c0be0e1c5a19`
reached the static staged-layout check after the Go build calls.  The check
incorrectly appended the installation-root-relative `app\ChatGPT.exe` value
below the staged `app` directory, producing the false path
`<staged>\app\app\ChatGPT.exe`.

Commit `522c60a6d91e965cf0b7bd4f9ffa6d4d41ea0009` fixes the contract with
`resolve_staged_launch_path`, which accepts only `app\ChatGPT.exe` and
`app\Codex.exe` and resolves them from the staged installation root.  It also
uses `validate_staged_layout` to report each missing required file by name and
path without including control-token contents.  `launch.json` remains:

```json
{
  "schema_version": 1,
  "desktop_launch_executable": "app\\ChatGPT.exe"
}
```

The regression fixture covers both supported launch names, rejects traversal,
drive-qualified, UNC, outside-`app`, and unsupported paths, and verifies the
exact missing-file diagnostic.  No `go.mod`, renderer variant, reviewed-source
record, bootstrap, integrity, source-discovery, host-context, LOCALAPPDATA, or
production ACL decision changed.  The production ACL strategy remains `NONE`.

The implementation result is:

```text
PHASE 2A.5 STAGING FIX PASS
```

The required `checks` and `windows-go-core` jobs both passed for that exact
commit in GitHub Actions run `33302529462`.  The aggregate Phase 2A.5 verdict
still requires the independent native rerun below.

## Codex-hosted validator evidence

The previous native Phase 2A.4 run was performed from the packaged Codex host
context.  Its requested `%LOCALAPPDATA%\Codex Subscription Router\_smoke` root
resolved under the `OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local` package cache.
Although its A/B/C probes reported `PASS`, that evidence is not treated as
unpackaged-host compatibility evidence.

The Phase 2A.5 runner now stops at the host-context gate when the current
process has package identity, and stops at the physical canary when
LOCALAPPDATA is redirected.  It does not copy the source, change ACLs, or
launch `ChatGPT.exe` from a blocked host.

## External-host evidence

Not yet run in this workspace.  The required manual operation is:

```powershell
Set-Location -LiteralPath 'E:\Projects\codex-subscription-router-for-windows'
.\scripts\windows\run_phase2a5_host_validation.ps1 --ci-verified
```

The runner prints the process, package identity, physical LOCALAPPDATA,
repository commit, Python, Node, Go, and the structured Go toolchain probes at
startup.  It writes only a
credential-free diagnostic artifact under `docs/generated/`, which is ignored
by Git.  It never logs in, adds an account, sends a chat, consumes reset
credits, or modifies the official WindowsApps installation.

The artifact must be reviewed for, in order:

1. `has_package_identity = false` from the native API;
2. `filesystem_virtualized = false` from the canary;
3. Probe A normal-sandbox success;
4. Probe B and C only when A has the exact Chromium sandbox signature;
5. the selected ACL strategy;
6. normal-sandbox patched-shell, account-menu, health, and mux-chain evidence;
7. exact-root cleanup and unchanged official source hashes;
8. source stability at the end of validation;
9. green `checks` and `windows-go-core` CI for the recorded commit.

The native runner may execute direct Probe A when Go is unavailable, but it
must stop before creating the patched shell with the exact status
`PATCHED SHELL TOOLCHAIN BLOCKED`.  It never installs Go or changes PATH.

Only after reviewing those two CI jobs may the operator rerun the same manual
runner with `--ci-verified`; that switch is the explicit gate for the
aggregate `FULL PHASE 2A.5 PASS` verdict.

Packaged-host and external-host results must not be combined.  The current
compatibility record remains unchanged until the external normal-sandbox
patched shell passes and the result is reviewed.

## Desktop authentication preparation

The disposable infrastructure smoke uses a fresh `User Data` directory and
does not ask the operator to log in.  The authenticated Router UI gate uses a
separate persistent profile at:

```text
%LOCALAPPDATA%\Codex Subscription Router\_validation-profile\User Data
```

From an independently opened ordinary PowerShell, start the one-time
preparation workflow:

```powershell
Set-Location -LiteralPath 'E:\Projects\codex-subscription-router-for-windows'
.\scripts\windows\prepare_phase2a5_desktop_auth.ps1
```

The workflow builds the exact reviewed patched shell, keeps the normal
Chromium sandbox and `NONE` ACL strategy, and waits up to 15 minutes for the
user to complete normal ChatGPT login in the visible Router window.  It does
not read, copy, print, or automate credentials, cookies, local storage, or
official Desktop profile files.  The profile is preserved after the window is
closed or authentication is detected.

After authentication is detected, rerun the external validator with its
explicit CI gate:

```powershell
.\scripts\windows\run_phase2a5_host_validation.ps1 --ci-verified
```

If the preparation window is closed before login completes, the result remains
`ROUTER_DESKTOP_AUTH_REQUIRED`; this is a prerequisite result, not a Router
injection failure or a Phase 2B signal.

## Verdict policy

The runner uses the following Phase 2A.5 verdicts:

```text
FULL PHASE 2A.5 PASS
PHASE 2A.5 HOST CONTEXT BLOCKED
PHASE 2A.5 FILESYSTEM VIRTUALIZED
PHASE 2A.5 DIRECT HOST PASS
PHASE 2A.5 ACL FIX CONFIRMED
PHASE 2A.5 GPU SANDBOX REGRESSION
PHASE 2A.5 PATCHED SHELL BLOCKED
PHASE 2A.5 SOURCE REVIEW REQUIRED
PHASE 2A.5 SOURCE CHANGED DURING VALIDATION
PATCHED SHELL TOOLCHAIN BLOCKED
PHASE 2A.5 FAIL
```

`PHASE 2B` is not ready and must not be started automatically.

## Next manual operation

Both CI gates are now green.  From an independently opened ordinary
PowerShell, run the native validation with the explicit CI gate:

```powershell
Set-Location -LiteralPath 'E:\Projects\codex-subscription-router-for-windows'
.\scripts\windows\run_phase2a5_host_validation.ps1 --ci-verified
```

Do not add a second account, send a real chat, or begin Phase 2B.  Do not
launch this external-host validation automatically from Codex.
