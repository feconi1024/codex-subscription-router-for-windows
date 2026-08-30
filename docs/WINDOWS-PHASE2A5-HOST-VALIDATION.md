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
.\scripts\windows\run_phase2a5_host_validation.ps1
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
