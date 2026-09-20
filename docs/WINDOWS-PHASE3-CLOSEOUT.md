# Phase 3 closeout attempt — 2026-09-21

Status: **INCOMPLETE; do not merge or claim native parity.**

This record distinguishes source-code checks from tests of the retained native
build. The retained build is `26.901.6511.0-e75bae2b-ce75edb120f2` and does not
contain the new installation-status menu or expanded diagnostics UI wiring.
Today's official installation is `26.915.4065.0`; the previous official 6511
source is no longer present. The new source audit reports missing renderer
anchors and has not been promoted into the reviewed registry.

## Completed in this attempt

- Added an authenticated, read-only installation-status endpoint. It exports
  allowlisted status values, not source paths, diagnostics or account data.
  The managed launcher supplies its installation root. The account menu shows
  when an unreviewed official update retains the previous build, and when
  Computer Use is unavailable while routing remains available. API and renderer
  behavior tests pass; these changes still require a compatible native rebuild.
- Extended `doctor` with current official-source review status, local port
  occupancy and maintenance readiness. Native acceptance remains explicitly
  unverified, independent of installed-payload health.
- Added transaction tests for unchanged source, reviewed newer source, changed
  CLI, unknown-source refusal, failed startup, native-required versus optional
  operation, and process termination before activation. Abrupt termination
  releases the OS lock and preserves the old pointer, payload and data.
- Tested the protected-copy primitive's byte preservation and overwrite refusal.
  This does not claim encrypted WindowsApps fallback acceptance.
- Exercised the real unknown-source update: 4065 was refused, the pointer was
  unchanged, and the retained 6511 build passed isolated unauthenticated startup
  and graceful exit with the sandbox enabled. Evidence:
  `docs/generated/phase3-unknown-source-e2e.json`.
- Created the real per-user Start Menu shortcut, checked its target and working
  directory, and removed the newly created shortcut. Existing shortcut ownership
  rules were preserved. Evidence: `docs/generated/phase3-shortcut-native.json`.
- Confirmed this Windows test process is not an elevated administrator. This
  establishes the context for these native checks, not a new clean-install pass.
- Added a Windows release checklist and a Windows CI dependency before creation
  of a source-only release draft. No version tag or release was created.
- Generated compatibility documentation now separates source patchability,
  Computer Use acceptance, Appshots status and overall Phase 3 acceptance.
- Current supervising Computer Use initialized and enumerated windows
  successfully. Its session was reset immediately afterwards. This supersedes
  the old supervising initialization failure as a current blocker; it does not
  establish Router child/helper parity.

## Remaining acceptance gates

| Gate | Remaining requirement |
| --- | --- |
| Final native build | Obtain the exact reviewed source or implement and review a new renderer contract for 4065; rebuild all final changes without bypassing the gate |
| Core regression | Two-account auth, Profile/Usage, Plugins/MCP scope, quota routing/failover/depletion, sticky ownership, subscription section and crash recovery on the final build |
| Computer Use | Router-originated pipe/helper lifecycle, primary/secondary operations, sticky follow-ups, sequential/concurrent use, crash/restart recovery and same-source official differential |
| Appshots | Actual official-versus-Router availability comparison, and operations only where officially available |
| Runtime fallback | Forced official-package/encrypted-copy path and native degraded-mode core/UI acceptance |
| Updates | Real reviewed-version upgrade, interrupted full official rebuild and final authenticated state-preservation regression; synthetic transaction tests are not substitutes |
| Installer | Final clean-user bootstrap-to-launch flow, final upgrade/repair and real-profile disposable purge; earlier native install/repair/keep-data reinstall results remain valid historical evidence |
| Signing | An existing valid private code-signing certificate; none is currently available. Do not manufacture a certificate or change trust settings to label this PASS |
| Release | Native acceptance, optional configured-signing verification, final evidence reconciliation and explicit release intent |

Both test accounts were logged out before this attempt. Authentication is a
manual user step; the assistant must not automate sign-in dialogs. No usage
reset credit is consumed merely to claim test completion. Source-only CI does
not replace these acceptance gates.
