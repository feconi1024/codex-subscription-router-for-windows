# Windows Phase 3: native features and maintainable installs

Status: implementation in progress on `codex/phase3-windows-parity`.

## Baseline and scope

Phase 2 closed at `2c91a93`. The final acceptance in
[WINDOWS-PHASE2-RECOVERY.md](WINDOWS-PHASE2-RECOVERY.md) supersedes the historical
failed attempt in WINDOWS-PHASE2-REPORT.md. Baseline: all Go package tests and
141 Python tests passed on 2026-09-08.

The upstream feature inventory includes quota routing, sticky ownership,
failover, account management, pooled/per-account profiles, Plugins/MCP account
selection, usage resets, Computer Use, Appshots, independent installation and
rebuild. The first seven retain Phase 2's implementation and require regression
testing. This phase implements the Windows installation and native integration
contracts without changing the official installation.

## Revised implementation sequence

1. Separate production Data from replaceable builds; generate compatibility
   documentation from the exact reviewed-source registry.
2. Audit the installed official Windows source, preserve its CUA/native helper
   loading contract, acquire a matching runtime, and validate native operations.
3. Add immutable side-by-side builds, a stable launcher and atomic current.json,
   fail-closed reconciliation, rollback, repair and diagnostics.
4. Add the per-user installer, explicit data-preserving uninstall, state DACLs,
   and optional signing of project-owned executables.
5. Run fixture/transaction tests, Windows regression tests, and differential
   two-account native acceptance. Do not equate static patchability or runtime
   detection with authenticated end-to-end acceptance.

## Decisions supported by the current source

- Store has advanced from reviewed 26.901.5280.0 to 26.901.6511.0. A new exact
  review is required; unattended updates must never use the development override.
- The official runtime resolver discovers resources/cua_node and derives both
  executable and module paths from it. Setting only a Node environment variable
  does not restore that complete contract.
- The staged runtime's manifest, Node and node_repl match the installed package;
  the Computer Use helper has a valid OpenAI signature. Router copies verified
  runtime bytes into its disposable build. It does not depend on shared staging
  paths surviving official cache cleanup, and does not modify WindowsApps ACLs.
- 26.901.6511.0 includes a Windows capture bridge and Windows Appshots handlers,
  but also an internal-build availability gate. Preserve that gate. Appshots
  cannot be labeled absent just because older planning assumed macOS-only;
  availability and operations must be compared with the official client.
- Production Data is never copied into binary backups. Existing Phase 2
  validation profiles remain in place; a new installation does not silently
  move or duplicate credentials. No signing certificate is assumed available.

## Acceptance gates

| Area | Required evidence | Current result |
| --- | --- | --- |
| Source review | Exact identity, anchors, integrity, immutable input | 26.901.6511.0 static review passes; see source report |
| Core | Phase 2 matrix on final build | Pending |
| Native runtime | Matching content, signatures, sandbox, helper lifecycle | Pending |
| Computer Use | Primary/secondary, sticky follow-ups, concurrency, recovery | Pending |
| Appshots | Official availability comparison and capture where available | Pending |
| Maintenance | Install, reconcile, interrupted update, rollback, repair | Native install, repair, rollback, rollback pin and running-process refusal pass; full matrix in progress |
| State | No credentials in builds; private DACLs; state survives update | Native private DACLs and sealed payload checks pass; authenticated persistence pending |
| Uninstall | Keep-data default; explicit purge; active-process refusal | Pending |
| Release | CI, source-only packaging, signing verification if configured | Pending |

## Implementation checkpoint

Production launcher supports a managed pointer and fixed Data root, retaining
the legacy validation launcher contract. A shared OS file lock serializes
launch admission with maintenance. State directories and token files use native
Windows owner/SYSTEM DACLs. Build activation requires a sealed inventory and a
passing isolated unauthenticated startup smoke; failed activation leaves the old
pointer intact. Rollback pins the selected version until an explicit update.
Reconciliation compares exact source, native CLI, Router tooling and control-token
digests. Runtime acquisition verifies the whole CUA tree and signatures, and
keeps official sandbox/code-mode siblings next to the CLI.

At this checkpoint all Go tests/vet and 163 Python tests pass. Official staged
Node/module resolution smoke passes. This is not native Desktop or two-account
acceptance. 26.901.6511.0 has an exact reviewed renderer binding, with all 33
replacement anchors matched and all five patched JavaScript assets passing
syntax checks. See [the source review](WINDOWS-PHASE3-SOURCE-6511.md).

The per-user installer, Start Menu ownership checks, optional project signing,
and persistent signing/native requirements are implemented. Native installation
testing found Store-host filesystem redirection and PowerShell ACL writes that
requested audit privileges. Initialization now reports redirected roots; private
state uses the DACL-only Windows API, with read-back verification.

On 2026-09-08, the current host's Computer Use JavaScript tool failed before
initialization with `failed to write kernel assets: ... (os error 3)`. Reset and
one retry produced the same result. The session was reset again; no UI input or
authentication occurred. This is a host-tool blocker, not evidence that the
Router helper passed or failed native operations.

On 2026-09-09, initialization recovered. A disposable local window passed
observation, click and text-entry checks through the official helper after app
access approval. Importing the copied JavaScript package still used the host's
official helper, so it is not counted as Router helper end-to-end acceptance.
Scratch windows were closed and the Computer Use session was reset.

Native managed installs of 26.901.6511.0 passed the isolated unauthenticated
renderer startup and graceful-exit checks without disabling the sandbox. A
real repair produced a second sealed build; rollback selected the earlier build,
launch-time reconcile returned `ROLLBACK_PINNED`, and the newer build could be
selected again. `doctor` passed payload, CLI signature, stable launcher, state
layout and private DACL checks with zero remaining processes. Running-process
maintenance refusal also passed. An explicit update of an unchanged pinned
build exposed a resume bug, now fixed with a regression test.

CI for commit `f112072` passed on both macOS and Windows. Final authenticated
account/native acceptance and CI for subsequent changes remain required.

After restoring the minimized test window on 2026-09-09, the authenticated
Codex-mode profile menu passed native observation and click checks. The Router
menu rendered one connected subscription and its usage. The diagnostic bridge
confirmed the renderer patch, mounted account menu, successful account loading,
`AUTHENTICATED` state, a ready profile controller and zero renderer runtime
errors. The second-subscription device sign-in entry also appeared. Completion
of that authentication, two-account routing and Router-originated Computer Use
remain pending. Earlier unknown authentication and minimized-window HTTP 500
results are not evidence of a missing renderer patch.

Generated host evidence belongs in ignored docs/generated. Never commit tokens,
profiles, OpenAI executables, ASAR archives or runtime payloads. Log out accounts
added during acceptance and release desktop control after each native test run.
