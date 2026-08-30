# Windows Phase 2A.6 source refresh

Phase 2A.6 refreshes the Windows Desktop MVP against the exact currently
installed source.  It records the source contract and compatibility evidence;
it does not promote the source to the final compatibility list or start
Phase 2B.

## Read-only source audit

The audited package root was:

```text
C:\Program Files\WindowsApps\OpenAI.Codex_26.825.5331.0_x64__2p2nqsd0c76g0
```

| Item | Observed value |
| --- | --- |
| Package | `OpenAI.Codex` |
| Package version | `26.825.5331.0` |
| Architecture | `X64` |
| Publisher | `CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B` |
| Authoritative desktop shell | `app\ChatGPT.exe` |
| ChatGPT.exe File/ProductVersion | `151.0.7922.174` |
| ChatGPT.exe Authenticode | `Valid`; OpenAI OpCo, LLC signer |
| Source `resources\app.asar` SHA-256 | `178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b` |
| ASAR header SHA-256 | `65349bb4cd49494d04898f0463f9d548fb77a86ba3c815231eebadad175427b6` |
| AppxBlockMap files | `5958`; parse error `null` |
| Bootstrap strategy | `environment-only`; audit PASS |
| Payload ACL strategy | `UNRESOLVED` until external native evidence |

The actual carrier audit found `chrome.dll` and a nine-fuse wire.  The
carried states were `EnableEmbeddedAsarIntegrityValidation=off` and
`OnlyLoadAppFromAsar=off`, so the resolved integrity state is
`FUSE_PRESENT_ASAR_VALIDATION_DISABLED`.  The audit found one carrier and no
embedded ASAR validation resource.  The official WindowsApps tree was read
only; no package file, fuse, ACL, or installation metadata was changed.

The bootstrap audit independently passed the user-data hook, updater
environment/removal strategy, guarded UI test bridge, and native-optional
Computer Use platform guard.  No macOS Computer Use patch was enabled.

## Renderer comparison and exact contract

`compare_renderer_contract(extracted, reference_variant="windows-26.820")` is
metadata-independent and read-only.  It reports evidence only and always
returns `patch_permission_granted=false` and `patchable=false`.

The 26.825 renderer is not byte- or identifier-identical to 26.820.  The
following surfaces were recorded as exact, separately reviewed adaptations:

- native profile menu and app-server bridge identifiers;
- profile statistics request;
- Usage modal, reset-credit query, reset-credit mutation, and Usage header;
- profile menu open-state hooks and usage slot;
- app/list, app/installed, app/read, MCP login, and MCP status wrappers;
- profile avatar, display name, and username/plan anchors;
- moved/renamed local-thread component and thread-summary insertion point;
- unchanged renderer CSP and subscription-depletion messages.

The exact renderer audit has 28 unique checks, including the profile, plugin,
thread, CSP, host-scoped RPC, Usage, and reset surfaces.  The implementation
uses the distinct `windows-26.825` contract and its exact source ASAR hash;
the `windows-26.820` contract remains unchanged.

## Reviewed-source registry

`scripts/windows/reviewed_sources.json` contains exact `PATCHABLE` records for
26.820 and 26.825.  A record requires package name/version, architecture,
ChatGPT file version, whole-ASAR hash, ASAR-header hash, renderer variant,
authoritative shell, bootstrap strategy, integrity state, and payload ACL
strategy.  Phase 2A.5 passes the record into the build gate.  A new or changed
source stops with:

```text
PHASE 2A.5 SOURCE REVIEW REQUIRED
```

The source identity retained in the diagnostic artifact includes the package
identity, architecture, ChatGPT version and hash, source root, executable,
ASAR path, ASAR hash, and ASAR-header hash.  The validator also re-reads this
identity after native validation and stops with:

```text
PHASE 2A.5 SOURCE CHANGED DURING VALIDATION
```

if the source disappears or any relevant fingerprint changes.

## Toolchain and operator boundary

The validator exposes `go_toolchain.selected`, `go_toolchain.usable`, and all
read-only probes.  It does not install Go or alter PATH.  Direct Probe A may
run without Go; before a patched-shell build, an unavailable toolchain yields:

```text
PATCHED SHELL TOOLCHAIN BLOCKED
```

After the implementation and CI gates pass, the remaining native operation is
manual and must be started from an independently opened ordinary PowerShell:

```powershell
Set-Location -LiteralPath 'E:\Projects\codex-subscription-router-for-windows'
.\scripts\windows\run_phase2a5_host_validation.ps1
```

Do not auto-run the patched shell, log in accounts, consume reset credits,
submit chats, or begin Phase 2B.  If the runner reports an actionable manual
operation, follow its printed instruction and report the resulting artifact.

## Final verdict vocabulary

The Phase 2A.6 review uses these explicit outcomes:

```text
FULL PHASE 2A.6 SOURCE REVIEW PASS
PHASE 2A.6 RENDERER ADAPTATION REQUIRED
PHASE 2A.6 BOOTSTRAP BLOCKED
PHASE 2A.6 INTEGRITY BLOCKED
PHASE 2A.6 FAIL
```

The current source passed the read-only bootstrap and actual-carrier audit and
required the exact renderer adaptation recorded above.  It is not added to
`docs/WINDOWS-COMPATIBILITY.md` by this source-refresh round.

## CI result

The local Python, JavaScript, and release checks pass.  The required remote
`checks` and `windows-go-core` jobs are run against the pushed commit and will
be recorded here before this round is closed.
