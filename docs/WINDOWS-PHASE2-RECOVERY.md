# Windows Desktop MVP recovery review

Date: 2026-09-06. Baseline: `main@ce706f6` and
`codex/windows-desktop-mvp@496eabc`.

## Decision and acceptance scope

Continue on `codex/windows-desktop-mvp`. It descends from `main`; the branch
adds the Windows launcher, source acquisition, controlled mirror, shared
renderer patching and native validation. Earlier host evidence establishes
that the launcher/mux/real-Codex chain can run. Rebuilding from `main` would
discard that work without addressing the observed defects.

Phase 2 remains the complete independent Windows Desktop MVP, not merely a
successful Phase 2A.5 transport or menu probe. Acceptance includes:

- An isolated patched Desktop, unchanged official installation, normal sandbox
  and a native `CODEX_CLI_PATH -> codex-mux.exe -> codex.real.exe` chain.
- Two separately authenticated subscriptions; add/login/logout and account UI.
- Combined/per-account Profile, Usage/reset selection and Plugins/MCP scoping.
- Real GUI thread creation, routing, sticky follow-up and depletion preview.
- Restart persistence, normal/abnormal exit cleanup and absence of stale ports.

Computer Use, Appshots, installers, signing and automatic Store-update rebuilds
remain outside this phase. No full Phase 2 pass is claimed by this document.

## Findings supported by code and source inspection

1. `run_patched_shell_smoke` stopped fetching app state after the first
   transport-READY response. A successfully captured loading frame could be
   reused for the entire timeout. It now fetches a fresh observation every poll.
2. Both renderer and bridge inferred AUTH_REQUIRED from a completed document
   with an empty root. Missing UI is now UNKNOWN. Cached auth is no longer used
   to replace a live UNKNOWN observation.
3. Router-menu mounting supplied the authenticated marker even though opening
   that menu required authentication. That circular dependency was removed.
4. Native profile-host presence is also insufficient proof: the reviewed host
   renders sign-in choices. The 26.901 adapter observes the native AuthProvider's
   loading/auth-method/requires-auth state through an unconditional lifecycle
   hook before opening the menu. Unmount removes its evidence and controller.
   Explicit login routes retain precedence. Older source bindings retain their
   existing composer/controller positive evidence, without the negative rule.
   `requiresAuth` is the provider requirement, not a signed-out flag: the native
   provider keeps it true with ChatGPT credentials. A resolved `chatgpt` method
   is positive evidence regardless of that flag; a regression covers this case.
5. Current Electron separates the ASAR-validation fuse in `chrome.dll` from
   `INTEGRITY/ELECTRONASAR` in `ChatGPT.exe`. The planner now inventories resource
   targets separately and updates/readbacks the staged executable's ASAR header
   digest while preserving the fuse carrier. It does not disable validation.
6. An explicit source removed by a Store update returned `None` and then caused
   an AttributeError before writing a new result. It now returns a failed source
   diagnostic. Never interpret an older result file as evidence for a crashed run.

## Exact 26.901 source bindings

The installed version changed from 26.901.4073.0 to 26.901.5280.0 during the
operator interruption. The latter was copied through the controlled mirror
into the ignored `build/OpenAI.Codex_26.901.5280.0_x64__2p2nqsd0c76g0` directory,
with matching original/copied ASAR SHA-256. Validation uses that fixed input.

| Source | ASAR SHA-256 |
| --- | --- |
| 26.901.4073.0 | `689a59eccd6b4d38f3ddaf202dac05b7cf5ca9cba93b2703f7aa8a44be90b23e` |
| 26.901.5280.0 | `6579c4326cccdb508d079ecc878ad4725451b2234370d2ed9d4db53939cf99c7` |

The manifest files in `scripts/windows/renderer_26_901*.json` record hashes of
all five modified input assets and exact replacement anchors per binding.
Every hash and anchor is checked before renderer mutation. The installer still
requires the full reviewed package identity; recognizing a renderer is not
authorization to patch an unknown package.

The profile host and Usage dialog moved to `app-primary`. The app-server,
profile-query and reset-query code remains in `app-initial`. The initial module
gets a React-independent plugin-scope adapter because it can send requests
before the primary module is loaded. Profile, Plugins and thread UI live in
their own chunks. The thread ownership row wraps the source section so that a
thread without external sources can still show its subscription owner.

React-compiler caches are significant: the Usage parent must re-evaluate the
selected account, and its content remounts on account change. Merely replacing
global values would leave a memoized native dialog showing the previous account.

## Validation evidence and remaining work

- Go package tests and `go vet ./...`: passed locally.
- JavaScript behavior tests cover empty/loading roots, stale saved auth, login
  route precedence, native authentication without menu mounting, and teardown.
- The polling regression transitions from transport READY/auth UNKNOWN through
  authentication and delayed account loading, with exactly one menu activation.
- A real PE resource fixture verifies split-carrier resource update/readback and
  unchanged DLL bytes. Missing-source diagnostics have a separate regression.
- Both exact source bindings passed Node parsing after applying their complete
  five-asset renderer patch. This is syntax evidence, not runtime acceptance.
- Python suite: 139 tests passed, plus two new exact-contract tests passed.
  The latter verify complete operation/hash coverage and rejection before any
  write if a later input asset has been tampered with.
- The 26.901.5280.0 native run passed the pristine normal-sandbox probe and
  `PATCHED_SHELL_PASS`. It reported `AUTHENTICATED`, one loaded account,
  successful profile-menu activation/mount, zero renderer errors, and all nine
  production gates passing, including cleanup. Evidence is in the ignored
  `docs/generated/phase2-recovery-5280-host.json` artifact.
- This run used harness cleanup; it does not establish the separate full-MVP
  normal-exit/restart acceptance matrix. No reset credits were consumed and no
  new account was logged in. The existing persistent profile has one account;
  the operator must authenticate a second before the two-account GUI matrix.
- CI must be checked against the pushed revision. Full Phase 2 acceptance is
  still pending two-account add/login/logout, Profile/Usage/reset selection,
  Plugins/MCP scope, real GUI routing/stickiness/depletion preview, and restart
  persistence plus normal/abnormal exit checks.

No account was authenticated by the agent during implementation. Any accounts
authenticated for interactive acceptance must be logged out at session end, as
required by this repository's AGENTS.md. Existing validation credentials are
not copied into reports, source snapshots or release artifacts.

## Two-account acceptance follow-up

The operator authenticated a second account for the interactive follow-up.
Both accounts were confirmed connected through the isolated Router. The
earlier single-account evidence above remains a historical result.

Interactive checks found and corrected three account-selection defects:

- Profile plan badges now follow the selected subscription. Combined mode
  identifies itself explicitly, and native edit/share actions are available
  only when viewing the primary account, whose credentials those writes use.
- Plugin selection cancels outstanding connection queries and clears their
  caches before loading the other account. The primary account's Apps list
  disappeared when selecting the second account and returned when selecting
  the primary. MCP entries also differed between the accounts, while shared
  plugin installations remained visible.
- Leaving the second account's Profile page now clears the selection and
  refetches the shared native profile cache, preventing its identity from
  lingering in the sidebar. This final correction has a behavior regression
  test; its rebuilt GUI verification is pending.

The follow-up JavaScript suite has five passing behavior tests. Go tests and
vet pass. The Python suite reports 141 tests with three bridge tests initially
skipped because the native test bridge occupied their port; all three passed
when rerun after the native process cleanup. Full acceptance remains pending real task
routing, subsequent-turn ownership, depletion/reset previews, lifecycle
checks, and logout of the account added for this session. No real reset credit
has been redeemed.
