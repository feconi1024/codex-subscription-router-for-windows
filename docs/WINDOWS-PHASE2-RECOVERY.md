# Windows Desktop MVP recovery review

Date: 2026-09-06. Baseline: `main@ce706f6` and
`codex/windows-desktop-mvp@496eabc`.

## Final acceptance status — 2026-09-08

Full Phase 2 acceptance is complete for the reviewed Windows Desktop source
26.901.5280.0 on this host. After verification of the accepted commit's CI
and native evidence, `codex/windows-desktop-mvp` was merged into `main`
on 2026-09-08 with explicit operator authorization.

The entries below this status section preserve the investigation history;
their earlier pending statements describe those checkpoints.

| Requirement | Result |
| --- | --- |
| Isolated Windows Desktop, integrity enforcement, native mux chain | PASS on reviewed 26.901.5280.0 |
| Two-account add and operator authentication | PASS |
| Combined and per-account Profile, Usage, reset selection | PASS |
| Reset count first load and refresh after simulated redemption | PASS |
| Account-scoped Apps and MCP connections | PASS |
| Real task routing and sticky follow-up | PASS |
| Depletion advice with and without a known reset time | PASS |
| Persistence across crash, restart, and rebuild | PASS: both connections and all existing ownership entries retained |
| Normal and abnormal exit cleanup | PASS: zero isolated processes and control listeners |
| Secondary-account logout through the desktop menu | PASS: session-added account disconnected; primary retained |

Local verification: nine JavaScript behavior tests and 141 Python tests pass.
Go tests and vet passed earlier and are also checked by CI. Real reset credit
redemption was never performed; the UI flow used explicit test-only credits.
The official installation and its existing session were not modified.

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
remain outside this phase.

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

### Real task routing

The operator-unlocked desktop was used to submit minimal fixed-response tasks
through the real editor. With a test-only primary-account depletion preview,
the new task returned `ROUTER_PHASE2_OK` and displayed the second subscription
as owner. After clearing the preview, a subsequent message in the same task
returned `ROUTER_STICKY_OK` and retained that owner. A new task under normal
quotas returned `ROUTER_NORMAL_OK` and selected the primary subscription.
Persisted ownership metadata agreed with the visible subscription rows.

The native model selector automatically migrated the selected, retired
GPT-5.4 Mini to GPT-5.6 Luna. The routing assertions concern subscription
ownership, not the model alias.

The all-account depletion preview exposed another integration defect: the
backend returned an actionable depletion message, but the pending-task page
discarded it and displayed only "Could not start this chat". Both reviewed
renderer bindings now preserve recognized depletion messages through settled
and thrown creation failures. The page displays that message, including the
reset time when supplied, and retains the native back/retry action. Other
errors continue to use the native generic message. Memoization tracks the
pending state, including its error text. Native verification of this final
correction passed native verification: the failure page displayed the
add-subscription/wait advice and, in a separate test, the exact supplied
local reset time. The back action restored the draft without submitting it.

### Reset, profile teardown, and normal exit

The native Usage dialog showed separate primary/secondary account selectors.
With explicitly configured test credits (primary zero, secondary one), the
second account's confirmation flow displayed a successful reset and its
available count became zero. The control API confirmed that only the second
account's test count decreased. Both accounts were in preview mode, so no
real reset credit could be redeemed by this test.

This revealed a stale count in the selector above the native reset panel.
Successful redemptions now notify the selector to reload its account counts;
the redemption itself is never retried by this refresh. Seven JavaScript
behavior tests and all 141 Python tests pass. Rebuilt GUI verification of the
selector refresh is pending.

The Profile teardown correction passed visually: after viewing the secondary
profile and returning to the task, the sidebar restored the primary identity.
The application File > Quit action also passed: after shutdown completed,
there were zero processes under the isolated shell directory and no listeners
on either test/control port. Abnormal exit and final account logout remain.

### Selector memoization follow-up

The rebuilt redemption flow still left the selector at one while the native
panel showed zero. The native modal memoizes its heading, so refreshing the
outer hook did not replace the cached selector element. Reset counts now live
inside the selector component, which subscribes to successful redemptions and
ignores obsolete responses and responses after unmount. This also fixes the
initial count remaining unavailable until the account selection changed.
Eight JavaScript behavior tests and all 141 Python tests pass. Native
verification of this additional correction is pending.

The abnormal-exit check passed: terminating only the isolated Electron main
process caused the launcher, mux, and children to exit automatically. The
subsequent inventory found zero isolated processes and zero listeners on
48123/48124. No child process was manually terminated in this check.

The selector correction passed native verification on 2026-09-08: first load
showed primary zero/secondary one without changing selection; redeeming the
secondary test credit updated both the selector and native panel to zero.
The rebuilt host probe passed all nine production gates with two accounts and
zero renderer errors (`phase2-selector-owned-host.json`). Commit `791d623`
also passed GitHub CI. Restart preserved both connections, the two visible
acceptance tasks, and all nine existing ownership entries; the harness added
one additional ownership record.

Final logout inspection found that the secondary account row had no logout
action despite backend support. The menu now gives each connected secondary
subscription an explicitly labeled logout action, refreshes the connected
account list on success, and displays request failures. A regression verifies
that only the selected secondary account receives the logout request and the
primary remains in the connected cache. Native verification and final logout
of the session-added account are pending this rebuild.

### Final closure

Commit `678b7da` passed GitHub CI and the rebuilt native host probe
(`phase2-final-logout-host.json`): all nine production gates passed, two
accounts loaded, and zero renderer errors were recorded. The desktop menu's
`Log out Subscription 2` action then succeeded. The menu showed one connected
subscription, the secondary account reported disconnected, and its actual
`codex-home/auth.json` was absent. The primary connection predated this
session and was retained.

The final graceful exit completed with zero processes under the isolated
shell and zero listeners on 48123/48124. All in-memory quota/reset previews
were cleared by the intervening shutdowns; the final logout run used normal
quotas. Local evidence is recorded in `final-logout-result.json`,
`final-cleanup-result.json`, and `persistence-final-result.json` under the
ignored `docs/generated` directory. Generated evidence and authentication
material are not committed. The final status table supersedes the historical
pending entries above.
