# Windows Desktop MVP — Phase 2 Round 2 E2E Validation Report

Date: 2026-08-28  
Branch: `codex/windows-desktop-mvp`  
Validation scope: native Windows Desktop MVP only; Phase 3 work and Computer
Use/Appshots/sandbox-helper work are out of scope.

This report records the Round 2 validation attempt. The repository checks and
local helper tests ran successfully, but the native Desktop E2E entry artifact
was not available on this host. No unsupported protected-install workaround
was used, and no OAuth token or unmasked account credential was collected.

## Environment

| Item | Result |
| --- | --- |
| Host OS | Windows 10 Home China, 25H2, build `26200.9168` (as recorded by the Phase 1 host report) |
| Python | `3.11.5` (`C:\Python311\python.exe`) |
| Node.js | `v24.15.0` |
| npm | `11.12.1` |
| Go | Not installed (`go` and `gofmt` were not found) |
| Branch | `codex/windows-desktop-mvp` |
| Starting worktree | Clean; no unrelated changes were present |

The official Windows app was visible to the native app enumerator as
`OpenAI.Codex_2p2nqsd0c76g0!App` with a `ChatGPT` window. It was not operated
by this validation because the patched local app was unavailable.

Repository checks completed locally:

| Check | Result |
| --- | --- |
| `python -m unittest discover -s scripts/tests -p "test_*.py" -v` | PASS — 11/11 |
| `python -m compileall -q scripts` | PASS |
| `node --check` for the three patched UI files | PASS |
| `python scripts/check_release.py` | PASS — v0.1.0 metadata consistent |
| `git diff --check` | PASS |
| `go test ./...` | NOT RUN — Go toolchain unavailable |
| `go vet ./...` | NOT RUN — Go toolchain unavailable |
| Windows launcher build | NOT RUN — Go toolchain unavailable |

## Official source metadata

No exact source package metadata could be recorded in this round.

The current-user `Get-AppxPackage` query returned no accessible matching
OpenAI/ChatGPT/Codex package. The `-AllUsers` query was access denied. The
known per-user package-data directories were present, but read-only searching
found no `ChatGPT.exe` and no `app.asar`:

```text
C:\Users\hehao\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0
C:\Users\hehao\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0
```

Accordingly, the following values remain **not observed**:

| Field | Result |
| --- | --- |
| AppX package name/version/architecture | Not accessible |
| Official `ChatGPT.exe` or legacy `Codex.exe` file version | Not observed |
| Official `resources\\app.asar` SHA-256 | Not observed |
| Real Windows Desktop renderer anchor audit | Not run |

The validated per-user native Codex runtime was available as a separate input:

| Field | Value |
| --- | --- |
| Path | `C:\Users\hehao\AppData\Local\OpenAI\Codex\bin\d0097be4feba73d0\codex.exe` |
| `--version` | `codex-cli 0.150.0-alpha.8` |
| SHA-256 | `09D6723925E724EDF0BBBBC7B9E204526E0FB1462C86BD2A4997311FD5071EBA` |
| Authenticode | `Valid` |
| Signer | `OpenAI OpCo, LLC` |

This binary was only inspected and version-checked. It was not used to claim
that the Desktop package itself was available or validated.

## Local staged build metadata

No Round 1 staged build was present at any expected location:

```text
C:\Users\hehao\AppData\Local\Codex Subscription Router
E:\Projects\codex-subscription-router-for-windows\dist
E:\Projects\codex-subscription-router-for-windows\build
E:\Projects\codex-subscription-router-for-windows\staging
```

Therefore there was no local `Codex Subscription Router.exe`,
`app\\ChatGPT.exe`, `resources\\app.asar`, `runtime\\codex-mux.exe`,
`runtime\\codex.real.exe`, or `metadata.json` to hash or launch. The Windows
staging command was not run without an exact source package.

## Fuses

No official or staged Windows executable was modified. The real fuse audit was
therefore **NOT RUN**.

The existing synthetic Electron fixture tests passed. They verify that the
development fuse writer changes only the ASAR-integrity fuse and preserves the
other fuse values; this is fixture evidence, not evidence about the missing
official Windows PE.

## Launcher/env

The launcher source and unit-test contract are present in the branch, but the
Windows launcher could not be built or executed locally because Go is absent.
No runtime environment was observed. The intended launch contract remains:

```text
Codex Subscription Router.exe
  -> app\\ChatGPT.exe (or legacy app\\Codex.exe)
     CODEX_CLI_PATH=runtime\\codex-mux.exe
     CODEX_MUX_REAL_CODEX=runtime\\codex.real.exe
     CODEX_MUX_DESKTOP_USER_DATA=User Data\\
```

`CODEX_HOME` is intended to be preserved, and an inherited Chromium
`--user-data-dir` is intended to be replaced by the isolated Router profile.
`CODEX_MUX_UI_TESTS=1` was not used because there was no local app to launch.

## Startup

**NOT RUN.** The required local `Codex Subscription Router.exe` was absent, so
there was no safe target for native launch, startup timing, loopback readiness,
or stale-port testing.

## Account UI

**NOT RUN.** The following could not be validated without the patched local
Desktop surface:

- Codex surface and account menu;
- Primary account selection;
- adding/authenticating a second subscription;
- avatars, labels, masked email, plan, and pooled usage.

The official app was not changed or used as a substitute for the patched app.

## Profile

**NOT RUN.** Combined profile view, per-account profile data, switching back to
Primary, and duplicate-profile checks were not observable.

## Plugins

**NOT RUN.** Primary/Secondary plugin and MCP scoping could not be checked.

## Usage

**NOT RUN.** No reset selector was opened, no real reset was consumed, and the
`CODEX_MUX_UI_TESTS` preview path was not exercised. The planned depleted
Primary simulation was not attempted.

## Routing

**NOT RUN.** No loopback API, mux request, or Desktop Codex request could be
observed. No claim is made about GUI routing behavior.

## Sticky ownership

**NOT RUN.** No real GUI chat or follow-up was created. Consequently, chat
ownership, the non-depleted-account indicator, `state.json`, sticky follow-up
behavior, preview clearing, and normal-thread creation remain unvalidated.

Because no real message was sent, no representational communication occurred
in this round.

## Persistence

**NOT RUN.** The Router could not be restarted, so isolated user-data
persistence, account/profile restoration, and duplicate-profile behavior were
not checked.

## Lifecycle

**NOT RUN.** Normal quit cleanup, abnormal local `ChatGPT.exe` termination,
`codex-mux`/`codex.real` descendant cleanup, relaunch behavior, and port 48123
stale-process/conflict handling were not checked. No unrelated official
processes were terminated.

## Unified shell smoke

**NOT RUN.** The native ChatGPT/Codex shell could not be launched from the
Router. The requested scope remains limited to Codex routing; this report does
not claim Chat/Work multi-subscription support.

Computer Use, Appshots, and the Windows sandbox helper were not tested, as
required by the MVP scope. Their unsupported status was not changed.

## Limitations

Manual operations are required before the Desktop matrix can continue:

1. Provide an accessible exact Windows package/app directory containing
   `app\\ChatGPT.exe` (or legacy `app\\Codex.exe`) and
   `app\\resources\\app.asar`, or provide the completed Round 1 staged build
   at `%LOCALAPPDATA%\\Codex Subscription Router`. Do not change
   `WindowsApps` ACLs or take ownership for this purpose.
2. Provide/install a local Go toolchain if local `go test`, `go vet`, and
   launcher-build evidence is required; otherwise those checks remain CI-only.
3. If the second-account test reaches device-code authentication, a human must
   complete that confirmation. Authentication dialogs will not be automated.
4. Before a real GUI chat is sent, the user must confirm the representational
   send action at that point. The current round sent no messages.

## Official-install integrity

No protected WindowsApps ACL or ownership change was attempted. No official
package file, official executable, official `app.asar`, updater, or official
user-data directory was written by this round. No updater test was run because
the local Router build was absent.

## Verdict

**PHASE 2 FAIL — blocked before native Desktop E2E execution.**

The implementation-level Windows helper tests and static checks pass, but the
required exact Windows Desktop source and local patched executable are absent,
and the Go launcher/runtime build could not be reproduced locally. A
`FULL PHASE 2 PASS` is not justified. Resume Round 2 after the manual artifact
and toolchain prerequisites are available; do not begin Phase 3 based on this
report.
