# Windows Phase 1 Core Feasibility Report

Tested on 27 August 2026 against the native Windows build in this worktree.

## Environment

| Item | Tested value |
| --- | --- |
| Windows | Windows 10 Home China, 25H2, build `26200.9168` |
| CPU architecture | `AMD64` / x86_64 |
| PowerShell | `7.6.4` |
| Go | `1.26.0 windows/amd64` |
| Control service | Loopback port `49231` with a temporary test token |
| Test root | `C:\Users\hehao\AppData\Local\Temp\codex-mux-phase1-20260827` |

The official installation and the production `C:\Users\hehao\.codex` home were
treated as read-only test inputs. No WindowsApps ACLs, package files, official
executables, application archives, or production credentials were changed.

## Tested commit / working tree

- Branch: `codex/core-adaptation`
- HEAD at test start: `72a4b3611a1f29d781cab7452eec6bedd887ec52`
- The only pre-existing worktree change at test start was the user's `AGENTS.md`
  ignore entry in `.gitignore`.
- Native testing exposed a missing `prefix` declaration in
  `internal/backend/child.go`. The one-line correction was applied in the
  worktree and the complete Go validation was rerun successfully.
- This report and the narrow source correction are intentionally uncommitted;
  the test instructions said not to commit unless explicitly requested.

## Official Codex binary

The test used this OpenAI-signed Windows Codex executable:

`C:\Users\hehao\AppData\Local\OpenAI\Codex\bin\d0097be4feba73d0\codex.exe`

- Authenticode status: `Valid`; signer: `OpenAI OpCo, LLC`
- SHA-256: `09D6723925E724EDF0BBBBC7B9E204526E0FB1462C86BD2A4997311FD5071EBA`
- `--version`: `codex-cli 0.150.0-alpha.8`
- `app-server help` and `app-server generate-json-schema --out <temp-dir>`
  both worked; the latter produced 292 schema files.

AppX/WindowsApps enumeration was permission-blocked, and no ACL or ownership
changes were attempted. The OpenAI-signed per-user binary above was executable
and served as the official Windows app-server test input. Exact Store packaging
layout remains a pre-Phase-2 deployment question.

## Automated Go validation

| Test | Result | Evidence | Notes |
| --- | --- | --- | --- |
| `go test ./...` | PASS | All repository packages passed natively on Windows | Required one-line `child.go` correction was included in the rerun |
| `go vet ./...` | PASS | Exit code 0 | No findings |
| Windows build | PASS | `codex-mux.exe` built as `windows/amd64` | Output was written only to the isolated test root |

## Passthrough test

PASS. With `CODEX_MUX_REAL_CODEX` set to the official executable, direct and
muxed `--version` output matched, and direct and muxed `app-server help` output
matched byte-for-byte. The temporary adjacent-fixture test also confirmed that
`codex-mux.exe` resolves `codex.real.exe` when the explicit override is absent.

## App-server initialization

PASS. A long-lived `codex-mux.exe app-server` process was driven over stdin by
the JSON-RPC harness. Initialization accepted the schema-derived minimal
`clientInfo` payload and returned:

- `platformFamily: windows`
- `platformOs: windows`
- the isolated primary `codexHome`
- the expected official Codex user-agent/version

The real child app-servers remained alive after initialization. Both account
children were independently initialized after restart as well.

## Control API

PASS.

- `GET /v1/health` returned `{"ok":true}`.
- Protected `GET /v1/accounts` returned `401` without the token.
- The same route succeeded with the temporary `X-Codex-Mux-Token`.
- Account snapshots exercised real `account/read` and
  `account/rateLimits/read` requests through the child processes.

## Primary login

PASS. Device-code authentication completed manually through the official
verification page. The isolated Primary snapshot reported `connected=true`,
`authType=chatgpt`, plan metadata `Plus`, rate-limit metadata, and no account
error.

## Secondary login

PASS. A second isolated account was created through `POST /v1/accounts`, its
child app-server started, and its generated configuration contained exactly the
two intended non-secret settings:

```toml
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"
```

Device-code authentication completed manually for the second account. Both
accounts then reported `connected=true`, `authType=chatgpt`, and no error. The
two authenticated identities were compared internally without displaying
either email address and were distinct. The secondary plan metadata was
`Free`.

## Account isolation

PASS. The Primary and secondary `CODEX_HOME` paths were different temporary
directories. Both temporary homes contained their own authentication file;
credential contents were never read or printed. The production auth-file path
was inspected only for filesystem metadata, not contents, and was not a target
of the test harness. The persisted mux state contained two account definitions.

## Rate-limit RPC

PASS. Live account snapshots returned rate-limit data for both connected
accounts. With `CODEX_MUX_UI_TESTS=1`, the authenticated preview endpoint also
passed:

- `single_depleted` marked only Primary as depleted.
- `all_depleted` marked both accounts depleted and emitted the expected
  legacy-depletion metadata.
- `clear` restored live rate-limit values after the test.

## New-thread routing

PASS. With Primary simulated as depleted, a real minimal `thread/start` request
through the mux created a thread on the non-depleted secondary account. The
control API identified the same account as the thread owner, and the persisted
thread count reflected the assignment.

## Sticky ownership

PASS. A minimal real turn returned exactly `OK`. A follow-up on the same thread
returned exactly `STICKY_OK` and remained owned by Primary, proving that an
existing thread's owner takes precedence over a new quota choice.

## State persistence

PASS. After the first run was stopped, the mux was restarted with the same
isolated homes and state root. A fresh initialize succeeded; both accounts were
rediscovered as connected, both account snapshots still had rate-limit data,
and both previously recorded thread-to-account owner mappings were intact.

## Process shutdown

PASS. On normal mux termination, the mux process and each direct official
`codex.exe app-server` child started by the test exited. A pre-existing official
Codex process remained alive and was not touched. No test-attributable direct
child remained after either shutdown check.

## Failures / deviations

| Item | Result | Details |
| --- | --- | --- |
| Initial sandbox device-code request | PARTIAL | Outbound authentication was blocked by the restricted sandbox; the network-enabled isolated run then completed successfully. |
| First restart invocation | PARTIAL | The harness initially omitted the `app-server` argument, which opened the official CLI TUI; it was interrupted without changing state and rerun correctly. |
| Official plugin startup | PARTIAL | The official child emitted non-fatal temporary-path, GitHub rate-limit, and Windows filename-length warnings while syncing bundled plugins. Core RPC and routing remained healthy. |
| PowerShell shell snapshot | PARTIAL | The official app reported that shell snapshots are not yet supported for PowerShell; this did not affect app-server protocol tests. |
| AppX package enumeration | NOT TESTED | Protected WindowsApps metadata could not be read normally; no ACL changes were attempted. The signed per-user official binary was tested instead. |

## Deferred risks

Before Phase 2, validate the exact Microsoft Store/Desktop package layout and
launcher wiring, including ASAR/resource parity, profile/home isolation,
Windows ACL hardening, self-update behavior, and packaging of the adjacent
`codex.real.exe` contract. Process termination currently guarantees direct
child cleanup via Windows process termination; deeper descendants should be
revisited with Job Objects if later Desktop integrations create them. Computer
Use, account-menu UI, installer work, and GUI integration were not part of this
round.

## Conclusion

**FULL PHASE 1 PASS**

The Windows-native `codex-mux.exe` successfully operated in front of the real
OpenAI-signed Windows Codex app-server. The test established working
passthrough, initialization, authenticated control APIs, isolated two-account
homes, independent account RPCs, deterministic failover, sticky thread
ownership, all-depleted behavior, state persistence, and direct child cleanup.
There is enough evidence to begin Phase 2 Desktop integration, subject to the
packaging and deferred-risk checks above. No Phase 2 implementation was done in
this round.
