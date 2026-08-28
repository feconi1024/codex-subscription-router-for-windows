# Windows Phase 2A.4 — Chromium Sandbox / ACL Validation

Status: `PHASE 2A.4 FAIL`

This phase adds bounded Chromium sandbox diagnostics, a read-only AppContainer
ACL audit, and a narrow remediation that is allowed only on a Router-owned
temporary `app` payload. It does not modify the official `WindowsApps`
installation and it does not persist Chromium sandbox bypass flags.

## Implementation gates

- For `OpenAI.Codex 26.820.7780.0`, `app\ChatGPT.exe` is the authoritative
  manifest shell. `app\Codex.exe` is retained as a diagnostic candidate and
  does not gate ChatGPT-specific verdicts.
- Chromium evidence records GPU child launch attempts, child exit codes,
  renderer-child failures, the fatal line, and raw matching log lines.
- The ACL audit records owner, SDDL/DACL data, protected-DACL state,
  inheritance, the two known AppContainer package SIDs, unknown
  `S-1-15-*` SIDs, and the access entries without mutating the filesystem.
- Remediation, when explicitly run, grants only exact inherited
  `(OI)(CI)(RX)` ACEs for `S-1-15-2-1` and `S-1-15-2-2` on
  `<Router smoke root>\app`, then verifies the readback. Runtime, `User Data`,
  and control-token state are excluded.
- The full patched shell is attempted only after a usable normal-sandbox
  ChatGPT probe. Its production command contains no `--disable-gpu-sandbox`
  or `--no-sandbox` argument.

## Native evidence collected

The source selected during the native run was the exact `OpenAI.Codex
26.820.7780.0` package, with `app\ChatGPT.exe` authoritative. The temporary
root was requested at:

```text
C:\Users\hehao\AppData\Local\Codex Subscription Router\_smoke\phase2a4-j34ky5jg
```

The Codex-hosted process resolved that path to the package-cache location:

```text
C:\Users\hehao\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\Codex Subscription Router\_smoke\phase2a4-j34ky5jg
```

The runner recorded `path_virtualized: true`, `native_evidence_usable: false`,
and therefore failed closed. The observed probe statuses were `PASS`, `PASS`,
and `PASS` for A (normal), B (`--disable-gpu-sandbox`, diagnostic only), and C
(ACL plus normal sandbox), respectively. Those statuses cannot be used to
claim a production ACL fix or a Windows GPU-sandbox conclusion because the
root was not the requested user-local path.

The narrow ACL operation itself returned `PASS` and readback verified both
known package SIDs, while the official source fingerprints remained unchanged.
The cleanup pass also encountered a permission error in a generated Codex
plugin-clone temporary file; this is another reason the run remains manual-
required rather than being treated as a release gate.

Runtime metadata collected read-only from the package was:

| Item | Value |
| --- | --- |
| Packaged app version | `26.820.60940` |
| Packaged Electron dependency declaration | `42.3.0` |
| ChatGPT.exe File/ProductVersion | `151.0.7922.170` |
| chrome.dll File/ProductVersion | `151.0.7922.170` |
| Host Windows build | Windows 25H2, `26200.9168` |

The official app directory, `ChatGPT.exe`, and `chrome.dll` are owned by
`NT AUTHORITY\SYSTEM`, have unprotected inherited DACLs, and do not contain
the two known package-wide AppContainer ACEs (`S-1-15-2-1` and
`S-1-15-2-2`). Each has two unresolved `S-1-15-3-*` capability SIDs. They are
recorded as unknown capabilities, not as malicious entries, and were not
modified. The local smoke mirror was `false/false` for the two known SIDs
before remediation and `true/true` after the narrow app-only remediation;
that readback occurred on the virtualized package-cache target and therefore
does not establish final-layout support.

The earlier Phase 2A.3 native evidence contained the GPU signature
`GPU process isn't usable`, `gpu_process_host`, `exit_code=-2147483645`, and
`0x80000003`. The Phase 2A.4 classifier recognizes that signature as
`BLOCKED_CHROMIUM_SANDBOX` and preserves the attempts, exit codes, renderer
failures, fatal line, and raw lines. The Phase 2A.4 virtualized-root run did
not reproduce a usable normal-sandbox failure, so no sandbox diagnosis is
promoted from it.

## Manual operation required

Run the Phase 2A.4 command from an ordinary non-AppContainer Windows process
running as the intended user, or from a Windows CI runner where
`%LOCALAPPDATA%` resolves to the real user-local directory. Do not grant broad
parent-directory access and do not run `takeown`, `icacls /reset`, or any
operation against `WindowsApps`. Rerun the matrix only after the report shows
`path_virtualized: false`, `native_evidence_usable: true`, and successful
cleanup.

Until that rerun and the disposable full patched-shell gates pass,
`docs/WINDOWS-COMPATIBILITY.md` is intentionally not updated to claim Phase
2A.4 support.

## Patched shell and CI result

The full patched-shell smoke was **not run**. It is correctly gated on
`native_evidence_usable: true`; the native final-layout root was virtualized
and cleanup was not usable on this host. The development-only bypass is also
not claimed or persisted.

For commit [`c668976`](https://github.com/feconi1024/codex-subscription-router-for-windows/commit/c66897655a85c3ce632618c74a29310b26db330c), both required CI jobs passed:

- `checks`: success
- `windows-go-core`: success

CI run: [33182217090](https://github.com/feconi1024/codex-subscription-router-for-windows/actions/runs/33182217090)

Therefore the final Phase 2A.4 verdict remains `PHASE 2A.4 FAIL`: code and CI
are green, but the required native final-layout and patched-shell evidence is
still blocked by this host’s AppContainer virtualization.
