# Security model

## Trust boundaries

- The official ChatGPT app is trusted build input and remains unchanged.
- The patcher has local filesystem and code-signing access by design.
- Each real Codex child is trusted with only its assigned account home.
- The injected renderer is trusted with the loopback control token.
- Other local users and remote origins are outside the control API boundary.
- Processes running as the same macOS user are not considered isolated from
  one another; they can already read that user's app data subject to macOS
  permissions.

## Credentials

OAuth material stays in `auth.json` under each account's Codex home. The
multiplexer reads an account token only to call the same authenticated ChatGPT
profile and rate-limit-reset endpoints used by the desktop experience. It does
not log or return tokens. State persisted by the mux contains account paths,
labels, enabled state, and thread ownership only.

The state root is mode `0700`; state, config, and control-token files are mode
`0600`. Existing control tokens are validated as 256-bit hexadecimal values and
their permissions are repaired on startup.

On Windows, Router state directories and token/state files use protected DACLs
granting access to the current Windows user and SYSTEM. Managed account and
desktop data live outside versioned builds. The account boundary is logical
isolation within one Windows user; it is not protection against that same user
or an administrator. The local renderer necessarily contains its loopback
control token; build inventories must not be published.

Plugin and MCP configuration is deliberately synchronized from the Primary
account so installed definitions remain consistent. Inline environment values
inside those definitions are therefore copied into every isolated account home
with mode `0600`; account isolation is not a separate secret boundary for
shared plugin configuration.

## Network

The control server binds to `127.0.0.1`. Private endpoints require the token
embedded into the independently built local renderer. Profile images must use
HTTPS. Response sizes and JSON request bodies are bounded.

The project itself does not provide a telemetry or update endpoint. Network
traffic beyond loopback is performed by the official Codex children or by the
documented ChatGPT profile and rate-limit APIs.

## Signing and native access

The source app is copied into a temporary staging directory. Native modules,
the Computer Use helper, Node runtime, mux, and final app are signed under one
selected Apple team and verified before replacement. Official OpenAI
application-group and keychain entitlements are removed from modified callers.

The native helper's caller allowlist is patched to the selected team and the
independent desktop bundle ID. This is required for the helper's peer checks;
it does not bypass macOS Accessibility or Screen Recording consent.

The Windows path preserves the official native helper and runtime bytes and
verifies their signatures and complete file inventory. It does not change the
helper protocol or bypass official feature gates. Optional Windows signing
applies only to the project launcher and multiplexer, with a user-supplied
code-signing certificate. A patched official desktop executable may no longer
have a valid original Authenticode signature; its reviewed ASAR integrity
metadata is updated locally and its sealed build inventory is checked during
maintenance. The official installation is never modified.

Windows updates create a new build, run an isolated unauthenticated startup
probe, and atomically select it only after validation. Unknown official sources
require review. Failed builds cannot be selected by rollback without a passing
seal. These checks detect accidental corruption; a locally writable manifest
is not a signature or a defense against an attacker already running as the user.

## Diagnostics

`CODEX_MUX_UI_TESTS=1` enables deterministic preview and screenshot endpoints.
They are unavailable during a normal launch, bind only to loopback, and require
the same control token. Release workflows never set this variable.

## Distribution

Releases contain source only. Publishing the patched `.app`, the official ASAR,
or any extracted OpenAI binary is outside this project's release process.
