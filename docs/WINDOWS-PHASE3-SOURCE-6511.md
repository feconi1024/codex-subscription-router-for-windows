# Exact source review: 26.901.6511.0

The source contract is recorded in scripts/windows/reviewed_sources.json.
The renderer binding is renderer_26_901_6511.json: five exact asset hashes,
33 replacements, and the renderer CSP. All 39 audit rows pass and all five
patched assets pass Node's syntax parser. Bootstrap startup-chain and actual
ASAR-integrity carrier audits pass. Before/after source identity is stable.

The binding was reviewed against the installed source, including these changes
that cannot be recovered by blindly renaming identifiers:

- The native menu value is usageItems:Dt; the other usageItems occurrence is
  the menu component's destructured parameter and must not be replaced.
- The reset modal is tq, with Qon memoization; the modal scope is zx(qv),
  opened through QC. Query-client access is Cx.
- The profile data query is M, while B now names a mutation. Profile selection
  must call M.refetch(), not the old binding's B.refetch().
- Settled local-creation failure now stores M; the projectless path still
  stores N. Both retain the correct callback's t.message.
- Thread ownership reads Fo(Mr). The native sources component remains Zw.
- React/JSX, menu components, usage icon and authenticated avatar URL resolver
  were checked in their defining module before retargeting the injected UI.

Native capability review found resources/cua_node as the shared source for
Node, node_repl, @oai/sky and the Windows capture bridge. The staged runtime
identity is b474a88d5d105afa, matching the manifest/Node/REPL fingerprints of
this official package. Executable signatures validate as OpenAI. Node can
resolve @oai/sky from that runtime.

Windows Appshots code exists, including capture, frontmost-window and hotkey
handlers. Current source disables appshotsEnabled for non-internal Windows
builds. Router preserves that official availability decision; no feature gate
or consent is bypassed.

PATCHABLE records source review only. Native Desktop, two-account Computer Use,
Appshots availability comparison, and complete Phase 3 acceptance are pending.
Local detailed audit artifacts remain under ignored docs/generated.
