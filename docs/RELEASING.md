# Releasing

Releases are source-only. Never attach a patched app, ASAR, extracted official
file, signing certificate, provisioning profile, or account data.

1. Update `VERSION`, `package.json`, and both version fields in
   `package-lock.json`.
2. Move changelog entries from Unreleased into `## [x.y.z] - YYYY-MM-DD`.
3. Record the tested official app version, build, architecture, and ASAR hash in
   `docs/COMPATIBILITY.md`.
4. Run `npm ci --ignore-scripts`, `npm run check`, and
   `npm run release:check` on macOS.
5. Complete `docs/SMOKE-TEST.md` with a team-backed signature and record the
   exact commit, macOS version, and signing team in the release draft.
6. Review `git diff --check` and confirm no ignored credentials or app bundles
   are staged.
7. Configure the protected `release` environment, tag the reviewed commit as
   `vX.Y.Z`, and push the tag.

The release workflow verifies that the tag matches `VERSION`, repeats all
checks, and creates a draft GitHub source release with generated notes. Review
the draft and smoke-test record before publishing it manually.

## Windows release gate

Windows source releases additionally require the tag's Windows checks and a
local native acceptance record. CI uses synthetic package/runtime fixtures;
official executables and credentials never enter CI. A passing CI job does
not establish native feature parity.

1. Record the exact commit, Windows version, architecture, official package
   identity and ASAR digest in `docs/WINDOWS-PHASE3.md`. Update the reviewed
   source registry only after reviewing the exact source. Generate compatibility
   documentation with `python -m scripts.windows.generate_compatibility`.
2. Run `go test ./...`, `go vet ./...`,
   `python -m unittest discover -s scripts/tests -p "test_*.py"`,
   `node --test scripts/tests/desktop_auth.test.cjs`, `npm run check:js`,
   `python -m compileall -q scripts`, and `python scripts/check_release.py`.
3. From a normal, non-administrator PowerShell, test `install.ps1`, its Start
   Menu shortcut, launch and all `routerctl.ps1` maintenance commands. Verify
   clean install, upgrade, repair, reinstall, keep-data uninstall and explicit
   purge on a disposable profile. Never purge a user's existing profile.
4. Verify same-source reuse, a reviewed newer-source rebuild, rejection of an
   unknown source while the old build remains launchable, interrupted/failed
   update recovery, rollback pin/resume, changed CLI detection, active-process
   refusal, and persistent-data preservation. Distinguish native evidence
   from fixture tests in the report.
5. Run the full two-account core regression and Computer Use differential
   matrix against the same official source. Record helper/pipe isolation,
   primary and secondary task ownership, sequential/concurrent use, input,
   capture and crash/restart recovery. Preserve upstream Appshots gates and
   record actual availability before marking an operation inapplicable.
6. Run `routerctl.ps1 doctor`. Check payload integrity, state DACLs, official
   source status, port readiness and cleanup. Its payload `PASS` is not a
   Phase 3 acceptance result. Log out session test accounts and release control.
7. If shipping signed project binaries, supply an existing CurrentUser code
   signing certificate using `-SigningThumbprint`. Verify launcher/mux signatures
   after build and update. Never re-sign patched OpenAI executables. If no
   certificate is configured, label project signing `NOT_CONFIGURED`, not PASS.
8. Record remaining blockers and do not mark FULL PASS or merge until required
   gates pass. The source-only draft workflow does not publish a Windows
   installer or bundle; a version tag or public release requires release intent.

Keep native evidence in ignored `docs/generated`. Publish only redacted
summaries; never include profile files, tokens, official payloads or certificates.
