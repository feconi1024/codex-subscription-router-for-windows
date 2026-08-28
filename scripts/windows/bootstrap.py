"""Windows-specific Electron bootstrap/profile patching."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path


DESKTOP_PROFILE_NAME = "Codex Subscription Router"


@dataclass(frozen=True)
class BootstrapPatchReport:
    bootstrap: Path
    main: Path
    profile_anchor: str
    updater_disabled: bool
    ui_test_bridge: Path | None
    user_data_patched: bool = True
    ui_test_bridge_injected: bool = True
    strategy: str = "profile-and-updater"


def _profile_matches(bootstrap: str) -> tuple[list[re.Match[str]], list[re.Match[str]]]:
    exact_profile_pattern = re.compile(
        r"(?P<electron>[A-Za-z_$][\w$]*)\.app\.setPath\("
        r"`userData`,[A-Za-z_$][\w$]*\(\{"
        r"appDataPath:(?P=electron)\.app\.getPath\(`appData`\),"
        r"buildFlavor:[^,}]+,env:process\.env\}\)\)"
    )
    generic_matches = list(
        re.finditer(
            r"(?P<electron>[A-Za-z_$][\w$]*)\.app\.setPath\("
            r"(?P<quote>[`\"'])userData(?P=quote),(?P<expression>[^;]{1,800})\)",
            bootstrap,
        )
    )
    return list(exact_profile_pattern.finditer(bootstrap)), generic_matches


def _updater_matches(bootstrap: str) -> list[re.Match[str]]:
    """Find the supported updater initializer immediately before main startup."""
    pattern = re.compile(
        r"await [A-Za-z_$][\w$]*\.initialize\(\);"
        r"(?=try\{let\{runMainAppStartup:|let\{runMainAppStartup:)"
    )
    return list(pattern.finditer(bootstrap))


def audit_bootstrap(extracted: Path, project_root: Path) -> dict[str, object]:
    """Read-only dry-run audit of the Windows bootstrap transformation points."""
    try:
        bootstrap_path = _single_bundle(extracted, "bootstrap-*.js", "ChatGPT bootstrap")
        main_path = _single_bundle(extracted, "main-*.js", "ChatGPT main")
    except RuntimeError as error:
        return {
            "audit_pass": False,
            "error": str(error),
            "bootstrap": None,
            "main": None,
            "user_data_hook": {"status": "MISSING"},
            "updater_hook": {"status": "MISSING"},
            "main_bundle": {"status": "MISSING"},
            "ui_test_bridge": {"status": "MISSING"},
            "computer_use": {"status": "UNKNOWN"},
        }
    bootstrap = bootstrap_path.read_text(encoding="utf-8")
    main = main_path.read_text(encoding="utf-8")
    exact_matches, generic_matches = _profile_matches(bootstrap)
    candidates = [
        match
        for match in generic_matches
        if "appData" in match.group("expression")
        and "getPath" in match.group("expression")
    ]
    profile_match_count = len(exact_matches) if exact_matches else len(candidates)
    profile_match = exact_matches[0] if len(exact_matches) == 1 else candidates[0] if len(candidates) == 1 else None
    updater_matches = _updater_matches(bootstrap)
    bridge = project_root / "ui" / "ui-test-bridge.cjs"
    computer_use_markers = [
        marker
        for marker in ("SKY_CUA_SERVICE_PATH", "Codex Computer Use.app")
        if marker in main
    ]
    native_optional_computer_use = bool(computer_use_markers) and (
        "cua_node" in main and "process.platform===`darwin`" in main
    )
    user_data_status = "PASS" if profile_match is not None and profile_match_count == 1 else "MISSING"
    updater_status = "PASS" if len(updater_matches) == 1 else "AMBIGUOUS" if updater_matches else "MISSING"
    main_status = (
        "PASS"
        if not computer_use_markers
        else "PASS_NATIVE_OPTIONAL"
        if native_optional_computer_use
        else "COMPUTER_USE_PRESENT"
    )
    bridge_status = "PASS" if bridge.is_file() and main_path.is_file() else "MISSING"
    return {
        "audit_pass": all(
            status in {"PASS", "PASS_NATIVE_OPTIONAL"}
            for status in (user_data_status, updater_status, main_status, bridge_status)
        ),
        "bootstrap": bootstrap_path.name,
        "main": main_path.name,
        "user_data_hook": {
            "status": user_data_status,
            "match_count": profile_match_count,
            "environment_variables": [
                "CODEX_ELECTRON_USER_DATA_PATH",
                "CODEX_MUX_DESKTOP_USER_DATA",
            ],
            "dry_run_replacement": profile_match is not None,
        },
        "updater_hook": {
            "status": updater_status,
            "initializer_count": len(updater_matches),
            "dry_run_removal": len(updater_matches) == 1,
        },
        "main_bundle": {"status": main_status, "computer_use_markers": computer_use_markers},
        "ui_test_bridge": {
            "status": bridge_status,
            "source": str(bridge),
            "injection": "CODEX_MUX_UI_TESTS=1 guarded require",
        },
        "computer_use": {
            "status": (
                "ABSENT"
                if not computer_use_markers
                else "NATIVE_OPTIONAL"
                if native_optional_computer_use
                else "PRESENT"
            ),
            "markers": computer_use_markers,
            "accidental_macos_code": "ABSENT" if native_optional_computer_use or not computer_use_markers else "UNRESOLVED",
            "native_platform_guard_count": main.count("process.platform===`darwin`")
            if native_optional_computer_use
            else 0,
        },
    }


def _single_bundle(root: Path, pattern: str, label: str) -> Path:
    matches = list((root / ".vite" / "build").glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {label} bundle, found {len(matches)}")
    return matches[0]


def patch_bootstrap(
    extracted: Path,
    project_root: Path,
    *,
    patch_user_data: bool = True,
    disable_updater: bool = True,
    inject_ui_test_bridge: bool = True,
) -> BootstrapPatchReport:
    """Apply only the requested bootstrap changes to an extracted app.

    The default preserves the Phase 2A.2 patch. Minimal-bootstrap validation
    can request updater removal without touching renderer/UI hooks and can
    leave the source userData hook intact when the environment/argument
    contract already proved sufficient.
    """
    bootstrap_path = _single_bundle(extracted, "bootstrap-*.js", "ChatGPT bootstrap")
    bootstrap = bootstrap_path.read_text(encoding="utf-8")
    exact_matches, generic_matches = _profile_matches(bootstrap)
    if len(exact_matches) > 1:
        raise RuntimeError("ambiguous Electron userData profile hooks")
    profile_anchor = "unchanged"
    user_data_patched = False
    if patch_user_data:
        if exact_matches:
            profile_match = exact_matches[0]
            profile_anchor = "current"
        else:
            candidates = [
                match
                for match in generic_matches
                if "appData" in match.group("expression")
                and "getPath" in match.group("expression")
            ]
            if len(candidates) != 1:
                raise RuntimeError(
                    "could not prove the semantic Windows Electron userData hook"
                )
            profile_match = candidates[0]
            profile_anchor = "generic-semantic"

        electron = profile_match.group("electron")
        fallback = f'{electron}.app.getPath(`appData`)+`/{DESKTOP_PROFILE_NAME}`'
        replacement = (
            f"{electron}.app.setPath(`userData`,"
            f"process.env.CODEX_ELECTRON_USER_DATA_PATH||"
            f"process.env.CODEX_MUX_DESKTOP_USER_DATA||{fallback})"
        )
        bootstrap = bootstrap[: profile_match.start()] + replacement + bootstrap[profile_match.end() :]
        user_data_patched = True

    updater_replacements = 0
    if disable_updater:
        updater_pattern = re.compile(
            r"await [A-Za-z_$][\w$]*\.initialize\(\);"
            r"(?=try\{let\{runMainAppStartup:|let\{runMainAppStartup:)"
        )
        bootstrap, updater_replacements = updater_pattern.subn("", bootstrap, count=1)
        if updater_replacements != 1:
            raise RuntimeError("could not disable updates in the copied ChatGPT app")
    if user_data_patched or disable_updater:
        bootstrap_path.write_text(bootstrap, encoding="utf-8")

    main_path = _single_bundle(extracted, "main-*.js", "ChatGPT main")
    main = main_path.read_text(encoding="utf-8")
    ui_test_bridge = extracted / ".vite" / "build" / "ui-test-bridge.cjs"
    bridge_injected = False
    if inject_ui_test_bridge:
        # The Windows package's main bundle contains platform-conditional CUA
        # loaders. They are pre-existing source code; the mirror excludes the
        # optional CUA runtime and this patch does not inject or enable it.
        shutil.copy2(project_root / "ui" / "ui-test-bridge.cjs", ui_test_bridge)
        main += (
            "\n;if(process.env.CODEX_MUX_UI_TESTS===`1`)"
            "require(require(`node:path`).join(__dirname,`ui-test-bridge.cjs`)).start();"
        )
        main_path.write_text(main, encoding="utf-8")
        bridge_injected = True
    return BootstrapPatchReport(
        bootstrap=bootstrap_path,
        main=main_path,
        profile_anchor=profile_anchor,
        updater_disabled=bool(disable_updater),
        ui_test_bridge=ui_test_bridge if bridge_injected else None,
        user_data_patched=user_data_patched,
        ui_test_bridge_injected=bridge_injected,
        strategy=(
            "profile-and-updater"
            if user_data_patched and disable_updater
            else "profile-only"
            if user_data_patched
            else "updater-only"
            if disable_updater
            else "environment-only"
        ),
    )
