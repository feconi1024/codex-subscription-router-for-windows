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
    ui_test_bridge: Path


def _single_bundle(root: Path, pattern: str, label: str) -> Path:
    matches = list((root / ".vite" / "build").glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {label} bundle, found {len(matches)}")
    return matches[0]


def patch_bootstrap(extracted: Path, project_root: Path) -> BootstrapPatchReport:
    """Use the launcher-provided profile and remove the copied updater startup."""
    bootstrap_path = _single_bundle(extracted, "bootstrap-*.js", "ChatGPT bootstrap")
    bootstrap = bootstrap_path.read_text(encoding="utf-8")
    exact_profile_pattern = re.compile(
        r"(?P<electron>[A-Za-z_$][\w$]*)\.app\.setPath\("
        r"`userData`,[A-Za-z_$][\w$]*\(\{"
        r"appDataPath:(?P=electron)\.app\.getPath\(`appData`\),"
        r"buildFlavor:[^,}]+,env:process\.env\}\)\)"
    )
    exact_matches = list(exact_profile_pattern.finditer(bootstrap))
    generic_matches = list(
        re.finditer(
            r"(?P<electron>[A-Za-z_$][\w$]*)\.app\.setPath\("
            r"(?P<quote>[`\"'])userData(?P=quote),(?P<expression>[^;]{1,800})\)",
            bootstrap,
        )
    )
    if len(exact_matches) > 1:
        raise RuntimeError("ambiguous Electron userData profile hooks")
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
        f"process.env.CODEX_MUX_DESKTOP_USER_DATA||{fallback})"
    )
    bootstrap = bootstrap[: profile_match.start()] + replacement + bootstrap[profile_match.end() :]

    updater_pattern = re.compile(
        r"await [A-Za-z_$][\w$]*\.initialize\(\);"
        r"(?=try\{let\{runMainAppStartup:)"
    )
    bootstrap, updater_replacements = updater_pattern.subn("", bootstrap, count=1)
    if updater_replacements != 1:
        raise RuntimeError("could not disable updates in the copied ChatGPT app")
    bootstrap_path.write_text(bootstrap, encoding="utf-8")

    main_path = _single_bundle(extracted, "main-*.js", "ChatGPT main")
    main = main_path.read_text(encoding="utf-8")
    if "SKY_CUA_SERVICE_PATH" in main or "Codex Computer Use.app" in main:
        raise RuntimeError(
            "Windows patch path encountered Computer Use-specific main code; refusing to port it"
        )
    ui_test_bridge = extracted / ".vite" / "build" / "ui-test-bridge.cjs"
    shutil.copy2(project_root / "ui" / "ui-test-bridge.cjs", ui_test_bridge)
    main += (
        "\n;if(process.env.CODEX_MUX_UI_TESTS===`1`)"
        "require(require(`node:path`).join(__dirname,`ui-test-bridge.cjs`)).start();"
    )
    main_path.write_text(main, encoding="utf-8")
    return BootstrapPatchReport(
        bootstrap=bootstrap_path,
        main=main_path,
        profile_anchor=profile_anchor,
        updater_disabled=True,
        ui_test_bridge=ui_test_bridge,
    )
