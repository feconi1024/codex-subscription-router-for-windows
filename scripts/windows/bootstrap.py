"""Windows-specific Electron bootstrap/profile patching."""

from __future__ import annotations

import json
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
    ui_test_bridge_anchor: str = "not-injected"
    ui_test_bridge_module_system: str = "commonjs"


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


def _main_startup_matches(bootstrap: str) -> list[re.Match[str]]:
    """Find the reviewed CommonJS boundary immediately before main startup."""

    pattern = re.compile(
        r"let\{runMainAppStartup:[A-Za-z_$][\w$]*\}="
        r"await Promise\.resolve\(\)\.then\(\(\)=>require\("
        r"(?P<quote>[`\"'])\.\/main-[^`\"']+(?P=quote)\)\);"
    )
    return list(pattern.finditer(bootstrap))


def _bootstrap_module_system(bootstrap: str) -> str:
    """Classify the entrypoint using syntax that the patch actually relies on."""

    has_commonjs_require = bool(re.search(r"\brequire\(", bootstrap))
    has_esm_boundary = bool(re.search(r"(?:^|[;{}])\s*(?:import|export)\s", bootstrap))
    if has_commonjs_require and not has_esm_boundary:
        return "commonjs"
    if has_esm_boundary and not has_commonjs_require:
        return "esm"
    return "hybrid"


def _ui_test_bridge_loader() -> str:
    """Return a self-contained, bounded loader for the CommonJS bootstrap."""

    return (
        ";(()=>{"
        "const p=process.env.CODEX_MUX_UI_BRIDGE_STATUS_PATH;"
        "const names=new Set([`Error`,`EvalError`,`RangeError`,`ReferenceError`,`SyntaxError`,`TypeError`,`URIError`]);"
        "const codes=new Set([`BRIDGE_EXPORT_INVALID`,`CONTROL_TOKEN_MISSING`,`EADDRINUSE`,`EACCES`,`ENOENT`,`EEXIST`,`ERR_MODULE_NOT_FOUND`,`ERR_REQUIRE_ESM`,`MODULE_NOT_FOUND`,`TOKEN_INVALID_FORMAT`]);"
        "const stages=new Set([`NOT_STARTED`,`LOADER_REACHED`,`TEST_MODE_CONFIRMED`,`MODULE_LOAD_STARTED`,`MODULE_LOADED`,`START_CALLED`,`LISTENING`,`FAILED`]);"
        "const failedStages=new Set([`MODULE_LOAD`,`START`,`CONTROL_TOKEN_READ`,`LISTEN`]);"
        "const safeName=e=>names.has(typeof e?.name===`string`?e.name:e)?e.name:`Error`;"
        "const safeCode=e=>codes.has(typeof e?.code===`string`?e.code:e)?e.code:null;"
        "const write=(stage,details={})=>{try{if(typeof p!==`string`||p.length===0||!stages.has(stage))return;"
        "const value={schema_version:1,stage};"
        "if(stage===`FAILED`){"
        "const failedStage=details.failed_stage;"
        "if(failedStages.has(failedStage))value.failed_stage=failedStage;"
        "const error=details.error;"
        "const name=details.error_name??safeName(error);"
        "if(names.has(name))value.error_name=name;"
        "const code=details.error_code??safeCode(error);"
        "if(codes.has(code))value.error_code=code;"
        "}"
        "require(`node:fs`).writeFileSync(p,JSON.stringify(value)+`\\n`,`utf8`)}catch{}};"
        "write(`LOADER_REACHED`);"
        "if(process.env.CODEX_MUX_UI_TESTS!==`1`){write(`NOT_STARTED`);return;}"
        "write(`TEST_MODE_CONFIRMED`);write(`MODULE_LOAD_STARTED`);"
        "let bridge;"
        "try{bridge=require(`./ui-test-bridge.cjs`);write(`MODULE_LOADED`)}"
        "catch(error){write(`FAILED`,{failed_stage:`MODULE_LOAD`,error});return;}"
        "if(bridge==null||typeof bridge.start!==`function`){write(`FAILED`,{failed_stage:`MODULE_LOAD`,error_name:`TypeError`,error_code:`BRIDGE_EXPORT_INVALID`});return;}"
        "write(`START_CALLED`);"
        "try{Promise.resolve(bridge.start()).catch(()=>{})}"
        "catch(error){write(`FAILED`,{failed_stage:`START`,error})}"
        "})();"
    )


def _startup_chain_audit(
    extracted: Path,
    bootstrap_path: Path,
    main_path: Path,
    bootstrap: str,
    main: str,
) -> dict[str, object]:
    """Prove the packaged entrypoint-to-main startup chain without executing it."""

    build_root = extracted / ".vite" / "build"
    early_path = build_root / "early-bootstrap.js"
    package_path = extracted / "package.json"
    package_main: str | None = None
    package_error: str | None = None
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
        if isinstance(package, dict) and isinstance(package.get("main"), str):
            package_main = package["main"]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        package_error = type(error).__name__
    early = ""
    early_error: str | None = None
    try:
        early = early_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        early_error = type(error).__name__
    package_entrypoint_pass = package_main == f".vite/build/{early_path.name}"
    early_to_bootstrap_pass = (
        early_error is None
        and f'require("./{bootstrap_path.name}")' in early
    )
    bootstrap_to_main_pass = (
        len(_main_startup_matches(bootstrap)) == 1
        and f'require("./{main_path.name}")' in bootstrap
    )
    main_export_count = main.count("exports.runMainAppStartup")
    main_export_pass = main_export_count == 1
    return {
        "status": "PASS"
        if package_entrypoint_pass
        and early_to_bootstrap_pass
        and bootstrap_to_main_pass
        and main_export_pass
        else "MISSING",
        "package_main": package_main,
        "package_main_status": "PASS" if package_entrypoint_pass else "MISSING",
        "early_bootstrap": early_path.name if early_error is None else None,
        "early_to_bootstrap": "PASS" if early_to_bootstrap_pass else "MISSING",
        "bootstrap_to_main": "PASS" if bootstrap_to_main_pass else "MISSING",
        "main_export": "PASS" if main_export_pass else "MISSING",
        "main_export_count": main_export_count,
        "package_error": package_error,
        "early_error": early_error,
    }


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
            "startup_chain": {"status": "MISSING"},
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
    startup_matches = _main_startup_matches(bootstrap)
    module_system = _bootstrap_module_system(bootstrap)
    startup_chain = _startup_chain_audit(
        extracted,
        bootstrap_path,
        main_path,
        bootstrap,
        main,
    )
    static_hook_status = (
        "PASS"
        if bridge.is_file()
        and len(startup_matches) == 1
        and module_system == "commonjs"
        and startup_chain["status"] == "PASS"
        else "AMBIGUOUS"
        if len(startup_matches) > 1
        else "INCOMPATIBLE"
        if len(startup_matches) == 1
        else "MISSING"
    )
    return {
        "audit_pass": all(
            status in {"PASS", "PASS_NATIVE_OPTIONAL"}
            for status in (user_data_status, updater_status, main_status, static_hook_status)
        ),
        "bootstrap": bootstrap_path.name,
        "main": main_path.name,
        "ui_test_bridge_static_hook": static_hook_status,
        "native_runtime_validation_required": True,
        "native_bootstrap_runtime_proven": False,
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
        "startup_chain": startup_chain,
        "ui_test_bridge": {
            "status": "STATIC_BOOTSTRAP_COMPATIBLE" if static_hook_status == "PASS" else static_hook_status,
            "static_hook": static_hook_status,
            "native_runtime_validation_required": True,
            "native_bootstrap_runtime_proven": False,
            "source": str(bridge),
            "injection": "semantic pre-main CommonJS require at runMainAppStartup boundary",
            "module_system": module_system,
            "startup_anchor_count": len(startup_matches),
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
    main_path = _single_bundle(extracted, "main-*.js", "ChatGPT main")
    ui_test_bridge = extracted / ".vite" / "build" / "ui-test-bridge.cjs"
    bridge_injected = False
    bridge_anchor = "not-injected"
    bridge_module_system = _bootstrap_module_system(bootstrap)
    if inject_ui_test_bridge:
        # The Windows package's main bundle contains platform-conditional CUA
        # loaders. They are pre-existing source code; the mirror excludes the
        # optional CUA runtime and this patch does not inject or enable it.
        startup_matches = _main_startup_matches(bootstrap)
        if len(startup_matches) != 1:
            raise RuntimeError(
                "could not prove the unique CommonJS runMainAppStartup bootstrap boundary"
            )
        if bridge_module_system != "commonjs":
            raise RuntimeError(
                f"unsupported bootstrap module system for UI test bridge: {bridge_module_system}"
            )
        if main_path.read_text(encoding="utf-8").count("exports.runMainAppStartup") != 1:
            raise RuntimeError("could not prove the unique runMainAppStartup export in the main bundle")
        shutil.copy2(project_root / "ui" / "ui-test-bridge.cjs", ui_test_bridge)
        anchor = startup_matches[0]
        bootstrap = bootstrap[: anchor.start()] + _ui_test_bridge_loader() + bootstrap[anchor.start() :]
        bridge_injected = True
        bridge_anchor = "bootstrap-before-runMainAppStartup"
    if user_data_patched or disable_updater or bridge_injected:
        bootstrap_path.write_text(bootstrap, encoding="utf-8")
    return BootstrapPatchReport(
        bootstrap=bootstrap_path,
        main=main_path,
        profile_anchor=profile_anchor,
        updater_disabled=bool(disable_updater),
        ui_test_bridge=ui_test_bridge if bridge_injected else None,
        user_data_patched=user_data_patched,
        ui_test_bridge_injected=bridge_injected,
        ui_test_bridge_anchor=bridge_anchor,
        ui_test_bridge_module_system=bridge_module_system,
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
