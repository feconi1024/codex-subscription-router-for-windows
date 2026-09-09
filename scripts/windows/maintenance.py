"""Transactional build activation. Persistent account data is never a payload."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath

from .discovery import (discover_real_codex, locate_desktop_source, read_authenticode,
                        sha256_file, inventory_processes_under_root)
from .managed_paths import Layout, atomic_json, build_id, maintenance_lock, reject_reparse
from .private_state import secure_directory
from .reviewed_sources import find_reviewed_source, reviewed_source_is_patchable
from .integrity import asar_header_digest

MANIFEST = "build-manifest.json"
PROJECT = Path(__file__).resolve().parents[2]


def tooling_digest() -> str:
    digest = hashlib.sha256()
    paths = [PROJECT / name for name in ("go.mod", "package-lock.json", "VERSION")]
    for directory in ("cmd", "internal", "ui", "scripts"):
        paths.extend(path for path in (PROJECT / directory).rglob("*")
                     if path.is_file() and path.suffix in {".go", ".py", ".js", ".cjs", ".mjs", ".json"}
                     and "__pycache__" not in path.parts)
    for path in sorted(paths):
        digest.update(path.relative_to(PROJECT).as_posix().encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def source_identity(source) -> dict:
    return {"package_name": source.package.name, "package_full_name": source.package.package_full_name,
            "package_version": source.package.version, "architecture": source.package.architecture,
            "app_file_version": source.file_version, "app_asar_sha256": sha256_file(source.app_asar),
            "app_asar_header_sha256": asar_header_digest(source.app_asar).hash}


def payload_hashes(root: Path) -> dict[str, str]:
    reject_reparse(root)
    for relative in ("User Data", "codex-home", "runtime/.codex-mux", "Data"):
        if (root / relative).exists():
            raise RuntimeError("persistent state must not be included in a managed build")
    hashes = {}
    for directory, dirs, names in os.walk(root):
        for name in dirs + names:
            reject_reparse(Path(directory) / name)
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative != MANIFEST:
                hashes[relative] = sha256_file(path)
    return dict(sorted(hashes.items()))


def seal_build(root: Path, identity: dict, smoke: dict) -> dict:
    if smoke.get("status") != "PASS":
        raise RuntimeError("a failed or missing startup smoke cannot be activated")
    manifest = {"schema_version": 1, "source": identity, "startup_smoke": smoke, "files": payload_hashes(root)}
    required = {"app/ChatGPT.exe", "app/resources/app.asar", "runtime/codex-mux.exe",
                "runtime/codex.real.exe", "launch.json", "metadata.json", "Codex Subscription Router.exe"}
    if not required <= manifest["files"].keys():
        raise RuntimeError("managed payload is incomplete")
    atomic_json(root / MANIFEST, manifest)
    return manifest


def verify_build(root: Path) -> dict:
    reject_reparse(root / MANIFEST)
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("startup_smoke", {}).get("status") != "PASS":
        raise RuntimeError("build is not sealed with a passing startup smoke")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("invalid build manifest")
    for name in files:
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
            raise RuntimeError("invalid manifest payload path")
    if payload_hashes(root) != files:
        raise RuntimeError("build payload differs from its sealed manifest; run repair")
    return manifest


def activate(layout: Layout, identifier: str, *, validate=verify_build, auto_update: bool = True) -> dict:
    """Called under maintenance_lock; the only commit point is current.json."""
    target = layout.build(identifier)
    validate(target)
    previous = layout.current()
    pointer = {"schema_version": 1, "build": identifier}
    if not auto_update:
        pointer["auto_update"] = False
    if previous and previous["build"] != identifier:
        pointer["previous_build"] = previous["build"]
    elif previous and previous.get("previous_build"):
        pointer["previous_build"] = build_id(previous["previous_build"])
    atomic_json(layout.root / "current.json", pointer)
    return pointer


def require_idle(layout: Layout) -> None:
    if inventory_processes_under_root(layout.builds):
        raise RuntimeError("Router is running; quit it before maintenance")


def initialize(root: Path, *, adopt_validation_profile: bool = False) -> Layout:
    if (root / "installation.json").exists():
        return Layout.load(root)
    layout = Layout(root, "_validation-profile" if adopt_validation_profile else "Data")
    if root.exists():
        allowed = {"_host-check", "_host-validation", "_smoke", "_validation-profile", "maintenance.lock", "Source"}
        if any(path.name not in allowed for path in root.iterdir()):
            raise RuntimeError("refusing to adopt a nonempty unmanaged installation root")
    if adopt_validation_profile and not (layout.data / "mux-home/control-token").is_file():
        raise RuntimeError("no existing Router validation profile to adopt")
    with maintenance_lock(layout):
        if layout.root.resolve() != layout.root:
            raise RuntimeError("installation directory is redirected by the Store host; run install.ps1 from a normal PowerShell window or choose a non-virtualized --root")
        atomic_json(layout.root / "installation.json", layout.marker())
        layout.builds.mkdir(exist_ok=True)
        secure_directory(layout.data)
    return layout


def _verify_official(candidate: Path) -> None:
    signature = read_authenticode(candidate)
    if signature.status.casefold() != "valid" or "openai" not in (signature.signer or "").casefold():
        raise RuntimeError(f"official executable signature is not valid OpenAI: {candidate.name}")


def install_launcher(layout: Layout, build: Path, *, on_launch: bool = False) -> None:
    launcher = layout.root / "Codex Subscription Router.exe"
    reject_reparse(launcher)
    # The launcher has a stable schema contract. A running launcher cannot be
    # replaced on Windows; keep it during launch-time reconciliation.
    changed = not launcher.exists() or sha256_file(launcher) != sha256_file(build / launcher.name)
    if changed and (not on_launch or not launcher.exists()):
        temporary = layout.root / (".launcher-" + uuid.uuid4().hex + ".exe")
        shutil.copyfile(build / launcher.name, temporary)
        os.replace(temporary, launcher)
    script = PROJECT / "scripts/routerctl.py"
    atomic_json(layout.root / "manager.json", {"schema_version": 1, "python": sys.executable,
                "script": str(script), "script_sha256": sha256_file(script)})
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    (layout.root / "routerctl.ps1").write_text(
        "& " + quote(sys.executable) + " " + quote(script) + " --root " + quote(layout.root) + " @args\nexit $LASTEXITCODE\n", encoding="utf-8")


def reconcile(layout: Layout, *, source_path: Path | None = None, real_path: Path | None = None,
              repair: bool = False, require_native: bool = False, signing_thumbprint: str | None = None,
              on_launch: bool = False) -> dict:
    from ..patch_app_windows import build_windows_desktop
    from .startup_smoke import startup_smoke
    with maintenance_lock(layout):
        policy_path = layout.root / "maintenance-policy.json"
        reject_reparse(policy_path)
        policy = json.loads(policy_path.read_text(encoding="utf-8")) if policy_path.exists() else {}
        signing_thumbprint = signing_thumbprint or policy.get("signing_thumbprint")
        require_native = require_native or policy.get("require_native", False)
        source = locate_desktop_source(source_path)
        identity = source_identity(source)
        record = find_reviewed_source(identity)
        ok, reason = reviewed_source_is_patchable(identity, record)
        previous = layout.current()
        if not ok:
            return {"status": "SOURCE_REVIEW_REQUIRED", "reason": reason, "source": identity, "current": previous}
        real, _ = discover_real_codex(real_path)
        tooling = tooling_digest()
        if previous and not repair:
            current = verify_build(layout.build(previous["build"]))
            metadata = json.loads((layout.build(previous["build"]) / "metadata.json").read_text(encoding="utf-8"))
            if (current["source"] == identity and metadata.get("real_codex_sha256") == real.sha256
                    and metadata.get("tooling_sha256") == tooling
                    and metadata.get("signing_thumbprint") == signing_thumbprint
                    and (not require_native or metadata.get("computer_use", {}).get("status") == "VERIFIED")
                    and metadata.get("control_token_sha256") == sha256_file(layout.data / "mux-home/control-token")):
                install_launcher(layout, layout.build(previous["build"]), on_launch=on_launch)
                if not on_launch and previous.get("auto_update") is False:
                    # An explicit update also resumes updates when the selected
                    # build already matches every input. Reuse the inventory
                    # verification performed above under this same lock.
                    previous = activate(layout, previous["build"], validate=lambda _: current)
                return {"status": "UNCHANGED", "current": previous}
        require_idle(layout)
        _verify_official(source.executable)
        _verify_official(real.path)
        # Unique final path from the start: the patched application may embed
        # absolute paths in generated metadata. Never rename it after the smoke.
        identifier = build_id(source.package.version + "-" + identity["app_asar_sha256"][:8] + "-" + uuid.uuid4().hex[:12])
        build = layout.build(identifier)
        metadata = build_windows_desktop(source, real, build, force=False, allow_untested_source=False,
                    reviewed_source=record, launch_executable=str(record["authoritative_shell"]),
                    payload_acl_strategy=str(record["payload_acl_strategy"]),
                    production_data_root=layout.data, include_computer_use=True)
        metadata["tooling_sha256"] = tooling
        metadata["signing_thumbprint"] = signing_thumbprint
        metadata["control_token_sha256"] = sha256_file(layout.data / "mux-home/control-token")
        try:
            # Codex's native sandbox/code-mode commands locate these siblings.
            # Keep the complete official helper group with the renamed CLI.
            for name in ("codex-code-mode-host.exe", "codex-windows-sandbox-setup.exe", "codex-command-runner.exe"):
                candidate = real.path.parent / name
                _verify_official(candidate)
                shutil.copyfile(candidate, build / "runtime" / name)
                if sha256_file(candidate) != sha256_file(build / "runtime" / name):
                    raise RuntimeError("official Codex helper changed while copying")
            if require_native and metadata["computer_use"].get("status") != "VERIFIED":
                raise RuntimeError("required Computer Use runtime is unavailable")
            if signing_thumbprint:
                from .signing import sign_project_binaries
                metadata["project_signatures"] = sign_project_binaries(build, signing_thumbprint)
            atomic_json(build / "metadata.json", metadata)
            smoke = startup_smoke(layout, build)
            if source_identity(source) != identity or sha256_file(real.path) != real.sha256 or tooling_digest() != tooling:
                raise RuntimeError("official source changed during build; current version was retained")
            seal_build(build, identity, smoke)
            install_launcher(layout, build, on_launch=on_launch)
            pointer = activate(layout, identifier)
            atomic_json(policy_path, {"schema_version": 1, "signing_thumbprint": signing_thumbprint,
                                      "require_native": bool(require_native)})
            return {"status": "UPDATED", "current": pointer, "computer_use": metadata["computer_use"], "startup_smoke": smoke}
        except BaseException:
            # Retain the unactivated build for diagnosis. It cannot be selected
            # by rollback without a valid seal, and never contains account state.
            raise


def rollback(layout: Layout, identifier: str | None = None) -> dict:
    with maintenance_lock(layout):
        require_idle(layout)
        current = layout.current()
        target = identifier or (current or {}).get("previous_build")
        if not target:
            raise RuntimeError("no previous build is available")
        pointer = activate(layout, target, auto_update=False)
        return {"status": "ROLLED_BACK", "current": pointer}


def doctor(layout: Layout) -> dict:
    report = {"status": "PASS", "current": None, "checks": {}}
    try:
        current = layout.current()
        report["current"] = current
        if not current:
            raise RuntimeError("no active build")
        root = layout.build(current["build"])
        verify_build(root)
        report["checks"]["payload"] = "PASS"
        metadata = json.loads((root / "metadata.json").read_text(encoding="utf-8"))
        report["computer_use"] = metadata.get("computer_use")
        _verify_official(root / "runtime/codex.real.exe")
        report["checks"]["official_cli_signature"] = "PASS"
        for relative in metadata.get("project_signatures", {}):
            if read_authenticode(root / relative).status.casefold() != "valid":
                raise RuntimeError("project executable signature no longer validates")
        report["checks"]["project_signatures"] = "PASS" if metadata.get("project_signatures") else "NOT_CONFIGURED"
        launcher = layout.root / "Codex Subscription Router.exe"
        report["checks"]["launcher"] = "PASS" if sha256_file(launcher) == sha256_file(root / launcher.name) else "UPDATE_DEFERRED_UNTIL_EXPLICIT_UPDATE"
        for path in (layout.data, layout.data / "mux-home", layout.data / "codex-home"):
            reject_reparse(path)
            if not path.is_dir():
                raise RuntimeError("persistent data layout is incomplete")
            secure_directory(path, verify_only=True)
        report["checks"]["state_layout"] = "PASS"
        report["checks"]["state_dacl"] = "PASS"
    except (OSError, RuntimeError, ValueError) as error:
        report.update(status="FAIL", reason=str(error))
    report["running_process_count"] = len(inventory_processes_under_root(layout.builds))
    return report


def uninstall(layout: Layout, *, purge_data: bool = False) -> dict:
    with maintenance_lock(layout):
        require_idle(layout)
        if inventory_processes_under_root(layout.data):
            raise RuntimeError("an adopted validation build is still running")
        # Never recursively delete the installation root. Validate every exact
        # owned target and leave Data, Source and unknown files alone by default.
        reject_reparse(layout.builds)
        if layout.builds.exists():
            for child in layout.builds.iterdir():
                layout.build(child.name)
                reject_reparse(child)
            shutil.rmtree(layout.builds)
        for name in ("current.json", "Codex Subscription Router.exe", "routerctl.ps1", "manager.json"):
            target = layout.root / name
            reject_reparse(target)
            target.unlink(missing_ok=True)
        if purge_data:
            reject_reparse(layout.data)
            if layout.data.exists():
                shutil.rmtree(layout.data)
        # Retain the marker to make a keep-data reinstall unambiguous.
        return {"status": "UNINSTALLED", "data_preserved": not purge_data}
