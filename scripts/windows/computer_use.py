"""Acquire the official Windows native runtime without patching its helpers.

The copied Desktop's existing resources/cua_node resolver supplies Node, REPL,
module paths, and the Windows capture bridge. No feature flag is forced on.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from .discovery import read_authenticode, sha256_file
from .managed_paths import reject_reparse

IDENTITY_FILES = ("manifest.json", "bin/node.exe", "bin/node_repl.exe")


def inventory(root: Path) -> dict[str, str]:
    reject_reparse(root)
    if not root.is_dir():
        raise RuntimeError("Computer Use runtime directory is missing")
    files = {}
    # os.walk does not follow directory links; reject them rather than silently
    # omitting potentially essential content from the verified inventory.
    for directory, dirs, names in os.walk(root):
        for name in dirs + names:
            reject_reparse(Path(directory) / name)
        for name in sorted(names):
            path = Path(directory) / name
            if not path.is_file():
                raise RuntimeError("non-regular Computer Use runtime entry")
            files[path.relative_to(root).as_posix()] = sha256_file(path)
    return dict(sorted(files.items()))


def identity(root: Path) -> str:
    digest = hashlib.sha256()
    for name in IDENTITY_FILES:
        reject_reparse(root / name)
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(sha256_file(root / name).encode())
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def validate(root: Path, architecture: str) -> dict:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    arch = architecture.casefold()
    if arch not in {"x64", "arm64"} or manifest.get("platform") != "windows" or manifest.get("arch") != arch:
        raise RuntimeError("Computer Use runtime platform/architecture mismatch")
    if manifest.get("node_path") != "bin/node.exe" or manifest.get("node_repl_path") != "bin/node_repl.exe" or manifest.get("node_modules") != "bin/node_modules":
        raise RuntimeError("unreviewed Computer Use manifest layout")
    modules = root / "bin/node_modules"
    helper_name = "codex-computer-use-arm64.exe" if arch == "arm64" else "codex-computer-use.exe"
    helper = modules / "@oai/sky/bin/windows" / helper_name
    if not helper.is_file():
        raise RuntimeError("Computer Use helper for this architecture is missing")
    binaries = {"helper": helper, "node": root / "bin/node.exe", "node_repl": root / "bin/node_repl.exe"}
    signatures = {}
    for name, path in binaries.items():
        reject_reparse(path)
        signature = read_authenticode(path)
        # Node is signed by its own publisher. OpenAI binaries must retain the
        # OpenAI signer; all executable signatures must validate on the host.
        if signature.status.casefold() != "valid" or (name != "node" and "openai" not in (signature.signer or "").casefold()):
            raise RuntimeError(f"invalid official {name} Authenticode signature")
        signatures[name] = {"status": signature.status, "signer": signature.signer, "sha256": sha256_file(path)}
    return {"status": "VERIFIED", "identity": identity(root), "architecture": arch,
            "runtime_version": manifest.get("runtime_archive_version"), "signatures": signatures}


def protected_copy(source: Path, destination: Path) -> None:
    """Normal Windows decrypted-destination copy, without source ACL changes."""
    reject_reparse(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    if os.name != "nt":
        shutil.copyfile(source, destination)
        return
    api = ctypes.WinDLL("kernel32", use_last_error=True).CopyFileExW
    api.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    api.restype = ctypes.c_int
    # COPY_FILE_FAIL_IF_EXISTS | COPY_FILE_ALLOW_DECRYPTED_DESTINATION
    if not api(str(source), str(destination), None, None, None, 0x9):
        raise ctypes.WinError(ctypes.get_last_error())


def acquire(source_resources: Path, destination: Path, architecture: str,
            staged_root: Path | None = None) -> dict:
    source = source_resources / "cua_node"
    if destination.exists():
        raise RuntimeError("runtime destination must be new")
    reject_reparse(destination)
    expected = inventory(source)
    expected_id = identity(source)
    staged_base = staged_root or Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "OpenAI/Codex/runtimes/cua_node"
    candidate = staged_base / expected_id
    strategy = "OFFICIAL_PACKAGE"
    selected = source
    if candidate.is_dir():
        # The official 16-character identity covers only three files. Check the
        # entire tree as well, including JavaScript modules and native helpers.
        if inventory(candidate) == expected:
            selected, strategy = candidate, "OPENAI_STAGED"
    report = validate(selected, architecture)
    destination.mkdir(parents=True, exist_ok=False)
    try:
        for name in expected:
            protected_copy(selected / name, destination / name)
        if inventory(destination) != expected or inventory(source) != expected:
            raise RuntimeError("Computer Use runtime changed during acquisition")
        verified = validate(destination, architecture)
        if verified != report:
            raise RuntimeError("staged runtime verification changed")
        return {**report, "strategy": strategy, "file_count": len(expected),
                "tree_sha256": hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest(),
                "layout": "app/resources/cua_node", "native_acceptance": "NOT_RUN"}
    except BaseException:
        # Only remove this call's newly created destination, never a shared cache.
        reject_reparse(destination)
        shutil.rmtree(destination)
        raise


def smoke(runtime: Path) -> dict:
    """Executable/module smoke only; it does not claim desktop control worked."""
    node = runtime / "bin/node.exe"
    command = [str(node), "-e", "console.log(JSON.stringify({node:process.versions.node,sky:require.resolve('@oai/sky')}))"]
    result = subprocess.run(command, cwd=runtime / "bin", capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("Computer Use Node/module smoke failed: " + result.stderr[:500])
    observed = json.loads(result.stdout)
    if not Path(observed["sky"]).resolve().is_relative_to(runtime.resolve()):
        raise RuntimeError("Computer Use module resolved outside the staged runtime")
    return {"status": "PASS", "node_version": observed["node"], "native_pipe": "NOT_TESTED"}
