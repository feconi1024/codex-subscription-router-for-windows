"""Bounded, unauthenticated startup probe for a new, unactivated build."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from .discovery import inventory_processes_under_root, terminate_processes_under_root
from .managed_paths import atomic_json, reject_reparse
from .private_state import secure_directory


def startup_smoke(layout, build, *, timeout: float = 60) -> dict:
    for port in (48123, 48124):
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(f"startup smoke requires an unused local port {port}")
    reject_reparse(layout.data)
    diagnostics = layout.data / "logs"
    secure_directory(diagnostics)
    # This profile has no OAuth material. Only the renderer's shared local
    # control token is used to verify the bridge, and is never logged.
    with tempfile.TemporaryDirectory(prefix=".startup-smoke-", dir=layout.data) as temporary:
        from pathlib import Path
        root = Path(temporary)
        for directory in (root, root / "mux-home", root / "codex-home", root / "User Data"):
            secure_directory(directory)
        token = (layout.data / "mux-home/control-token").read_text(encoding="utf-8").strip()
        (root / "mux-home/control-token").write_text(token, encoding="utf-8")
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith("CODEX_MUX_") and key.upper() not in {"ELECTRON_RUN_AS_NODE", "NODE_OPTIONS"}}
        env.update(CODEX_HOME=str(root / "codex-home"), CODEX_SQLITE_HOME=str(root / "codex-home"),
                   CODEX_MUX_HOME=str(root / "mux-home"), CODEX_MUX_UI_TESTS="1",
                   CODEX_CLI_PATH=str(build / "runtime/codex-mux.exe"),
                   CODEX_MUX_REAL_CODEX=str(build / "runtime/codex.real.exe"),
                   CODEX_SPARKLE_ENABLED="false", CODEX_ELECTRON_USER_DATA_PATH=str(root / "User Data"),
                   CODEX_MUX_DESKTOP_USER_DATA=str(root / "User Data"))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(path):
            req = urllib.request.Request("http://127.0.0.1:48124" + path,
                                         headers={"x-codex-mux-token": token})
            with opener.open(req, timeout=5) as response:
                return json.load(response)

        with (root / "desktop.log").open("wb") as log:
            process = subprocess.Popen([str(build / "app/ChatGPT.exe"), "--user-data-dir=" + str(root / "User Data")],
                                       cwd=build / "app", env=env, stdout=log, stderr=log,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            observed = None
            last_debug = {}
            graceful = False
            try:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("staged Desktop exited before startup smoke completed")
                    try:
                        state = request("/v1/test/app-state?debug=1&delayMs=0")
                        debug = state.get("debug", {})
                        last_debug = debug
                        runtime = debug.get("renderer_runtime") or {}
                        if debug.get("runtime_errors") or runtime.get("runtimeErrorCount", 0):
                            raise RuntimeError("staged Desktop reported renderer errors")
                        if debug.get("readyState") == "complete" and runtime.get("rootChildCount", 0) > 0:
                            observed = {"status": "PASS", "renderer": "READY", "profile": "ISOLATED_UNAUTHENTICATED",
                                        "authenticated_acceptance": "NOT_RUN", "sandbox_disabled": False}
                            break
                    except (OSError, ValueError, urllib.error.URLError):
                        pass
                    time.sleep(0.5)
                if observed is None:
                    raise RuntimeError("staged Desktop did not reach a rendered login/app shell before timeout")
            finally:
                try:
                    request("/v1/test/app-state?action=validation-shell-graceful-quit&delayMs=0")
                    process.wait(timeout=15)
                    graceful = not inventory_processes_under_root(build)
                except (OSError, ValueError, subprocess.TimeoutExpired, urllib.error.URLError):
                    pass
                if not graceful:
                    terminate_processes_under_root(build)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                if inventory_processes_under_root(build):
                    raise RuntimeError("staged Desktop cleanup failed; build was not activated")
                log.flush()
                shutil.copyfile(root / "desktop.log", diagnostics / (build.name + "-startup.log"))
                atomic_json(diagnostics / (build.name + "-startup.json"), {
                    "status": "PASS" if observed and graceful else "FAIL",
                    "graceful_exit": graceful, "renderer_debug": last_debug,
                    "profile": "ISOLATED_UNAUTHENTICATED"})
            if not graceful:
                raise RuntimeError("staged Desktop required forced cleanup; build was not activated")
            return {**observed, "graceful_exit": "PASS"}
