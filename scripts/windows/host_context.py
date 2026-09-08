"""Native host-context and LOCALAPPDATA preflight checks for Windows validation."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import sys
import time
import uuid
from pathlib import Path


APPMODEL_ERROR_NO_PACKAGE = 15700
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SUCCESS = 0
FILE_NAME_NORMALIZED = 0


def _safe_error(error: BaseException | str) -> str:
    value = str(error) if not isinstance(error, str) else error
    value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    return value[:500] or type(error).__name__


def _common_fields() -> dict[str, object]:
    try:
        current_executable = str(Path(sys.executable).expanduser().resolve(strict=False))
    except OSError:
        current_executable = str(sys.executable)
    return {
        "has_package_identity": None,
        "package_full_name": None,
        "appmodel_result": None,
        "appmodel_result_name": None,
        "current_executable": current_executable,
        "pid": os.getpid(),
        "LOCALAPPDATA": os.environ.get("LOCALAPPDATA"),
        "USERPROFILE": os.environ.get("USERPROFILE"),
    }


def detect_windows_host_context() -> dict[str, object]:
    """Report package identity using GetCurrentPackageFullName.

    Paths and environment variables are deliberately not used to infer package
    identity.  A successful Win32 package-name lookup is the only positive
    identity signal; ``APPMODEL_ERROR_NO_PACKAGE`` is the only definitive
    no-package result.  Unknown API failures stay fail-closed for validation.
    """

    result = _common_fields()
    if os.name != "nt":
        result.update(
            {
                "has_package_identity": False,
                "appmodel_result": "NOT_WINDOWS",
                "appmodel_result_name": "NOT_WINDOWS",
                "reason": "native package identity API is only available on Windows",
            }
        )
        return result

    try:
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise RuntimeError("ctypes.WinDLL is unavailable")
        kernel32 = win_dll("kernel32", use_last_error=True)
        api = getattr(kernel32, "GetCurrentPackageFullName", None)
        if api is None:
            raise RuntimeError("GetCurrentPackageFullName is unavailable")
        api.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
        api.restype = ctypes.c_long

        length = ctypes.c_uint32(0)
        appmodel_result = int(api(ctypes.byref(length), None))
        result["appmodel_result"] = appmodel_result
        if appmodel_result == APPMODEL_ERROR_NO_PACKAGE:
            result.update(
                {
                    "has_package_identity": False,
                    "appmodel_result_name": "APPMODEL_ERROR_NO_PACKAGE",
                    "reason": "the current process has no Windows package identity",
                }
            )
            return result
        if appmodel_result != ERROR_INSUFFICIENT_BUFFER:
            result.update(
                {
                    "appmodel_result_name": "UNEXPECTED_RESULT",
                    "reason": f"GetCurrentPackageFullName returned {appmodel_result}",
                }
            )
            return result

        buffer = ctypes.create_unicode_buffer(max(int(length.value), 1))
        appmodel_result = int(api(ctypes.byref(length), buffer))
        result["appmodel_result"] = appmodel_result
        package_full_name = buffer.value.strip()
        if appmodel_result == ERROR_SUCCESS and package_full_name:
            result.update(
                {
                    "has_package_identity": True,
                    "package_full_name": package_full_name,
                    "appmodel_result_name": "ERROR_SUCCESS",
                    "reason": "the current process has a Windows package identity",
                }
            )
            return result
        result.update(
            {
                "appmodel_result_name": (
                    "ERROR_SUCCESS_EMPTY_PACKAGE_NAME"
                    if appmodel_result == ERROR_SUCCESS
                    else "UNEXPECTED_RESULT"
                ),
                "reason": (
                    "GetCurrentPackageFullName returned success without a package name"
                    if appmodel_result == ERROR_SUCCESS
                    else f"GetCurrentPackageFullName returned {appmodel_result}"
                ),
            }
        )
        return result
    except (OSError, AttributeError, TypeError, ValueError, RuntimeError) as error:
        result.update(
            {
                "appmodel_result_name": "API_ERROR",
                "reason": _safe_error(error),
            }
        )
        return result


def _strip_extended_prefix(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\") or value.startswith("\\??\\"):
        return value[4:]
    return value


def _native_final_path(path: Path) -> tuple[str | None, str | None]:
    """Return a handle-backed final path for one file on Windows."""

    if os.name != "nt":
        return None, "native final-path API is only available on Windows"
    try:
        import msvcrt

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return None, "ctypes.WinDLL is unavailable"
        kernel32 = win_dll("kernel32", use_last_error=True)
        api = getattr(kernel32, "GetFinalPathNameByHandleW", None)
        if api is None:
            return None, "GetFinalPathNameByHandleW is unavailable"
        api.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar),
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        api.restype = ctypes.c_uint32
        with path.open("rb") as handle:
            native_handle = int(msvcrt.get_osfhandle(handle.fileno()))
            if native_handle == -1:
                return None, "could not obtain the native file handle"
            for size in (512, 2048, 8192, 32768):
                buffer = ctypes.create_unicode_buffer(size)
                length = int(api(ctypes.c_void_p(native_handle), buffer, size, FILE_NAME_NORMALIZED))
                if length == 0:
                    error = getattr(ctypes, "get_last_error", lambda: 0)()
                    return None, f"GetFinalPathNameByHandleW failed with {error}"
                if length < size - 1:
                    return _strip_extended_prefix(buffer.value[:length]), None
            return None, "GetFinalPathNameByHandleW path exceeded the probe buffer"
    except (OSError, AttributeError, TypeError, ValueError) as error:
        return None, _safe_error(error)


def _path_is_within(path: Path, root: Path) -> bool:
    def variants(value: Path) -> tuple[str, ...]:
        raw = os.path.normcase(os.path.normpath(str(value)))
        values = [raw]
        if any(re.search(r"~\d(?:$|\.)", part) for part in value.parts):
            try:
                resolved = os.path.normcase(os.path.normpath(str(value.resolve(strict=True))))
            except OSError:
                resolved = raw
            if resolved not in values:
                values.append(resolved)
        return tuple(values)

    try:
        candidates = variants(path)
        parents = variants(root)
        return any(
            candidate == parent or candidate.startswith(parent + os.sep)
            for candidate in candidates
            for parent in parents
        )
    except (OSError, ValueError):
        return False


def _cleanup_exact(path: Path) -> dict[str, object]:
    removed = False
    last_error: str | None = None
    for _attempt in range(5):
        try:
            shutil.rmtree(path)
        except OSError as error:
            last_error = _safe_error(error)
            time.sleep(0.1)
        else:
            removed = True
            break
    if not removed:
        # Only the exact generated canary directory is retried.  Never widen
        # cleanup to the host-check parent or to LOCALAPPDATA.
        shutil.rmtree(path, ignore_errors=True)
    return {
        "path": str(path),
        "removed": removed,
        "error": last_error,
    }


def run_localappdata_canary(local_appdata: Path | None = None) -> dict[str, object]:
    """Create a physical-path canary beneath the Router-owned LOCALAPPDATA root."""

    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "filesystem_virtualized": False,
            "physical_path_authoritative": False,
            "reason": "the LOCALAPPDATA canary is Windows-only",
            "cleanup": {"removed": True, "error": None},
        }

    raw_local_appdata = local_appdata or Path(
        os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    )
    requested_base = raw_local_appdata.expanduser() / "Codex Subscription Router"
    # Keep the caller's logical LOCALAPPDATA spelling for this comparison.
    # Path.resolve() can itself expose an AppContainer package-cache target,
    # which would make a redirected canary look falsely in-bounds.
    requested_base_for_compare = Path(os.path.abspath(str(requested_base)))
    canary_root = requested_base / "_host-check" / uuid.uuid4().hex
    canary_file = canary_root / "canary.txt"
    cleanup: dict[str, object] = {"path": str(canary_root), "removed": False, "error": None}
    try:
        canary_root.mkdir(parents=True, exist_ok=False)
        canary_file.write_text("codex-router-host-canary\n", encoding="utf-8")
        native_path, native_error = _native_final_path(canary_file)
        if native_path is not None:
            physical_file = Path(native_path)
            path_method = "GetFinalPathNameByHandleW"
            physical_path_authoritative = True
        else:
            physical_file = canary_file.resolve(strict=True)
            path_method = "Path.resolve fallback"
            physical_path_authoritative = False
        filesystem_virtualized = not _path_is_within(physical_file, requested_base_for_compare)
        status = "HOST FILESYSTEM VIRTUALIZED" if filesystem_virtualized else "PASS"
        result: dict[str, object] = {
            "status": status,
            "requested_localappdata": str(raw_local_appdata),
            "requested_base": str(requested_base),
            "requested_base_resolved": str(requested_base_for_compare),
            "requested_canary_file": str(canary_file),
            "physical_canary_file": str(physical_file),
            "path_method": path_method,
            "physical_path_authoritative": physical_path_authoritative,
            "native_final_path_error": native_error,
            "filesystem_virtualized": filesystem_virtualized,
            "within_requested_base": not filesystem_virtualized,
            "manual_operation_required": bool(filesystem_virtualized),
            "cleanup": cleanup,
        }
    except (OSError, RuntimeError, ValueError) as error:
        result = {
            "status": "BLOCKED",
            "requested_localappdata": str(raw_local_appdata),
            "requested_base": str(requested_base),
            "requested_base_resolved": str(requested_base_for_compare),
            "requested_canary_file": str(canary_file),
            "physical_canary_file": None,
            "path_method": None,
            "physical_path_authoritative": False,
            "native_final_path_error": None,
            "filesystem_virtualized": None,
            "within_requested_base": None,
            "reason": _safe_error(error),
            "manual_operation_required": True,
            "cleanup": cleanup,
        }
    finally:
        cleanup.update(_cleanup_exact(canary_root))
    result["cleanup"] = dict(cleanup)
    result["manual_operation_required"] = bool(
        result.get("manual_operation_required") or cleanup.get("removed") is not True
    )
    return result
