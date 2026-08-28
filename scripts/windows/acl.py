"""Read-only Windows ACL diagnostics and narrowly scoped payload remediation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

try:
    from .discovery import is_windowsapps_path, path_is_within
except ImportError:
    from discovery import is_windowsapps_path, path_is_within


ALL_APPLICATION_PACKAGES_SID = "S-1-15-2-1"
ALL_RESTRICTED_APPLICATION_PACKAGES_SID = "S-1-15-2-2"
APPCONTAINER_SID_PREFIX = "S-1-15-"
APP_CONTAINER_RX_INHERITANCE = "(OI)(CI)(RX)"
_SID_PATTERN = re.compile(r"S-1-15-[0-9-]+", re.IGNORECASE)


class AclMutationBlockedError(RuntimeError):
    """The requested ACL mutation was outside the Router-owned app payload."""


@dataclass(frozen=True)
class AclAudit:
    """A non-localized read-only snapshot of one Windows DACL."""

    path: Path
    exists: bool
    accessible: bool
    owner: str | None
    sddl: str | None
    protected_dacl: bool | None
    inheritance: dict[str, object]
    all_application_packages_rx: bool
    all_restricted_application_packages_rx: bool
    unknown_appcontainer_sids: tuple[str, ...]
    access_entries: tuple[dict[str, object], ...] = ()
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "accessible": self.accessible,
            "owner": self.owner,
            "sddl": self.sddl,
            "protected_dacl": self.protected_dacl,
            "inheritance": self.inheritance,
            "all_application_packages_rx": self.all_application_packages_rx,
            "all_restricted_application_packages_rx": self.all_restricted_application_packages_rx,
            "unknown_appcontainer_sids": list(self.unknown_appcontainer_sids),
            "access_entries": list(self.access_entries),
            "error": self.error,
        }


def _safe_error(error: BaseException) -> str:
    return str(error).strip() or error.__class__.__name__


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _powershell_executable() -> str | None:
    return shutil.which("pwsh.exe") or shutil.which("powershell.exe") or shutil.which("pwsh")


def _run_acl_query(path: Path) -> tuple[dict[str, object] | None, str | None]:
    if os.name != "nt":
        return None, "Windows ACL inspection is only available on Windows"
    powershell = _powershell_executable()
    if powershell is None:
        return None, "PowerShell is unavailable for Windows ACL inspection"
    script = f"""
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath {_powershell_quote(str(path))}
$entries = @($acl.Access | ForEach-Object {{
  $sid = $null
  try {{
    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  }} catch {{
    $sid = [string]$_.IdentityReference.Value
  }}
  [pscustomobject]@{{
    Sid = [string]$sid
    Rights = [string]$_.FileSystemRights
    AccessType = [string]$_.AccessControlType
    IsInherited = [bool]$_.IsInherited
    InheritanceFlags = [string]$_.InheritanceFlags
    PropagationFlags = [string]$_.PropagationFlags
  }}
}})
[pscustomobject]@{{
  Owner = [string]$acl.Owner
  Sddl = [string]$acl.Sddl
  ProtectedDacl = [bool]$acl.AreAccessRulesProtected
  Access = $entries
}} | ConvertTo-Json -Depth 8 -Compress
"""
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, _safe_error(error)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
        return None, detail.splitlines()[-1] if detail else f"exit code {result.returncode}"
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return None, f"PowerShell ACL output was not JSON: {_safe_error(error)}"
    if not isinstance(parsed, dict):
        return None, "PowerShell ACL output was not an object"
    return parsed, None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.casefold().strip()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def _entry_list(value: object) -> list[dict[str, object]]:
    values = value if isinstance(value, list) else [value]
    return [item for item in values if isinstance(item, dict)]


def _entry_sid(entry: Mapping[str, object]) -> str | None:
    value = entry.get("Sid")
    if value is None:
        value = entry.get("sid")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _entry_allows_read_execute(entry: Mapping[str, object]) -> bool:
    access_type = str(entry.get("AccessType", entry.get("access_type", ""))).casefold()
    if access_type and access_type != "allow":
        return False
    rights = str(entry.get("Rights", entry.get("rights", ""))).replace(" ", "").casefold()
    return (
        "fullcontrol" in rights
        or "readandexecute" in rights
        or ("read" in rights and ("execute" in rights or "executefile" in rights))
    )


def _unknown_appcontainer_sids(
    entries: Iterable[Mapping[str, object]],
    sddl: str | None,
) -> tuple[str, ...]:
    values: set[str] = set()
    for entry in entries:
        sid = _entry_sid(entry)
        if sid and sid.casefold().startswith(APPCONTAINER_SID_PREFIX.casefold()):
            values.add(sid.upper())
    if sddl:
        values.update(match.upper() for match in _SID_PATTERN.findall(sddl))
    known = {
        ALL_APPLICATION_PACKAGES_SID.casefold(),
        ALL_RESTRICTED_APPLICATION_PACKAGES_SID.casefold(),
    }
    return tuple(sorted((value for value in values if value.casefold() not in known), key=str.casefold))


def _inheritance_summary(
    entries: Iterable[Mapping[str, object]],
    protected_dacl: bool | None,
) -> dict[str, object]:
    rows = list(entries)
    inherited = [row for row in rows if _as_bool(row.get("IsInherited", row.get("is_inherited"))) is True]
    explicit = [row for row in rows if _as_bool(row.get("IsInherited", row.get("is_inherited"))) is not True]
    flags = sorted(
        {
            str(row.get("InheritanceFlags", row.get("inheritance_flags", ""))).strip()
            for row in rows
            if str(row.get("InheritanceFlags", row.get("inheritance_flags", ""))).strip()
        },
        key=str.casefold,
    )
    return {
        "protected_dacl": protected_dacl,
        "has_inherited_entries": bool(inherited),
        "has_explicit_entries": bool(explicit),
        "inherited_entry_count": len(inherited),
        "explicit_entry_count": len(explicit),
        "inheritance_flags": flags,
    }


def _audit_from_payload(path: Path, payload: dict[str, object]) -> AclAudit:
    owner = payload.get("Owner")
    owner = owner.strip() if isinstance(owner, str) and owner.strip() else None
    sddl = payload.get("Sddl")
    sddl = sddl.strip() if isinstance(sddl, str) and sddl.strip() else None
    protected = _as_bool(payload.get("ProtectedDacl"))
    entries = _entry_list(payload.get("Access"))
    def has_sid(sid: str) -> bool:
        return any(
            (_entry_sid(entry) or "").casefold() == sid.casefold()
            and _entry_allows_read_execute(entry)
            for entry in entries
        )

    return AclAudit(
        path=path,
        exists=True,
        accessible=True,
        owner=owner,
        sddl=sddl,
        protected_dacl=protected,
        inheritance=_inheritance_summary(entries, protected),
        all_application_packages_rx=has_sid(ALL_APPLICATION_PACKAGES_SID),
        all_restricted_application_packages_rx=has_sid(ALL_RESTRICTED_APPLICATION_PACKAGES_SID),
        unknown_appcontainer_sids=_unknown_appcontainer_sids(entries, sddl),
        access_entries=tuple(entries),
    )


def read_acl_audit(path: Path) -> AclAudit:
    """Read one DACL/SDDL without changing it or requiring elevation."""
    resolved = path.expanduser().resolve(strict=False)
    if not resolved.exists():
        return AclAudit(
            path=resolved,
            exists=False,
            accessible=False,
            owner=None,
            sddl=None,
            protected_dacl=None,
            inheritance={"protected_dacl": None},
            all_application_packages_rx=False,
            all_restricted_application_packages_rx=False,
            unknown_appcontainer_sids=(),
            error="path does not exist",
        )
    payload, error = _run_acl_query(resolved)
    if payload is None:
        return AclAudit(
            path=resolved,
            exists=True,
            accessible=False,
            owner=None,
            sddl=None,
            protected_dacl=None,
            inheritance={"protected_dacl": None},
            all_application_packages_rx=False,
            all_restricted_application_packages_rx=False,
            unknown_appcontainer_sids=(),
            error=error,
        )
    return _audit_from_payload(resolved, payload)


def audit_acl_scope(paths: Mapping[str, Path] | Iterable[tuple[str, Path]]) -> dict[str, object]:
    """Audit named official/local paths and return deterministic structured evidence."""
    items = paths.items() if isinstance(paths, Mapping) else paths
    audits = {str(label): read_acl_audit(path) for label, path in items}
    return {
        "read_only": True,
        "manual_operation_required": False,
        "audits": {label: audit.to_dict() for label, audit in audits.items()},
        "paths": [audit.to_dict() for audit in audits.values()],
    }


def validate_router_app_root(staged_app: Path, router_root: Path | None = None) -> tuple[Path, Path]:
    """Validate that the exact mutation target is ``<router-root>\\app``."""
    target = staged_app.expanduser().resolve(strict=False)
    root = (router_root or target.parent).expanduser().resolve(strict=False)
    if is_windowsapps_path(root) or is_windowsapps_path(target):
        raise AclMutationBlockedError("refusing ACL mutation under WindowsApps")
    if root == target or target.name.casefold() != "app":
        raise AclMutationBlockedError("ACL target must be a Router-owned app directory")
    if root == target.parent.parent or not path_is_within(target, root) or target.parent != root:
        raise AclMutationBlockedError("ACL target must be exactly <Router root>\\app")
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        local_root = Path(local_appdata).expanduser().resolve(strict=False)
        if root == local_root or target == local_root:
            raise AclMutationBlockedError("refusing ACL mutation on the LOCALAPPDATA root")
    if target.is_symlink():
        raise AclMutationBlockedError("refusing ACL mutation through an app-directory symlink")
    if not target.is_dir():
        raise AclMutationBlockedError(f"Router app directory is not present: {target}")
    return root, target


def _existing_aces_preserved(before: AclAudit, after: AclAudit) -> bool | None:
    if not before.accessible or not after.accessible:
        return None
    after_keys = {
        (
            _entry_sid(entry),
            str(entry.get("Rights", entry.get("rights", ""))),
            str(entry.get("AccessType", entry.get("access_type", ""))),
            str(entry.get("InheritanceFlags", entry.get("inheritance_flags", ""))),
            str(entry.get("PropagationFlags", entry.get("propagation_flags", ""))),
            _as_bool(entry.get("IsInherited", entry.get("is_inherited"))),
        )
        for entry in after.access_entries
    }
    for entry in before.access_entries:
        key = (
            _entry_sid(entry),
            str(entry.get("Rights", entry.get("rights", ""))),
            str(entry.get("AccessType", entry.get("access_type", ""))),
            str(entry.get("InheritanceFlags", entry.get("inheritance_flags", ""))),
            str(entry.get("PropagationFlags", entry.get("propagation_flags", ""))),
            _as_bool(entry.get("IsInherited", entry.get("is_inherited"))),
        )
        if key not in after_keys:
            return False
    return True


def prepare_windows_electron_payload_acl(
    staged_app: Path,
    *,
    router_root: Path | None = None,
    apply: bool = True,
) -> dict[str, object]:
    """Add only AppContainer RX ACEs to a validated, Router-owned app tree."""
    root, target = validate_router_app_root(staged_app, router_root)
    before = read_acl_audit(target)
    command: list[str] = []
    if os.name != "nt":
        return {
            "status": "NOT AVAILABLE",
            "router_root": str(root),
            "target": str(target),
            "scope": str(target),
            "before": before.to_dict(),
            "after": None,
            "verified": False,
            "manual_operation_required": False,
            "reason": "Windows ACL mutation is only available on Windows",
        }
    icacls = shutil.which("icacls.exe") or shutil.which("icacls")
    if icacls is None:
        return {
            "status": "BLOCKED",
            "router_root": str(root),
            "target": str(target),
            "scope": str(target),
            "before": before.to_dict(),
            "after": None,
            "verified": False,
            "manual_operation_required": True,
            "reason": "icacls.exe is unavailable",
        }
    command = [
        icacls,
        str(target),
        "/grant",
        f"*{ALL_APPLICATION_PACKAGES_SID}:{APP_CONTAINER_RX_INHERITANCE}",
        f"*{ALL_RESTRICTED_APPLICATION_PACKAGES_SID}:{APP_CONTAINER_RX_INHERITANCE}",
        "/T",
    ]
    result_payload: dict[str, object] = {
        "status": "DRY RUN" if not apply else "BLOCKED",
        "router_root": str(root),
        "target": str(target),
        "scope": str(target),
        "command": command,
        "command_line": subprocess.list2cmdline(command),
        "before": before.to_dict(),
        "after": None,
        "verified": False,
        "manual_operation_required": False if not apply else True,
        "official_paths_touched": False,
        "runtime_user_data_scope": "excluded",
    }
    if not apply:
        result_payload["reason"] = "ACL command was prepared but not executed"
        return result_payload
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        result_payload["reason"] = _safe_error(error)
        return result_payload
    after = read_acl_audit(target)
    verified = (
        completed.returncode == 0
        and after.accessible
        and after.all_application_packages_rx
        and after.all_restricted_application_packages_rx
        and (before.owner is None or before.owner == after.owner)
        and _existing_aces_preserved(before, after) is not False
    )
    result_payload.update(
        {
            "status": "PASS" if verified else "FAIL",
            "return_code": completed.returncode,
            "stdout": (completed.stdout or "")[-8_000:],
            "stderr": (completed.stderr or "")[-8_000:],
            "after": after.to_dict(),
            "verified": verified,
            "owner_preserved": before.owner is None or before.owner == after.owner,
            "existing_aces_preserved": _existing_aces_preserved(before, after),
            "manual_operation_required": not verified,
            "reason": (
                "narrow AppContainer RX ACEs were added and verified"
                if verified
                else "ACL command completed but the required read-back invariants were not proven"
            ),
        }
    )
    return result_payload
