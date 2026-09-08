"""Confined paths and crash-safe metadata for managed Windows installations."""
from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

PRODUCT = "Codex Subscription Router"
BUILD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\Z")


def reject_reparse(path: Path) -> None:
    """Inspect lexical components before resolve() can conceal a junction."""
    for candidate in (path, *path.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError(f"managed paths must not contain reparse points: {candidate}")


def build_id(value: str) -> str:
    if not isinstance(value, str) or not BUILD_ID.fullmatch(value) or ".." in value or value.endswith("."):
        raise ValueError("invalid managed build ID")
    if value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}:
        raise ValueError("reserved Windows build ID")
    return value


def atomic_json(path: Path, value: dict) -> None:
    reject_reparse(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Layout:
    root: Path
    data_directory: str = "Data"

    def __post_init__(self):
        root = Path(os.path.abspath(self.root.expanduser()))
        reject_reparse(root)
        if root == Path(root.anchor) or any(p.casefold() == "windowsapps" for p in root.parts):
            raise ValueError("installation must be outside WindowsApps and filesystem roots")
        if self.data_directory not in {"Data", "_validation-profile"}:
            raise ValueError("unsupported persistent data directory")
        object.__setattr__(self, "root", root)

    @property
    def builds(self) -> Path:
        return self.root / "builds"

    @property
    def data(self) -> Path:
        return self.root / self.data_directory

    def build(self, identifier: str) -> Path:
        path = self.builds / build_id(identifier)
        reject_reparse(path)
        return path

    def marker(self) -> dict:
        return {"schema_version": 1, "product": PRODUCT, "data_directory": self.data_directory}

    @classmethod
    def load(cls, root: Path) -> "Layout":
        reject_reparse(root / "installation.json")
        value = json.loads((root / "installation.json").read_text(encoding="utf-8"))
        if value.get("schema_version") != 1 or value.get("product") != PRODUCT:
            raise ValueError("not a managed Router installation")
        layout = cls(root, value.get("data_directory", ""))
        reject_reparse(layout.builds)
        reject_reparse(layout.data)
        return layout

    def current(self) -> dict | None:
        path = self.root / "current.json"
        reject_reparse(path)
        if not path.exists():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("invalid current.json schema")
        self.build(value.get("build", ""))
        return value


@contextlib.contextmanager
def maintenance_lock(layout: Layout):
    """OS-held lock: process death releases it; stale files never block repair."""
    path = layout.root / "maintenance.lock"
    reject_reparse(path)
    layout.root.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("another Router maintenance operation is running") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
