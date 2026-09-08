#!/usr/bin/env python3
"""Install and maintain a local Windows Codex Subscription Router."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.windows.managed_paths import Layout, atomic_json
from scripts.windows.maintenance import initialize, reconcile, rollback, doctor, uninstall


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Codex Subscription Router")
    parser.add_argument("command", choices=["install", "update", "reconcile", "repair", "rollback", "doctor", "uninstall"])
    parser.add_argument("--source", type=Path)
    parser.add_argument("--real-codex", type=Path)
    parser.add_argument("--build", help="rollback target; defaults to previous build")
    parser.add_argument("--adopt-validation-profile", action="store_true", help="reuse the existing Router validation profile in place; never copies OAuth state")
    parser.add_argument("--require-native", action="store_true", help="refuse activation without verified Computer Use runtime")
    parser.add_argument("--signing-thumbprint", help="CurrentUser My code-signing certificate for project executables")
    parser.add_argument("--purge-data", action="store_true", help="uninstall: permanently delete Router account/profile data")
    parser.add_argument("--on-launch", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("routerctl is Windows-only")
    if args.purge_data and args.command != "uninstall":
        parser.error("--purge-data is only valid with uninstall")
    if args.adopt_validation_profile and args.command != "install":
        parser.error("--adopt-validation-profile is only valid with install")
    try:
        layout = initialize(args.root, adopt_validation_profile=args.adopt_validation_profile) if args.command == "install" else Layout.load(args.root)
        if args.on_launch and (layout.current() or {}).get("auto_update") is False:
            print(json.dumps({"status": "ROLLBACK_PINNED"}))
            return 0
        if args.command in {"install", "update", "repair", "reconcile"}:
            result = reconcile(layout, source_path=args.source, real_path=args.real_codex,
                               repair=args.command == "repair", require_native=args.require_native,
                               signing_thumbprint=args.signing_thumbprint)
        elif args.command == "rollback":
            result = rollback(layout, args.build)
        elif args.command == "doctor":
            result = doctor(layout)
        else:
            result = uninstall(layout, purge_data=args.purge_data)
        if args.command != "doctor":
            atomic_json(layout.root / "last-maintenance.json", result)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] not in {"FAIL", "SOURCE_REVIEW_REQUIRED"} or args.on_launch else 1
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "FAIL", "reason": str(error), "current_preserved": True}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
