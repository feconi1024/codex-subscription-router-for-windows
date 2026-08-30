from __future__ import annotations

import os
import hashlib
import inspect
import json
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from scripts.patch_common import (
    _plugin_mapping_anchors,
    audit_renderer_anchors,
    compare_renderer_contract,
    ensure_asar_tool,
    patch_renderer,
    renderer_variant_template,
    select_renderer_variant,
)
from scripts.patch_app_windows import (
    _payload_acl_for_strategy,
    audit_windows_source,
    build_windows_desktop,
    pack_asar,
    probe_go_toolchain,
    resolve_staged_launch_path,
    validate_staged_layout,
    verify_asar_listing,
)
from scripts.windows.compatibility import (
    PAYLOAD_ACL_APPCONTAINER_RX,
    PAYLOAD_ACL_NONE,
    PAYLOAD_ACL_UNRESOLVED,
    load_compatibility_records,
)
from scripts.windows.bootstrap import audit_bootstrap, patch_bootstrap
from scripts.windows.discovery import (
    AuthenticodeMetadata,
    DesktopExecutableCandidate,
    DesktopSource,
    PackageMetadata,
    RealCodexCandidate,
    RunningProcessCandidate,
    SourceDiagnostics,
    SourceProbeResult,
    copy_byte_identical,
    desktop_source_from_executable,
    discover_real_codex,
    format_source_diagnostics,
    locate_desktop_source,
    parse_appx_block_map,
    read_appx_manifest_aumids,
    read_appx_manifest_metadata,
    recognize_start_app_aumids,
    select_running_process,
    process_tree_pids,
    attributable_process_pids,
    inventory_desktop_executables,
    select_authoritative_desktop_candidate,
    path_is_within,
)
from scripts.windows.fuses import FUSE_INDEX, FUSE_VALUES, SENTINEL, FuseSnapshot, read_fuses, write_fuse
from scripts.windows.integrity import (
    FUSE_PRESENT_RESOURCE_MISSING,
    FUSE_PRESENT_ASAR_VALIDATION_DISABLED,
    RESOURCE_ABSENT_NO_VALIDATION_METADATA,
    RESOURCE_PRESENT_UPDATE_REQUIRED,
    AsarHeaderDigest,
    WindowsAsarIntegrityPlan,
    apply_windows_asar_integrity,
    asar_header_digest,
    read_pe_integrity_resources,
    resolve_windows_asar_integrity,
    scan_fuse_carriers,
)
from scripts.windows.smoke import (
    APP_CONTAINER_ACCESS_FIX_CONFIRMED,
    BLOCKED_CHROMIUM_SANDBOX,
    BLOCKED_NATIVE_MODULE,
    BLOCKED_OTHER_PACKAGE_IDENTITY,
    BLOCKED_RESOURCE,
    BLOCKED_SINGLE_INSTANCE_LOCK,
    BLOCKED_UPDATER_IDENTITY,
    CRASHED,
    LOCAL_APP_ACL_FIX_CONFIRMED,
    PATCHED_SHELL_BLOCKED,
    PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
    PASS,
    _probe_candidate,
    classify_probe_output,
    final_layout_smoke_root,
    _phase2a4_display_verdict,
    _phase2a4_verdict,
    native_evidence_is_usable,
    run_patched_shell_smoke,
)
from scripts.windows.host_context import (
    APPMODEL_ERROR_NO_PACKAGE,
    detect_windows_host_context,
    run_localappdata_canary,
)
from scripts.windows.phase2a5_host_validation import (
    PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED,
    PHASE2A5_SOURCE_CHANGED_DURING_VALIDATION,
    PHASE2A5_SOURCE_REVIEW_REQUIRED,
    _go_toolchain_report,
    _run_external_patched_shell,
    _source_identity,
    _source_stability,
    run_phase2a5_host_validation,
)
from scripts.windows.reviewed_sources import (
    find_reviewed_source,
    load_reviewed_sources,
)
from scripts.windows.acl import (
    ALL_APPLICATION_PACKAGES_SID,
    ALL_RESTRICTED_APPLICATION_PACKAGES_SID,
    AclAudit,
    AclMutationBlockedError,
    APP_CONTAINER_RX_INHERITANCE,
    _audit_from_payload,
    audit_acl_scope,
    prepare_windows_electron_payload_acl,
    read_acl_audit,
    validate_router_app_root,
)
from scripts.windows.mirror import (
    DirectoryEnumerationBlockedError,
    PackagingBlockedError,
    derive_unpack_directories,
    derive_unpack_files,
    mirror_directory,
    mirror_desktop_source,
    should_exclude,
)


def write_pe(path: Path, machine: int = 0x8664) -> None:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(data)


def write_exact_26_820_renderer_fixture(root: Path) -> dict[str, object]:
    values = renderer_variant_template("windows-26.820")
    webview = root / "webview"
    assets = webview / "assets"
    assets.mkdir(parents=True)
    tick = chr(96)
    bundle_parts = [str(values["component_anchor"])]
    bundle_parts.extend(
        str(spec["current"])
        for spec in values["plugin_mappings"]
        if spec["name"] != "mcpServerStatus/list RPC call"
    )
    bundle_parts.extend(
        [
            str(values["app_server_anchor"]),
            str(values["profile_query"]),
            str(values["usage_modal"]),
            str(values["reset_query"]),
            str(values["reset_mutation"]),
            "let y=v;if(g!=null){",
            str(values["usage_header"]),
            str(values["usage_slot"]),
            str(values["open_change"][0]),
            str(values["open_preserved"]),
            f"defaultMessage:{tick}You’re out of Codex and Work usage{tick}",
            f"defaultMessage:{tick}You’ve used all Codex and Work usage{tick}",
            f"defaultMessage:{tick}You’ve reached your usage limit{tick}",
        ]
    )
    (webview / "index.html").write_text("connect-src &#39;self&#39;", encoding="utf-8")
    (assets / "app-initial-26-820.js").write_text("\n".join(bundle_parts), encoding="utf-8")
    (assets / "profile-26-820.js").write_text(
        " ".join(str(values[key]) for key in ("profile_avatar", "profile_name", "profile_identity")),
        encoding="utf-8",
    )
    (assets / "plugins-page-26-820.js").write_text(str(values["plugin_anchor"]), encoding="utf-8")
    (assets / "local-conversation-thread-26-820.js").write_text(
        str(values["thread_anchor"]) + " " + str(values["thread_summary_anchor"]),
        encoding="utf-8",
    )
    return values


class WindowsDesktopHelpersTests(unittest.TestCase):
    def test_windows_bootstrap_isolates_profile_and_disables_updater(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            build = extracted / ".vite" / "build"
            build.mkdir(parents=True)
            (build / "bootstrap-fixture.js").write_text(
                "e.app.setPath(`userData`,x({appDataPath:e.app.getPath(`appData`),"
                "buildFlavor:`stable`,env:process.env}))"
                "await u.initialize();try{let{runMainAppStartup:startup}=x}",
                encoding="utf-8",
            )
            (build / "main-fixture.js").write_text("main", encoding="utf-8")
            report = patch_bootstrap(extracted, Path(__file__).resolve().parents[2])
            bootstrap = (build / "bootstrap-fixture.js").read_text(encoding="utf-8")
            main = (build / "main-fixture.js").read_text(encoding="utf-8")
            self.assertTrue(report.updater_disabled)
            self.assertIn("CODEX_MUX_DESKTOP_USER_DATA", bootstrap)
            self.assertNotIn("await u.initialize();", bootstrap)
            self.assertIn("ui-test-bridge.cjs", main)
            self.assertNotIn("SKY_CUA_SERVICE_PATH", main)

    def test_desktop_source_prefers_chatgpt_over_legacy_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            resources = app / "resources"
            resources.mkdir(parents=True)
            (resources / "app.asar").write_bytes(b"asar")
            write_pe(app / "ChatGPT.exe")
            write_pe(app / "Codex.exe")
            with patch("scripts.windows.discovery.read_file_version", return_value="1.2.3"):
                source = locate_desktop_source(root)
            self.assertEqual(source.executable.name, "ChatGPT.exe")
            self.assertEqual(source.app_asar, (resources / "app.asar").resolve(strict=False))

    def test_running_process_selection_prefers_official_chatgpt_path(self) -> None:
        candidates = [
            RunningProcessCandidate(
                pid=10,
                name="codex.exe",
                executable=Path(r"C:\Users\test\.vscode\extensions\codex.exe"),
            ),
            RunningProcessCandidate(
                pid=11,
                name="ChatGPT.exe",
                executable=Path(r"C:\Users\test\AppData\Local\OpenAI\ChatGPT\ChatGPT.exe"),
            ),
            RunningProcessCandidate(
                pid=12,
                name="ChatGPT.exe",
                executable=Path(r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__publisher\app\ChatGPT.exe"),
            ),
        ]
        selected = select_running_process(candidates)
        self.assertIsNotNone(selected)
        self.assertIn("WindowsApps", str(selected.executable))

        legacy = select_running_process(
            [
                RunningProcessCandidate(
                    pid=13,
                    name="codex.exe",
                    executable=Path(r"C:\Users\test\AppData\Local\OpenAI\Codex\Codex.exe"),
                )
            ]
        )
        self.assertEqual(legacy.name, "codex.exe")

    def test_process_tree_scope_never_includes_unrelated_processes(self) -> None:
        snapshot = [
            RunningProcessCandidate(pid=10, name="ChatGPT.exe", parent_pid=1),
            RunningProcessCandidate(pid=11, name="helper.exe", parent_pid=10),
            RunningProcessCandidate(pid=12, name="unrelated.exe", parent_pid=99),
        ]
        self.assertEqual(process_tree_pids(10, snapshot), (10, 11))

    def test_attributed_cleanup_scope_tracks_new_mirror_and_descendant_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror = root / "app"
            snapshot = [
                RunningProcessCandidate(pid=10, name="ChatGPT.exe", parent_pid=1, executable=mirror / "ChatGPT.exe"),
                RunningProcessCandidate(pid=11, name="helper.exe", parent_pid=10, executable=mirror / "helper.exe"),
                RunningProcessCandidate(pid=12, name="unrelated.exe", parent_pid=99, executable=root / "other" / "unrelated.exe"),
                RunningProcessCandidate(pid=13, name="old.exe", parent_pid=10, executable=mirror / "old.exe"),
            ]
            tracked = attributable_process_pids(10, {13}, snapshot, mirror)
            self.assertEqual(tracked, (10, 11))
            self.assertTrue(path_is_within(mirror / "nested.exe", mirror))
            self.assertFalse(path_is_within(root / "application.exe", mirror))

    def test_desktop_inventory_is_root_only_and_records_absent_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            resources = app / "resources"
            resources.mkdir(parents=True)
            write_pe(app / "ChatGPT.exe")
            (resources / "codex.exe").write_bytes(b"bundled runtime")
            (root / "AppxManifest.xml").write_text(
                "<Package><Applications><Application Executable=\"app/ChatGPT.exe\"/></Applications></Package>",
                encoding="utf-8",
            )
            source = DesktopSource(
                source_root=root,
                app_dir=app,
                executable=app / "ChatGPT.exe",
                resources_dir=resources,
                app_asar=resources / "app.asar",
                package=PackageMetadata(name="OpenAI.Codex"),
                source_kind="fixture",
                file_version="1.0.0",
            )
            with patch(
                "scripts.windows.discovery.read_file_versions",
                return_value={"FileVersion": "1.0.0", "ProductVersion": "1.0.0"},
            ), patch(
                "scripts.windows.discovery.read_authenticode",
                return_value=AuthenticodeMetadata("Valid", "CN=OpenAI"),
            ), patch(
                "scripts.windows.integrity.read_pe_integrity_resources",
                return_value={"resources": []},
            ):
                inventory = inventory_desktop_executables(source)
            self.assertEqual([item.relative_path for item in inventory], [r"app\ChatGPT.exe", r"app\Codex.exe"])
            self.assertTrue(inventory[0].present)
            self.assertTrue(inventory[0].appx_manifest_declared)
            self.assertFalse(inventory[1].present)
            self.assertEqual(inventory[1].authenticode.status, "NOT PRESENT")
            self.assertNotIn(r"resources\codex.exe", [item.relative_path for item in inventory])

    def test_exact_26_820_chatgpt_shell_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            app.mkdir()
            source = DesktopSource(
                source_root=root,
                app_dir=app,
                executable=app / "ChatGPT.exe",
                resources_dir=app / "resources",
                app_asar=app / "resources" / "app.asar",
                package=PackageMetadata(
                    name="OpenAI.Codex",
                    version="26.820.7780.0",
                ),
                source_kind="fixture",
                file_version="151.0.7922.170",
            )
            def candidate(relative: str, declared: bool) -> DesktopExecutableCandidate:
                return DesktopExecutableCandidate(
                    path=root / relative.replace("\\", "/"),
                    relative_path=relative,
                    present=True,
                    file_size=1,
                    file_version="151.0.7922.170",
                    product_version="151.0.7922.170",
                    authenticode=AuthenticodeMetadata("Valid", "CN=OpenAI"),
                    pe_machine=0x8664,
                    appx_manifest_declared=declared,
                    fuse_wire_present=False,
                    fuse=None,
                    fuse_error=None,
                    integrity_resource_present=False,
                    integrity_resources=(),
                    integrity_error=None,
                )

            selected = select_authoritative_desktop_candidate(
                source,
                (candidate(r"app\ChatGPT.exe", True), candidate(r"app\Codex.exe", False)),
            )
            self.assertEqual(selected.relative_path, r"app\ChatGPT.exe")

    def test_acl_audit_normalizes_appcontainer_sids_without_calling_them_malicious(self) -> None:
        audit = _audit_from_payload(
            Path(r"C:\router\app"),
            {
                "Owner": "S-1-5-21-owner",
                "Sddl": "O:S-1-5-21-ownerD:(A;;0x1200a9;;;S-1-15-2-1)(A;;0x1200a9;;;S-1-15-2-2)(A;;0x1200a9;;;S-1-15-99-1)",
                "ProtectedDacl": False,
                "Access": [
                    {
                        "Sid": ALL_APPLICATION_PACKAGES_SID,
                        "Rights": "ReadAndExecute, Synchronize",
                        "AccessType": "Allow",
                        "IsInherited": False,
                        "InheritanceFlags": "ContainerInherit, ObjectInherit",
                    },
                    {
                        "Sid": ALL_RESTRICTED_APPLICATION_PACKAGES_SID,
                        "Rights": "ReadAndExecute, Synchronize",
                        "AccessType": "Allow",
                        "IsInherited": False,
                        "InheritanceFlags": "ContainerInherit, ObjectInherit",
                    },
                ],
            },
        )
        self.assertTrue(audit.all_application_packages_rx)
        self.assertTrue(audit.all_restricted_application_packages_rx)
        self.assertEqual(audit.unknown_appcontainer_sids, ("S-1-15-99-1",))
        self.assertFalse(audit.inheritance["protected_dacl"])

    def test_acl_scope_is_read_only_and_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "app"
            path.mkdir()
            with patch(
                "scripts.windows.acl._run_acl_query",
                return_value=(
                    {
                        "Owner": "S-1-5-18",
                        "Sddl": "O:S-1-5-18",
                        "ProtectedDacl": True,
                        "Access": [],
                    },
                    None,
                ),
            ):
                result = audit_acl_scope({"local_app": path})
            self.assertTrue(result["read_only"])
            self.assertFalse(result["manual_operation_required"])
            self.assertEqual(result["audits"]["local_app"]["path"], str(path.resolve()))

    def test_acl_mutation_rejects_windowsapps_and_paths_outside_router_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "WindowsApps" / "package" / "app"
            app.mkdir(parents=True)
            with self.assertRaises(AclMutationBlockedError):
                validate_router_app_root(app, app.parent)

            local_root = root / "router"
            local_app = local_root / "app"
            local_app.mkdir(parents=True)
            with self.assertRaises(AclMutationBlockedError):
                validate_router_app_root(local_app, root)

    def test_acl_mutation_adds_only_two_rx_appcontainer_aces_and_verifies_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "router"
            app = root / "app"
            app.mkdir(parents=True)
            before = AclAudit(
                path=app,
                exists=True,
                accessible=True,
                owner="S-1-5-21-owner",
                sddl="O:S-1-5-21-owner",
                protected_dacl=False,
                inheritance={"protected_dacl": False},
                all_application_packages_rx=False,
                all_restricted_application_packages_rx=False,
                unknown_appcontainer_sids=(),
                access_entries=(
                    {
                        "Sid": "S-1-5-18",
                        "Rights": "FullControl",
                        "AccessType": "Allow",
                        "IsInherited": False,
                    },
                ),
            )
            after = AclAudit(
                path=app,
                exists=True,
                accessible=True,
                owner=before.owner,
                sddl=before.sddl,
                protected_dacl=False,
                inheritance={"protected_dacl": False},
                all_application_packages_rx=True,
                all_restricted_application_packages_rx=True,
                unknown_appcontainer_sids=(),
                access_entries=before.access_entries
                + (
                    {"Sid": ALL_APPLICATION_PACKAGES_SID, "Rights": "ReadAndExecute", "AccessType": "Allow", "IsInherited": False},
                    {"Sid": ALL_RESTRICTED_APPLICATION_PACKAGES_SID, "Rights": "ReadAndExecute", "AccessType": "Allow", "IsInherited": False},
                ),
            )
            with patch("scripts.windows.acl.os.name", "nt"), patch(
                "scripts.windows.acl.shutil.which", return_value=r"C:\Windows\System32\icacls.exe"
            ), patch("scripts.windows.acl.read_acl_audit", side_effect=[before, after]), patch(
                "scripts.windows.acl.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout="processed", stderr=""),
            ) as run_command:
                result = prepare_windows_electron_payload_acl(app, router_root=root)
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["verified"])
            self.assertEqual(result["scope"], str(app.resolve()))
            command = run_command.call_args.args[0]
            self.assertIn(f"*{ALL_APPLICATION_PACKAGES_SID}:{APP_CONTAINER_RX_INHERITANCE}", command)
            self.assertIn(f"*{ALL_RESTRICTED_APPLICATION_PACKAGES_SID}:{APP_CONTAINER_RX_INHERITANCE}", command)
            self.assertIn("/T", command)
            self.assertEqual(result["runtime_user_data_scope"], "excluded")

    def test_launch_classification_does_not_treat_plain_windowsapps_path_as_identity(self) -> None:
        result = classify_probe_output(
            r"Launching C:\Program Files\WindowsApps\OpenAI.Codex\app\ChatGPT.exe",
            still_running=False,
            return_code=3,
        )
        self.assertEqual(result["status"], CRASHED)
        self.assertNotIn("package identity", str(result["relevant_log_lines"]))

    def test_launch_classification_uses_exact_identity_categories_and_preserves_lines(self) -> None:
        updater_line = "Failed to set up updater: process package ID is missing"
        updater = classify_probe_output(updater_line, still_running=False, return_code=3)
        self.assertEqual(updater["status"], BLOCKED_UPDATER_IDENTITY)
        self.assertIn(updater_line, updater["relevant_log_lines"]["updater_identity"])

        other = classify_probe_output("AppX activation context failed for package identity", still_running=False, return_code=3)
        self.assertEqual(other["status"], BLOCKED_OTHER_PACKAGE_IDENTITY)
        single = classify_probe_output("requestSingleInstanceLock returned false", still_running=False, return_code=1)
        self.assertEqual(single["status"], BLOCKED_SINGLE_INSTANCE_LOCK)
        native = classify_probe_output("native addon.node could not be found", still_running=False, return_code=1)
        self.assertEqual(native["status"], BLOCKED_NATIVE_MODULE)
        resource = classify_probe_output("failed to open resources\\app.asar", still_running=False, return_code=1)
        self.assertEqual(resource["status"], BLOCKED_RESOURCE)

    def test_launch_classification_recognizes_gpu_not_usable_fatal_line(self) -> None:
        result = classify_probe_output(
            "[gpu_process_host] launch GPU process\nGPU process isn't usable. Goodbye.",
            still_running=False,
            return_code=-2147483645,
        )
        self.assertEqual(result["status"], BLOCKED_CHROMIUM_SANDBOX)
        self.assertEqual(result["chromium_sandbox"]["fatal_line"], "GPU process isn't usable. Goodbye.")
        self.assertGreaterEqual(result["chromium_sandbox"]["gpu_child_launch_attempt_count"], 1)

    def test_launch_classification_separates_gpu_sandbox_failure_and_records_child_evidence(self) -> None:
        log = "\n".join(
            [
                "GPU process launch attempt 1",
                "gpu_process_host: GPU process exited unexpectedly: exit_code=-2147483645",
                "GPU process launch attempt 2",
                "GPU process exited unexpectedly: exit_code=0x80000003",
                "renderer process exited unexpectedly",
                "GPU process isn't usable. Goodbye.",
            ]
        )
        result = classify_probe_output(log, still_running=False, return_code=2147483651)
        self.assertEqual(result["status"], BLOCKED_CHROMIUM_SANDBOX)
        evidence = result["chromium_sandbox"]
        self.assertEqual(evidence["gpu_child_launch_attempt_count"], 4)
        self.assertEqual(evidence["gpu_child_exit_codes"], ["-2147483645", "0x80000003"])
        self.assertTrue(evidence["renderer_child_process_failure_observed"])
        self.assertEqual(evidence["fatal_line"], "GPU process isn't usable. Goodbye.")
        self.assertIn("GPU process isn't usable. Goodbye.", result["relevant_log_lines"]["chromium_sandbox"]["gpu"])

    def test_normal_crash_remains_crashed_without_gpu_evidence(self) -> None:
        result = classify_probe_output("fatal: unrelated startup failure", still_running=False, return_code=1)
        self.assertEqual(result["status"], CRASHED)

    def test_forced_probe_cleanup_gpu_exit_is_not_sandbox_evidence(self) -> None:
        result = classify_probe_output(
            "[gpu_process_host] GPU process exited unexpectedly: exit_code=49374",
            still_running=True,
            return_code=None,
        )
        self.assertEqual(result["status"], PASS)
        self.assertTrue(result["chromium_sandbox"]["cleanup_artifact_only"])

    def test_phase2a4_final_layout_root_uses_localappdata_and_is_disposable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cleanup: dict[str, object] = {}
            with patch("scripts.windows.smoke.os.name", "nt"), patch(
                "scripts.windows.smoke.os.environ",
                {"LOCALAPPDATA": temporary},
            ):
                with final_layout_smoke_root(cleanup) as root:
                    self.assertTrue(root.is_dir())
                    self.assertTrue(root.parent.parent.name == "Codex Subscription Router")
                    self.assertTrue((root / "app").is_dir())
                    self.assertTrue((root / "User Data").is_dir())
                    self.assertTrue((root / "codex-home").is_dir())
                    kept_root = root
            self.assertFalse(kept_root.exists())
            self.assertFalse(cleanup["path_virtualized"])
            self.assertTrue(cleanup["removed"])

    def test_native_evidence_requires_cleanup_after_context_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cleanup: dict[str, object] = {}
            with patch("scripts.windows.smoke.os.name", "nt"), patch(
                "scripts.windows.smoke.os.environ",
                {"LOCALAPPDATA": temporary},
            ):
                with final_layout_smoke_root(cleanup) as root:
                    self.assertFalse(native_evidence_is_usable(cleanup))
                    self.assertTrue(root.is_dir())
            self.assertTrue(native_evidence_is_usable(cleanup))
        self.assertTrue(native_evidence_is_usable({"path_virtualized": False, "removed": True}))
        self.assertFalse(native_evidence_is_usable({"path_virtualized": False, "removed": False}))
        self.assertFalse(native_evidence_is_usable({"path_virtualized": True, "removed": True}))

    def test_host_context_detects_no_package_from_native_api(self) -> None:
        class FakePackageApi:
            argtypes = None
            restype = None

            def __call__(self, length, buffer):
                return APPMODEL_ERROR_NO_PACKAGE

        fake_kernel32 = SimpleNamespace(GetCurrentPackageFullName=FakePackageApi())
        with patch("scripts.windows.host_context.os.name", "nt"), patch(
            "scripts.windows.host_context.ctypes.WinDLL",
            return_value=fake_kernel32,
            create=True,
        ):
            result = detect_windows_host_context()
        self.assertFalse(result["has_package_identity"])
        self.assertEqual(result["package_full_name"], None)
        self.assertEqual(result["appmodel_result"], APPMODEL_ERROR_NO_PACKAGE)
        self.assertEqual(result["appmodel_result_name"], "APPMODEL_ERROR_NO_PACKAGE")

    def test_host_context_detects_successful_package_identity_from_native_api(self) -> None:
        class FakePackageApi:
            argtypes = None
            restype = None

            def __call__(self, length, buffer):
                if buffer is None:
                    length._obj.value = len("OpenAI.Codex_2p2nqsd0c76g0") + 1
                    return 122
                buffer.value = "OpenAI.Codex_2p2nqsd0c76g0"
                return 0

        fake_kernel32 = SimpleNamespace(GetCurrentPackageFullName=FakePackageApi())
        with patch("scripts.windows.host_context.os.name", "nt"), patch(
            "scripts.windows.host_context.ctypes.WinDLL",
            return_value=fake_kernel32,
            create=True,
        ):
            result = detect_windows_host_context()
        self.assertTrue(result["has_package_identity"])
        self.assertEqual(result["package_full_name"], "OpenAI.Codex_2p2nqsd0c76g0")
        self.assertEqual(result["appmodel_result_name"], "ERROR_SUCCESS")

    def test_localappdata_canary_records_physical_path_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            local_appdata = Path(temporary)

            def final_path(path: Path) -> tuple[str, str | None]:
                return str(path.resolve()), None

            with patch("scripts.windows.host_context.os.name", "nt"), patch(
                "scripts.windows.host_context._native_final_path",
                side_effect=final_path,
            ):
                result = run_localappdata_canary(local_appdata)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["filesystem_virtualized"])
        self.assertTrue(result["cleanup"]["removed"])

    def test_localappdata_canary_detects_package_cache_redirection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            local_appdata = Path(temporary)

            def redirected_path(_path: Path) -> tuple[str, str | None]:
                return str(local_appdata / "Packages" / "OpenAI.Codex" / "LocalCache" / "canary.txt"), None

            with patch("scripts.windows.host_context.os.name", "nt"), patch(
                "scripts.windows.host_context._native_final_path",
                side_effect=redirected_path,
            ):
                result = run_localappdata_canary(local_appdata)
        self.assertEqual(result["status"], "HOST FILESYSTEM VIRTUALIZED")
        self.assertTrue(result["filesystem_virtualized"])
        self.assertTrue(result["cleanup"]["removed"])

    def test_phase2a5_packaged_host_aborts_before_source_or_canary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "result.json"
            context = {
                "has_package_identity": True,
                "package_full_name": "OpenAI.Codex_2p2nqsd0c76g0",
                "appmodel_result": 0,
                "current_executable": "C:\\Windows\\python.exe",
                "pid": 1,
                "LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local",
                "USERPROFILE": "C:\\Users\\test",
            }
            with patch(
                "scripts.windows.phase2a5_host_validation.detect_windows_host_context",
                return_value=context,
            ), patch(
                "scripts.windows.phase2a5_host_validation.run_localappdata_canary"
            ) as canary, patch(
                "scripts.windows.phase2a5_host_validation.discover_desktop_source"
            ) as discover:
                result = run_phase2a5_host_validation(repo_root=root, artifact_path=artifact)
            self.assertTrue(artifact.is_file())
        self.assertEqual(result["status"], "PHASE 2A.5 HOST CONTEXT BLOCKED")
        self.assertIn("independently from an unpackaged Windows process", result["reason"])
        canary.assert_not_called()
        discover.assert_not_called()

    def test_phase2a5_powershell_runner_forwards_python_flags(self) -> None:
        runner = (Path(__file__).resolve().parents[2] / "scripts" / "windows" / "run_phase2a5_host_validation.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[CmdletBinding(PositionalBinding = $false)]", runner)
        self.assertIn(
            "Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))",
            runner,
        )
        self.assertIn("$pythonArguments += $RunnerArguments", runner)

    def test_payload_acl_strategy_is_explicit_and_default_is_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            app.mkdir()
            with patch("scripts.patch_app_windows.prepare_windows_electron_payload_acl") as prepare:
                none = _payload_acl_for_strategy(app, router_root=root, strategy=PAYLOAD_ACL_NONE)
                unresolved = _payload_acl_for_strategy(
                    app,
                    router_root=root,
                    strategy=PAYLOAD_ACL_UNRESOLVED,
                )
            prepare.assert_not_called()
        self.assertEqual(none["strategy"], PAYLOAD_ACL_NONE)
        self.assertFalse(none["applied"])
        self.assertEqual(unresolved["strategy"], PAYLOAD_ACL_UNRESOLVED)
        self.assertFalse(unresolved["applied"])

    def test_phase2a5_selected_real_candidate_is_not_replaced_by_first_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = RealCodexCandidate(
                path=root / "first.exe",
                version="first",
                sha256="a" * 64,
                authenticode=AuthenticodeMetadata("Unknown", None),
                modified_time=1.0,
                valid_native=True,
            )
            selected = RealCodexCandidate(
                path=root / "selected.exe",
                version="selected",
                sha256="b" * 64,
                authenticode=AuthenticodeMetadata("Valid", "CN=OpenAI"),
                modified_time=2.0,
                valid_native=True,
            )

            @contextmanager
            def fake_smoke_root(cleanup, **_kwargs):
                cleanup.update({"path_virtualized": False, "requested_path": str(root), "resolved_path": str(root)})
                yield root
                cleanup.update({"removed": True, "error": None})

            with patch(
                "scripts.windows.phase2a5_host_validation.final_layout_smoke_root",
                side_effect=fake_smoke_root,
            ), patch(
                "scripts.windows.phase2a5_host_validation.build_windows_desktop",
                return_value={
                    "desktop_launch_executable": "app\\ChatGPT.exe",
                    "payload_acl_strategy": PAYLOAD_ACL_NONE,
                },
            ) as build, patch(
                "scripts.windows.phase2a5_host_validation.run_patched_shell_smoke",
                return_value={
                    "status": "PATCHED_SHELL_PASS",
                    "manual_operation_required": False,
                    "mux_process_observed": True,
                    "real_codex_process_observed": True,
                },
            ):
                _run_external_patched_shell(
                    SimpleNamespace(),
                    selected,
                    acl_strategy=PAYLOAD_ACL_NONE,
                    timeout_seconds=1.0,
                )
        self.assertIs(build.call_args.args[1], selected)
        self.assertIsNot(build.call_args.args[1], first)

    def test_phase2a4_verdict_ignores_codex_diagnostic_failure(self) -> None:
        probe_a = {"status": BLOCKED_CHROMIUM_SANDBOX}
        probe_b = {"status": PASS}
        probe_c = {"status": PASS}
        self.assertEqual(_phase2a4_verdict(probe_a, probe_b, probe_c, None), LOCAL_APP_ACL_FIX_CONFIRMED)
        self.assertEqual(
            _phase2a4_verdict(probe_a, {"status": "CRASHED"}, probe_c, None),
            APP_CONTAINER_ACCESS_FIX_CONFIRMED,
        )
        self.assertEqual(
            _phase2a4_display_verdict(LOCAL_APP_ACL_FIX_CONFIRMED),
            PHASE2A4_LOCAL_ACL_FIX_CONFIRMED,
        )

    def test_sandbox_bypass_flags_are_not_in_production_launcher_or_builder(self) -> None:
        builder = inspect.getsource(build_windows_desktop)
        self.assertNotIn("--disable-gpu-sandbox", builder)
        self.assertNotIn("--no-sandbox", builder)
        launcher = (Path(__file__).resolve().parents[2] / "cmd" / "codex-router-launcher" / "main.go").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"--disable-gpu-sandbox"', launcher)
        self.assertNotIn('"--no-sandbox"', launcher)

    def test_patched_shell_smoke_requires_an_explicit_disposable_root(self) -> None:
        with patch("scripts.windows.smoke.os.name", "nt"):
            result = run_patched_shell_smoke(Path(tempfile.gettempdir()) / "router", object())
        self.assertEqual(result["status"], PATCHED_SHELL_BLOCKED)
        self.assertTrue(result["manual_operation_required"])
        self.assertIn("disposable", result["reason"])

    def test_patched_shell_sandbox_flag_requires_development_only_mode(self) -> None:
        with patch("scripts.windows.smoke.os.name", "nt"):
            result = run_patched_shell_smoke(
                Path(tempfile.gettempdir()) / "router",
                object(),
                disposable_root=True,
                diagnostic_arguments=("--disable-gpu-sandbox",),
            )
        self.assertEqual(result["status"], PATCHED_SHELL_BLOCKED)
        self.assertTrue(result["manual_operation_required"])

    def test_builder_copies_mux_token_into_router_owned_runtime_state(self) -> None:
        source = inspect.getsource(build_windows_desktop)
        self.assertIn('staged_runtime / ".codex-mux"', source)
        self.assertIn('staged_mux_home / "control-token"', source)
        self.assertIn("staged_control_token.write_text(token", source)

    def test_minimal_bootstrap_patch_has_no_renderer_or_ui_bridge_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            build = extracted / ".vite" / "build"
            build.mkdir(parents=True)
            bootstrap_path = build / "bootstrap-fixture.js"
            main_path = build / "main-fixture.js"
            bootstrap_path.write_text(
                "e.app.setPath(`userData`,x({appDataPath:e.app.getPath(`appData`),"
                "buildFlavor:`stable`,env:process.env}))"
                "await u.initialize();try{let{runMainAppStartup:startup}=x}",
                encoding="utf-8",
            )
            main_path.write_text("renderer sentinel", encoding="utf-8")
            before_main = main_path.read_text(encoding="utf-8")
            report = patch_bootstrap(
                extracted,
                Path(__file__).resolve().parents[2],
                patch_user_data=False,
                disable_updater=True,
                inject_ui_test_bridge=False,
            )
            self.assertEqual(report.strategy, "updater-only")
            self.assertFalse(report.user_data_patched)
            self.assertTrue(report.updater_disabled)
            self.assertFalse(report.ui_test_bridge_injected)
            self.assertIsNone(report.ui_test_bridge)
            self.assertEqual(main_path.read_text(encoding="utf-8"), before_main)
            self.assertNotIn("await u.initialize();", bootstrap_path.read_text(encoding="utf-8"))
            self.assertNotIn("CODEX_MUX_UI_TESTS", main_path.read_text(encoding="utf-8"))

    def test_probe_contract_uses_temporary_profiles_and_cli_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror = root / "mirror"
            mirror.mkdir()
            executable = mirror / "ChatGPT.exe"
            executable.write_bytes(b"desktop")
            real_path = root / "codex.exe"
            write_pe(real_path)
            candidate = DesktopExecutableCandidate(
                path=executable,
                relative_path=r"app\ChatGPT.exe",
                present=True,
                file_size=executable.stat().st_size,
                file_version="1.0.0",
                product_version="1.0.0",
                authenticode=AuthenticodeMetadata("Valid", "CN=OpenAI"),
                pe_machine=0x8664,
                appx_manifest_declared=True,
                fuse_wire_present=False,
                fuse=None,
                fuse_error=None,
                integrity_resource_present=False,
                integrity_resources=(),
                integrity_error=None,
            )
            real = RealCodexCandidate(
                path=real_path,
                version="codex-cli test",
                sha256="a" * 64,
                authenticode=AuthenticodeMetadata("Valid", "CN=OpenAI"),
                modified_time=0,
                valid_native=True,
            )
            captured: dict[str, object] = {}

            class FakeProcess:
                pid = 91234

                def poll(self) -> int:
                    return 0

                def terminate(self) -> None:
                    return None

                def wait(self, timeout: float | None = None) -> int:
                    del timeout
                    return 0

            def fake_popen(command: list[str], **kwargs: object) -> FakeProcess:
                captured["command"] = command
                captured["env"] = kwargs["env"]
                stdout = kwargs["stdout"]
                assert hasattr(stdout, "write")
                stdout.write("packaged=true enableUpdater=false app-server ready\\n")
                return FakeProcess()

            with patch("scripts.windows.smoke.os.name", "nt"), patch(
                "scripts.windows.smoke.subprocess.Popen", side_effect=fake_popen
            ), patch("scripts.windows.smoke.discover_process_snapshot_native", return_value=[]), patch(
                "scripts.windows.smoke.enumerate_windows_for_processes", return_value=[]
            ), patch(
                "scripts.windows.smoke.terminate_attributed_processes",
                return_value={"tracked": [91234], "requested": [], "terminated": [], "errors": []},
            ), patch("scripts.windows.smoke._official_instance_present", return_value=False), patch(
                "scripts.windows.smoke.time.sleep"
            ):
                result = _probe_candidate(
                    mirror,
                    root,
                    real,
                    candidate,
                    timeout_seconds=0,
                )
            self.assertEqual(result["status"], CRASHED)
            self.assertEqual(result["profile_isolation"]["contract_valid"], True)
            self.assertEqual(result["profile_isolation"]["sparkle_enabled"], False)
            self.assertIn("--user-data-dir=", captured["command"][1])
            environment = captured["env"]
            self.assertEqual(environment["CODEX_CLI_PATH"], str(real_path))
            self.assertEqual(environment["CODEX_ELECTRON_USER_DATA_PATH"], result["profile_isolation"]["user_data"])
            self.assertEqual(environment["CODEX_HOME"], result["profile_isolation"]["codex_home"])
            self.assertEqual(environment["CODEX_SPARKLE_ENABLED"], "false")

    def test_integrity_plan_follows_actual_carrier_not_manifest_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "ChatGPT.exe"
            carrier = root / "chrome.dll"
            executable.write_bytes(b"manifest executable")
            carrier.write_bytes(b"actual carrier")
            fuse = FuseSnapshot(1, 9, ("on", "off", "on", "on", "off", "off", "off", "on", "on"), 0)
            with patch("scripts.windows.integrity.read_fuses", return_value=fuse), patch(
                "scripts.windows.integrity.read_pe_integrity_resources",
                return_value={"resources": []},
            ):
                plan = resolve_windows_asar_integrity(executable, carrier_paths=[carrier])
            self.assertEqual(plan.state, FUSE_PRESENT_ASAR_VALIDATION_DISABLED)
            self.assertTrue(plan.resolved)
            self.assertTrue(plan.carrier_paths_known)
            self.assertEqual(plan.carrier_paths, (carrier,))
            self.assertEqual(plan.to_dict()["carrier_records"][0]["relative"], "chrome.dll")
            self.assertEqual(plan.to_dict()["carrier_records"][0]["fuse"]["fuses"], list(fuse.fuses))

    def test_fuse_scan_records_carrier_state_and_scans_dlls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            carrier = root / "ChatGPT.exe"
            carrier.write_bytes(
                b"MZ" + SENTINEL + bytes([1, 9]) + bytes(FUSE_VALUES["on"] for _ in range(9))
            )
            (root / "helper.dll").write_bytes(b"dll")
            report = scan_fuse_carriers(root)
            self.assertEqual(report["carrier_count"], 1)
            self.assertEqual(report["carriers"][0]["relative"], "ChatGPT.exe")
            self.assertEqual(report["carriers"][0]["fuse"]["fuses"][8], "on")
            self.assertEqual(len(report["scanned_files"]), 2)

    def test_known_executable_derives_package_layout_without_parent_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_root = Path(temporary) / "OpenAI.Codex_1.0.0.0_x64__publisher"
            app = package_root / "app"
            (app / "resources").mkdir(parents=True)
            executable = app / "ChatGPT.exe"
            executable.write_bytes(b"desktop")
            (app / "resources" / "app.asar").write_bytes(b"asar")
            package = PackageMetadata(
                name="OpenAI.Codex",
                package_full_name=package_root.name,
                version="1.0.0.0",
                install_location=package_root,
                architecture="X64",
            )
            with patch("scripts.windows.discovery.read_file_version", return_value="1.2.3"), patch(
                "pathlib.Path.iterdir", side_effect=AssertionError("source parent enumeration is forbidden")
            ):
                source = desktop_source_from_executable(
                    executable,
                    package=package,
                    source_kind="running-process",
                )
            self.assertEqual(source.source_root, package_root.resolve(strict=False))
            self.assertEqual(source.app_dir, app.resolve(strict=False))
            self.assertEqual(source.app_asar, (app / "resources" / "app.asar").resolve(strict=False))

    def test_start_apps_recognition_uses_aumid_not_display_name(self) -> None:
        rows = [
            {"Name": "Localized product name", "AppID": "OpenAI.Codex_2p2nqsd0c76g0!App"},
            {"Name": "ChatGPT", "AppID": "OpenAI.ChatGPT_2p2nqsd0c76g0!App"},
            {"Name": "Codex", "AppID": "Vendor.Codex_other!App"},
            {"Name": "OpenAI", "AppID": "OpenAI.Codex_2p2nqsd0c76g0!Other"},
        ]
        self.assertEqual(
            recognize_start_app_aumids(rows),
            ("OpenAI.ChatGPT_2p2nqsd0c76g0!App", "OpenAI.Codex_2p2nqsd0c76g0!App"),
        )

    def test_manifest_metadata_and_aumid_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_root = Path(temporary) / "OpenAI.Codex_26.820.7780.0_x64__2p2nqsd0c76g0"
            package_root.mkdir()
            (package_root / "AppxManifest.xml").write_text(
                "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\">"
                "<Identity Name=\"OpenAI.Codex\" Publisher=\"CN=publisher\" "
                "Version=\"26.820.7780.0\" ProcessorArchitecture=\"x64\"/>"
                "<Applications><Application Id=\"App\" Executable=\"app/ChatGPT.exe\"/>"
                "<Application Id=\"Updater\" Executable=\"app/Updater.exe\"/></Applications></Package>",
                encoding="utf-8",
            )
            metadata, error = read_appx_manifest_metadata(package_root)
            self.assertIsNone(error)
            self.assertEqual(metadata.publisher, "CN=publisher")
            self.assertEqual(
                read_appx_manifest_aumids(package_root, metadata),
                ("OpenAI.Codex_2p2nqsd0c76g0!App", "OpenAI.Codex_2p2nqsd0c76g0!Updater"),
            )

    def test_appx_block_map_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "AppxBlockMap.xml"
            path.write_text(
                "<BlockMap><File Name=\"app/../outside.exe\"><Block Hash=\"x\"/></File></BlockMap>",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                parse_appx_block_map(path)

    def test_block_map_mirror_is_used_after_directory_enumeration_denial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_root = root / "package"
            app = package_root / "app"
            resources = app / "resources"
            resources.mkdir(parents=True)
            (app / "ChatGPT.exe").write_bytes(b"desktop")
            (app / "resources.pak").write_bytes(b"pak")
            (resources / "app.asar").write_bytes(b"asar")
            (resources / "cua_node").mkdir()
            (resources / "cua_node" / "node.exe").write_bytes(b"optional")
            (package_root / "AppxBlockMap.xml").write_text(
                "<BlockMap>"
                "<File Name=\"app/ChatGPT.exe\"/><File Name=\"app/resources.pak\"/>"
                "<File Name=\"app/resources/app.asar\"/>"
                "<File Name=\"app/resources/cua_node/node.exe\"/>"
                "</BlockMap>",
                encoding="utf-8",
            )
            source = DesktopSource(
                source_root=package_root,
                app_dir=app,
                executable=app / "ChatGPT.exe",
                resources_dir=resources,
                app_asar=resources / "app.asar",
                package=PackageMetadata(name="OpenAI.Codex"),
                source_kind="appx",
                file_version="1.0.0",
            )
            destination = root / "mirror"
            with patch(
                "scripts.windows.mirror.mirror_directory",
                side_effect=DirectoryEnumerationBlockedError("access denied"),
            ):
                report = mirror_desktop_source(source, destination)
            self.assertEqual(report.strategy, "appx-block-map")
            self.assertTrue((destination / "ChatGPT.exe").is_file())
            self.assertTrue((destination / "resources.pak").is_file())
            self.assertTrue((destination / "resources" / "app.asar").is_file())
            self.assertFalse((destination / "resources" / "cua_node").exists())
            self.assertTrue(any("cua_node" in item for item in report.excluded))

    def test_required_mirror_copy_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "ChatGPT.exe").write_bytes(b"desktop")
            with patch(
                "scripts.windows.mirror.shutil.copy2",
                side_effect=OSError("access denied"),
            ):
                with self.assertRaises(PackagingBlockedError):
                    mirror_directory(source, root / "destination")

    def test_source_probe_output_is_structured_and_non_sensitive(self) -> None:
        diagnostics = SourceDiagnostics(
            probes=[SourceProbeResult("test-method", "PASS", ("C:/candidate",))]
        )
        rendered = format_source_diagnostics(diagnostics)
        self.assertIn("test-method: PASS", rendered)
        self.assertEqual(diagnostics.to_dict()["probes"][0]["status"], "PASS")

    def test_audit_only_does_not_modify_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            resources = app / "resources"
            resources.mkdir(parents=True)
            executable = app / "ChatGPT.exe"
            executable.write_bytes(b"desktop")
            asar = resources / "app.asar"
            asar.write_bytes(b"asar")
            (root / "AppxManifest.xml").write_text("<Package><Identity Name=\"OpenAI.Codex\"/></Package>", encoding="utf-8")
            (root / "AppxBlockMap.xml").write_text(
                "<BlockMap><File Name=\"app/ChatGPT.exe\"/><File Name=\"app/resources/app.asar\"/></BlockMap>",
                encoding="utf-8",
            )
            source = DesktopSource(
                source_root=root,
                app_dir=app,
                executable=executable,
                resources_dir=resources,
                app_asar=asar,
                package=PackageMetadata(name="OpenAI.Codex"),
                source_kind="fixture",
                file_version="1.0.0",
            )
            executable_before = executable.read_bytes()
            asar_before = asar.read_bytes()
            with patch("scripts.patch_app_windows.ensure_asar_tool", return_value=Path("asar")), patch(
                "scripts.patch_app_windows.read_file_versions",
                return_value={"FileVersion": "1.0.0", "ProductVersion": "1.0.0"},
            ), patch(
                "scripts.patch_app_windows.read_authenticode",
                return_value=AuthenticodeMetadata("Valid", "CN=OpenAI"),
            ), patch(
                "scripts.patch_app_windows.asar_header_digest",
                return_value=AsarHeaderDigest("sha256", "a" * 64, 4, 3),
            ), patch("scripts.patch_app_windows.run"), patch(
                "scripts.patch_app_windows.audit_renderer_anchors", return_value=[]
            ):
                result = audit_windows_source(source)
            self.assertEqual(result["electron_fuses"]["status"], "NOT PRESENT")
            self.assertEqual(executable.read_bytes(), executable_before)
            self.assertEqual(asar.read_bytes(), asar_before)

    def test_windows_ci_setup_go_sha_is_pinned_to_correct_commit(self) -> None:
        workflow = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("actions/setup-go@b7ad1dad31d06c5925ef5d2fc7ad053ef454303e", workflow)
        self.assertGreaterEqual(
            workflow.count("actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"),
            2,
        )

    def test_build_uses_executable_inside_staged_app(self) -> None:
        source = inspect.getsource(build_windows_desktop)
        self.assertIn("staged_source_executable = staged_app / source.executable.name", source)
        self.assertNotIn("staged / source.executable.name", source)
        self.assertIn("selected_staged_desktop = resolve_staged_launch_path(staged, selected_launch_executable)", source)
        self.assertNotIn("staged_app / Path(selected_launch_executable", source)

    def test_staged_launch_path_uses_installation_root_relative_metadata(self) -> None:
        staged_root = Path(r"C:\staged\Codex Subscription Router")
        chatgpt = resolve_staged_launch_path(staged_root, r"app\ChatGPT.exe")
        codex = resolve_staged_launch_path(staged_root, r"app\Codex.exe")
        self.assertEqual(chatgpt, staged_root / "app" / "ChatGPT.exe")
        self.assertEqual(codex, staged_root / "app" / "Codex.exe")
        self.assertNotEqual(chatgpt, staged_root / "app" / "app" / "ChatGPT.exe")

    def test_staged_launch_path_rejects_unsafe_or_unsupported_metadata(self) -> None:
        staged_root = Path(r"C:\staged\Codex Subscription Router")
        for launch_executable in (
            r"..\ChatGPT.exe",
            r"C:\Program Files\ChatGPT.exe",
            r"\\server\share\ChatGPT.exe",
            r"resources\ChatGPT.exe",
            "arbitrary.exe",
        ):
            with self.subTest(launch_executable=launch_executable), self.assertRaises(RuntimeError):
                resolve_staged_launch_path(staged_root, launch_executable)

    def test_staged_layout_fixture_passes_and_reports_exact_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staged_root = Path(temporary) / "staged"
            required_layout = {
                "launcher": staged_root / "Codex Subscription Router.exe",
                "mux": staged_root / "runtime" / "codex-mux.exe",
                "real_codex": staged_root / "runtime" / "codex.real.exe",
                "selected_desktop": resolve_staged_launch_path(staged_root, r"app\ChatGPT.exe"),
                "source_desktop": staged_root / "app" / "ChatGPT.exe",
                "app_asar": staged_root / "app" / "resources" / "app.asar",
                "launch_metadata": staged_root / "launch.json",
                "control_token": staged_root / "runtime" / ".codex-mux" / "control-token",
            }
            for path in required_layout.values():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            (required_layout["launch_metadata"]).write_text(
                '{"schema_version":1,"desktop_launch_executable":"app\\\\ChatGPT.exe"}\n',
                encoding="utf-8",
            )
            required_layout["control_token"].write_text("fixture-token\n", encoding="utf-8")

            launch_config = json.loads(required_layout["launch_metadata"].read_text(encoding="utf-8"))
            self.assertEqual(launch_config["desktop_launch_executable"], r"app\ChatGPT.exe")
            result = validate_staged_layout(required_layout)
            self.assertEqual(result["status"], "PASS")

            missing_path = required_layout["selected_desktop"]
            missing_path.unlink()
            with self.assertRaises(RuntimeError) as raised:
                validate_staged_layout(required_layout)
            message = str(raised.exception)
            self.assertIn(f"missing selected_desktop={missing_path}", message)
            self.assertNotIn("fixture-token", message)

    def test_bootstrap_dry_run_audit_matches_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            build = extracted / ".vite" / "build"
            build.mkdir(parents=True)
            (build / "bootstrap-fixture.js").write_text(
                "e.app.setPath(`userData`,x({appDataPath:e.app.getPath(`appData`),"
                "buildFlavor:`stable`,env:process.env}))"
                "await u.initialize();try{let{runMainAppStartup:startup}=x}",
                encoding="utf-8",
            )
            (build / "main-fixture.js").write_text("main", encoding="utf-8")
            report = audit_bootstrap(extracted, Path(__file__).resolve().parents[2])
            self.assertTrue(report["audit_pass"], report)
            self.assertEqual(report["updater_hook"]["initializer_count"], 1)

    def test_exact_26_820_variant_requires_multiple_fingerprints(self) -> None:
        values = renderer_variant_template("windows-26.820")
        bundle = "\n".join(
            [
                str(values["component_anchor"]),
                str(values["app_server_anchor"]),
                str(values["profile_query"]),
                str(values["usage_modal"]),
                str(values["reset_query"]),
                str(values["reset_mutation"]),
                str(values["usage_slot"]),
                str(values["open_change"][0]),
            ]
        )
        selected = select_renderer_variant(
            bundle,
            package_name="OpenAI.Codex",
            package_version="26.820.7780.0",
            app_asar_sha256="5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2",
        )
        self.assertEqual(selected.variant_id, "windows-26.820")
        with self.assertRaises(RuntimeError):
            select_renderer_variant(
                bundle.replace(str(values["reset_mutation"]), "reset-mutation-drift"),
                package_name="OpenAI.Codex",
                package_version="26.820.7780.0",
                app_asar_sha256="5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2",
            )

    def test_exact_26_825_variant_requires_multiple_fingerprints(self) -> None:
        values = renderer_variant_template("windows-26.825")
        bundle = "\n".join(
            [
                str(values["component_anchor"]),
                str(values["app_server_anchor"]),
                str(values["profile_query"]),
                str(values["usage_modal"]),
                str(values["reset_query"]),
                str(values["reset_mutation"]),
                str(values["open_change"][0]),
            ]
        )
        selected = select_renderer_variant(
            bundle,
            package_name="OpenAI.Codex",
            package_version="26.825.5331.0",
            app_asar_sha256="178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b",
        )
        self.assertEqual(selected.variant_id, "windows-26.825")
        with self.assertRaises(RuntimeError):
            select_renderer_variant(
                bundle.replace(str(values["reset_query"]), "reset-query-drift"),
                package_name="OpenAI.Codex",
                package_version="26.825.5331.0",
                app_asar_sha256="178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b",
            )

    def test_reviewed_source_registry_matches_old_and_new_and_rejects_hash_drift(self) -> None:
        records = load_reviewed_sources()
        self.assertEqual({record["renderer_variant"] for record in records}, {"windows-26.820", "windows-26.825"})
        for record in records:
            identity = {
                "package_name": record["package_name"],
                "package_version": record["package_version"],
                "architecture": record["architecture"],
                "app_file_version": record["app_file_version"],
                "app_asar_sha256": record["app_asar_sha256"],
                "app_asar_header_sha256": record["app_asar_header_sha256"],
            }
            self.assertEqual(find_reviewed_source(identity, records), record)
            wrong_hash = dict(identity, app_asar_sha256="0" * 64)
            self.assertIsNone(find_reviewed_source(wrong_hash, records))
        old = next(record for record in records if record["renderer_variant"] == "windows-26.820")
        changed_same_version = dict(
            old,
            app_asar_sha256="1" * 64,
            app_asar_header_sha256="2" * 64,
        )
        identity = {
            "package_name": old["package_name"],
            "package_version": old["package_version"],
            "architecture": old["architecture"],
            "app_file_version": old["app_file_version"],
            "app_asar_sha256": changed_same_version["app_asar_sha256"],
            "app_asar_header_sha256": changed_same_version["app_asar_header_sha256"],
        }
        self.assertIsNone(find_reviewed_source(identity, records))

    def test_renderer_contract_comparison_is_read_only_and_never_patch_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            write_exact_26_820_renderer_fixture(extracted)
            before = {path: path.read_bytes() for path in extracted.rglob("*") if path.is_file()}
            comparison = compare_renderer_contract(extracted)
            after = {path: path.read_bytes() for path in extracted.rglob("*") if path.is_file()}
        self.assertTrue(comparison["read_only"])
        self.assertFalse(comparison["patch_permission_granted"])
        self.assertFalse(comparison["patchable"])
        self.assertEqual(comparison["reference_fingerprint_count"], 8)
        self.assertTrue(comparison["host_scoped_rpc"]["read_only"])
        self.assertEqual(before, after)
        self.assertTrue(all(item["status"] == "UNCHANGED" for item in comparison["surface_status"]), comparison)

    def test_source_stability_detects_asar_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "app" / "ChatGPT.exe"
            asar = root / "app" / "resources" / "app.asar"
            executable.parent.mkdir(parents=True)
            asar.parent.mkdir(parents=True)
            executable.write_bytes(b"chatgpt")
            asar.write_bytes(b"asar-before")
            source = SimpleNamespace(
                source_root=root,
                app_dir=root / "app",
                executable=executable,
                app_asar=asar,
                package=SimpleNamespace(
                    name="OpenAI.Codex",
                    package_full_name="OpenAI.Codex_26.825.5331.0_x64__publisher",
                    version="26.825.5331.0",
                    architecture="X64",
                    publisher="CN=OpenAI",
                ),
                file_version="151.0.7922.174",
                source_kind="fixture",
            )
            with patch(
                "scripts.windows.phase2a5_host_validation.asar_header_digest",
                return_value=AsarHeaderDigest("sha256", "a" * 64, 1, 1),
            ):
                initial = _source_identity(source)
                asar.write_bytes(b"asar-after")
                stability = _source_stability(source, initial)
        self.assertFalse(stability["stable"])
        self.assertIn("app_asar_sha256", stability["changed_fields"])

    def test_unknown_source_stops_before_real_probe_and_keeps_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            resources = app / "resources"
            resources.mkdir(parents=True)
            executable = app / "ChatGPT.exe"
            asar = resources / "app.asar"
            executable.write_bytes(b"chatgpt")
            asar.write_bytes(b"unreviewed-source")
            source = DesktopSource(
                source_root=root,
                app_dir=app,
                executable=executable,
                resources_dir=resources,
                app_asar=asar,
                package=PackageMetadata(
                    name="OpenAI.Codex",
                    package_full_name="OpenAI.Codex_99.0.0.0_x64__publisher",
                    version="99.0.0.0",
                    architecture="X64",
                    publisher="CN=OpenAI",
                ),
                source_kind="fixture",
                file_version="199.0.0.0",
            )
            with patch(
                "scripts.windows.phase2a5_host_validation.collect_startup_runtime",
                return_value={"go_toolchain": {"selected": None, "usable": False, "probes": []}},
            ), patch(
                "scripts.windows.phase2a5_host_validation.detect_windows_host_context",
                return_value={"has_package_identity": False, "LOCALAPPDATA": str(root / "local")},
            ), patch(
                "scripts.windows.phase2a5_host_validation.run_localappdata_canary",
                return_value={"filesystem_virtualized": False},
            ), patch(
                "scripts.windows.phase2a5_host_validation.discover_desktop_source",
                return_value=(source, SourceDiagnostics()),
            ), patch(
                "scripts.windows.phase2a5_host_validation.asar_header_digest",
                return_value=AsarHeaderDigest("sha256", "b" * 64, 1, 1),
            ), patch(
                "scripts.windows.phase2a5_host_validation.discover_real_codex",
                side_effect=AssertionError("unreviewed source must stop before real probe"),
            ):
                result = run_phase2a5_host_validation(repo_root=root)
        self.assertEqual(result["status"], PHASE2A5_SOURCE_REVIEW_REQUIRED)
        self.assertIn("99.0.0.0", result["source_identity"]["package_version"])
        self.assertEqual(result["source_identity"]["app_asar"], str(asar))
        self.assertEqual(result["source_identity"]["app_asar_sha256"], hashlib.sha256(b"unreviewed-source").hexdigest())
        self.assertEqual(result["source_review"]["status"], "SOURCE REVIEW REQUIRED")

    def test_source_changed_verdict_is_exact_and_discards_downstream_results(self) -> None:
        initial = {
            "source_root": r"C:\\WindowsApps\\OpenAI.Codex_26.825",
            "package_name": "OpenAI.Codex",
            "package_version": "26.825.5331.0",
            "architecture": "X64",
            "app_file_version": "151.0.7922.174",
            "executable": r"C:\\WindowsApps\\OpenAI.Codex_26.825\\app\\ChatGPT.exe",
            "chatgpt_exe_sha256": "a" * 64,
            "app_asar": r"C:\\WindowsApps\\OpenAI.Codex_26.825\\app\\resources\\app.asar",
            "app_asar_sha256": "b" * 64,
            "app_asar_header_sha256": "c" * 64,
        }
        source = SimpleNamespace()
        with patch(
            "scripts.windows.phase2a5_host_validation._source_identity",
            return_value=dict(initial, app_asar_sha256="d" * 64),
        ):
            stability = _source_stability(source, initial)
        self.assertFalse(stability["stable"])
        self.assertEqual(stability["changed_fields"], ["app_asar_sha256"])
        self.assertEqual(PHASE2A5_SOURCE_CHANGED_DURING_VALIDATION, "PHASE 2A.5 SOURCE CHANGED DURING VALIDATION")

    def test_no_go_toolchain_blocks_patched_shell_before_build(self) -> None:
        with patch(
            "scripts.windows.phase2a5_host_validation.build_windows_desktop",
            side_effect=AssertionError("build must not run without Go"),
        ):
            result = _run_external_patched_shell(
                SimpleNamespace(),
                object(),
                acl_strategy=PAYLOAD_ACL_NONE,
                timeout_seconds=1.0,
                go_toolchain={"selected": None, "usable": False, "probes": []},
            )
        self.assertEqual(result["status"], PHASE2A5_PATCHED_SHELL_TOOLCHAIN_BLOCKED)
        self.assertFalse(result["manual_operation_required"])

    def test_go_toolchain_report_exposes_known_and_missing_paths(self) -> None:
        with patch(
            "scripts.windows.phase2a5_host_validation.probe_go_toolchain",
            return_value={"selected": r"C:\\Go\\bin\\go.exe", "probes": []},
        ), patch(
            "scripts.windows.phase2a5_host_validation.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="go version go1.24 windows/amd64", stderr=""),
        ):
            known = _go_toolchain_report()
        self.assertEqual(known["selected"], r"C:\\Go\\bin\\go.exe")
        self.assertTrue(known["usable"])
        with patch(
            "scripts.windows.phase2a5_host_validation.probe_go_toolchain",
            return_value={"selected": None, "probes": []},
        ):
            missing = _go_toolchain_report()
        self.assertIsNone(missing["selected"])
        self.assertFalse(missing["usable"])

    def test_go_probe_finds_known_path_when_path_lookup_is_missing(self) -> None:
        with patch(
            "scripts.patch_app_windows.shutil.which",
            return_value=None,
        ), patch(
            "scripts.patch_app_windows.Path.is_file",
            return_value=True,
        ):
            report = probe_go_toolchain()
        self.assertTrue(report["selected"].replace("/", "\\").casefold().endswith(r"go\bin\go.exe"))
        self.assertEqual(report["probes"][0]["status"], "FAIL")
        self.assertEqual(report["probes"][2]["status"], "PASS")

    def test_exact_26_820_renderer_patches_host_scoped_plugin_requests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            values = write_exact_26_820_renderer_fixture(extracted)
            audit = audit_renderer_anchors(extracted)
            self.assertTrue(all(item.status == "UNCHANGED" for item in audit), audit)
            patch_renderer(extracted, "c" * 64)
            bundle = next((extracted / "webview" / "assets").glob("app-initial-*.js")).read_text(
                encoding="utf-8"
            )
            self.assertIn("function CodexMuxAccountMenu(", bundle)
            self.assertIn("function qg(e,t){let n=e.get(Jg)", bundle)
            self.assertIn('codexMuxScopePluginRequest("list-apps"', bundle)
            self.assertIn('codexMuxScopePluginRequest("list-installed-apps"', bundle)
            self.assertIn('codexMuxScopePluginRequest("read-apps"', bundle)
            self.assertIn('codexMuxScopePluginRequest("login-mcp-server"', bundle)
            self.assertIn('codexMuxScopePluginRequest("list-mcp-server-status"', bundle)
            self.assertIn("open:s,onOpenChange:l,contentWidth:`panel`,triggerButton:Ot", bundle)
            self.assertIn("CodexMuxProfileMenuOpenChange(l)", bundle)
            self.assertIn("CodexMuxThreadSubscription,{conversationId:a}", (
                extracted / "webview" / "assets" / "local-conversation-thread-26-820.js"
            ).read_text(encoding="utf-8"))
            self.assertIn("CodexMuxProfileAvatarStack", (
                extracted / "webview" / "assets" / "profile-26-820.js"
            ).read_text(encoding="utf-8"))

    def test_pe_integrity_resource_read_update_and_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "ChatGPT.exe"
            initial_payload = json.dumps(
                [{"file": "resources\\app.asar", "alg": "sha256", "value": "0" * 64}],
                separators=(",", ":"),
            )
            fixture_script = Path(__file__).resolve().parents[1] / "windows" / "pe_resources.mjs"
            subprocess.run(
                ["node", str(fixture_script), "fixture", str(executable)],
                input=initial_payload,
                text=True,
                check=True,
                stdout=subprocess.PIPE,
            )
            before = read_pe_integrity_resources(executable)
            self.assertEqual(before["resources"][0]["parsed"][0]["value"], "0" * 64)
            extracted = root / "asar-source"
            extracted.mkdir()
            (extracted / "index.js").write_text("fixture", encoding="utf-8")
            archive = root / "app.asar"
            pack_asar(ensure_asar_tool(), extracted, archive, (), ())
            plan = WindowsAsarIntegrityPlan(
                RESOURCE_PRESENT_UPDATE_REQUIRED,
                True,
                "fixture",
                None,
                None,
                True,
                tuple(before["resources"]),
                None,
            )
            result = apply_windows_asar_integrity(executable, archive, plan)
            expected = asar_header_digest(archive).hash
            self.assertTrue(result["resource_updated"])
            self.assertEqual(result["asar_header"]["hash"], expected)
            after = read_pe_integrity_resources(executable)
            self.assertEqual(after["resources"][0]["parsed"][0]["value"], expected)

    def test_asar_header_digest_is_not_whole_archive_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "index.js").write_text("header fixture", encoding="utf-8")
            archive = root / "app.asar"
            pack_asar(ensure_asar_tool(), source, archive, (), ())
            header = asar_header_digest(archive)
            whole = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(header.algorithm, "sha256")
            self.assertEqual(len(header.hash), 64)
            self.assertNotEqual(header.hash, whole)

    def test_integrity_plan_accepts_absent_metadata_but_blocks_fuse_without_resource(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ChatGPT.exe"
            executable.write_bytes(b"fixture")
            with patch(
                "scripts.windows.integrity.read_fuses",
                side_effect=RuntimeError("Electron fuse sentinel not found"),
            ), patch(
                "scripts.windows.integrity.read_pe_integrity_resources",
                return_value={"resources": []},
            ):
                absent = resolve_windows_asar_integrity(executable)
            self.assertEqual(absent.state, RESOURCE_ABSENT_NO_VALIDATION_METADATA)
            self.assertTrue(absent.resolved)

            fuse = FuseSnapshot(1, 9, ("on",) * 9, 0)
            with patch("scripts.windows.integrity.read_fuses", return_value=fuse), patch(
                "scripts.windows.integrity.read_pe_integrity_resources",
                return_value={"resources": []},
            ):
                missing_resource = resolve_windows_asar_integrity(executable)
            self.assertEqual(missing_resource.state, FUSE_PRESENT_RESOURCE_MISSING)
            self.assertFalse(missing_resource.resolved)

    def test_semantic_renderer_counterpart_is_not_patchable_by_old_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            webview = extracted / "webview"
            assets = webview / "assets"
            assets.mkdir(parents=True)
            (webview / "index.html").write_text("connect-src &#39;self&#39;", encoding="utf-8")
            (assets / "app-initial-current.js").write_text(
                "function QLs(e){return e}"
                "function c6s(e){let t=(0,u6s.c)(28),{defaultResetCreditsOpen:n,"
                "errorMessage:r,initialAvailableCount:i,isResetting:a,onClose:o,"
                "onResetCredit:s}=e,{data:c}=lH(),{data:l}=J(BO),"
                "{data:u,isLoading:d}=WAa()",
                encoding="utf-8",
            )
            audit = audit_renderer_anchors(extracted)
            usage = next(item for item in audit if item.name == "native usage modal")
            self.assertEqual(usage.status, "SEMANTICALLY_CHANGED")
            with self.assertRaises(RuntimeError):
                patch_renderer(extracted, "c" * 64)

    def test_real_codex_prefers_valid_openai_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            older = root / "older" / "codex.exe"
            newer = root / "newer" / "codex.exe"
            older.parent.mkdir()
            newer.parent.mkdir()
            write_pe(older)
            write_pe(newer)
            os.utime(older, (100, 100))
            os.utime(newer, (200, 200))

            def signature(path: Path) -> AuthenticodeMetadata:
                return (
                    AuthenticodeMetadata("Valid", "CN=OpenAI OpCo, LLC")
                    if path == older
                    else AuthenticodeMetadata("Unknown", None)
                )

            with patch("scripts.windows.discovery.read_codex_version", return_value="codex-cli test"), patch(
                "scripts.windows.discovery.read_authenticode", side_effect=signature
            ):
                selected, candidates = discover_real_codex(bin_root=root)
            self.assertEqual(selected.path, older)
            self.assertEqual(len(candidates), 2)
            self.assertEqual(selected.version, "codex-cli test")

    def test_real_codex_copy_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "codex.exe"
            destination = root / "runtime" / "codex.real.exe"
            write_pe(source)
            expected = source.read_bytes()
            digest = copy_byte_identical(source, destination)
            self.assertEqual(destination.read_bytes(), expected)
            self.assertEqual(len(digest), 64)

    def test_mirror_excludes_bundled_runtimes_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            (source / "resources" / "app.asar.unpacked" / "node_modules" / "native").mkdir(parents=True)
            (source / "resources" / "cua_node").mkdir(parents=True)
            (source / "ChatGPT.exe").write_bytes(b"desktop")
            (source / "Codex.exe").write_bytes(b"legacy desktop")
            (source / "resources" / "app.asar").write_bytes(b"asar")
            (source / "resources" / "codex.exe").write_bytes(b"bundled")
            (source / "resources" / "cua_node" / "node.exe").write_bytes(b"cua")
            (source / "resources" / "app.asar.unpacked" / "node_modules" / "native" / "addon.node").write_bytes(b"native")
            report = mirror_directory(source, destination)
            self.assertTrue((destination / "ChatGPT.exe").is_file())
            self.assertTrue((destination / "Codex.exe").is_file())
            self.assertTrue((destination / "resources" / "app.asar").is_file())
            self.assertTrue((destination / "resources" / "app.asar.unpacked" / "node_modules" / "native" / "addon.node").is_file())
            self.assertFalse((destination / "resources" / "codex.exe").exists())
            self.assertFalse((destination / "resources" / "cua_node").exists())
            self.assertGreaterEqual(len(report.excluded), 2)
            self.assertFalse(should_exclude(Path("Codex.exe")))

    def test_unpack_layout_is_derived_from_actual_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unpacked = Path(temporary) / "app.asar.unpacked"
            (unpacked / "node_modules" / "better-sqlite3").mkdir(parents=True)
            (unpacked / "node_modules" / "better-sqlite3" / "addon.node").write_bytes(b"nested")
            (unpacked / "native.node").write_bytes(b"native")
            (unpacked / "assets" / "helper.js").parent.mkdir()
            (unpacked / "assets" / "helper.js").write_text("helper", encoding="utf-8")
            self.assertEqual(derive_unpack_directories(unpacked), ("assets", "node_modules"))
            self.assertEqual(derive_unpack_files(unpacked), ("native.node",))

    def test_locked_asar_cli_keeps_derived_files_unpacked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extracted = root / "extracted"
            (extracted / "node_modules" / "native").mkdir(parents=True)
            (extracted / "node_modules" / "native" / "addon.node").write_bytes(b"nested")
            (extracted / "native.node").write_bytes(b"root")
            (extracted / "ui-test-bridge.cjs").write_text("bridge", encoding="utf-8")
            unpacked_source = root / "app.asar.unpacked"
            (unpacked_source / "node_modules" / "native").mkdir(parents=True)
            (unpacked_source / "node_modules" / "native" / "addon.node").write_bytes(b"nested")
            (unpacked_source / "native.node").write_bytes(b"root")
            archive = root / "app.asar"
            listing = pack_asar(
                ensure_asar_tool(),
                extracted,
                archive,
                ("node_modules",),
                ("native.node",),
            )
            normalized_listing = listing.replace("\\", "/")
            self.assertIn("unpack : /node_modules/native/addon.node", normalized_listing)
            self.assertIn("unpack : /native.node", normalized_listing)
            verify_asar_listing(
                listing,
                unpacked_source,
                ("node_modules",),
                ("native.node",),
            )

    def test_fuse_schema_values_and_writer_change_only_selected_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "ChatGPT.exe"
            before_bytes = b"MZ" + b"prefix" + SENTINEL + bytes([1, 9]) + bytes(FUSE_VALUES["on"] for _ in range(9)) + b"suffix"
            binary.write_bytes(before_bytes)
            before = read_fuses(binary)
            self.assertEqual(FUSE_VALUES, {"off": 0x30, "on": 0x31, "removed": 0x72, "inherit": 0x90})
            self.assertEqual(FUSE_INDEX["WasmTrapHandlers"], 8)
            self.assertNotIn("ResetAdHocDarwinSignature", FUSE_INDEX)
            previous, updated = write_fuse(binary, "EnableEmbeddedAsarIntegrityValidation", "off")
            after = read_fuses(binary)
            self.assertEqual(before.fuses[4], previous)
            self.assertEqual(updated, "off")
            self.assertEqual(after.fuses[4], "off")
            for index in (0, 1, 2, 3, 5, 6, 7, 8):
                self.assertEqual(before.fuses[index], after.fuses[index])
            changed = [index for index, (left, right) in enumerate(zip(before_bytes, binary.read_bytes())) if left != right]
            self.assertEqual(changed, [before.offset + 4])

    def test_compatibility_record_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "compat.md"
            fence = chr(96) * 3
            path.write_text(
                fence + "json\n"
                "[{\"architecture\":\"X64\",\"package_name\":\"OpenAI.Codex\","
                "\"package_version\":\"1.0.0\",\"app_file_version\":\"1.0.0\","
                "\"app_asar_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                "\"real_codex_version\":\"codex-cli test\","
                "\"real_codex_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
                "\"tested_patch_anchors\":\"fixture\"}]\n"
                + fence + "\n",
                encoding="utf-8",
            )
            records = load_compatibility_records(path)
            self.assertEqual(records[0].package_name, "OpenAI.Codex")
            self.assertEqual(records[0].real_codex_version, "codex-cli test")

    def test_shared_renderer_patch_applies_exact_fixture_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            webview = extracted / "webview"
            assets = webview / "assets"
            assets.mkdir(parents=True)
            values = renderer_variant_template("electron-original")
            tick = chr(96)
            bundle_parts = [str(values["component_anchor"])]
            bundle_parts.extend(_plugin_mapping_anchors(str(values["rpc_wrapper"]), str(values["status_rpc_wrapper"])))
            bundle_parts.extend(
                [
                    str(values["app_server_anchor"]),
                    str(values["profile_query"]),
                    str(values["usage_modal"]),
                    str(values["reset_query"]),
                    str(values["reset_mutation"]),
                    "let y=v;if(g!=null){",
                    str(values["usage_header"]),
                    str(values["usage_slot"]),
                    *values["open_change"],
                    f"defaultMessage:{tick}You’re out of Codex and Work usage{tick}",
                    f"defaultMessage:{tick}You’ve used all Codex and Work usage{tick}",
                    f"defaultMessage:{tick}You’ve reached your usage limit{tick}",
                ]
            )
            (webview / "index.html").write_text("connect-src &#39;self&#39;", encoding="utf-8")
            (assets / "app-initial-fixture.js").write_text("\n".join(bundle_parts), encoding="utf-8")
            (assets / "profile-fixture.js").write_text(
                " ".join(str(values[key]) for key in ("profile_avatar", "profile_name", "profile_identity")),
                encoding="utf-8",
            )
            (assets / "plugins-settings-fixture.js").write_text(str(values["plugin_anchor"]), encoding="utf-8")
            (assets / "local-conversation-thread-fixture.js").write_text(
                str(values["thread_anchor"]) + " children:[c,l,u,d,f,p,m,h,g,_,v,y,b,x]",
                encoding="utf-8",
            )
            audit = audit_renderer_anchors(extracted)
            self.assertTrue(all(item.status == "UNCHANGED" for item in audit), audit)
            patch_renderer(extracted, "a" * 64)
            patched = (assets / "app-initial-fixture.js").read_text(encoding="utf-8")
            self.assertIn("function CodexMuxAccountMenu(", patched)
            self.assertIn("All connected subscriptions are depleted", patched)
            self.assertIn("http://127.0.0.1:48123", (webview / "index.html").read_text(encoding="utf-8"))
            self.assertIn("a" * 64, patched)

    def test_shared_renderer_patch_supports_6662_renamed_fixture_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            webview = extracted / "webview"
            assets = webview / "assets"
            assets.mkdir(parents=True)
            marker = "function Icl(e){let t=(0,Vcl.c)(248),"
            values = renderer_variant_template("electron-6662")
            tick = chr(96)
            bundle_parts = [marker]
            bundle_parts.extend(
                _plugin_mapping_anchors(
                    str(values["rpc_wrapper"]),
                    str(values["status_rpc_wrapper"]),
                )
            )
            bundle_parts.extend(
                [
                    str(values["app_server_anchor"]),
                    str(values["profile_query"]),
                    str(values["usage_modal"]),
                    str(values["reset_query"]),
                    str(values["reset_mutation"]),
                    "let y=v;if(g!=null){",
                    str(values["usage_header"]),
                    str(values["usage_slot"]),
                    *values["open_change"],
                    f"defaultMessage:{tick}You’re out of Codex and Work usage{tick}",
                    f"defaultMessage:{tick}You’ve used all Codex and Work usage{tick}",
                    f"defaultMessage:{tick}You’ve reached your usage limit{tick}",
                ]
            )
            (webview / "index.html").write_text("connect-src &#39;self&#39;", encoding="utf-8")
            (assets / "app-initial-6662.js").write_text("\n".join(bundle_parts), encoding="utf-8")
            (assets / "profile-6662.js").write_text(
                " ".join(
                    str(values[key])
                    for key in ("profile_avatar", "profile_name", "profile_identity")
                ),
                encoding="utf-8",
            )
            (assets / "plugins-page-6662.js").write_text(
                str(values["plugin_anchor"]),
                encoding="utf-8",
            )
            (assets / "local-conversation-thread-6662.js").write_text(
                str(values["thread_anchor"]) + " children:[c,l,u,d,f,p,m,h,g,_,v,y,b,x]",
                encoding="utf-8",
            )
            audit = audit_renderer_anchors(extracted)
            statuses = {item.name: item.status for item in audit}
            self.assertEqual(statuses["native profile menu"], "RENAMED")
            self.assertEqual(statuses["Plugins settings content"], "MOVED")
            self.assertEqual(statuses["usage-window selection"], "UNCHANGED")
            self.assertFalse(
                any(item.status in {"MISSING", "SEMANTICALLY_CHANGED", "AMBIGUOUS"} for item in audit),
                audit,
            )
            patch_renderer(extracted, "b" * 64)
            patched = (assets / "app-initial-6662.js").read_text(encoding="utf-8")
            self.assertIn("function CodexMuxAccountMenu(", patched)
            self.assertIn("b" * 64, patched)


if __name__ == "__main__":
    unittest.main()
