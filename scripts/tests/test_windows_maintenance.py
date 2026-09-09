"""Failure-oriented tests using synthetic payloads, never official binaries."""
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from scripts.windows.managed_paths import Layout, atomic_json, build_id, maintenance_lock
from scripts.windows.maintenance import activate, seal_build, verify_build, uninstall, rollback, initialize, install_launcher, reconcile
from scripts.windows.discovery import sha256_file
from scripts.windows.computer_use import identity, validate, acquire_codex_resources, CODEX_RESOURCE_FILES


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.layout = Layout(Path(self.temporary.name) / "Router")
        self.layout.builds.mkdir(parents=True)
        self.layout.data.mkdir()
        atomic_json(self.layout.root / "installation.json", self.layout.marker())
        # Deliberately distinctive sentinel: update/rollback must never copy or
        # modify this account-state stand-in.
        (self.layout.data / "private-sentinel").write_text("private-original")

    def build(self, name):
        root = self.layout.build(name)
        for relative in ("app/ChatGPT.exe", "app/resources/app.asar", "runtime/codex-mux.exe",
                         "runtime/codex.real.exe", "launch.json", "metadata.json", "Codex Subscription Router.exe"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        seal_build(root, {"version": name}, {"status": "PASS"})
        return root

    def test_switch_and_rollback_preserve_data_and_both_payloads(self):
        old, new = self.build("old"), self.build("new")
        activate(self.layout, "old")
        activate(self.layout, "new")
        with mock.patch("scripts.windows.maintenance.require_idle"):
            result = rollback(self.layout)
        self.assertEqual(result["current"]["build"], "old")
        self.assertFalse(result["current"]["auto_update"])
        self.assertEqual((self.layout.data / "private-sentinel").read_text(), "private-original")
        verify_build(old)
        verify_build(new)

    def test_failed_validation_never_replaces_pointer(self):
        self.build("old")
        new = self.build("new")
        activate(self.layout, "old")
        before = (self.layout.root / "current.json").read_bytes()
        (new / "app/ChatGPT.exe").write_text("corrupt")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            activate(self.layout, "new")
        self.assertEqual((self.layout.root / "current.json").read_bytes(), before)

    def test_pointer_replace_failure_retains_previous_bytes(self):
        self.build("old")
        self.build("new")
        activate(self.layout, "old")
        before = (self.layout.root / "current.json").read_bytes()
        with mock.patch("scripts.windows.managed_paths.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                activate(self.layout, "new")
        self.assertEqual((self.layout.root / "current.json").read_bytes(), before)
        self.assertFalse(list(self.layout.root.glob(".current.json-*")))

    def test_unsealed_or_failed_smoke_build_cannot_activate(self):
        root = self.layout.build("unsealed")
        root.mkdir()
        with self.assertRaises(FileNotFoundError):
            activate(self.layout, "unsealed")
        with self.assertRaisesRegex(RuntimeError, "startup smoke"):
            seal_build(root, {}, {"status": "FAIL"})

    def test_extra_payload_files_are_detected(self):
        root = self.build("extra")
        (root / "unexpected.dll").write_text("not sealed")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            verify_build(root)

    def test_state_is_forbidden_inside_payload(self):
        root = self.build("state")
        (root / "User Data").mkdir()
        with self.assertRaisesRegex(RuntimeError, "persistent state"):
            verify_build(root)

    def test_build_ids_reject_traversal_streams_devices_and_absolute_paths(self):
        for value in ("..", "../Data", "a/../b", "C:\\temp", "a:b", "new.", "CON", "nul.exe", "new ", "a\\b", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_id(value)

    def test_malformed_pointer_never_falls_back(self):
        (self.layout.root / "current.json").write_text('{"schema_version":1,"build":"../Data"}')
        with self.assertRaises(ValueError):
            self.layout.current()

    def test_os_lock_releases_and_stale_file_is_harmless(self):
        with maintenance_lock(self.layout):
            with self.assertRaisesRegex(RuntimeError, "another Router"):
                with maintenance_lock(self.layout):
                    self.fail("second holder admitted")
        with maintenance_lock(self.layout):
            pass

    def test_uninstall_preserves_data_and_unknown_files(self):
        self.build("old")
        activate(self.layout, "old")
        (self.layout.root / "user-notes.txt").write_text("keep")
        with mock.patch("scripts.windows.maintenance.inventory_processes_under_root", return_value=[]):
            result = uninstall(self.layout)
        self.assertTrue(result["data_preserved"])
        self.assertEqual((self.layout.data / "private-sentinel").read_text(), "private-original")
        self.assertTrue((self.layout.root / "user-notes.txt").exists())
        self.assertEqual(Layout.load(self.layout.root), self.layout)
        self.assertFalse(self.layout.builds.exists())

    def test_purge_requires_explicit_flag(self):
        with mock.patch("scripts.windows.maintenance.inventory_processes_under_root", return_value=[]):
            uninstall(self.layout, purge_data=True)
        self.assertFalse(self.layout.data.exists())

    def test_busy_uninstall_makes_no_changes(self):
        self.build("old")
        with mock.patch("scripts.windows.maintenance.inventory_processes_under_root", return_value=[object()]):
            with self.assertRaisesRegex(RuntimeError, "running"):
                uninstall(self.layout)
        self.assertTrue(self.layout.build("old").exists())
        self.assertTrue(self.layout.data.exists())

    def test_reinstall_reuses_marker_without_reinitializing_data(self):
        self.assertEqual(initialize(self.layout.root), self.layout)
        self.assertEqual((self.layout.data / "private-sentinel").read_text(), "private-original")

    def test_refuses_nonempty_unmanaged_root(self):
        other = self.layout.root / "other"
        other.mkdir()
        (other / "unrelated.txt").write_text("keep")
        with self.assertRaisesRegex(RuntimeError, "nonempty"):
            initialize(other)

    def test_manifest_cannot_escape_build(self):
        root = self.build("manifest")
        manifest = json.loads((root / "build-manifest.json").read_text())
        manifest["files"]["../Data/private-sentinel"] = "0" * 64
        atomic_json(root / "build-manifest.json", manifest)
        with self.assertRaisesRegex(RuntimeError, "invalid manifest"):
            verify_build(root)

    def test_launcher_update_is_deferred_only_during_launch(self):
        old, new = self.build("old"), self.build("new")
        install_launcher(self.layout, old)
        installed = self.layout.root / "Codex Subscription Router.exe"
        install_launcher(self.layout, new, on_launch=True)
        self.assertEqual(installed.read_text(), "old")
        install_launcher(self.layout, new)
        self.assertEqual(installed.read_text(), "new")

    def test_explicit_unchanged_update_releases_rollback_pin(self):
        root = self.build("same")
        token = self.layout.data / "mux-home/control-token"
        token.parent.mkdir()
        token.write_text("synthetic-test-token")
        atomic_json(root / "metadata.json", {
            "real_codex_sha256": "real", "tooling_sha256": "tools",
            "control_token_sha256": sha256_file(token)})
        identity = {"version": "same"}
        seal_build(root, identity, {"status": "PASS"})
        activate(self.layout, "same", auto_update=False)
        with mock.patch.multiple("scripts.windows.maintenance",
                locate_desktop_source=mock.Mock(return_value=object()),
                source_identity=mock.Mock(return_value=identity),
                find_reviewed_source=mock.Mock(return_value={}),
                reviewed_source_is_patchable=mock.Mock(return_value=(True, "reviewed")),
                discover_real_codex=mock.Mock(return_value=(SimpleNamespace(sha256="real"), None)),
                tooling_digest=mock.Mock(return_value="tools")):
            result = reconcile(self.layout)
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertNotEqual(result["current"].get("auto_update"), False)
        self.assertEqual(self.layout.current(), result["current"])

    def test_failed_private_directory_setup_can_be_retried(self):
        other = self.layout.root / "fresh"
        with mock.patch("scripts.windows.maintenance.secure_directory", side_effect=RuntimeError("DACL failure")):
            with self.assertRaisesRegex(RuntimeError, "DACL failure"):
                initialize(other)
        self.assertEqual(initialize(other), Layout(other))
        self.assertIsNone(Layout.load(other).current())

    @unittest.skipUnless(os.name == "nt", "Windows short paths")
    def test_short_path_parent_is_not_mistaken_for_store_redirection(self):
        import ctypes
        parent = self.layout.root / "Long Router Installation Parent"
        parent.mkdir()
        api = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        api.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        api.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        if not api(str(parent), buffer, len(buffer)) or "~" not in buffer.value:
            self.skipTest("volume does not provide 8.3 names")
        short_root = Path(buffer.value) / "fresh"
        with mock.patch("scripts.windows.maintenance.secure_directory"):
            installed = initialize(short_root)
        self.assertEqual(installed.root, parent / "fresh")
        self.assertEqual(Layout.load(short_root), installed)


class RuntimeTests(unittest.TestCase):
    def test_bundled_plugin_cli_lookup_has_complete_matching_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "official"
            destination = Path(temporary) / "app/resources"
            source.mkdir()
            destination.mkdir(parents=True)
            for name in CODEX_RESOURCE_FILES:
                (source / name).write_text("official " + name)
            # The shell mirror can already contain the sibling executables.
            sibling = "codex-code-mode-host.exe"
            (destination / sibling).write_bytes((source / sibling).read_bytes())
            with mock.patch("scripts.windows.computer_use.read_authenticode",
                            return_value=SimpleNamespace(status="Valid", signer="OpenAI")):
                report = acquire_codex_resources(source / "codex.exe", destination,
                                                 sha256_file(source / "codex.exe"))
            self.assertEqual(report["status"], "VERIFIED")
            for name in CODEX_RESOURCE_FILES:
                self.assertEqual((destination / name).read_bytes(), (source / name).read_bytes())

    def test_bundled_cli_rejects_mixed_runtime_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "official"
            destination = Path(temporary) / "resources"
            source.mkdir()
            destination.mkdir()
            for name in CODEX_RESOURCE_FILES:
                (source / name).write_text(name)
            (destination / "codex-code-mode-host.exe").write_text("different version")
            with mock.patch("scripts.windows.computer_use.read_authenticode",
                            return_value=SimpleNamespace(status="Valid", signer="OpenAI")):
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    acquire_codex_resources(source / "codex.exe", destination,
                                            sha256_file(source / "codex.exe"))
            self.assertFalse((destination / "codex.exe").exists())

    def test_bundled_cli_rejects_untrusted_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "codex.exe"
            source.write_text("untrusted")
            destination = Path(temporary) / "resources"
            with mock.patch("scripts.windows.computer_use.read_authenticode",
                            return_value=SimpleNamespace(status="Valid", signer="Other")):
                with self.assertRaisesRegex(RuntimeError, "signature"):
                    acquire_codex_resources(source, destination, sha256_file(source))
            self.assertFalse(destination.exists())

    def test_runtime_identity_changes_when_repl_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            for name in ("manifest.json", "bin/node.exe", "bin/node_repl.exe"):
                (root / name).write_text(name)
            before = identity(root)
            (root / "bin/node_repl.exe").write_text("updated")
            self.assertNotEqual(identity(root), before)

    def test_manifest_cannot_select_external_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps({"platform": "windows", "arch": "x64", "node_path": "../../external.exe"}))
            with self.assertRaisesRegex(RuntimeError, "layout"):
                validate(root, "x64")

    def test_wrong_architecture_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps({"platform": "windows", "arch": "arm64"}))
            with self.assertRaisesRegex(RuntimeError, "architecture"):
                validate(root, "x64")


if __name__ == "__main__":
    unittest.main()
