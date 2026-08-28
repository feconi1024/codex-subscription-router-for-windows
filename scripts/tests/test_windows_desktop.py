from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.patch_common import (
    _plugin_mapping_anchors,
    _renderer_variant_values,
    audit_renderer_anchors,
    ensure_asar_tool,
    patch_renderer,
)
from scripts.patch_app_windows import audit_windows_source, pack_asar, verify_asar_listing
from scripts.windows.compatibility import load_compatibility_records
from scripts.windows.bootstrap import patch_bootstrap
from scripts.windows.discovery import (
    AuthenticodeMetadata,
    DesktopSource,
    PackageMetadata,
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
)
from scripts.windows.fuses import SENTINEL, disable_asar_integrity_validation, read_fuses
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
            self.assertEqual(source.app_asar, resources / "app.asar")

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
            self.assertEqual(source.source_root, package_root)
            self.assertEqual(source.app_dir, app)
            self.assertEqual(source.app_asar, app / "resources" / "app.asar")

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
                "scripts.patch_app_windows.read_fuses",
                side_effect=RuntimeError("fixture has no fuse sentinel"),
            ), patch("scripts.patch_app_windows.run"), patch(
                "scripts.patch_app_windows.audit_renderer_anchors", return_value=[]
            ):
                result = audit_windows_source(source)
            self.assertEqual(result["electron_fuses"]["status"], "UNAVAILABLE")
            self.assertEqual(executable.read_bytes(), executable_before)
            self.assertEqual(asar.read_bytes(), asar_before)

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

    def test_fuse_writer_changes_only_asar_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "ChatGPT.exe"
            backup = root / "ChatGPT.exe.before"
            before_bytes = b"MZ" + b"prefix" + SENTINEL + bytes([1, 9]) + b"011111111" + b"suffix"
            binary.write_bytes(before_bytes)
            before = read_fuses(binary)
            before_snapshot, after_snapshot = disable_asar_integrity_validation(binary, backup)
            self.assertEqual(before_snapshot, before)
            self.assertEqual(after_snapshot.fuses[4], "off")
            for index in (0, 1, 2, 3, 5, 6, 7, 8):
                self.assertEqual(before_snapshot.fuses[index], after_snapshot.fuses[index])
            self.assertEqual(backup.read_bytes(), before_bytes)

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
            values = _renderer_variant_values("fixture")
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
            values = _renderer_variant_values(marker)
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
