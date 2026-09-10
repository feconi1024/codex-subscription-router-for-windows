import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.windows import renderer_26_901 as renderer


class ExactRendererTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for renderer execution')
    def test_authenticated_thread_renders_with_each_reviewed_section_namespace(self):
        project = Path(__file__).resolve().parents[2]
        # Names observed in the reviewed source bundles, independent of the
        # patcher's binding. An unauthenticated render returns before using it.
        for manifest, namespace in [('renderer_26_901.json', 'Q'),
                                    ('renderer_26_901_5280.json', 'Q'),
                                    ('renderer_26_901_6511.json', 'Z')]:
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as directory:
                spec = json.loads(Path(renderer.__file__).with_name(manifest).read_text(encoding='utf-8'))
                root = Path(directory)
                for name in spec['assets']:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('', encoding='utf-8')
                (root / 'webview/index.html').write_text("connect-src &#39;self&#39;", encoding='utf-8')
                with patch.object(renderer, 'contract', return_value=spec), patch.object(renderer, 'audit', return_value=[]):
                    renderer.patch(root, 'test-token', project, lambda text, _: text)
                component = (root / spec['thread']).read_text(encoding='utf-8')
                harness = '''
const assert = require('node:assert/strict');
const section = () => {};
const Q = NAMESPACE === 'Q' ? {Section: section} : {};
const Z = {Section: section};
const Ei = () => null, Fo = () => null, Ml = () => null, ou = {}, Mr = {}, Cc = {};
const nT = {useState: () => [{label: 'Test subscription', rateLimits: {primary: {usedPercent: 25}}}, () => {}], useEffect: () => {}};
const jsx = (type, props) => {assert.ok(type, 'undefined React component'); return {type, props};};
const rT = {jsx, jsxs: jsx};
'''.replace('NAMESPACE', json.dumps(namespace))
                result = subprocess.run(['node', '-e', harness + component + '''
const rendered = CodexMuxThreadSubscription({conversationId: 'test-thread'});
assert.equal(rendered.type, section);
assert.equal(rendered.props.sectionKey, 'codex-mux-subscription');
assert.equal(rendered.props.children.props.children[1].props.children, '75% remaining');
'''], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_reviewed_manifests_bind_every_operation_to_a_hashed_asset(self):
        for path in Path(renderer.__file__).parent.glob('renderer_26_901*.json'):
            with self.subTest(binding=path.name):
                spec = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(len(spec['assets']), 5)
                for operation in spec['operations']:
                    self.assertIn(operation['asset'], spec['assets'])
                    self.assertTrue(operation['old'])
                    self.assertNotEqual(operation['old'], operation['new'])
                self.assertIn(spec['primary'], spec['assets'])
                self.assertIn(spec['thread'], spec['assets'])
                self.assertIn('lt', spec['component_replacements'])
                self.assertIn('manage plugins account picker', {op['name'] for op in spec['operations']})

    def test_late_asset_tampering_rejects_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = ['webview/assets/app-initial-test.js', 'webview/assets/profile-test.js']
            for name in assets:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('reviewed', encoding='utf-8')
            (root / 'webview/index.html').write_text("connect-src &#39;self&#39;", encoding='utf-8')
            spec = {
                'assets': {name: hashlib.sha256(b'reviewed').hexdigest() for name in assets},
                'operations': [{'name': 'first replacement', 'asset': assets[0],
                                'old': 'reviewed', 'new': 'modified'}],
            }
            (root / assets[-1]).write_text('tampered', encoding='utf-8')
            before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with patch.object(renderer, 'contract', return_value=spec):
                with self.assertRaisesRegex(RuntimeError, 'before mutation'):
                    renderer.patch(root, 'test-token', root, lambda text, _: text)
            self.assertEqual(before, {p: p.read_bytes() for p in before})
