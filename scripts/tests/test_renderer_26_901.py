import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.windows import renderer_26_901 as renderer


class ExactRendererTests(unittest.TestCase):
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
