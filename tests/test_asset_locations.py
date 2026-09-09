import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from sudetect.asset_locations import export_locations, main
from sudetect.locators import LocatorStore


class AssetLocationTests(unittest.TestCase):
    def test_private_resolution_scope_isolation_and_safe_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / 'locators.sqlite'
            with LocatorStore(store) as db:
                ref = db.put('team', 'https://example.test/private-file.json?token=SYNTHETIC')
            report = root / 'report.json'
            report.write_text(json.dumps({'scope_id': 'team', 'assets': [{'asset_id': 'data-1', 'locator_ref': ref}]}))
            before = store.read_bytes()
            result = export_locations(report, store, 'team')
            self.assertIn('private-file.json', result['assets'][0]['private_location'])
            self.assertEqual(before, store.read_bytes())
            with self.assertRaises(ValueError):
                export_locations(report, store, 'other')
            out = io.StringIO()
            target = root / 'private.json'
            with contextlib.redirect_stdout(out):
                self.assertEqual(0, main(['--input', str(report), '--locator-store', str(store), '--scope-id', 'team', '--output', str(target)]))
            self.assertNotIn('SYNTHETIC', out.getvalue())
            self.assertIn('SYNTHETIC', target.read_text())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(2, main(['--input', str(report), '--locator-store', str(store), '--scope-id', 'team', '--output', str(target)]))

    def test_missing_reference_never_crosses_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / 'locators.sqlite'
            with LocatorStore(store) as db:
                ref = db.put('other', 'https://example.test/data.json')
            report = root / 'report.json'
            report.write_text(json.dumps({'assets': [{'asset_id': 'a', 'locator_ref': ref}, {'asset_id': 'b'}]}))
            result = export_locations(report, store, 'team')
            self.assertEqual(['NOT_FOUND_IN_SCOPE', 'NO_REFERENCE'], [x['location_state'] for x in result['assets']])
            self.assertNotIn('private_location', json.dumps(result))
