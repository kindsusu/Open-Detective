import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.locators import LocatorStore, LocatorError, resolve_target
from sudetect.probe import main as probe_main
from sudetect.transport import FetchResult


class LocatorTests(unittest.TestCase):
    def test_private_path_mapping_stable_and_scope_isolated(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'private.sqlite'
            with LocatorStore(path) as store:
                a = store.put('team', 'https://app.example/a?cap=fixture-one')
                b = store.put('team', 'https://app.example/b?cap=fixture-two')
                self.assertNotEqual(a, b)
                self.assertNotIn('fixture', a)
                with self.assertRaises(LocatorError):
                    store.get('other', a)
            with LocatorStore(path) as store:
                self.assertEqual(a, store.put('team', 'https://app.example/a?cap=fixture-one'))
                self.assertEqual('https://app.example/b?cap=fixture-two', store.get('team', b))
            with self.assertRaises(LocatorError):
                resolve_target('https://app.example/', path, 'team', a)

    def test_reference_is_bound_to_real_requested_url_and_scope_rechecked(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'private.sqlite'
            with LocatorStore(path) as store:
                ref = store.put('team', 'https://app.example/exact-path')
            policy = {'policy_id': 'fixture-policy', 'expires_at': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                      'targets': [{'origin': 'https://app.example', 'owner': 'team',
                                   'ownership_evidence': 'fixture:owner', 'path_prefixes': ['/']} ]}
            def fetched(url, scope):
                self.assertEqual(url, 'https://app.example/exact-path')
                return FetchResult({'observation_id': 'fixture', 'policy_id': scope.policy_id,
                                    'access': 'BODY_SERVED', 'capture_complete': True, 'http_status': 200}, b'ok', {})
            out = io.StringIO()
            with patch('sudetect.probe.fetch', fetched), contextlib.redirect_stdout(out):
                code = probe_main(['--scope', json.dumps(policy), '--locator-store', str(path),
                                   '--locator-scope', 'team', '--locator-ref', ref])
            self.assertEqual(code, 0)
            data = json.loads(out.getvalue())
            self.assertEqual(data['target_id'], ref)
            self.assertEqual(data['policy_id'], 'fixture-policy')
            self.assertNotIn('exact-path', out.getvalue())


if __name__ == '__main__':
    unittest.main()
