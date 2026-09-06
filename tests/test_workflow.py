"""Name-only discovery -> private handoff -> scoped CLI -> closure/regression."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from sudetect.__main__ import main
from sudetect.ledger import Ledger
from sudetect.locators import LocatorStore
from sudetect.search_plan import create_plan, run_plan
from sudetect.transport import FetchResult


class WorkflowTests(unittest.TestCase):
    def call(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(args)
        self.assertEqual(code, 0, output.getvalue())
        return json.loads(output.getvalue())

    def test_name_only_discovery_rechecks_the_exact_original_path(self):
        def api(url, headers):
            self.assertNotIn('Authorization', headers)
            path = urlsplit(url).path
            if path == '/search/repositories':
                row = {'name': 'hidden-docs', 'full_name': 'starlight-ops/hidden-docs',
                       'owner': {'login': 'starlight-ops'}, 'private': False, 'has_pages': True}
                return 200, {'items': [row], 'total_count': 1, 'incomplete_results': False}, {}
            if path == '/search/users':
                return 200, {'items': [], 'total_count': 0, 'incomplete_results': False}, {}
            if path.startswith('/users/'):
                return 200, [], {}
            self.fail('unexpected metadata endpoint')

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / 'locators.sqlite'
            plan = create_plan(scope_id='fixture-team', company_en='Starlight Research',
                               query_budget=1, account_budget=1)
            with LocatorStore(store_path) as store:
                result = run_plan(plan, fetch=api, locator_store=store)
                candidate = result['runs'][0]['result']['candidates'][0]
                ref = candidate['locator_ref']
                exact = store.get('fixture-team', ref)
            self.assertEqual(exact, 'https://starlight-ops.github.io/hidden-docs/')
            self.assertEqual(candidate['pages_url_candidate'], 'https://starlight-ops.github.io')

            # Ownership approval is a separate, explicit operator input.
            policy_path = root / 'scope.json'
            policy_path.write_text(json.dumps({
                'policy_id': 'fixture-approved-policy',
                'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                'targets': [{'origin': 'https://starlight-ops.github.io', 'owner': 'fixture-owner',
                             'ownership_evidence': 'fixture:verified-owner',
                             'path_prefixes': ['/hidden-docs/']}],
            }), encoding='utf-8')
            db_path = root / 'ledger.sqlite'
            self.call(['locators', '--store', str(store_path), 'bind', '--scope-id', 'fixture-team',
                       '--locator-ref', ref, '--scope', str(policy_path), '--db', str(db_path),
                       '--asset-id', 'asset-1', '--provider', 'github'])
            probe_args = ['probe', '--scope', str(policy_path), '--locator-store', str(store_path),
                          '--locator-scope', 'fixture-team', '--locator-ref', ref]

            def observe(status):
                def fetch(url, policy):
                    self.assertEqual(url, exact)
                    policy.authorize(url)
                    return FetchResult({
                        'observation_id': f'fixture-http-{status}', 'policy_id': policy.policy_id,
                        'observed_at': datetime.now(timezone.utc).isoformat(),
                        'access': 'ACCESS_DENIED_OBSERVED' if status == 403 else 'BODY_SERVED',
                        'content': 'NOT_INSPECTED', 'http_status': status, 'capture_complete': True,
                        'reason': 'access_denied_status' if status == 403 else 'response_observed',
                    }, b'<html></html>', {'content-type': 'text/html'})
                with patch('sudetect.probe.fetch', side_effect=fetch):
                    report = self.call(probe_args)
                self.assertEqual(report['target_id'], ref)
                self.assertNotIn('hidden-docs', json.dumps(report))
                return report

            with Ledger(db_path) as ledger:
                finding = ledger.open_finding('asset-1', evidence_ref='fixture:original')
                ledger.record_remediation(finding, evidence_ref='fixture:change')
                ledger.import_observation(observe(403), asset_id='asset-1', expected_policy=True,
                                          policy_evidence_ref='fixture:policy', control_healthy=True,
                                          control_evidence_ref='fixture:control')
                ledger.close_finding(finding, evidence_ref='fixture:closed')
                self.assertEqual('CLOSED', ledger.list_findings()[0]['status'])
                ledger.import_observation(observe(200), asset_id='asset-1')
                self.assertNotEqual('CLOSED', ledger.list_findings()[0]['status'])


if __name__ == '__main__':
    unittest.main()
