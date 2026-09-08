"""Offline cross-module lifecycle: probe JSON -> ledger -> remediation -> recheck."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.__main__ import main
from sudetect.browser import observe
from sudetect.inventory import import_inventory
from sudetect.ledger import Ledger
from sudetect.policy import Scope, PolicyError
from sudetect.transport import FetchResult


ROOT = Path(__file__).resolve().parents[1]


class IntegrationTests(unittest.TestCase):
    def call(self, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(args)
        self.assertEqual(code, 0, out.getvalue())
        return json.loads(out.getvalue())

    def test_probe_to_closed_finding_and_new_alias_reopens(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory, 'ledger.sqlite'))
            payload_path = Path(directory, 'observation.json')
            policy_path = Path(directory, 'scope.json')
            now = datetime.now(timezone.utc)
            policy = {'policy_id': 'fixture-policy', 'expires_at': (now + timedelta(hours=1)).isoformat(),
                      'targets': [{'origin': 'https://app.example', 'owner': 'fixture-owner',
                                   'ownership_evidence': 'fixture:ownership', 'path_prefixes': ['/']}]}
            policy_path.write_text(json.dumps(policy), encoding='utf-8')
            observation = {'observation_id': 'fixture-denial', 'observed_at': now.isoformat(), 'policy_id': 'fixture-policy',
                           'access': 'ACCESS_DENIED_OBSERVED', 'content': 'NOT_INSPECTED',
                           'capture_complete': True, 'http_status': 401, 'reason': 'access_denied_status'}
            with patch('sudetect.probe.fetch', return_value=FetchResult(observation, b'{"error":"login required"}', {'content-type': 'application/json'})):
                probe = self.call(['probe', '--scope', str(policy_path), 'https://app.example/'])
            self.assertEqual(probe['content'], 'NOT_INSPECTED')
            self.assertTrue(probe['target_id'].startswith(('opaque:', 'hmac-sha256:')))
            payload_path.write_text(json.dumps(probe), encoding='utf-8')
            command = ['ledger', '--db', db]
            self.call(command + ['register', 'asset-1', '--provider', 'fixture', '--scope-id', 'fixture-team',
                                 '--target-id', probe['target_id'], '--policy-id', probe['policy_id']])
            finding = self.call(command + ['open', 'asset-1', '--evidence-ref', 'fixture:original'])['finding_id']
            self.call(command + ['remediate', finding, '--evidence-ref', 'fixture:owner-change', '--at', (now - timedelta(minutes=1)).isoformat()])
            self.call(command + ['import-observation', '--input', str(payload_path), '--asset-id', 'asset-1',
                                 '--expected-policy', '--policy-evidence-ref', 'fixture:policy-proof',
                                 '--control-healthy', '--control-evidence-ref', 'fixture:control-proof'])
            self.call(command + ['close', finding, '--evidence-ref', 'fixture:closure'])
            self.assertEqual(self.call(command + ['list'])['findings'][0]['status'], 'CLOSED')
            self.call(command + ['register', 'asset-1', '--provider', 'fixture', '--scope-id', 'fixture-team', '--alias-id', 'preview-new'])
            self.assertEqual(self.call(command + ['list'])['findings'][0]['status'], 'REOPENED')

    def test_shipped_policy_is_expired_until_operator_configures_it(self):
        with self.assertRaises(PolicyError):
            Scope.load(ROOT / 'examples/scope.example.json')

    def test_json_schemas_and_sanitized_inventory_example(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            self.skipTest('optional jsonschema test dependency not installed')
        schemas = {}
        for path in (ROOT / 'schemas').glob('*.json'):
            schema = json.loads(path.read_text(encoding='utf-8'))
            Draft202012Validator.check_schema(schema)
            schemas[path.stem] = Draft202012Validator(schema, format_checker=FormatChecker())
        schemas['scope.schema'].validate(json.loads((ROOT / 'examples/scope.example.json').read_text(encoding='utf-8')))
        inventory = import_inventory('fixture-team', ROOT / 'examples/inventory-import.json')
        self.assertEqual(inventory['status'], 'COMPLETE', inventory)
        self.assertEqual(len(inventory['assets']), 1)
        schemas['inventory.schema'].validate(inventory)
        self.assertNotIn('never-export-this', json.dumps(inventory))

    @unittest.skipUnless(importlib.util.find_spec('playwright'), 'optional Playwright not installed')
    def test_real_browser_reports_import_with_fail_closed_contract(self):
        policy = Scope.from_dict({
            'policy_id':'browser-policy','expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
            'targets':[{'origin':'https://browser.example','owner':'fixture-owner',
                        'ownership_evidence':'fixture:ownership','path_prefixes':['/']}],
            'max_bytes':65536,'max_requests':5,'timeout':3,'max_redirects':1,
        })

        def broker(status, body, *, complete=True):
            def fetch(url, scope, **kwargs):
                access = ('ACCESS_DENIED_OBSERVED' if status in (401,403) else
                          'NOT_FOUND_OBSERVED' if status == 404 else 'BODY_SERVED')
                return FetchResult({
                    'observation_id':'transport-observation','observed_at':datetime.now(timezone.utc).isoformat(),
                    'policy_id':scope.policy_id,'access':access,'content':'NOT_INSPECTED','http_status':status,
                    'sha256':hashlib.sha256(body).hexdigest(),'capture_complete':complete,
                    'analysis_complete':complete,'reason':'synthetic_fixture','redirects':[],
                }, body, {'content-type':'text/html'})
            return fetch

        for status in (401,403,404):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                report = observe('https://browser.example/', policy, duration=.05,
                                 fetcher=broker(status,b'<html><body></body></html>'), target_id='browser-target')
                self.assertTrue(report['complete'], report)
                self.assertFalse(report['content_review_complete'])
                ledger=Ledger(Path(directory)/'ledger.sqlite')
                ledger.register_asset('asset',provider='fixture',scope_id='permission-scope',
                                      target_id='browser-target',policy_id='browser-policy')
                finding=ledger.open_finding('asset',evidence_ref='fixture:open')
                ledger.record_remediation(finding,evidence_ref='fixture:change',
                                          remediated_at=(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat())
                ledger.import_observation(report,asset_id='asset',expected_policy=True,
                                          policy_evidence_ref='fixture:policy',control_healthy=True,
                                          control_evidence_ref='fixture:control')
                ledger.close_finding(finding,evidence_ref='fixture:close')
                self.assertEqual('CLOSED',ledger.list_findings()[0]['status'])
                ledger.close()

        with tempfile.TemporaryDirectory() as directory:
            ledger=Ledger(Path(directory)/'ledger.sqlite')
            ledger.register_asset('asset',provider='fixture',scope_id='permission-scope',
                                  target_id='browser-target',policy_id='browser-policy')
            sensitive = observe('https://browser.example/', policy, duration=.05,
                                fetcher=broker(200,b'SU_DETECT_SYNTHETIC_BROWSER_IMPORT'),
                                synthetic_markers=('SU_DETECT_SYNTHETIC_BROWSER_IMPORT',),target_id='browser-target')
            ledger.import_observation(sensitive,asset_id='asset')
            self.assertEqual('SENSITIVE_CONTENT_CONFIRMED',ledger.db.execute(
                "SELECT content FROM observations WHERE observation_id=?",(sensitive['observation_id'],)).fetchone()[0])

            incomplete = observe('https://browser.example/', policy, duration=.05,
                                 fetcher=broker(403,b'<html></html>',complete=False),target_id='browser-target')
            ledger.import_observation(incomplete,asset_id='asset')
            row=ledger.db.execute("SELECT capture_complete,reason_code FROM observations WHERE observation_id=?",
                                  (incomplete['observation_id'],)).fetchone()
            self.assertEqual((0,'PROBE_INCOMPLETE'),tuple(row))
            ledger.close()


if __name__ == '__main__':
    unittest.main()
