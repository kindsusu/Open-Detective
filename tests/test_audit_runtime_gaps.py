"""Offline regression for observed runtime gaps; no company fixtures."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.audit import Case, init_case, run_case, report_case, case_status, write_json
from sudetect.gate_review import review_gate
from sudetect.policy import Scope
from sudetect.repository_history import history_url, analyze_history
from sudetect.asset_trace import extract_references
from test_audit import policy, response


class RuntimeGapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'case'
        init_case(self.root, {'scope_id': 'fixture', 'identity': {'company_en': 'Orion Auto Services', 'domains': ['seed.test']}})

    def tearDown(self):
        self.temp.cleanup()

    def test_queue_success_does_not_hide_unfinished_search(self):
        with Case(self.root) as case:
            case.ledger.db.execute("UPDATE audit_jobs SET state='succeeded'")
            case.ledger.db.commit()
            status = case_status(case)
            self.assertTrue(status['queue_complete'])
            self.assertFalse(status['complete'])
            self.assertGreater(status['search_work_remaining'], 0)

    def test_large_image_does_not_hide_later_document_reference(self):
        scope = policy()
        scope.max_bytes = 24 * 1024 * 1024
        body = (b'<html><img src="data:image/png;base64,' + b'A' * (17 * 1024 * 1024) +
                b'"><a href="https://archive.test/documents/check.pdf">check</a></html>')
        def fetched(url, scope):
            item = response(url, scope)
            item.body = body
            item.observation['sha256'] = hashlib.sha256(body).hexdigest()
            return item
        with Case(self.root) as case:
            run_case(case, {'max_requests': 1, 'max_analysis_bytes': 32 * 1024 * 1024,
                           'max_download_bytes': 32 * 1024 * 1024}, scope=scope, fetcher=fetched)
            report = next(r['report'] for r in report_case(case)['results'] if r['report'].get('target_id'))
            self.assertTrue(report['capture_complete'])
            self.assertFalse(report['review_complete'])
            self.assertIn('inline_image_ocr_unexamined', report['gaps'])
            self.assertTrue(report['media_projection']['analysis_only'])
            self.assertLess(report['media_projection']['projected_bytes'], 300)
            self.assertTrue(any(url == 'https://archive.test/documents/check.pdf'
                                for _, url in case.locators.db.execute('SELECT ref,url FROM locators')))
            self.assertNotIn('archive.test', json.dumps(report))

    def test_medium_gate_is_analyzed_without_replay(self):
        scope = policy()
        scope.max_bytes = 4 * 1024 * 1024
        body = b' ' * 1_100_000 + b'<input type="password"><div hidden>cost 123</div>'
        report = review_gate(body, 'text/html', 'https://seed.test/', scope=scope, replay_browser=False)
        self.assertTrue(report['auth_ui_present'])
        self.assertFalse(report['client_gate_tested'])
        self.assertFalse(report['server_authorization_tested'])

    def test_old_capture_gets_one_versioned_review_on_resume(self):
        calls = []
        def fetched(url, scope):
            calls.append(url)
            item = response(url, scope)
            item.body = b'public text'
            item.headers = {'content-type': 'text/plain'}
            return item
        with Case(self.root) as case:
            save = case.save_result
            def old_save(job, report):
                report = dict(report)
                report.pop('engine_review_version', None)
                return save(job, report)
            with patch.object(case, 'save_result', side_effect=old_save):
                run_case(case, {'max_requests': 1}, scope=policy(), fetcher=fetched)
            self.assertEqual(1, len(calls))
            run_case(case, {'max_requests': 1}, scope=policy(), fetcher=fetched)
            self.assertEqual(2, len(calls))
            self.assertEqual(1, sum(j['dedupe_key'].startswith('engine-review:2:') for j in case.queue.status()['jobs']))
            run_case(case, {'max_requests': 1}, scope=policy(), fetcher=fetched)
            self.assertEqual(2, len(calls))

    def test_observed_history_snapshots_only(self):
        candidate = {'slug': 'orion-team/portal', 'source_revision': {'kind': 'branch_mutable', 'value': 'release/v2'}}
        url = history_url(candidate)
        self.assertIn('sha=release%2Fv2', url)
        report, refs = analyze_history(json.dumps([{'sha': 'a' * 40, 'commit': {'author': {'name': 'do-not-report'}}}]).encode(), url)
        self.assertEqual(1, report['commits_examined'])
        self.assertIn('history_window_not_exhaustive', report['pending_reviews'])
        self.assertEqual([('repository_snapshot', 'https://api.github.com/repos/orion-team/portal/git/trees/' + 'a' * 40 + '?recursive=1')], refs)
        self.assertNotIn('do-not-report', json.dumps(report))
        bad, refs = analyze_history(b'[{"sha":"../evil"}]', url)
        self.assertFalse(bad['analysis_complete'])
        self.assertEqual([], refs)
        deep, refs = analyze_history(b'[' * 2000 + b']' * 2000, url)
        self.assertIn('history_metadata_incomplete', deep['pending_reviews'])
        self.assertEqual([], refs)

    def test_script_fetch_uses_document_base_not_script_directory(self):
        calls = []
        def fetched(url, scope):
            calls.append(url)
            item = response(url, scope)
            if url == 'https://seed.test/':
                item.body = b'<base href="/ui/"><script src="js/app.js"></script>'
            elif url == 'https://seed.test/ui/js/app.js':
                item.body = b'fetch("./data.json")'
                item.headers = {'content-type': 'application/javascript'}
            else:
                item.body = b'{}'
                item.headers = {'content-type': 'application/json'}
            return item
        with Case(self.root) as case, patch('sudetect.browser.observe', return_value={'complete': True}):
            run_case(case, {'max_requests': 3}, scope=policy(), fetcher=fetched)
        self.assertEqual(['https://seed.test/', 'https://seed.test/ui/js/app.js', 'https://seed.test/ui/data.json'], calls)

    def test_secret_evidence_holds_related_fetch_but_preserves_locator(self):
        calls = []
        def fetched(url, scope):
            calls.append(url)
            item = response(url, scope)
            item.body = b'<p>ghp_' + b'Z' * 40 + b'</p><a href="/affected.pdf">document</a>'
            return item
        with Case(self.root) as case:
            run_case(case, {'max_requests': 3}, scope=policy(), fetcher=fetched)
            jobs = case.queue.status()['jobs']
            self.assertEqual(['https://seed.test/'], calls)
            self.assertTrue(any('SENSITIVE_MATERIAL_FOLLOWUP_REVIEW' in (j.get('checkpoint') or {}).get('reason_codes', []) for j in jobs))

    def test_dynamic_document_fragments_are_not_requested_as_complete_urls(self):
        refs, gaps, _ = extract_references(b'const doc = bucket + "/records/check.pdf";', 'application/javascript')
        self.assertEqual([], refs)
        self.assertIn('document_expression_unresolved', gaps)

    def test_failed_requests_do_not_create_endless_successor_jobs(self):
        def failed_plan(plan, **kwargs):
            plan['status'] = 'PARTIAL'
            kwargs['fetch']('https://api.github.com/search/users?q=orion&per_page=100&page=1', {})
            plan['last_execution'] = {'requests_used': 1, 'stop_reason': 'batch_limit_reached'}
            return plan
        with Case(self.root) as case, patch('sudetect.search_plan.run_plan', side_effect=failed_plan):
            run_case(case, {'max_requests': 2}, api_fetch=lambda *_: (200, {'items': [], 'total_count': 0}, {}))
            jobs = [j for j in case.queue.status()['jobs'] if j['job_type'] == 'discovery']
            self.assertEqual(1, len(jobs))
            self.assertEqual('retry_wait', jobs[0]['state'])


if __name__ == '__main__':
    unittest.main()
