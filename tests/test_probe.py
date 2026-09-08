import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sudetect.probe import _rows, _run_one, main
from sudetect.policy import Scope
from sudetect.transport import FetchResult


def raw_scope():
    return {
        "policy_id": "probe-test",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "targets": [{"origin": "https://app.example", "owner": "team",
                     "ownership_evidence": "record-id", "path_prefixes": ["/"]}],
        "exclude_urls": [], "max_bytes": 10, "max_requests": 5,
        "timeout": 1, "max_redirects": 1,
    }


def fake_fetch(url, scope):
    return FetchResult({
        "observation_id": "00000000-0000-0000-0000-000000000000",
        "observed_at": "2099-01-01T00:00:00Z", "policy_id": scope.policy_id,
        "target_ref": "https://app.example/", "access": "BODY_SERVED",
        "content": "NOT_INSPECTED", "http_status": 200,
        "sha256": "0" * 64, "capture_complete": True,
        "reason": "response_observed", "redirects": [],
    }, b'<input type="password">', {"content-type": "text/html"})


class ProbeTests(unittest.TestCase):
    def test_scope_is_required(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(2, main(["https://app.example/"]))
        self.assertEqual("scope_required\n", err.getvalue())

    def test_inline_scope_single_url_jsonl(self):
        out = io.StringIO()
        with patch("sudetect.probe.fetch", fake_fetch), redirect_stdout(out):
            self.assertEqual(0, main(["--scope", json.dumps(raw_scope()), "https://app.example/", "safe-label"]))
        parsed = json.loads(out.getvalue())
        self.assertEqual("BODY_SERVED", parsed["access"])
        self.assertEqual("NOT_INSPECTED", parsed["content"])
        self.assertTrue(parsed["target_id"].startswith(("opaque:", "hmac-sha256:")))
        self.assertEqual("safe-label", parsed["label"])
        self.assertNotIn("EXPOSED", out.getvalue())
        self.assertNotIn("WEAK-GATE", out.getvalue())

    def test_url_correlation_requires_key_for_stability(self):
        ids = []
        for key in ('', '', 'fixture-key', 'fixture-key'):
            out = io.StringIO()
            with patch.dict(os.environ, {'SUDETECT_LOCATOR_HMAC_KEY': key}), patch('sudetect.probe.fetch', fake_fetch), redirect_stdout(out):
                main(['--scope', json.dumps(raw_scope()), 'https://app.example/'])
            ids.append(json.loads(out.getvalue())['target_id'])
        self.assertNotEqual(ids[0], ids[1])
        self.assertEqual(ids[2], ids[3])
        self.assertTrue(ids[2].startswith('hmac-sha256:'))

    def test_rejected_url_does_not_leak_credentials(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, main(["--scope", json.dumps(raw_scope()), "https://user:pw@app.example/"]))
        self.assertNotIn("user:pw", out.getvalue())
        self.assertEqual("INDETERMINATE", json.loads(out.getvalue())["access"])

    def test_unsafe_label_is_omitted(self):
        out = io.StringIO()
        with patch("sudetect.probe.fetch", fake_fetch), redirect_stdout(out):
            self.assertEqual(0, main(["--scope", json.dumps(raw_scope()), "https://app.example/", "secret=VALUE WITH SPACE"]))
        self.assertNotIn("VALUE", out.getvalue())
        self.assertEqual("<label-omitted>", json.loads(out.getvalue())["label"])

    def test_batch_crlf_empty_columns_and_unterminated_final_row(self):
        rows = list(_rows(io.StringIO("\r\n# note\r\nhttps://app.example/a\t\r\nhttps://app.example/b\tlabel")))
        self.assertEqual([
            ("https://app.example/a", ""),
            ("https://app.example/b", "label"),
        ], rows)

    def test_batch_emits_one_json_object_per_nonblank_row(self):
        with tempfile.TemporaryDirectory() as directory:
            batch = Path(directory, "targets.tsv")
            batch.write_bytes(b"https://app.example/a\t\r\n\r\nhttps://app.example/b\tlast")
            out = io.StringIO()
            with patch("sudetect.probe.fetch", fake_fetch), redirect_stdout(out):
                self.assertEqual(0, main(["--scope", json.dumps(raw_scope()), "--batch", str(batch)]))
            self.assertEqual(2, len(out.getvalue().splitlines()))

    def test_truncated_identity_prefix_keeps_provisional_html_and_json_signals(self):
        scope = Scope.from_dict(raw_scope())
        for content_type, body, expected_signal in (
            ("text/html", b'<input type="password">', "LOGIN_FORM_INDICATOR"),
            ("application/json", b'{"email":"fixture@example.test"}', "SENSITIVE_VALUES_CANDIDATE"),
        ):
            with self.subTest(content_type=content_type):
                result = FetchResult({
                    "observation_id": "00000000-0000-0000-0000-000000000000",
                    "observed_at": "2099-01-01T00:00:00Z", "policy_id": scope.policy_id,
                    "target_ref": "https://app.example/", "access": "BODY_SERVED",
                    "content": "NOT_INSPECTED", "http_status": 200, "sha256": None,
                    "prefix_sha256": "1" * 64, "capture_complete": False,
                    "reason": "response_truncated", "redirects": [],
                }, body, {"content-type": content_type})
                with patch("sudetect.probe.fetch", return_value=result):
                    observed = _run_one(scope, "https://app.example/")
                self.assertFalse(observed["capture_complete"])
                self.assertFalse(observed["analysis_complete"])
                self.assertFalse(observed["content_review_complete"])
                self.assertEqual("captured_prefix", observed["analysis_scope"])
                self.assertIn(expected_signal, {signal["code"] for signal in observed["signals"]})
                self.assertNotIn("fixture@example.test", json.dumps(observed))

    def test_truncated_prefix_without_signals_stays_not_inspected_and_compressed_is_skipped(self):
        scope = Scope.from_dict(raw_scope())
        for headers, expected_analysis in (({"content-type": "text/plain"}, True),
                                           ({"content-type": "text/plain", "content-encoding": "gzip"}, False)):
            with self.subTest(headers=headers):
                result = FetchResult({
                    "observation_id": "00000000-0000-0000-0000-000000000000",
                    "observed_at": "2099-01-01T00:00:00Z", "policy_id": scope.policy_id,
                    "target_ref": "https://app.example/", "access": "BODY_SERVED",
                    "content": "NOT_INSPECTED", "http_status": 200, "sha256": None,
                    "capture_complete": False, "reason": "response_truncated", "redirects": [],
                }, b"ordinary prefix", headers)
                with patch("sudetect.probe.fetch", return_value=result):
                    observed = _run_one(scope, "https://app.example/")
                self.assertEqual("NOT_INSPECTED", observed["content"])
                self.assertEqual(expected_analysis, "analysis_scope" in observed)
                if expected_analysis:
                    self.assertFalse(observed["analysis_complete"])
                    self.assertEqual("captured_prefix", observed["analysis_scope"])
                else:
                    self.assertNotIn("signals", observed)


if __name__ == "__main__":
    unittest.main()
