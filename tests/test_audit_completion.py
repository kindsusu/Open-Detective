"""Final exports cannot conceal unfinished work or overwrite case inputs."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from sudetect.audit import Case, init_case, main, run_case
from test_audit import policy, response


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {
            "company_en": "Nebula", "domains": ["seed.test"]}})

    def tearDown(self):
        self.temp.cleanup()

    def test_inspection_only_preserves_discovery_without_invoking_it(self):
        def forbidden(*args, **kwargs):
            self.fail("inspection-only must not call discovery")
        with Case(self.root) as case:
            before = [j for j in case.queue.status()["jobs"] if j["job_type"] == "discovery"]
            result = run_case(case, {"max_requests": 3}, scope=policy(),
                              fetcher=response, api_fetch=forbidden, inspection_only=True)
            after = [j for j in result["jobs"] if j["job_type"] == "discovery"]
            self.assertEqual([j["job_id"] for j in before], [j["job_id"] for j in after])
            self.assertTrue(all(j["attempts"] == 0 for j in after))
            self.assertTrue(any(j["state"] == "succeeded" for j in result["jobs"]
                                if j["job_type"] == "capture"))
            self.assertFalse(result["complete"])

    def test_final_report_exports_gaps_and_returns_nonzero(self):
        output = Path(self.temp.name) / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["report", "--case", str(self.root), "--output", str(output), "--final"])
        self.assertEqual(code, 3)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["final_review_status"], "incomplete")
        self.assertFalse(report["coverage"]["complete"])

    def test_report_cannot_replace_repository_binding(self):
        output = self.root / "repository-bindings.json"
        output.write_text("{}", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["report", "--case", str(self.root), "--output", str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "{}")
