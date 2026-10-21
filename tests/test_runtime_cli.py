import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from sudetect.__main__ import main


class RuntimeCliTests(unittest.TestCase):
    def fixture(self, root):
        (root / "app.html").write_text("<script>PRIVATE_FIXTURE</script>", encoding="utf-8")
        (root / "data.json").write_text('{"price":1}', encoding="utf-8")
        manifest = {"input": "app.html", "content_type": "text/html", "authorization": {},
                    "resources": {"/data.json": {"input": "data.json", "content_type": "application/json"}}}
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    def test_manifest_relative_capture_and_dependencies_pass_to_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            output = root / "report.json"
            with patch("sudetect.runtime_review.review_runtime_source", return_value={
                    "runtime_observation_complete": True, "script_errors": 0}) as execute:
                code = main(["runtime-review", "--manifest", str(root / "manifest.json"),
                             "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual(b'{"price":1}', execute.call_args.kwargs["resources"]["/data.json"]["body"])
            self.assertNotIn("PRIVATE_FIXTURE", output.read_text())

    def test_incomplete_engine_result_is_preserved_with_exit_three(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            with patch("sudetect.runtime_review.review_runtime_source", return_value={
                    "runtime_observation_complete": False, "pending_reviews": ["runtime_time_limit"]}):
                self.assertEqual(3, main(["runtime-review", "--manifest", str(root / "manifest.json"),
                                         "--output", str(root / "report.json")]))
            self.assertIn("runtime_time_limit", (root / "report.json").read_text())

    def test_existing_output_never_executes_or_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            output = root / "report.json"
            output.write_text("keep")
            with patch("sudetect.runtime_review.review_runtime_source") as execute:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(2, main(["runtime-review", "--manifest", str(root / "manifest.json"),
                                             "--output", str(output)]))
            execute.assert_not_called()
            self.assertEqual("keep", output.read_text())

    def test_symlink_source_refused_without_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.fixture(root)
            try:
                (root / "link.html").symlink_to(root / "app.html")
            except OSError:
                self.skipTest("symlink unavailable")
            manifest["input"] = "link.html"
            (root / "manifest.json").write_text(json.dumps(manifest))
            with patch("sudetect.runtime_review.review_runtime_source") as execute:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(2, main(["runtime-review", "--manifest", str(root / "manifest.json"),
                                             "--output", str(root / "report.json")]))
            execute.assert_not_called()

    def test_case_mismatch_prevents_execution_and_evidence_append(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.fixture(root)
            manifest["authorization"] = {"case_id": "case_" + "1" * 32}
            (root / "manifest.json").write_text(json.dumps(manifest))
            case = MagicMock()
            case.meta = {"case_id": "case_" + "2" * 32}
            with patch("sudetect.audit.Case") as factory, patch("sudetect.runtime_review.review_runtime_source") as run:
                factory.return_value.__enter__.return_value = case
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(2, main(["runtime-review", "--manifest", str(root / "manifest.json"),
                        "--output", str(root / "report.json"), "--case", str(root)]))
            run.assert_not_called()
            case.ledger._event.assert_not_called()

    def test_case_result_is_appended_without_changing_asset_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.fixture(root)
            manifest["authorization"] = {"case_id": "case_" + "1" * 32}
            (root / "manifest.json").write_text(json.dumps(manifest))
            case = MagicMock()
            case.meta = {"case_id": manifest["authorization"]["case_id"]}
            report = {"runtime_observation_complete": True, "source_sha256": "a" * 64}
            with patch("sudetect.audit.Case") as factory, patch("sudetect.runtime_review.review_runtime_source", return_value=report):
                factory.return_value.__enter__.return_value = case
                self.assertEqual(0, main(["runtime-review", "--manifest", str(root / "manifest.json"),
                    "--output", str(root / "report.json"), "--case", str(root)]))
            case.ledger._event.assert_called_once_with("CAPTURED_RUNTIME_REVIEW", "a" * 64, report)
            case.ledger.set_state.assert_not_called()


if __name__ == "__main__":
    unittest.main()
