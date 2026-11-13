"""Synthetic, offline checks for the captured-file semantic review command."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.__main__ import main


class SemanticReviewCommandTests(unittest.TestCase):
    def test_local_bytes_are_reviewed_and_only_value_free_result_is_saved(self):
        secret = b'"customer_contact":"PRIVATE_FIXTURE_VALUE"'
        body = b"{" + secret + b"}"
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "capture.json"
            output = Path(temp) / "review.json"
            source.write_bytes(body)
            result = {"source_text_complete": True, "source_structure_complete": True,
                      "filled_field_count_by_category": {"contact": 1}, "pending_reviews": [],
                      "dom_flow": None}
            stdout = io.StringIO()
            with patch("sudetect.semantic_review.review_semantic_source", return_value=result) as review:
                with contextlib.redirect_stdout(stdout):
                    status = main(["semantic-review", "--input", str(source),
                                   "--content-type", "application/json", "--output", str(output)])
            self.assertEqual(status, 0)
            review.assert_called_once_with(body, "application/json", max_bytes=16 * 1024 * 1024)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["source_sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(saved["review_mode"], "offline_static")
            self.assertNotIn("PRIVATE_FIXTURE_VALUE", output.read_text(encoding="utf-8"))
            self.assertEqual(stdout.getvalue(), "")
            if os.name != "nt":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_pending_static_review_writes_result_and_exits_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.html"
            output = Path(temp) / "review.json"
            source.write_text("<script>dynamic()</script>", encoding="utf-8")
            result = {"source_text_complete": True, "source_structure_complete": False,
                      "pending_reviews": ["semantic_static_parser_incomplete"]}
            with patch("sudetect.semantic_review.review_semantic_source", return_value=result):
                self.assertEqual(main(["semantic-review", "--input", str(source),
                                       "--content-type", "text/html", "--output", str(output)]), 3)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["pending_reviews"],
                             ["semantic_static_parser_incomplete"])

    def test_existing_output_and_oversize_input_are_rejected_without_source_output(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.json"
            output = Path(temp) / "review.json"
            source.write_bytes(b"PRIVATE_FIXTURE_VALUE")
            output.write_text("keep", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["semantic-review", "--input", str(source),
                                       "--content-type", "application/json", "--output", str(output)]), 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")
            output.unlink()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["semantic-review", "--input", str(source),
                                       "--content-type", "application/json", "--output", str(output),
                                       "--max-bytes", "8"]), 2)
            self.assertFalse(output.exists())
            self.assertNotIn("PRIVATE_FIXTURE_VALUE", stderr.getvalue())

    def test_symlink_input_and_output_ancestor_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            link = root / "source-link.json"
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["semantic-review", "--input", str(link),
                                       "--content-type", "application/json",
                                       "--output", str(root / "out.json")]), 2)
            out_dir = root / "out-link"
            target_dir = root / "private"
            target_dir.mkdir()
            out_dir.symlink_to(target_dir, target_is_directory=True)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["semantic-review", "--input", str(source),
                                       "--content-type", "application/json",
                                       "--output", str(out_dir / "out.json")]), 2)
            self.assertFalse((target_dir / "out.json").exists())


if __name__ == "__main__":
    unittest.main()
