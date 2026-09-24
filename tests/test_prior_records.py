import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sudetect import prior_records


def sample_manifest():
    return {
        "schema_version": "1.0",
        "source": {"kind": "trusted_operator_export", "export_ref": "operator-export:unit",
                   "exported_at": "2026-09-10T09:00:00Z"},
        "reviews": [{
            "review_ref": "prior-review:unit", "reviewed_at": "2026-08-01T09:00:00Z",
            "lookup_status": "unavailable",
            "known_assets": [{"record_ref": "asset-record:unit"}],
            "unresolved": [{"record_ref": "issue-record:unit", "reason_ref": "reason:scope-expired"}],
            "due": [{"record_ref": "recheck-record:unit", "due_at": "2026-10-01"}],
        }],
    }


class PriorRecordsTests(unittest.TestCase):
    def test_reconcile_retains_history_without_authorization(self):
        result = prior_records.reconcile(sample_manifest(), {"scope_id": "TEAM-1"})
        self.assertEqual(False, result["authority"]["inherited"])
        self.assertEqual("current_scope_required", result["authority"]["network"])
        self.assertEqual("TEAM-1", result["authority"]["current_scope_id"])
        self.assertEqual("recorded_history", result["known_assets"][0]["history_state"])
        self.assertEqual(["prior-review:unit"], result["known_assets"][0]["review_refs"])
        self.assertTrue(result["known_assets"][0]["current_scope_required"])
        self.assertEqual("unavailable", result["reviews"][0]["lookup_status"])
        self.assertEqual("declared_not_verified", result["source"]["trust"])

    def test_repeated_asset_preserves_every_review_reference(self):
        manifest = sample_manifest()
        manifest["reviews"].append({
            "review_ref": "prior-review:second", "reviewed_at": "2026-08-02T09:00:00+09:00",
            "lookup_status": "unavailable", "known_assets": [{"record_ref": "asset-record:unit"}],
            "unresolved": [], "due": [],
        })
        result = prior_records.reconcile(manifest)
        self.assertEqual(["prior-review:unit", "prior-review:second"],
                         result["known_assets"][0]["review_refs"])
        self.assertEqual("2026-08-02T00:00:00Z", result["reviews"][1]["reviewed_at"])

    def test_timestamps_are_utc_and_naive_datetimes_are_rejected(self):
        manifest = sample_manifest()
        manifest["source"]["exported_at"] = "2026-09-10T18:00:00+09:00"
        result = prior_records.reconcile(manifest)
        self.assertEqual("2026-09-10T09:00:00Z", result["source"]["exported_at"])
        manifest["source"]["exported_at"] = "2026-09-10T09:00:00"
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "INVALID_EXPORTED_AT"):
            prior_records.reconcile(manifest)

    def test_rejects_url_reference(self):
        manifest = sample_manifest()
        manifest["reviews"][0]["known_assets"][0]["record_ref"] = "https://example.test/private"
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "INVALID_ASSET_RECORD_REF"):
            prior_records.reconcile(manifest)

    def test_cli_reads_only_explicit_manifest_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "operator-export.json"
            output = root / "summary.json"
            manifest.write_text(json.dumps(sample_manifest()), encoding="utf-8")
            self.assertEqual(0, prior_records.main(["--manifest", str(manifest), "--output", str(output)]))
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("trusted_operator_export", result["source"]["kind"])
        self.assertEqual(1, result["summary"]["known_asset_count"])

    def test_cli_refuses_output_under_a_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "operator-export.json"
            unsafe_parent = root / "linked-parent"
            unsafe_parent.mkdir()
            output = unsafe_parent / "summary.json"
            manifest.write_text(json.dumps(sample_manifest()), encoding="utf-8")
            with patch.object(prior_records, "_is_reparse_path",
                              side_effect=lambda path: path == unsafe_parent):
                self.assertEqual(2, prior_records.main(
                    ["--manifest", str(manifest), "--output", str(output)]))
            self.assertFalse(output.exists())

    def test_cli_does_not_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "operator-export.json"
            output = root / "summary.json"
            manifest.write_text(json.dumps(sample_manifest()), encoding="utf-8")
            output.write_text("existing", encoding="utf-8")
            self.assertEqual(2, prior_records.main(
                ["--manifest", str(manifest), "--output", str(output)]))
            self.assertEqual("existing", output.read_text(encoding="utf-8"))

    def test_rejects_ambiguous_review_and_none_with_assets(self):
        manifest = sample_manifest()
        duplicate = dict(manifest["reviews"][0])
        duplicate["reviewed_at"] = "2026-08-02T09:00:00Z"
        manifest["reviews"].append(duplicate)
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "AMBIGUOUS_REVIEW_REF"):
            prior_records.reconcile(manifest)
        manifest = sample_manifest()
        manifest["reviews"][0]["lookup_status"] = "none"
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "LOOKUP_NONE_WITH_ASSETS"):
            prior_records.reconcile(manifest)

    def test_unavailable_lookup_has_an_explicit_coverage_gap(self):
        result = prior_records.reconcile(sample_manifest())
        self.assertEqual(["lookup_unavailable"], result["reviews"][0]["coverage_gaps"])

    def test_rejects_review_list_over_the_bounded_input_cap(self):
        manifest = sample_manifest()
        manifest["reviews"] = manifest["reviews"] * 501
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "INVALID_REVIEWS"):
            prior_records.reconcile(manifest)

    def test_missing_or_untrusted_input_is_not_accepted(self):
        manifest = sample_manifest()
        manifest["source"]["kind"] = "filesystem_scan"
        with self.assertRaisesRegex(prior_records.PriorRecordsError, "UNTRUSTED_SOURCE"):
            prior_records.reconcile(manifest)


if __name__ == "__main__":
    unittest.main()
