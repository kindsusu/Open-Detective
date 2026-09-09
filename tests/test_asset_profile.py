import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from sudetect.__main__ import main
from sudetect.asset_profile import MAX_CONTENT_BYTES, build_asset_profile, profile_content


class AssetProfileTests(unittest.TestCase):
    def test_content_categories_are_value_free_and_zero_false_are_structural(self):
        secret_value = "do-not-report-this-contact@example.test"
        body = json.dumps({"customer_contact": False, "pricing_rate": 0, "internal_note": secret_value}).encode()
        report = profile_content(body, "application/json")
        rendered = json.dumps(report)
        self.assertEqual("data_file", report["asset_kind_hint"])
        self.assertIn("customer_contact", {x["category"] for x in report["business_data_categories"]})
        self.assertIn("pricing", {x["category"] for x in report["business_data_categories"]})
        self.assertNotIn(secret_value, rendered)
        self.assertNotIn("internal_note", rendered)
        self.assertEqual("supplied_bytes_only", report["analysis_scope"])

    def test_metadata_only_and_relationships_remain_uninspected(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.json"
            manifest.write_text(json.dumps({"assets": [
                {"asset_id": "site", "kind": "website", "locator_ref": "opaque:" + "1" * 32},
                {"asset_id": "child", "parent_asset_id": "site"},
            ]}), encoding="utf-8")
            result = build_asset_profile(manifest)
        self.assertEqual("NOT_INSPECTED", result["assets"][0]["inspection_state"])
        self.assertEqual("site", result["assets"][1]["parent_asset_id"])
        self.assertTrue(all(x["exposure"] == "NOT_ESTABLISHED_BY_LOCAL_ANALYSIS" for x in result["assets"]))

    def test_local_file_is_bounded_and_never_leaks_path_or_values(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); content = root / "captured.json"; content.write_bytes(b'{"margin":0,"x":"TOP_SECRET"}' + b" " * MAX_CONTENT_BYTES)
            manifest = root / "manifest.json"; manifest.write_text(json.dumps({"assets":[{"asset_id":"a", "local_file":"captured.json", "content_type":"application/json"}]}), encoding="utf-8")
            result = build_asset_profile(manifest)
        profile = result["assets"][0]["content_profile"]
        self.assertTrue(profile["truncated"])
        self.assertEqual(MAX_CONTENT_BYTES, profile["bytes_examined"])
        self.assertNotIn("TOP_SECRET", json.dumps(result))
        self.assertNotIn("captured.json", json.dumps(result))

    def test_rejects_duplicate_cycles_and_unsafe_local_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rows in (
                [{"asset_id":"a"}, {"asset_id":"a"}],
                [{"asset_id":"a", "parent_asset_id":"b"}, {"asset_id":"b", "parent_asset_id":"a"}],
                [{"asset_id":"a", "local_file":"../outside"}],
            ):
                path = root / (str(len(rows)) + str(rows[0]["asset_id"]) + ".json")
                path.write_text(json.dumps({"assets":rows}), encoding="utf-8")
                with self.assertRaises(ValueError): build_asset_profile(path)

    def test_cli_emits_safe_summary_and_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "page.html").write_text("<form>pricing</form>", encoding="utf-8")
            manifest = root / "manifest.json"; output = root / "report.json"; markdown = root / "report.md"
            manifest.write_text(json.dumps({"assets":[{"asset_id":"page", "local_file":"page.html", "content_type":"text/html"}]}), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout): self.assertEqual(0, main(["asset-profile", "--input", str(manifest), "--output", str(output), "--markdown", str(markdown)]))
            self.assertEqual(1, json.loads(stdout.getvalue())["assets"])
            self.assertTrue(output.is_file()); self.assertIn("NOT_ESTABLISHED_BY_LOCAL_ANALYSIS", markdown.read_text(encoding="utf-8"))

    def test_classifier_includes_safe_profile(self):
        from sudetect.classifiers import analyze
        result = analyze(b'{"financial":false}', "application/json").report
        self.assertEqual("supplied_bytes_only", result["asset_profile"]["analysis_scope"])
        self.assertEqual("NOT_INSPECTED", result["content"])

    def test_classifier_profile_only_claims_supplied_prefix(self):
        from sudetect.classifiers import analyze
        result = analyze(b'{"margin": 0}' + b" " * MAX_CONTENT_BYTES, "application/json").report
        self.assertFalse(result["analysis_complete"])
        self.assertEqual("supplied_bytes_only", result["asset_profile"]["analysis_scope"])

    def test_json_scripts_camelcase_and_underscore_counts(self):
        report = profile_content(b'<script type="application/json">{"cost_price":0,"customerName":false}</script>', "text/html")
        categories = {x["category"]: x for x in report["business_data_categories"]}
        self.assertEqual(1, categories["margin"]["candidate_count"])
        self.assertEqual(1, categories["margin"]["filled_field_count"])
        self.assertEqual(1, categories["customer_contact"]["filled_field_count"])
        self.assertIn("structured_field_names", categories["margin"]["evidence_bases"])

    def test_native_inventory_coverage_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "inventory.json"
            manifest.write_text(json.dumps({"inventory_id":"inv","scope_id":"scope", "status":"PARTIAL", "coverage":{}, "errors":[{}], "assets":[{"asset_id":"a","kind":"deployment"}], "edges":[]}), encoding="utf-8")
            report = build_asset_profile(manifest)
        self.assertEqual("partial", report["source_coverage"]["state"])
        self.assertEqual(1, report["source_coverage"]["error_count"])

    def test_native_hmac_reference_and_safe_file_metadata_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "inventory.json"
            ref = "hmac-sha256:" + "a" * 64
            manifest.write_text(json.dumps({"inventory_id":"inv", "assets":[{"asset_id":"file", "kind":"repository_file", "candidate_kind":"data_file", "locator_ref":ref, "extension":"json", "byte_size":0, "visibility":"private", "public_exposure":"not_measured", "locator_mutability":"branch_ref_mutable"}], "edges":[]}), encoding="utf-8")
            report = build_asset_profile(manifest)
        asset = report["assets"][0]
        self.assertEqual(ref, asset["locator_ref"])
        self.assertEqual(0, asset["asset_metadata"]["byte_size"])
        self.assertEqual("data_file", asset["declared_kind"])

    def test_native_metadata_rejects_unmeasured_status_or_untrusted_values(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "inventory.json"
            base = {"inventory_id":"inv", "assets":[{"asset_id":"file", "kind":"repository_file", "public_exposure":"confirmed"}], "edges":[]}
            manifest.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(ValueError): build_asset_profile(manifest)

    def test_symlink_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); target = root / "target.json"; target.write_text('{"assets":[]}', encoding="utf-8")
            link = root / "link.json"
            try: link.symlink_to(target)
            except OSError: self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError): build_asset_profile(link)


if __name__ == "__main__":
    unittest.main()
