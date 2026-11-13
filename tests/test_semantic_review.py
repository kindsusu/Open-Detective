"""Offline bounded semantic review; no original JavaScript is executed."""
import json
import unittest

from sudetect.semantic_review import MAX_SOURCE_BYTES, review_semantic_source


class SemanticReviewTests(unittest.TestCase):
    def test_duplicate_json_fields_do_not_silently_complete(self):
        report = review_semantic_source(b'{"customer_name":"hidden","customer_name":""}',
                                        "application/json")
        self.assertFalse(report["source_structure_complete"])
        self.assertIsNone(report["syntax_valid"])
        self.assertIn("semantic_json_duplicate_keys", report["pending_reviews"])
        self.assertNotIn("hidden", json.dumps(report))

    def test_valid_large_json_iterates_beyond_old_node_limit(self):
        body = json.dumps({"pricing": [{"price": index, "customer_name": "sample"}
                                      for index in range(3000)]}).encode()
        report = review_semantic_source(body, "application/json")
        self.assertTrue(report["syntax_valid"])
        self.assertTrue(report["source_structure_complete"], report["pending_reviews"])
        self.assertGreater(report["nodes_examined"], 2048)
        self.assertEqual(3000, report["filled_field_count_by_category"]["pricing"])
        self.assertNotIn("sample", json.dumps(report))

    def test_node_limit_is_explicit_incomplete(self):
        body = json.dumps({"pricing": [{"price": index} for index in range(100)]}).encode()
        report = review_semantic_source(body, "application/json", max_nodes=50)
        self.assertTrue(report["syntax_valid"])
        self.assertFalse(report["source_structure_complete"])
        self.assertEqual(50, report["nodes_examined"])
        self.assertIn("semantic_node_limit", report["pending_reviews"])

    def test_invalid_json_preserves_text_coverage(self):
        report = review_semantic_source(b'{"price":1', "application/json")
        self.assertTrue(report["source_text_complete"])
        self.assertFalse(report["syntax_valid"])
        self.assertIn("semantic_json_syntax_invalid", report["pending_reviews"])

    def test_html_flow_is_only_lexical_and_never_executes(self):
        source = (b'<html><div id="out"></div><script>'
                  b'const prices = [{price: 100}]; '
                  b'document.getElementById("out").innerHTML = prices.map(row => row.price).join(); '
                  b'document.addEventListener("click", renderPrices);'
                  b'</script></html>')
        report = review_semantic_source(source, "text/html")
        flow = report["dom_flow"]
        self.assertGreaterEqual(flow["static_data_declarations"], 1)
        self.assertGreaterEqual(flow["dom_write_sites"], 1)
        self.assertGreaterEqual(flow["event_binding_sites"], 1)
        self.assertGreaterEqual(flow["declaration_dom_proximity_links"], 1)
        self.assertFalse(flow["original_script_executed"])
        self.assertFalse(flow["runtime_flow_verified"])
        self.assertTrue(flow["lexical_scan_complete"])
        self.assertNotIn("flow_linkage_complete", flow)
        self.assertEqual(0, flow["network_request_attempts"])
        self.assertIsNone(report["syntax_valid"])

    def test_comment_proximity_is_never_runtime_flow_verification(self):
        report = review_semantic_source(
            b'// const prices=[{price:1}]; innerHTML = prices;', "text/javascript")
        self.assertEqual("lexical_candidate_only", report["dom_flow"]["link_strength"])
        self.assertTrue(report["dom_flow"]["lexical_scan_complete"])
        self.assertFalse(report["dom_flow"]["runtime_flow_verified"])

    def test_unsupported_format_cannot_report_structure_complete(self):
        for body, content_type in ((b"%PDF-1.7\n", "application/pdf"),
                                   (b"PK\x03\x04hello", "application/zip"),
                                   (b"ordinary text", "text/plain")):
            with self.subTest(content_type=content_type):
                report = review_semantic_source(body, content_type)
                self.assertEqual("other", report["document_type"])
                self.assertFalse(report["source_structure_complete"])
                self.assertIn("semantic_unsupported_content_type", report["pending_reviews"])
                self.assertIsNone(report["dom_flow"])

    def test_nonfinite_json_is_rejected(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
            with self.subTest(value=value):
                report = review_semantic_source(b'{"price":' + value + b'}', "application/json")
                self.assertFalse(report["syntax_valid"])
                self.assertFalse(report["source_structure_complete"])
                self.assertIn("semantic_json_syntax_invalid", report["pending_reviews"])

    def test_profile_only_structure_reason_is_preserved(self):
        report = review_semantic_source(
            b"<html><script type='application/json'>{</script></html>", "text/html")
        self.assertFalse(report["source_structure_complete"])
        self.assertIn("semantic_embedded_json_syntax_or_depth_invalid",
                      report["pending_reviews"])

    def test_bounds_and_image_projection_remain_explicit(self):
        self.assertEqual(16 * 1024 * 1024, MAX_SOURCE_BYTES)
        self.assertIn("semantic_byte_limit", review_semantic_source(
            b"x" * (MAX_SOURCE_BYTES + 1), "text/html")["pending_reviews"])
        self.assertIn("semantic_byte_limit", review_semantic_source(
            b"x" * 100, "text/plain", max_bytes=99)["pending_reviews"])
        self.assertIn("semantic_depth_limit", review_semantic_source(
            b"[" * 130 + b"0" + b"]" * 130, "application/json")["pending_reviews"])
        body = b'<html><script>const card = "data:image/png;base64,YWJj";</script></html>'
        report = review_semantic_source(body, "text/html")
        self.assertEqual(1, report["inline_images_projected"])
        self.assertIn("semantic_image_visual_review_separate", report["pending_reviews"])
        self.assertFalse(review_semantic_source(b"\xff", "application/json")["source_text_complete"])


if __name__ == "__main__":
    unittest.main()
