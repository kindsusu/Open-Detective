import json
import unittest

from sudetect.asset_profile import profile_content
from sudetect.classifiers import analyze
from sudetect.structured_data import inspect_static_json


class StaticStructuredDataTests(unittest.TestCase):
    def test_multiple_literals_count_roots_and_canonical_filled_fields(self):
        body = '''<script>
        const cars = [{"vehicle_model":"모형 A", "lease_rate":0, "price":120},
                      {"vehicle_model":"모형 B", "lease_rate":false, "price":null}];
        let clients = {"organization":"Blue Orchard Mobility", "customer_name":"Synthetic Person", "phone":"010-0000-0000"};
        </script>'''
        report = analyze(body.encode(), "text/html").report
        static = report["asset_profile"]["static_json_literals"]
        self.assertEqual((2, 3, True), (static["literal_count"], static["root_item_count"], static["analysis_complete"]))
        rows = {row["category"]: row for row in report["asset_profile"]["business_data_categories"]}
        self.assertEqual((4, 3), (rows["pricing"]["candidate_count"], rows["pricing"]["filled_field_count"]))
        self.assertEqual(2, rows["contract_vehicle_record"]["filled_field_count"])
        self.assertEqual("SENSITIVE_CANDIDATE", report["content"])
        self.assertIn("BUSINESS_DATA_VALUE_CANDIDATE", {signal["code"] for signal in report["signals"]})
        self.assertNotIn("Synthetic Person", json.dumps(report))
        self.assertNotIn("Blue Orchard Mobility", json.dumps(report))
        self.assertNotIn("모형 A", json.dumps(report, ensure_ascii=False))

    def test_non_json_js_and_large_inline_media_do_not_hide_later_literal(self):
        body = '<script>const media = "data:image/png;base64,' + 'A' * 110000 + '"; const bad = {price: 9}; var rates = [{"monthlyRate":450}];</script>'
        report = analyze(body.encode(), "text/html").report
        self.assertEqual(1, report["asset_profile"]["static_json_literals"]["literal_count"])
        self.assertEqual(1, report["asset_profile"]["static_json_literals"]["root_item_count"])
        self.assertEqual(1, next(row for row in report["asset_profile"]["business_data_categories"]
                                 if row["category"] == "pricing")["filled_field_count"])
        self.assertIn("image_or_base64_review", report["pending_reviews"])

    def test_template_calculation_and_field_names_are_separate(self):
        data = 'const data = {"price":"{{rate}}", "lease_rate":"=A1*B1", "vehicle":"", "customer":null, "cost_price":0}'
        report = analyze(data.encode(), "text/javascript").report
        rows = {row["category"]: row for row in report["asset_profile"]["business_data_categories"]}
        self.assertEqual((2, 0, 1, 1), (rows["pricing"]["candidate_count"],
                                           rows["pricing"]["filled_field_count"],
                                           rows["pricing"]["template_count"],
                                           rows["pricing"]["calculation_count"]))
        self.assertEqual(0, rows["contract_vehicle_record"]["filled_field_count"])
        self.assertEqual(1, rows["margin"]["filled_field_count"])

    def test_large_projected_page_and_populated_lease_rates_container(self):
        private_field = "planMatchInternalNote"
        document = {"leaseRates": [{"monthly": 740, "padding": "x" * 1_350_000}],
                    private_field: "Blue Orchard Mobility"}
        body = ("<script>const planMatch = " + json.dumps(document) + ";</script>").encode()
        self.assertGreater(len(body), 1_300_000)
        report = analyze(body, "text/html", max_bytes=2 * 1024 * 1024).report
        static = report["asset_profile"]["static_json_literals"]
        self.assertEqual((1, 1, True), (static["literal_count"], static["root_item_count"], static["analysis_complete"]))
        pricing = next(row for row in report["asset_profile"]["business_data_categories"]
                       if row["category"] == "pricing")
        self.assertEqual((1, 1), (pricing["candidate_count"], pricing["filled_field_count"]))
        self.assertEqual("SENSITIVE_CANDIDATE", report["content"])
        rendered = json.dumps(report)
        self.assertNotIn(private_field, rendered)
        self.assertNotIn("Blue Orchard Mobility", rendered)

        template = inspect_static_json('const x = {"leaseRates":[{"monthly":"{{rate}}"}]}', "text/javascript")
        self.assertEqual(0, template["categories"]["pricing"]["filled_field_count"])
        self.assertEqual(1, template["categories"]["pricing"]["template_count"])

    def test_css_margin_and_string_mentions_do_not_become_fields(self):
        body = '<style>.box{margin:20px}</style><script>const css = "margin: 20px"; const x = {"name":"margin"};</script>'
        profile = profile_content(body.encode(), "text/html")
        self.assertNotIn("margin", {row["category"] for row in profile["business_data_categories"]})

    def test_malformed_and_truncated_literals_fail_closed(self):
        for body in ('<script>const x = {"price": 1',
                     '<script>const x = {"price": 1};',
                     '<script>const x = {"price": }</script>'):
            with self.subTest(body=body):
                report = analyze(body.encode(), "text/html").report
                self.assertFalse(report["analysis_complete"])
                self.assertFalse(report["structure_analysis_complete"])

        mixed = inspect_static_json('const broken = {"price": }; const sound = {"price": 7};', "text/javascript")
        self.assertFalse(mixed["analysis_complete"])
        self.assertEqual(1, mixed["literal_count"])

    def test_node_and_depth_budgets_are_explicit(self):
        many = "const data = " + json.dumps([{"price": n} for n in range(12_000)])
        result = inspect_static_json(many, "text/javascript")
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(0, result["literal_count"])
        deep = "const data = " + "[" * 129 + "0" + "]" * 129
        self.assertFalse(inspect_static_json(deep, "text/javascript")["analysis_complete"])
        huge = 'const data = {"price":"' + 'x' * (2 * 1024 * 1024) + '"}'
        self.assertFalse(inspect_static_json(huge, "text/javascript")["analysis_complete"])

    def test_ignored_code_strings_and_comments(self):
        js = '''// const fake = {"price":900}
        const s = 'const fake = {"price":900}';
        /* let fake = {"price":900}; */
        let real = {"가격":1};'''
        result = inspect_static_json(js, "text/javascript")
        self.assertEqual(1, result["literal_count"])
        self.assertEqual(1, result["categories"]["pricing"]["filled_field_count"])


if __name__ == "__main__":
    unittest.main()
