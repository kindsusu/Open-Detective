import json
import unittest

from sudetect.asset_profile import profile_content
from sudetect.classifiers import _HTMLSignals, analyze
from sudetect.js_literals import LiteralError, parse_static_literal
from sudetect.structured_data import inspect_static_json


class StaticStructuredDataTests(unittest.TestCase):
    def test_many_short_scripts_are_analyzed_without_chunk_count_cutoff(self):
        body = '<html>' + ''.join(
            '<script>const rate' + str(index) + ' = {"price":' + str(index) + '};</script>'
            for index in range(24)) + '</html>'
        report = analyze(body.encode(), 'text/html').report
        self.assertTrue(report['analysis_complete'])
        self.assertEqual(24, report['asset_profile']['static_json_literals']['literal_count'])
        pricing = next(row for row in report['asset_profile']['business_data_categories']
                       if row['category'] == 'pricing')
        self.assertEqual(24, pricing['filled_field_count'])

    def test_split_json_script_is_reassembled_before_parsing(self):
        parser = _HTMLSignals()
        parser.feed('<script type="application/json">{"price":')
        parser.feed('42}</script>')
        self.assertEqual(['{"price":42}'], parser.json_chunks)
        self.assertFalse(parser.truncated)

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

    def test_static_js_object_and_large_inline_media_do_not_hide_later_literal(self):
        body = '<script>const media = "data:image/png;base64,' + 'A' * 110000 + '"; const bad = {price: 9}; var rates = [{"monthlyRate":450}];</script>'
        report = analyze(body.encode(), "text/html").report
        self.assertEqual(2, report["asset_profile"]["static_json_literals"]["literal_count"])
        self.assertEqual(2, report["asset_profile"]["static_json_literals"]["root_item_count"])
        self.assertEqual(2, next(row for row in report["asset_profile"]["business_data_categories"]
                                 if row["category"] == "pricing")["filled_field_count"])
        self.assertTrue(report['structure_analysis_complete'])
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

    def test_static_js_syntax_is_parsed_without_execution(self):
        source = "{rates: [{daily: 50000, active: true, note: 'demo',},], client: null, // } ignored\n price: -2.5e2,}"
        value = parse_static_literal(source)
        self.assertEqual(50000, value["rates"][0]["daily"])
        self.assertEqual(-250.0, value["price"])
        result = inspect_static_json("const data = " + source, "application/javascript")
        self.assertTrue(result["analysis_complete"])
        self.assertEqual([], result["incomplete_reasons"])
        self.assertEqual(1, result["literal_count"])
        self.assertEqual(2, result["categories"]["pricing"]["filled_field_count"])
        self.assertNotIn("demo", json.dumps(result))

    def test_dynamic_expressions_stay_unsupported(self):
        expressions = ("getPrice()", "1 + 2", "other.price", "`rate ${x}`", "...other",
                       "function() { return 1 }", "x => x + 1")
        for expression in expressions:
            with self.subTest(expression=expression):
                result = inspect_static_json("const data = {price: " + expression + "};", "text/javascript")
                self.assertFalse(result["analysis_complete"])
                self.assertIn("js_unsupported_dynamic_expression", result["incomplete_reasons"])
                self.assertEqual(0, result["literal_count"])

    def test_reason_codes_distinguish_malformed_json_js_and_limits(self):
        bad_json = inspect_static_json('{"price": }', "application/json")
        self.assertEqual(["json_malformed"], bad_json["incomplete_reasons"])
        unsupported = inspect_static_json("const x = {price: getRate()};", "text/javascript")
        self.assertIn("js_unsupported_dynamic_expression", unsupported["incomplete_reasons"])
        malformed = inspect_static_json("const x = {price: };", "text/javascript")
        self.assertIn("js_malformed_literal", malformed["incomplete_reasons"])
        limited = inspect_static_json("const x = " + "[" * 129 + "0" + "]" * 129, "text/javascript")
        self.assertIn("js_literal_limit", limited["incomplete_reasons"])
        bad_script_json = inspect_static_json('<script type="application/json">{"price": }</script>', "text/html")
        self.assertIn("json_malformed", bad_script_json["incomplete_reasons"])

    def test_literal_parser_bounds_and_invalid_tokens(self):
        cases = ("{price: Math.random()}", "{...other}", "{get price() { return 1 }}",
                 "{price: `value`}", "{price: NaN}", "{price: [1,,2]}")
        for source in cases:
            with self.subTest(source=source), self.assertRaises(LiteralError):
                parse_static_literal(source)
        with self.assertRaises(LiteralError) as depth:
            parse_static_literal("[" * 129 + "0" + "]" * 129)
        self.assertEqual("js_literal_limit", depth.exception.reason)
        with self.assertRaises(LiteralError) as size:
            parse_static_literal("[" + " " * (2 * 1024 * 1024) + "]")
        self.assertEqual("js_literal_limit", size.exception.reason)

    def test_suffix_expression_is_not_counted_as_assigned_static_value(self):
        sources = ("const rows = [1].map(fn);", "const prices = {fee: 1}.fee;",
                   "const data = [{fee: 1}] + other;", "const rows = [{fee: 1}][0];",
                   "const data = {fee: 1}?.fee;", "const data = {fee: 1}, next = 2;")
        for source in sources:
            with self.subTest(source=source):
                result = inspect_static_json(source, "application/javascript")
                self.assertFalse(result["analysis_complete"])
                self.assertEqual(0, result["literal_count"])
                self.assertIn("js_unsupported_dynamic_expression", result["incomplete_reasons"])
        static = inspect_static_json("const data = {fee: 1}\nconst other = {price: 2};", "text/javascript")
        self.assertTrue(static["analysis_complete"])
        self.assertEqual(2, static["literal_count"])

    def test_regex_and_comments_do_not_create_fake_declarations(self):
        source = ("const pattern = /const fake = {price: 900}\\/[a-z]/; "
                  "// const comment = {price: 901}\n"
                  "/* const hidden = {price: 902} */ "
                  "const visible = {price: 5};")
        result = inspect_static_json(source, "application/javascript")
        self.assertTrue(result["analysis_complete"])
        self.assertEqual(1, result["literal_count"])
        self.assertEqual(1, result["categories"]["pricing"]["filled_field_count"])
        returned_regex = inspect_static_json(
            "function pattern() { return /const fake = {price: 901}/; } const real = {price: 5};",
            "text/javascript")
        self.assertTrue(returned_regex["analysis_complete"])
        self.assertEqual(1, returned_regex["literal_count"])

    def test_nonfinite_number_does_not_become_static_value(self):
        for source in ("const data = {price: 1e999};", "const data = {price: NaN};",
                       "const data = {price: Infinity};"):
            with self.subTest(source=source):
                result = inspect_static_json(source, "text/javascript")
                self.assertFalse(result["analysis_complete"])
                self.assertEqual(0, result["literal_count"])
                self.assertTrue(set(result["incomplete_reasons"]) &
                                {"js_nonfinite_number", "js_unsupported_dynamic_expression"})

    def test_json_diagnostics_do_not_double_count_existing_json_walker(self):
        native = inspect_static_json('{"price": 5}', "application/json")
        embedded = inspect_static_json('<script type="application/json">{"price": 5}</script>', "text/html")
        self.assertTrue(native["analysis_complete"])
        self.assertTrue(embedded["analysis_complete"])
        self.assertEqual({}, native["categories"])
        self.assertEqual({}, embedded["categories"])
        self.assertEqual(1, next(row for row in profile_content(b'{"price": 5}', "application/json")
                                 ["business_data_categories"] if row["category"] == "pricing")
                         ["filled_field_count"])

    def test_native_and_embedded_json_reject_nonfinite(self):
        for number in ("NaN", "Infinity", "1e999"):
            payload = '{"price":' + number + '}'
            for text, kind in ((payload, "application/json"),
                               ('<script type="application/json">' + payload + '</script>', "text/html")):
                with self.subTest(number=number, kind=kind):
                    self.assertFalse(inspect_static_json(text, kind)["analysis_complete"])
                    profile = profile_content(text.encode(), kind)
                    self.assertFalse(profile["analysis_complete"])
                    self.assertFalse(any(row["filled_field_count"] for row in profile["business_data_categories"]))

    def test_unsupported_property_assignment_and_export_default_remain_pending(self):
        sources = (
            'window.rows = [{customer_phone:"fixture"}];',
            'globalThis["rows"] = [{customer_phone:"fixture"}];',
            'rows = /* captured */ [{customer_phone:"fixture"}];',
            'export default [{customer_phone:"fixture"}];',
            'module.exports = {customer_phone:"fixture"};',
        )
        for source in sources:
            with self.subTest(source=source):
                report = inspect_static_json(source, "application/javascript")
                self.assertFalse(report["analysis_complete"])
                self.assertIn("js_unsupported_assignment", report["incomplete_reasons"])
                self.assertEqual(0, report["literal_count"])
                self.assertFalse(profile_content(source.encode(), "application/javascript")
                                 ["structure_analysis_complete"])
        comparisons = 'const match = x == {price: 1}; const data = {price: 2};'
        report = inspect_static_json(comparisons, "application/javascript")
        self.assertTrue(report["analysis_complete"])
        self.assertEqual(1, report["literal_count"])

    def test_duplicate_static_js_keys_are_not_silently_discarded(self):
        for source in ('const data = {price: 1, price: 2};',
                       'const data = {price: 1, "price": 2};',
                       'const data = {"price": 1, "price": 2};'):
            with self.subTest(source=source):
                report = inspect_static_json(source, "application/javascript")
                self.assertFalse(report["analysis_complete"])
                self.assertEqual(0, report["literal_count"])
                self.assertIn("js_duplicate_key", report["incomplete_reasons"])
        with self.assertRaises(LiteralError) as duplicate:
            parse_static_literal('{price: 1, "price": 2}')
        self.assertEqual("js_duplicate_key", duplicate.exception.reason)


if __name__ == "__main__":
    unittest.main()
