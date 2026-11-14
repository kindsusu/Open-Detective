import json
import unittest

from sudetect.classifiers import MAX_MASKED_EXAMPLES, analyze, mask_value


class MaskedExampleTests(unittest.TestCase):
    def test_mask_rules_hide_tail_or_middle(self):
        self.assertEqual("010-****-5678", mask_value("phone", "010-1234-5678"))
        self.assertEqual("010-****-5678", mask_value("phone", "01012345678"))
        self.assertEqual("12가34**", mask_value("plate", "12가3456"))
        self.assertEqual("109-86-316**", mask_value("business", "109-86-31667"))
        self.assertEqual("900101-1******", mask_value("resident", "900101-1234567"))
        self.assertEqual("fi*****@example.test", mask_value("email", "fixture@example.test"))
        self.assertEqual("****", mask_value("unknown", "abcd"))

    def test_report_carries_bounded_masked_examples_without_full_values(self):
        plates = ["12가3456", "34나5678", "56다7890", "78라1234"]
        html = ("<html><body>상담 010-1234-5678 / " + " ".join(plates)
                + " fixture@example.test</body></html>")
        report = analyze(html.encode("utf-8"), "text/html").report
        encoded = json.dumps(report, ensure_ascii=False)
        for value in ["010-1234-5678", "fixture@example.test", *plates]:
            self.assertNotIn(value, encoded)
        by_code = {s["code"]: s for s in report["signals"]}
        plate = by_code["KR_VEHICLE_PLATE_CANDIDATE"]
        self.assertEqual(4, plate["unique_values"])
        self.assertEqual(MAX_MASKED_EXAMPLES, len(plate["masked_examples"]))
        self.assertEqual("12가34**", plate["masked_examples"][0])
        self.assertEqual(["010-****-5678"], by_code["KR_PHONE_VALUE_CANDIDATE"]["masked_examples"])


if __name__ == "__main__":
    unittest.main()
