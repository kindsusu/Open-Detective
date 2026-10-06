import json
import contextlib
import io
import logging
import time
import unittest

from sudetect.classifiers import analyze, analyze_stream
from sudetect.documents import analyze_document, _page_image_state, _run_isolated
from sudetect.evidence_redaction import redact_mapping, redact_screenshot, redact_text, safe_error_code


def codes(report):
    return {item["code"] for item in report["signals"]}


def _trusted_slow_worker():
    time.sleep(5)
    return {}


class _PdfObject(dict):
    def get_object(self): return self


class _PdfStream(_PdfObject):
    def __init__(self, data, **values):
        super().__init__(values)
        self._data = data


class ContentImprovementsTests(unittest.TestCase):
    def test_t06_structured_table_confidential_plate_and_business_number(self):
        # Synthetic checksum-valid business number; it represents no company.
        from sudetect.classifiers import _valid_business_number
        business = next(f"123-45-{n:05d}" for n in range(100000) if _valid_business_number(f"123-45-{n:05d}"))
        html = ("<section hidden>대외비</section><table><tr><th>영업 수수료</th><th>지급 조건</th><th>비율</th></tr>"
                "<tr><td>계약</td><td>달성</td><td>12%</td></tr></table>"
                f"<p>차량번호 123가4567 사업자등록번호 {business}</p>")
        report = analyze(html.encode(), "text/html").report
        self.assertTrue({"CONFIDENTIAL_MARKER_CANDIDATE", "COMMISSION_TABLE_STRUCTURE",
                         "KR_VEHICLE_PLATE_CANDIDATE", "KR_BUSINESS_NUMBER_CANDIDATE"} <= codes(report))
        self.assertNotIn(business, json.dumps(report))
        self.assertEqual("hidden_body", next(x for x in report["signals"] if x["code"] == "CONFIDENTIAL_MARKER_CANDIDATE")["location"])

    def test_t07_css_version_placeholders_and_zero(self):
        report = analyze(b'<style>body { margin: 12px }</style><script src="https://cdn.example/lib@1.2.3.js"></script>', "text/html").report
        self.assertNotIn("EMAIL_VALUE_CANDIDATE", codes(report))
        self.assertNotIn("margin", {x["category"] for x in report["asset_profile"]["business_data_categories"]})
        report = analyze(b'{"customer_name":"example","cost_price":0,"active":false}', "application/json").report
        self.assertEqual(1, next(x for x in report["signals"] if x["code"] == "SENSITIVE_VALUES_CANDIDATE")["count"])
        categories = {x["category"]: x for x in report["asset_profile"]["business_data_categories"]}
        self.assertEqual(0, categories["customer_contact"]["filled_field_count"])
        self.assertEqual(1, categories["margin"]["filled_field_count"])

    def test_t08_contact_and_person_list_are_separate(self):
        report = analyze(b'{"phone":"010-1234-5678","customers":[{"customer_name":"Synthetic One"}]}', "application/json").report
        self.assertTrue({"CONTACT_VALUE_CANDIDATE", "PERSON_LIST_CANDIDATE", "CUSTOMER_RECORD_CANDIDATE"} <= codes(report))

    def test_t09_stream_after_prefix_and_partial(self):
        data = b"x" * 270000 + b" sb_secret_abcdefghijklmnopqrstuvwx"
        report = analyze_stream((data[:270010], data[270010:]), "text/plain").report
        self.assertIn("SERVER_SECRET_CANDIDATE", codes(report))
        self.assertTrue(report["analysis_complete"])
        partial = analyze_stream((data,), "text/plain", max_bytes=270000).report
        self.assertFalse(partial["analysis_complete"])
        self.assertIn("analysis_byte_limit", partial["pending_reviews"])

    def test_t10_pdf_dependency_and_ocr_gap(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            report = analyze_document(b"%PDF-1.4\n", "application/pdf")
            self.assertIn("pdf_text_dependency_missing", report["pending_reviews"])
            self.assertFalse(report["analysis_complete"])
            return
        from io import BytesIO
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        output = BytesIO(); writer.write(output)
        report = analyze_document(output.getvalue(), "application/pdf")
        self.assertFalse(report["analysis_complete"])
        self.assertIn("ocr_not_run", report["pending_reviews"])
        from pypdf.generic import DictionaryObject, NameObject, StreamObject
        text_writer = PdfWriter()
        page = text_writer.add_blank_page(width=400, height=200)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                 NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"):
            DictionaryObject({NameObject("/F1"): text_writer._add_object(font)})})
        stream = StreamObject()
        stream._data = b"BT /F1 12 Tf 20 100 Td (sb_secret_abcdefghijklmnopqrstuvwx) Tj ET"
        page[NameObject("/Contents")] = text_writer._add_object(stream)
        output = BytesIO(); text_writer.write(output)
        text_report = analyze_document(output.getvalue(), "application/pdf")
        self.assertIn("SERVER_SECRET_CANDIDATE", codes(text_report))
        self.assertEqual("SENSITIVE_CANDIDATE", text_report["content"])
        self.assertNotIn("abcdefghijklmnopqrstuvwx", json.dumps(text_report))
        form = StreamObject()
        form._data = b""
        form[NameObject("/Subtype")] = NameObject("/Form")
        page["/Resources"][NameObject("/XObject")] = DictionaryObject({NameObject("/Fm0"): text_writer._add_object(form)})
        output = BytesIO(); text_writer.write(output)
        form_report = analyze_document(output.getvalue(), "application/pdf")
        self.assertIn("image_or_structure_review", form_report["pending_reviews"])
        self.assertFalse(form_report["image_review_complete"])
        image = analyze(b'<img src="data:image/png;base64,AAAA">', "text/html").report
        self.assertFalse(image["image_review_complete"])
        self.assertIn("image_or_base64_review", image["pending_reviews"])

    def test_t19_canary_redaction_across_outputs(self):
        canary = "SU_DETECT_SYNTHETIC_SECRET_ABCDEF"
        text = f"token={canary} fixture@example.test 010-1234-5678"
        rendered = json.dumps(redact_mapping({"log": text, "error": text, "password": canary}, canaries=[canary]))
        self.assertNotIn(canary, rendered)
        self.assertNotIn("fixture@example.test", rendered)
        self.assertNotIn("010-1234-5678", rendered)
        self.assertNotIn(canary, redact_text(text, canaries=[canary]))
        self.assertEqual("analysis_error", safe_error_code(RuntimeError(canary), code=canary))
        self.assertIsNone(redact_screenshot(canary.encode())["image"])

    def test_t19_malformed_pdf_parser_output_is_silent(self):
        canary = "SU_DETECT_SYNTHETIC_PDF_CANARY"
        output, errors = io.StringIO(), io.StringIO()
        events = []
        class Capture(logging.Handler):
            def emit(self, record): events.append(record.getMessage())
        handler = Capture()
        logging.getLogger().addHandler(handler)
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                report = analyze_document(("%PDF-1.4\n" + canary).encode(), "application/pdf")
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertNotIn(canary, output.getvalue() + errors.getvalue() + "".join(events) + json.dumps(report))
        self.assertFalse(report["analysis_complete"])

    def test_pdf_worker_has_hard_deadline(self):
        started = time.monotonic()
        status, payload = _run_isolated(_trusted_slow_worker, (), 0.25)
        self.assertEqual("timeout", status)
        self.assertIsNone(payload)
        self.assertLess(time.monotonic() - started, 3)

    def test_pdf_image_review_does_not_clear_nested_or_inline_content(self):
        text_stream = _PdfStream(b"BT /F1 12 Tf (synthetic text) Tj ET")
        page = _PdfObject({"/Contents": text_stream})
        self.assertEqual("clear", _page_image_state(page))
        page["/Contents"] = _PdfStream(b"BI /W 1 /H 1 ID 0 EI")
        self.assertEqual("image", _page_image_state(page))
        page["/Contents"] = _PdfStream(b"opaque", **{"/Filter": "/FlateDecode"})
        self.assertEqual("unknown", _page_image_state(page))
        page["/Contents"] = _PdfStream(b"/HiddenResource Do")
        self.assertEqual("unknown", _page_image_state(page))
        page["/Contents"] = text_stream
        page["/Resources"] = _PdfObject({"/XObject": _PdfObject({"/Fm": _PdfObject({"/Subtype": "/Form"})})})
        self.assertEqual("unknown", _page_image_state(page))
        page["/Resources"] = _PdfObject({"/XObject": _PdfObject({str(n): _PdfObject({"/Subtype": "/Image"}) for n in range(129)})})
        self.assertEqual("unknown", _page_image_state(page))


if __name__ == "__main__": unittest.main()
