"""Synthetic, offline regressions for observed document links and PDF coverage."""
import io
import json
import unittest

from sudetect.asset_trace import extract_references
from sudetect.documents import analyze_document, extract_document_references


class DocumentDiscoveryCoverageTests(unittest.TestCase):
    def test_hidden_external_object_storage_link_is_literal_only(self):
        url = "https://objects.example.test/bucket/private/record.pdf?opaque=secret-canary"
        html = ("<section hidden><a href='" + url + "'>file</a></section>"
                "<script>const observed='https:\\/\\/objects.example.test\\/bucket\\/private\\/record.pdf?opaque=secret-canary';"
                "const computed=`https://objects.example.test/bucket/${id}.pdf`;"
                "// 'https://objects.example.test/neighbor.pdf'\n</script>")
        refs, gaps, _ = extract_references(html.encode(), "text/html")
        self.assertIn(("document_dom", url), refs)
        self.assertIn(("document_literal", url), refs)
        self.assertFalse(any("neighbor.pdf" in ref for _, ref in refs))
        self.assertFalse(any("${id}" in ref for _, ref in refs))
        self.assertTrue(all(isinstance(gap, str) for gap in gaps))

    def test_document_reference_scan_limit_is_explicit(self):
        body = b"<p>" + b"x" * (8 * 1024 * 1024) + b"</p><a href='/later.pdf'>later</a>"
        refs, gaps, _ = extract_references(body, "text/html")
        self.assertNotIn(("document_dom", "/later.pdf"), refs)
        self.assertIn("document_reference_source_limit", gaps)

    def test_regex_and_computed_paths_do_not_create_document_urls(self):
        js = (b'const pattern = /"https:\\/\\/objects.example.test\\/fake.pdf"/; '
              b'const ratio = 4 / 2; '
              b'const real = "https:\\u002F\\u002Fobjects.example.test\\u002Factual.pdf";')
        refs, _, _ = extract_references(js, "text/javascript")
        self.assertEqual([("document_literal", "https://objects.example.test/actual.pdf")], refs)

    def test_pdf_annotation_is_transient_and_ocr_gap_is_per_page(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            self.skipTest("optional pypdf unavailable")
        url = "https://objects.example.test/documents/inspection.pdf?token=secret-canary"
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.add_blank_page(width=200, height=200)
        writer.add_uri(0, url, [0, 0, 100, 100])
        out = io.BytesIO(); writer.write(out)
        body = out.getvalue()
        refs, gaps = extract_document_references(body, "application/pdf")
        self.assertEqual([("document_annotation", url)], refs)
        self.assertEqual([], gaps)
        report = analyze_document(body, "application/pdf")
        self.assertEqual(2, report["pages_examined"])
        self.assertEqual([1, 2], [page["page"] for page in report["page_coverage"]])
        self.assertTrue(all(page["ocr_state"] == "not_run" for page in report["page_coverage"]))
        self.assertIn("ocr_not_run", report["pending_reviews"])
        self.assertFalse(report["text_analysis_complete"])
        self.assertNotIn(url, json.dumps(report))

    def test_page_limit_preserves_unexamined_gap(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            self.skipTest("optional pypdf unavailable")
        writer = PdfWriter()
        for _ in range(3): writer.add_blank_page(width=100, height=100)
        out = io.BytesIO(); writer.write(out)
        report = analyze_document(out.getvalue(), "application/pdf", max_pages=1)
        self.assertEqual(3, report["pages_total"])
        self.assertEqual(2, report["pages_unexamined"])
        self.assertEqual(1, len(report["page_coverage"]))
        self.assertIn("pdf_page_limit", report["pending_reviews"])
        self.assertFalse(report["analysis_complete"])

    def test_pdf_annotation_long_uri_and_unknown_action_are_gaps(self):
        try:
            from pypdf import PdfWriter
            from pypdf.generic import NameObject, TextStringObject
        except ImportError:
            self.skipTest("optional pypdf unavailable")
        for kind, expected in (("long", "pdf_annotation_uri_unusable"),
                               ("unknown", "pdf_annotation_structure_unresolved")):
            writer = PdfWriter()
            page = writer.add_blank_page(width=100, height=100)
            writer.add_uri(0, "https://objects.example.test/doc.pdf", [0, 0, 50, 50])
            annotation = page["/Annots"][0].get_object()
            action = annotation["/A"].get_object()
            if kind == "long":
                action[NameObject("/URI")] = TextStringObject(
                    "https://objects.example.test/" + "x" * 2050 + ".pdf")
            else:
                action[NameObject("/S")] = NameObject("/Launch")
            out = io.BytesIO(); writer.write(out)
            refs, gaps = extract_document_references(out.getvalue(), "application/pdf")
            self.assertEqual([], refs)
            self.assertIn(expected, gaps)


if __name__ == "__main__":
    unittest.main()
