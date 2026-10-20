import base64
import importlib.util
from io import BytesIO
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from sudetect.media_review import _OCR_CACHE, _image_header, _windows_ocr_available, analyze_image, analyze_inline_images


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (20).to_bytes(4, "big") + (10).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"
JPEG = b"\xff\xd8\xff\xc0\x00\x11\x08\x00\x0a\x00\x14" + b"\x01\x11\x00" * 3 + b"\xff\xd9"


class MediaReviewTests(unittest.TestCase):
    def setUp(self):
        _OCR_CACHE.clear()

    def test_header_and_limits_do_not_require_decoder(self):
        self.assertEqual(("png", 20, 10), _image_header(PNG))
        self.assertEqual(("jpeg", 20, 10), _image_header(JPEG))
        self.assertIsNone(_image_header(b"not an image"))
        self.assertIn("image_pixel_limit", analyze_image(PNG, max_pixels=100)["pending_reviews"])
        self.assertIn("capture_incomplete", analyze_image(PNG, capture_complete=False)["pending_reviews"])

    @patch("sudetect.media_review._windows_ocr_available", return_value=False)
    @patch("sudetect.media_review.importlib.util.find_spec", return_value=None)
    @patch("sudetect.media_review.shutil.which", return_value=None)
    def test_missing_engine_never_claims_analysis_complete(self, _which, _spec, _windows):
        result = analyze_image(PNG)
        self.assertEqual("not_run", result["ocr_state"])
        self.assertIn("ocr_engine_unavailable", result["pending_reviews"])
        self.assertFalse(result["analysis_complete"])

    @patch("sudetect.media_review.subprocess.run")
    def test_ocr_classifies_without_returning_recognized_text(self, run):
        raw = b"confidential contact 010-1234-5678"
        run.return_value = subprocess.CompletedProcess([], 0, raw, b"")
        result = analyze_image(PNG, tesseract_path="trusted-tesseract")
        self.assertEqual("completed", result["ocr_state"])
        self.assertEqual("SENSITIVE_CANDIDATE", result["content"])
        self.assertTrue(result["text_analysis_complete"])
        self.assertFalse(result["image_review_complete"])
        self.assertIn("image_visual_and_metadata_review_required", result["pending_reviews"])
        self.assertNotIn(raw.decode(), repr(result))
        self.assertEqual(PNG, run.call_args.kwargs["input"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stderr"])

    @patch("sudetect.media_review.subprocess.run", side_effect=subprocess.TimeoutExpired("ocr", 1))
    def test_timeout_is_explicit(self, _run):
        result = analyze_image(PNG, tesseract_path="trusted-tesseract", max_seconds=1)
        self.assertEqual("timeout", result["ocr_state"])
        self.assertIn("ocr_time_limit", result["pending_reviews"])

    @patch("sudetect.media_review.subprocess.run")
    def test_completed_ocr_cache_is_value_free_and_reused(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, b"ordinary label", b"")
        first = analyze_image(PNG, tesseract_path="trusted-tesseract", max_seconds=10)
        second = analyze_image(PNG, tesseract_path="trusted-tesseract", max_seconds=1)
        self.assertEqual(first, second)
        self.assertEqual(1, run.call_count)
        self.assertEqual(1, len(_OCR_CACHE))

    @patch("sudetect.media_review._windows_ocr_available", return_value=False)
    @patch("sudetect.media_review.importlib.util.find_spec", return_value=None)
    @patch("sudetect.media_review.shutil.which", return_value=None)
    def test_inline_image_counts_and_gaps_without_raw_data(self, _which, _spec, _windows):
        encoded = base64.b64encode(PNG)
        body = b'<img src="data:image/png;base64,' + encoded + b'">'
        report = analyze_inline_images(body)
        self.assertEqual(1, report["inline_images_found"])
        self.assertEqual(1, report["inline_images_examined"])
        self.assertEqual(0, report["ocr_completed"])
        self.assertIn("ocr_engine_unavailable", report["pending_reviews"])
        self.assertNotIn(encoded.decode(), repr(report))
        limited = analyze_inline_images(body + body, max_images=1)
        self.assertIn("inline_image_count_or_budget_limit", limited["pending_reviews"])

    @patch("sudetect.media_review.subprocess.run")
    def test_inline_stops_after_sensitive_candidate(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, b"confidential", b"")
        body = b"data:image/png;base64," + base64.b64encode(PNG)
        report = analyze_inline_images(body + b" " + body, tesseract_path="trusted-tesseract")
        self.assertEqual("SENSITIVE_CANDIDATE", report["content"])
        self.assertEqual(1, report["inline_images_examined"])
        self.assertEqual(1, report["inline_images_unexamined"])
        self.assertIn("inline_image_sensitive_candidate_stop", report["pending_reviews"])
        self.assertEqual(1, run.call_count)

    @unittest.skipUnless((_windows_ocr_available() or importlib.util.find_spec("rapidocr_onnxruntime")) and
                         Path("C:/Windows/Fonts/arial.ttf").is_file(),
                         "optional local OCR and Windows Arial font required")
    def test_real_offline_ocr_on_synthetic_image(self):
        from PIL import Image, ImageDraw, ImageFont

        picture = Image.new("RGB", (780, 160), "white")
        font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 72)
        ImageDraw.Draw(picture).text((20, 30), "CONFIDENTIAL", fill="black", font=font)
        stream = BytesIO()
        picture.save(stream, format="PNG")
        report = analyze_image(stream.getvalue(), max_seconds=60)
        self.assertIn(report.get("ocr_backend"), {"windows_ocr", "rapidocr_onnxruntime"})
        self.assertEqual("completed", report["ocr_state"])
        self.assertEqual("SENSITIVE_CANDIDATE", report["content"])
        self.assertIn("CONFIDENTIAL_MARKER_CANDIDATE", {signal["code"] for signal in report["signals"]})
        self.assertFalse(report["image_review_complete"])
        if report["ocr_backend"] == "windows_ocr":
            self.assertNotIn("ocr_requested_language_not_covered", report["pending_reviews"])
        else:
            self.assertIn("ocr_requested_language_not_covered", report["pending_reviews"])

    @unittest.skipUnless(_windows_ocr_available() and Path("C:/Windows/Fonts/malgun.ttf").is_file(),
                         "Windows Korean OCR and Malgun font required")
    def test_real_korean_windows_ocr(self):
        from PIL import Image, ImageDraw, ImageFont

        picture = Image.new("RGB", (620, 180), "white")
        font = ImageFont.truetype("C:/Windows/Fonts/malgun.ttf", 90)
        ImageDraw.Draw(picture).text((25, 25), "대외비", fill="black", font=font)
        stream = BytesIO()
        picture.save(stream, format="PNG")
        report = analyze_image(stream.getvalue(), max_seconds=20)
        self.assertEqual("windows_ocr", report.get("ocr_backend"))
        self.assertEqual("completed", report["ocr_state"])
        self.assertIn("ko", report["ocr_languages_used"])
        self.assertIn("CONFIDENTIAL_MARKER_CANDIDATE", {signal["code"] for signal in report["signals"]})
        self.assertFalse(report["image_review_complete"])

    @unittest.skipUnless(_windows_ocr_available() and importlib.util.find_spec("PIL"),
                         "Windows OCR and Pillow required")
    def test_additional_raster_formats_and_animation_gap(self):
        from PIL import Image, ImageDraw

        picture = Image.new("RGB", (160, 80), "white")
        ImageDraw.Draw(picture).text((10, 20), "TEST", fill="black")
        for image_format in ("BMP", "TIFF", "ICO", "AVIF"):
            with self.subTest(image_format=image_format):
                output = BytesIO()
                picture.save(output, format=image_format)
                report = analyze_image(output.getvalue(), max_seconds=20)
                self.assertEqual(image_format.casefold(), report["media_type"])
                self.assertEqual("completed", report["ocr_state"])
                self.assertEqual(1, report["image_frames_examined"])
                if image_format == "ICO":
                    self.assertGreater(report["dimensions"]["width"], 0)
                    self.assertGreater(report["dimensions"]["height"], 0)
                    self.assertIn("image_multi_resolution_unexamined", report["pending_reviews"])
                else:
                    self.assertEqual({"width": 160, "height": 80}, report["dimensions"])
        frames = [picture, Image.new("RGB", picture.size, "black")]
        output = BytesIO()
        frames[0].save(output, format="GIF", save_all=True, append_images=frames[1:], duration=100)
        animated = analyze_image(output.getvalue(), max_seconds=20)
        self.assertEqual(2, animated["image_frames_total"])
        self.assertEqual(1, animated["image_frames_examined"])
        self.assertIn("image_unexamined_frames", animated["pending_reviews"])
        self.assertFalse(animated["analysis_complete"])


if __name__ == "__main__":
    unittest.main()
