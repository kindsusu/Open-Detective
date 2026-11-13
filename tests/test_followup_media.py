"""Synthetic offline tests of full and partial inline OCR continuation."""
import base64
import json
import unittest
from unittest.mock import patch

from sudetect.followup_media import review_inline_media
from sudetect.media_review import analyze_inline_images


def fixture_images(count):
    return b" ".join(b"data:image/png;base64," + base64.b64encode(bytes([index % 256]))
                     for index in range(count))


class FollowupMediaTests(unittest.TestCase):
    def test_sensitive_first_image_does_not_stop_later_ocr(self):
        sensitive = {"ocr_state": "completed", "pending_reviews": [],
                     "content": "SENSITIVE_CANDIDATE",
                     "signals": [{"code": "KR_PHONE_VALUE_CANDIDATE"}]}
        clean = {"ocr_state": "completed", "pending_reviews": [],
                 "content": "NOT_INSPECTED", "signals": []}
        body = fixture_images(3)
        with patch("sudetect.media_review.analyze_image",
                   side_effect=[sensitive, clean, clean]) as image_review:
            report = review_inline_media(body, max_seconds=30)
        self.assertEqual(3, image_review.call_count)
        self.assertEqual(3, report["inline_images_found"])
        self.assertEqual(3, report["inline_images_examined"])
        self.assertEqual(0, report["inline_images_remaining"])
        self.assertEqual(3, report["ocr_completed"])
        self.assertTrue(report["ocr_coverage_complete"])
        self.assertFalse(report["visual_review_complete"])
        self.assertEqual(1, report["signal_counts"]["KR_PHONE_VALUE_CANDIDATE"])
        self.assertNotIn("inline_image_ocr_unexamined", report["pending_reviews"])
        self.assertNotIn("SENSITIVE_CANDIDATE", json.dumps(report))
        self.assertEqual(40_000_000, image_review.call_args.kwargs["max_pixels"])

    def test_batch_offset_and_aggregate_decoded_budget(self):
        body = fixture_images(2)
        first = {"inline_images_found": 2, "inline_images_next_index": 1,
                 "ocr_completed": 1, "inline_decoded_bytes_examined": 10,
                 "signal_counts": {"KR_PHONE_VALUE_CANDIDATE": 1},
                 "pending_reviews": ["inline_image_count_or_budget_limit"]}
        second = {"inline_images_found": 2, "inline_images_next_index": 2,
                  "ocr_completed": 1, "inline_decoded_bytes_examined": 20,
                  "signal_counts": {"KR_PHONE_VALUE_CANDIDATE": 1},
                  "pending_reviews": []}
        with patch("sudetect.followup_media.analyze_inline_images",
                   side_effect=[first, second]) as batches:
            report = review_inline_media(body, max_total_decoded_bytes=100)
        self.assertEqual(0, batches.call_args_list[0].kwargs["start_index"])
        self.assertEqual(1, batches.call_args_list[1].kwargs["start_index"])
        self.assertEqual(90, batches.call_args_list[1].kwargs["max_total_decoded_bytes"])
        self.assertEqual(30, report["decoded_bytes_examined"])
        self.assertEqual(2, report["signal_counts"]["KR_PHONE_VALUE_CANDIDATE"])
        self.assertTrue(report["ocr_coverage_complete"])

    def test_exact_partial_index_and_default_pixel_bound(self):
        clean = {"ocr_state": "completed", "pending_reviews": [],
                 "content": "NOT_INSPECTED", "signals": []}
        body = fixture_images(3)
        with patch("sudetect.media_review.analyze_image", return_value=clean) as image_review:
            batch = analyze_inline_images(body, max_images=1, max_pixels=40_000_000)
        self.assertEqual(1, batch["inline_images_next_index"])
        self.assertEqual(1, batch["inline_decoded_bytes_examined"])
        self.assertEqual(2, batch["inline_images_unexamined"])
        self.assertEqual(40_000_000, image_review.call_args.kwargs["max_pixels"])
        with patch("sudetect.media_review.analyze_image", return_value=clean) as image_review:
            analyze_inline_images(body, max_images=1)
        self.assertEqual(25_000_000, image_review.call_args.kwargs["max_pixels"])
        with patch("sudetect.media_review.analyze_image", return_value=clean):
            partial = review_inline_media(body, max_total_decoded_bytes=2)
        self.assertEqual(2, partial["next_index"])
        self.assertEqual(1, partial["inline_images_remaining"])
        self.assertEqual(2, partial["decoded_bytes_examined"])
        self.assertFalse(partial["ocr_coverage_complete"])
        self.assertIn("inline_image_byte_limit", partial["pending_reviews"])

    def test_empty_and_input_limits(self):
        empty = review_inline_media(b"", max_seconds=1)
        self.assertTrue(empty["ocr_coverage_complete"])
        self.assertEqual([], empty["pending_reviews"])
        with self.assertRaises(ValueError):
            review_inline_media(b"", max_total_decoded_bytes=512 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            analyze_inline_images(b"", max_pixels=0)


if __name__ == "__main__":
    unittest.main()
