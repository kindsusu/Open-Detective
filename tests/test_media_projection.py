import hashlib
import time
import unittest
from itertools import chain

from sudetect.media_projection import project_inline_images


class MediaProjectionTests(unittest.TestCase):
    def project(self, chunks, wire=1_000_000, projected=1_000_000):
        return project_inline_images(chunks, max_wire_bytes=wire, max_projected_bytes=projected)

    def test_delimiters_and_adjacent_text(self):
        body = (
            b'<img src="data:image/png;base64,YWJj">after '
            b"const icon='data:image/svg+xml;base64,YWJj';next(); "
            b"x{background:url(data:image/gif;base64,YWJj)}tail"
        )
        result = self.project((body,))
        expected = body.replace(b"YWJj", b"[inline-image-omitted]")
        self.assertEqual(result.projected, expected)
        self.assertEqual(result.skipped_images, 3)
        self.assertTrue(result.media_ocr_gap)
        self.assertEqual(result.original_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(result.projected_sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(result.original_bytes, len(body))
        self.assertEqual(result.projected_bytes, len(expected))
        self.assertFalse(result.projected_truncated)
        self.assertFalse(result.wire_truncated)

    def test_every_split_point_and_single_byte_chunks(self):
        body = b"pre data:image/PNG;BASE64,YWJj==\"post"
        expected = b"pre data:image/PNG;BASE64,[inline-image-omitted]\"post"
        for cut in range(len(body) + 1):
            with self.subTest(cut=cut):
                self.assertEqual(self.project((body[:cut], body[cut:])).projected, expected)
        self.assertEqual(self.project(bytes((byte,)) for byte in body).projected, expected)

    def test_non_images_and_invalid_candidates_are_preserved(self):
        parts = (
            b"data:text/plain;base64,YWJj ",
            b"data:image/png,abc ",
            b"data:image/png;base64,abc) ",
            b"data:image/png;base64,ab=c ",
            b"data:image/png;base64, ",
            b"data:image/" + b"x" * 65 + b";base64,YWJj",
        )
        body = b"".join(parts)
        result = self.project(bytes((byte,)) for byte in body)
        self.assertEqual(result.projected, body)
        self.assertEqual(result.skipped_images, 0)
        self.assertFalse(result.media_ocr_gap)

    def test_overlap_and_binary(self):
        body = b"\x00\xffdata:image/data:image/png;base64,YWJj\x80end"
        expected = b"\x00\xffdata:image/data:image/png;base64,[inline-image-omitted]\x80end"
        self.assertEqual(self.project(bytes((byte,)) for byte in body).projected, expected)

    def test_wire_and_projection_limits(self):
        body = b"a data:image/png;base64,YWJj! tail"
        result = self.project((body,), wire=10)
        self.assertEqual(result.original_bytes, 10)
        self.assertTrue(result.wire_truncated)
        self.assertEqual(result.projected, body[:10])
        self.assertEqual(result.original_sha256, hashlib.sha256(body[:10]).hexdigest())
        self.assertFalse(self.project((body,), wire=len(body)).wire_truncated)
        self.assertFalse(self.project((), wire=0).wire_truncated)
        self.assertTrue(self.project((b"x",), wire=0).wire_truncated)

        result = self.project((body,), projected=8)
        self.assertEqual(result.original_bytes, len(body))
        self.assertEqual(result.projected_bytes, 8)
        self.assertTrue(result.projected_truncated)
        self.assertEqual(result.skipped_images, 1)
        self.assertEqual(result.projected_sha256, hashlib.sha256(result.projected).hexdigest())

    def test_bounded_large_payload_and_metadata_types(self):
        prefix = b"data:image/jpeg;base64,"
        chunks = (prefix, *(b"A" * 8192 for _ in range(128)), b")next")
        result = self.project(chunks, wire=2_000_000, projected=100)
        self.assertEqual(result.projected, prefix + b"[inline-image-omitted])next")
        self.assertEqual(result.skipped_images, 1)
        self.assertTrue(result.media_ocr_gap)
        for name, value in vars(result).items():
            if name == "projected":
                continue
            self.assertIsInstance(value, (str, int, bool))
            if isinstance(value, str):
                self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_20_mib_image_then_json_under_time_budget(self):
        prefix = b'{"image":"data:image/png;base64,'
        payload = b"A" * (20 * 1024 * 1024)
        suffix = b'","after":{"count":2,"ok":true}}'
        chunks = chain(
            (prefix[:17], prefix[17:]),
            (payload[offset:offset + 65_537] for offset in range(0, len(payload), 65_537)),
            (suffix[:1], suffix[1:]),
        )
        started = time.perf_counter()
        result = self.project(chunks, wire=len(prefix) + len(payload) + len(suffix), projected=1024)
        elapsed = time.perf_counter() - started
        self.assertEqual(result.projected, prefix + b"[inline-image-omitted]" + suffix)
        self.assertEqual(result.original_bytes, len(prefix) + len(payload) + len(suffix))
        self.assertEqual(result.skipped_images, 1)
        self.assertFalse(result.wire_truncated)
        self.assertFalse(result.projected_truncated)
        self.assertLess(elapsed, 10.0)

    def test_20_mib_plain_tail_after_false_marker_under_time_budget(self):
        false_marker = b"data:image/png,not-base64\n"
        tail = b"x" * (20 * 1024 * 1024)
        suffix = b'{"after":true}'
        body_size = len(false_marker) + len(tail) + len(suffix)
        chunks = chain(
            (false_marker[:5], false_marker[5:]),
            (tail[offset:offset + 65_537] for offset in range(0, len(tail), 65_537)),
            (suffix,),
        )
        started = time.perf_counter()
        result = self.project(chunks, wire=body_size, projected=body_size)
        elapsed = time.perf_counter() - started
        self.assertEqual(result.projected, false_marker + tail + suffix)
        self.assertEqual(result.skipped_images, 0)
        self.assertFalse(result.media_ocr_gap)
        self.assertFalse(result.wire_truncated)
        self.assertFalse(result.projected_truncated)
        self.assertLess(elapsed, 10.0)

    def test_input_validation(self):
        for limit in (-1, True, "10"):
            with self.assertRaises(ValueError):
                project_inline_images((), max_wire_bytes=limit, max_projected_bytes=10)
        with self.assertRaises(TypeError):
            self.project((b"valid", "bad"))


if __name__ == "__main__":
    unittest.main()
