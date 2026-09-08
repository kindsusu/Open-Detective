import unittest

from sudetect.evidence import clean_text, safe_url, stable_ref


class EvidenceTests(unittest.TestCase):
    def test_safe_url_hides_all_locator_secrets(self):
        shown = safe_url("https://user:pw@app.example/customers/alice?token=secret#private")
        self.assertEqual("https://app.example/<path-omitted>?<query-omitted>#<fragment-omitted>", shown)
        for secret in ("user", "pw", "customers", "alice", "token", "secret", "private"):
            self.assertNotIn(secret, shown)

    def test_stable_hmac_ref(self):
        first = stable_ref("https://app.example/private/1", b"evidence-key")
        second = stable_ref("https://app.example/private/1", b"evidence-key")
        other = stable_ref("https://app.example/private/2", b"evidence-key")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first.startswith("hmac-sha256:"))
        self.assertNotIn("private", first)

    def test_keyless_reference_is_random_and_not_a_plain_hash(self):
        first = stable_ref("https://app.example/private/1")
        second = stable_ref("https://app.example/private/1")
        self.assertRegex(first, r"^opaque:[0-9a-f]{32}$")
        self.assertNotEqual(first, second)

    def test_clean_text_removes_record_delimiters(self):
        self.assertEqual("a b c", clean_text("a\tb\r\nc"))


if __name__ == "__main__":
    unittest.main()
