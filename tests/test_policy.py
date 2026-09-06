import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sudetect.policy import PolicyError, Scope


def policy(**changes):
    value = {
        "policy_id": "policy-1",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "targets": [{
            "origin": "https://app.example",
            "owner": "team",
            "ownership_evidence": "record-id",
            "path_prefixes": ["/allowed"],
        }],
        "exclude_urls": ["https://app.example/allowed/excluded"],
        "max_bytes": 262144,
        "max_requests": 20,
        "timeout": 10,
        "max_redirects": 5,
    }
    value.update(changes)
    return value


class ScopeTests(unittest.TestCase):
    def test_required_api_and_normalization(self):
        scope = Scope.from_dict(policy())
        self.assertEqual("policy-1", scope.policy_id)
        self.assertEqual(262144, scope.max_bytes)
        self.assertEqual("https://app.example/allowed/item", scope.authorize("https://APP.EXAMPLE:443/allowed/item"))

    def test_load(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "scope.json")
            path.write_text(json.dumps(policy()), encoding="utf-8")
            self.assertEqual("policy-1", Scope.load(path).policy_id)

    def test_exact_origin_and_path_boundary(self):
        scope = Scope.from_dict(policy())
        for url in (
            "https://evil.example/allowed",
            "https://app.example.evil/allowed",
            "https://app.example/allowedevil",
            "http://app.example/allowed",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                scope.authorize(url)

    def test_exclusion(self):
        with self.assertRaisesRegex(PolicyError, "excluded"):
            Scope.from_dict(policy()).authorize("https://app.example/allowed/excluded")

    def test_credentials_and_capability_queries_rejected(self):
        scope = Scope.from_dict(policy())
        for url in (
            "https://user:pw@app.example/allowed",
            "https://app.example/allowed?token=x",
            "https://app.example/allowed?apiKey=x",
            "https://app.example/allowed?X-Amz-Signature=x",
            "https://app.example/allowed?%2574oken=x",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                scope.authorize(url)

    def test_path_ambiguity_and_traversal_rejected(self):
        scope = Scope.from_dict(policy())
        for url in (
            "https://app.example/allowed/../secret",
            "https://app.example/allowed/%2e%2e/secret",
            "https://app.example/allowed/%252e%252e/secret",
            "https://app.example/allowed%5c..%5csecret",
            "https://app.example/allowed/%00secret",
            "https://app.example/allowed//secret",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                scope.authorize(url)

    def test_expiry_requires_future_utc(self):
        with self.assertRaises(PolicyError):
            Scope.from_dict(policy(expires_at="2099-01-01T00:00:00+09:00"))
        with self.assertRaises(PolicyError):
            Scope.from_dict(policy(expires_at="2000-01-01T00:00:00Z"))

    def test_unknown_or_unsafe_policy_fields_fail_closed(self):
        with self.assertRaises(PolicyError):
            Scope.from_dict(policy(max_request=3))
        with self.assertRaises(PolicyError):
            Scope.from_dict(policy(allow_credentials_in_url=True))


if __name__ == "__main__":
    unittest.main()
