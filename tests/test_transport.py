import unittest
from datetime import datetime, timedelta, timezone

from sudetect.policy import Budget, Scope
from sudetect.transport import fetch


def scope(**changes):
    raw = {
        "policy_id": "transport-test",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "targets": [{
            "origin": "https://app.example",
            "owner": "team",
            "ownership_evidence": "record-id",
            "path_prefixes": ["/"],
        }],
        "exclude_urls": [],
        "max_bytes": 8,
        "max_requests": 5,
        "timeout": 2,
        "max_redirects": 2,
    }
    raw.update(changes)
    return Scope.from_dict(raw)


class FakeResponse:
    def __init__(self, status=200, body=b"ok", headers=None):
        self.status = status
        self._body = body
        self._offset = 0
        self._headers = {key.lower(): value for key, value in (headers or {}).items()}

    def read(self, amount=-1):
        if amount < 0:
            amount = len(self._body) - self._offset
        value = self._body[self._offset:self._offset + amount]
        self._offset += len(value)
        return value

    def getheader(self, name):
        return self._headers.get(name.lower())


class FakeConnection:
    def __init__(self, response, record, pin):
        self.response = response
        self.record = record
        self.pin = pin

    def request(self, method, target, headers):
        self.record.append((method, target, headers, self.pin))

    def getresponse(self):
        return self.response

    def close(self):
        pass


def factory(responses, record):
    queue = list(responses)

    def make(host, port, pin, timeout):
        return FakeConnection(queue.pop(0), record, pin)

    return make


class TransportTests(unittest.TestCase):
    def test_get_is_anonymous_and_connection_uses_dns_pin(self):
        record = []
        result = fetch(
            "https://app.example/path", scope(),
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([FakeResponse(headers={"Content-Type": "text/plain"})], record),
        )
        self.assertEqual("BODY_SERVED", result.observation["access"])
        self.assertEqual("93.184.216.34", record[0][3])
        self.assertEqual("GET", record[0][0])
        lowered = {key.lower() for key in record[0][2]}
        self.assertFalse(lowered & {"authorization", "cookie", "referer", "origin"})
        self.assertEqual("text/plain", result.headers["content-type"])

    def test_every_dns_answer_must_be_public(self):
        record = []
        result = fetch(
            "https://app.example/", scope(),
            resolver=lambda host, port: ["93.184.216.34", "127.0.0.1"],
            connection_factory=factory([FakeResponse()], record),
        )
        self.assertEqual("INDETERMINATE", result.observation["access"])
        self.assertEqual("DNS returned a non-public address", result.observation["reason"])
        self.assertEqual([], record)

    def test_non_unicast_and_transition_addresses_are_rejected(self):
        blocked = (
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "2002:5db8:d822::1",
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        )
        for address in blocked:
            with self.subTest(address=address):
                record = []
                result = fetch(
                    "https://app.example/", scope(),
                    resolver=lambda host, port, address=address: [address],
                    connection_factory=factory([FakeResponse()], record),
                )
                self.assertEqual("DNS returned a non-public address", result.observation["reason"])
                self.assertEqual([], record)

    def test_getaddrinfo_style_resolver_injection_is_supported(self):
        record = []
        result = fetch(
            "https://app.example/", scope(),
            resolver=lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port))],
            connection_factory=factory([FakeResponse()], record),
        )
        self.assertEqual("BODY_SERVED", result.observation["access"])
        self.assertEqual("93.184.216.34", record[0][3])

    def test_redirect_is_authorized_before_second_request(self):
        record = []
        result = fetch(
            "https://app.example/", scope(),
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([
                FakeResponse(302, b"", {"Location": "https://evil.example/private"}),
            ], record),
        )
        self.assertEqual(1, len(record))
        self.assertEqual("INDETERMINATE", result.observation["access"])
        self.assertEqual("URL is outside authorized scope", result.observation["reason"])
        self.assertNotIn("evil.example/private", str(result.observation))

    def test_authorized_redirect_and_no_follow_mode(self):
        record = []
        result = fetch(
            "https://app.example/", scope(), follow_redirects=False,
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([
                FakeResponse(302, b"move", {"Location": "/login", "Cache-Control": "no-store"}),
            ], record),
        )
        self.assertEqual("INDETERMINATE", result.observation["access"])
        self.assertEqual("authorized_redirect_observed", result.observation["reason"])
        self.assertEqual("/login", result.headers["location"])
        self.assertEqual(1, len(record))

    def test_redirect_follow_and_shared_request_budget(self):
        record = []
        budget = Budget(2)
        result = fetch(
            "https://app.example/", scope(), budget=budget,
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([
                FakeResponse(301, b"", {"Location": "/next"}),
                FakeResponse(403, b"denied"),
            ], record),
        )
        self.assertEqual("ACCESS_DENIED_OBSERVED", result.observation["access"])
        self.assertEqual(2, budget.used)
        self.assertEqual(1, len(result.observation["redirects"]))

    def test_capture_cap_never_claims_full_hash(self):
        result = fetch(
            "https://app.example/", scope(max_bytes=4),
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([FakeResponse(200, b"abcdefgh")], []),
        )
        self.assertEqual(b"abcd", result.body)
        self.assertFalse(result.observation["capture_complete"])
        self.assertIsNone(result.observation["sha256"])
        self.assertEqual(64, len(result.observation["prefix_sha256"]))

    def test_206_and_encoded_responses_are_incomplete(self):
        for response, reason in (
            (FakeResponse(206, b"part"), "partial_resource"),
            (FakeResponse(200, b"compressed", {"Content-Encoding": "gzip"}), "unsupported_content_encoding"),
        ):
            with self.subTest(reason=reason):
                result = fetch(
                    "https://app.example/", scope(max_bytes=32),
                    resolver=lambda host, port: ["93.184.216.34"],
                    connection_factory=factory([response], []),
                )
                self.assertEqual(reason, result.observation["reason"])
                self.assertIsNone(result.observation["sha256"])
                self.assertEqual("NOT_INSPECTED", result.observation["content"])

    def test_caller_can_reduce_capture_limit(self):
        result = fetch(
            "https://app.example/", scope(max_bytes=8), max_bytes=3,
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([FakeResponse(200, b"12345")], []),
        )
        self.assertEqual(b"123", result.body)
        self.assertFalse(result.observation["capture_complete"])

    def test_connection_adapter_failure_is_sanitized(self):
        def broken(*args):
            raise RuntimeError("https://app.example/private?token=SECRET")

        result = fetch(
            "https://app.example/private?view=1", scope(),
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=broken,
        )
        self.assertEqual("transport_error", result.observation["reason"])
        self.assertNotIn("SECRET", str(result.observation))

    def test_status_observations_do_not_claim_safety(self):
        for status, access in ((401, "ACCESS_DENIED_OBSERVED"), (404, "NOT_FOUND_OBSERVED"), (500, "INDETERMINATE")):
            with self.subTest(status=status):
                result = fetch(
                    "https://app.example/", scope(),
                    resolver=lambda host, port: ["93.184.216.34"],
                    connection_factory=factory([FakeResponse(status, b"")], []),
                )
                self.assertEqual(access, result.observation["access"])
                self.assertEqual("NOT_INSPECTED", result.observation["content"])

    def test_scope_budget_is_shared_across_fetch_calls(self):
        policy = scope(max_requests=1)
        first_record = []
        fetch(
            "https://app.example/one", policy,
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([FakeResponse()], first_record),
        )
        second_record = []
        second = fetch(
            "https://app.example/two", policy,
            resolver=lambda host, port: ["93.184.216.34"],
            connection_factory=factory([FakeResponse()], second_record),
        )
        self.assertEqual("request budget exhausted", second.observation["reason"])
        self.assertEqual([], second_record)


if __name__ == "__main__":
    unittest.main()
