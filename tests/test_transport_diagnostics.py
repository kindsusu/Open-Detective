"""Offline regression tests for transport diagnostics and capture hash scope."""

import hashlib
import socket
import ssl
import unittest

from sudetect.transport import fetch
from sudetect.policy import PolicyError
from test_transport import FakeResponse, factory, scope


PUBLIC_PIN = "93.184.216.34"


def failing_connection(exc):
    def make(host, port, pin, timeout):
        raise exc

    return make


class TransportDiagnosticsTests(unittest.TestCase):
    def fetch_failure(self, exc, *, resolver=None):
        return fetch(
            "https://app.example/private?view=1", scope(),
            resolver=resolver or (lambda host, port: [PUBLIC_PIN]),
            connection_factory=failing_connection(exc),
        ).observation

    def test_t17_structured_transport_failures_do_not_expose_exception_text(self):
        cases = [
            (TimeoutError("SECRET"), "timeout"),
            (ConnectionRefusedError("SECRET"), "connection_refused"),
            (ConnectionResetError("SECRET"), "connection_reset"),
            (ssl.SSLError("SECRET"), "tls_error"),
            (OSError("SECRET"), "transport_error"),
            (PolicyError("SECRET"), "transport_error"),
        ]
        for exc, reason in cases:
            with self.subTest(reason=reason):
                observation = self.fetch_failure(exc)
                self.assertEqual(reason, observation["reason"])
                self.assertEqual("INDETERMINATE", observation["access"])
                self.assertIsNone(observation["sha256"])
                self.assertNotIn("SECRET", str(observation))

    def test_t17_certificate_codes_and_unknown_verification_fallback(self):
        for verify_code, reason in (
            (10, "tls_certificate_expired"),
            (62, "tls_hostname_mismatch"),
            (9999, "tls_verification_failed"),
        ):
            with self.subTest(code=verify_code):
                exc = ssl.SSLCertVerificationError(1, "SECRET")
                exc.verify_code = verify_code
                observation = self.fetch_failure(exc)
                self.assertEqual(reason, observation["reason"])
                self.assertNotIn("SECRET", str(observation))

    def test_t17_dns_failure_and_timeout_are_distinct(self):
        for exc, reason in (
            (socket.gaierror("SECRET"), "dns_failure"),
            (TimeoutError("SECRET"), "timeout"),
        ):
            with self.subTest(reason=reason):
                def resolver(host, port):
                    raise exc

                observation = self.fetch_failure(RuntimeError("unused"), resolver=resolver)
                self.assertEqual(reason, observation["reason"])
                self.assertNotIn("SECRET", str(observation))

    def test_t18_full_and_prefix_hashes_identify_different_capture_scope(self):
        original = b"same-prefix-original"
        changed = b"same-prefix-updated"

        def observe(body, *, limit):
            return fetch(
                "https://app.example/mirror", scope(max_bytes=64), max_bytes=limit,
                resolver=lambda host, port: [PUBLIC_PIN],
                connection_factory=factory([FakeResponse(200, body)], []),
            ).observation

        first = observe(original, limit=64)
        same = observe(original, limit=64)
        newer = observe(changed, limit=64)
        prefix = observe(changed, limit=11)

        self.assertTrue(first["capture_complete"])
        self.assertEqual(hashlib.sha256(original).hexdigest(), first["sha256"])
        self.assertEqual(first["sha256"], same["sha256"])
        self.assertNotEqual(first["sha256"], newer["sha256"])
        self.assertFalse(prefix["capture_complete"])
        self.assertIsNone(prefix["sha256"])
        self.assertEqual(hashlib.sha256(changed[:11]).hexdigest(), prefix["prefix_sha256"])
        self.assertNotIn("prefix_sha256", first)


if __name__ == "__main__":
    unittest.main()
