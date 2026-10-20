"""Offline DNS fixtures for paired NAT64 answers and fail-closed pinning."""
import socket
import unittest
from unittest.mock import patch

from sudetect.policy import PolicyError
from sudetect.transport import _default_resolver, _resolve_public


def dns(*addresses):
    return [(socket.AF_INET6 if ":" in address else socket.AF_INET,
             socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]


class NAT64ResolverTests(unittest.TestCase):
    def resolve(self, *addresses):
        with patch("sudetect.transport.socket.getaddrinfo", return_value=dns(*addresses)):
            return _default_resolver("api.github.com", 443, 1.0)

    def test_paired_public_ipv4_uses_only_real_public_pin(self):
        answer = self.resolve("20.200.245.245", "64:ff9b::14c8:f5f5")
        self.assertEqual(["20.200.245.245"], answer)
        self.assertEqual(["20.200.245.245"], _resolve_public("api.github.com", 443,
                         lambda _host, _port: answer))

    def test_standalone_or_unmatched_nat64_still_rejected(self):
        for addresses in (("64:ff9b::14c8:f5f5",),
                          ("20.200.245.245", "64:ff9b::808:808")):
            with self.subTest(addresses=addresses):
                answer = self.resolve(*addresses)
                self.assertTrue(any(value.startswith("64:ff9b:") for value in answer))
                with self.assertRaisesRegex(PolicyError, "non-public address"):
                    _resolve_public("api.github.com", 443, lambda _host, _port: answer)

    def test_private_or_loopback_pair_is_not_filtered(self):
        for addresses in (("10.0.0.1", "64:ff9b::a00:1"),
                          ("127.0.0.1", "64:ff9b::7f00:1")):
            with self.subTest(addresses=addresses):
                answer = self.resolve(*addresses)
                self.assertEqual(set(addresses), set(answer))
                with self.assertRaisesRegex(PolicyError, "non-public address"):
                    _resolve_public("api.github.com", 443, lambda _host, _port: answer)

    def test_other_transition_address_does_not_get_filtered(self):
        answer = self.resolve("20.200.245.245", "2002:14c8:f5f5::")
        self.assertEqual(2, len(answer))
        with self.assertRaisesRegex(PolicyError, "non-public address"):
            _resolve_public("api.github.com", 443, lambda _host, _port: answer)


if __name__ == "__main__":
    unittest.main()
