import unittest

from simple_x_forwarded_for_chain import ChainResult, parse_x_forwarded_for
from simple_x_forwarded_for_chain.core import untrusted_addresses


class TestParse(unittest.TestCase):
    def test_simple_chain(self):
        r = parse_x_forwarded_for("203.0.113.5, 198.51.100.1")
        self.assertEqual(r.direct_address, "203.0.113.5")
        self.assertEqual(r.proxy_addresses, ["198.51.100.1"])
        self.assertEqual(r.all_addresses, ["203.0.113.5", "198.51.100.1"])
        self.assertEqual(r.raw, "203.0.113.5, 198.51.100.1")

    def test_single_address(self):
        r = parse_x_forwarded_for("203.0.113.5")
        self.assertEqual(r.direct_address, "203.0.113.5")
        self.assertEqual(r.proxy_addresses, [])
        self.assertEqual(r.all_addresses, ["203.0.113.5"])

    def test_empty_header(self):
        r = parse_x_forwarded_for("")
        self.assertIsNone(r.direct_address)
        self.assertEqual(r.proxy_addresses, [])
        self.assertEqual(r.all_addresses, [])

    def test_none_header(self):
        r = parse_x_forwarded_for(None)  # type: ignore[arg-type]
        self.assertIsNone(r.direct_address)
        self.assertEqual(r.all_addresses, [])

    def test_whitespace_only(self):
        r = parse_x_forwarded_for("   ")
        self.assertIsNone(r.direct_address)
        self.assertEqual(r.all_addresses, [])

    def test_leading_and_trailing_whitespace_trimmed(self):
        r = parse_x_forwarded_for("  203.0.113.5  ,  198.51.100.1  ")
        self.assertEqual(r.direct_address, "203.0.113.5")
        self.assertEqual(r.proxy_addresses, ["198.51.100.1"])

    def test_malformed_tokens_dropped(self):
        r = parse_x_forwarded_for("203.0.113.5, not-an-ip, 198.51.100.1")
        # The junk token is dropped entirely; the two valid IPs remain in order.
        self.assertEqual(r.all_addresses, ["203.0.113.5", "198.51.100.1"])
        self.assertEqual(r.direct_address, "203.0.113.5")
        self.assertEqual(r.proxy_addresses, ["198.51.100.1"])

    def test_empty_token_between_commas(self):
        r = parse_x_forwarded_for("203.0.113.5, , 198.51.100.1")
        self.assertEqual(r.all_addresses, ["203.0.113.5", "198.51.100.1"])

    def test_ipv6_bare(self):
        r = parse_x_forwarded_for("2001:db8::1, 2001:db8::2")
        self.assertEqual(r.direct_address, "2001:db8::1")
        self.assertEqual(r.proxy_addresses, ["2001:db8::2"])

    def test_ipv6_bracketed(self):
        # Some proxies emit bracketed IPv6 in XFF; we accept it rather than
        # reject, because rejecting would silently drop real traffic.
        r = parse_x_forwarded_for("[2001:db8::1], [2001:db8::2]")
        self.assertEqual(r.direct_address, "[2001:db8::1]")
        self.assertEqual(r.proxy_addresses, ["[2001:db8::2]"])

    def test_all_malformed(self):
        r = parse_x_forwarded_for("junk, also junk, !!!")
        self.assertIsNone(r.direct_address)
        self.assertEqual(r.all_addresses, [])

    def test_result_type(self):
        r = parse_x_forwarded_for("203.0.113.5")
        self.assertIsInstance(r, ChainResult)


class TestUntrustedFilter(unittest.TestCase):
    def test_all_trusted_peers_stripped_to_client(self):
        # Chain: client=203.0.113.5, trusted proxies 198.51.100.1 and 198.51.100.2
        r = parse_x_forwarded_for("203.0.113.5, 198.51.100.1, 198.51.100.2")
        remaining = untrusted_addresses(r, ["198.51.100.1", "198.51.100.2"])
        # Rightmost is trusted -> strip; next is trusted -> strip; 203.0.113.5
        # has no trusted peer to its right, so it is the boundary.
        self.assertEqual(remaining, ["203.0.113.5"])

    def test_untrusted_peer_keeps_everything_left_of_it(self):
        r = parse_x_forwarded_for("203.0.113.5, 10.0.0.1, 198.51.100.1")
        remaining = untrusted_addresses(r, ["198.51.100.1"])
        # Rightmost is trusted -> strip. 10.0.0.1 is not trusted -> stop.
        self.assertEqual(remaining, ["203.0.113.5", "10.0.0.1"])

    def test_no_trusted_proxies(self):
        r = parse_x_forwarded_for("203.0.113.5, 198.51.100.1")
        remaining = untrusted_addresses(r, [])
        self.assertEqual(remaining, ["203.0.113.5", "198.51.100.1"])

    def test_single_address_chain(self):
        r = parse_x_forwarded_for("203.0.113.5")
        remaining = untrusted_addresses(r, ["198.51.100.1"])
        self.assertEqual(remaining, ["203.0.113.5"])

    def test_empty_chain(self):
        r = parse_x_forwarded_for("")
        remaining = untrusted_addresses(r, ["198.51.100.1"])
        self.assertEqual(remaining, [])

    def test_all_addresses_trusted(self):
        # When every address in the chain is a trusted proxy, the leftmost is
        # still returned because there is nothing untrusted to its left.
        r = parse_x_forwarded_for("198.51.100.1, 198.51.100.2")
        remaining = untrusted_addresses(r, ["198.51.100.1", "198.51.100.2"])
        self.assertEqual(remaining, ["198.51.100.1"])


if __name__ == "__main__":
    unittest.main()
