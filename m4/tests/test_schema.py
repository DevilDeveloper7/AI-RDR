import unittest

from m4_threat_intel.config import Settings
from m4_threat_intel.schema import (
    InvalidIndicator, hash_kind, is_non_routable, normalize, parse_request,
)


class HashTests(unittest.TestCase):
    def test_valid_hashes_lowercased_and_typed(self):
        for length, kind in ((32, "md5"), (40, "sha1"), (64, "sha256")):
            value = normalize("hash", "  " + "AB" * (length // 2) + " ")
            self.assertEqual(value, "ab" * (length // 2))
            self.assertEqual(hash_kind(value), kind)

    def test_invalid_hashes(self):
        for bad in ("abc", "g" * 64, "a" * 63, "a" * 128, "", "   ", None, 123):
            with self.assertRaises(InvalidIndicator, msg=repr(bad)):
                normalize("hash", bad)


class IpTests(unittest.TestCase):
    def test_valid_ips_canonicalised(self):
        self.assertEqual(normalize("ip", " 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(normalize("ip", "2001:DB8:0:0::1"), "2001:db8::1")

    def test_invalid_ips(self):
        for bad in ("999.1.1.1", "example.com", "1.2.3", "8.8.8.8/32"):
            with self.assertRaises(InvalidIndicator, msg=bad):
                normalize("ip", bad)

    def test_non_routable(self):
        for ip in ("10.0.0.5", "172.16.1.1", "192.168.1.10", "127.0.0.1", "::1",
                   "169.254.1.1", "fe80::1", "100.64.0.1", "0.0.0.0", "fd00::1",
                   "224.0.0.1", "240.0.0.1"):
            self.assertTrue(is_non_routable(ip), ip)

    def test_routable(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertFalse(is_non_routable(ip), ip)


class DomainTests(unittest.TestCase):
    def test_valid_domains(self):
        self.assertEqual(normalize("domain", "Example.COM."), "example.com")
        self.assertEqual(normalize("domain", "xn--bcher-kva.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize("domain", "a-b.sub.example.co.uk"), "a-b.sub.example.co.uk")

    def test_invalid_domains(self):
        for bad in ("localhost", "-bad.com", "bad-.com", "a..b", "1.2.3.4",
                    "has space.com", "a" * 64 + ".com", "http://example.com"):
            with self.assertRaises(InvalidIndicator, msg=bad):
                normalize("domain", bad)


class RequestTests(unittest.TestCase):
    def test_valid_request(self):
        self.assertEqual(parse_request({"alert_id": "A1", "type": "domain", "value": "Ex.com"}),
                         ("A1", "domain", "ex.com"))

    def test_invalid_requests(self):
        for body in (None, [], {}, {"alert_id": "", "type": "ip", "value": "8.8.8.8"},
                     {"alert_id": "A1", "type": "url", "value": "x"},
                     {"alert_id": "x" * 201, "type": "ip", "value": "8.8.8.8"}):
            with self.assertRaises(InvalidIndicator, msg=repr(body)):
                parse_request(body)


class SettingsTests(unittest.TestCase):
    def test_repr_never_shows_keys(self):
        s = Settings(abusech_auth_key="SECRET-ABC", otx_api_key="SECRET-XYZ")
        self.assertNotIn("SECRET", repr(s))


if __name__ == "__main__":
    unittest.main()
