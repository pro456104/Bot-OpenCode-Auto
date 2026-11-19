# -*- coding: utf-8 -*-
"""Parser tests: .conf text/file, wireguard:// URI, country classification."""
import os
import tempfile
import unittest
import urllib.parse

from vpnbot import parsing

SAMPLE_CONF = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.2.0.2/32
DNS = 10.2.0.1, 2a07:b944::2:1
MTU = 1420

[Peer]
PublicKey = zcfEQgUoPLK2kvDicsA/4B9F2AI7qfxX5ueDo/Zcjj4=
Endpoint = 149.36.51.3:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "zcfEQgUoPLK2kvDicsA/4B9F2AI7qfxX5ueDo/Zcjj4="


class TestConfText(unittest.TestCase):
    def test_valid(self):
        s, err = parsing.parse_conf_from_text(SAMPLE_CONF, source="Custom")
        self.assertIsNone(err)
        self.assertEqual(s["private_key"], PRIV)
        self.assertEqual(s["public_key"], PUB)
        self.assertEqual(s["endpoint"], "149.36.51.3:51820")
        self.assertEqual(s["address"], "10.2.0.2/32")
        self.assertEqual(s["mtu"], "1420")
        self.assertEqual(s["source"], "Custom")
        self.assertEqual(s["country"], "Unknown")
        self.assertEqual(s["name"], "wg-Unknown-CUST")

    def test_missing_private_key(self):
        s, err = parsing.parse_conf_from_text("[Interface]\nAddress = 10.0.0.2/32\n")
        self.assertIsNone(s)
        self.assertEqual(err, "Missing PrivateKey or Endpoint")

    def test_empty(self):
        s, err = parsing.parse_conf_from_text("")
        self.assertIsNone(s)
        self.assertTrue(err)

    def test_comments_and_case_insensitive_keys(self):
        text = "# comment\n; comment\n[Interface]\nprivatekey = " + PRIV + \
               "\n[Peer]\npublickey = " + PUB + "\nendpoint = 1.2.3.4:51820\n"
        s, err = parsing.parse_conf_from_text(text)
        self.assertIsNone(err)
        self.assertEqual(s["endpoint"], "1.2.3.4:51820")
        # defaults when DNS/MTU absent
        self.assertEqual(s["dns"], "1.1.1.1, 8.8.8.8")
        self.assertEqual(s["mtu"], "1420")

    def test_conf_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "wg-DE-TEST.conf")
            with open(p, "w", encoding="utf-8") as f:
                f.write(SAMPLE_CONF)
            s, err = parsing.parse_conf(p)
            self.assertIsNone(err)
            self.assertEqual(s["name"], "wg-DE-TEST")
            self.assertEqual(s["source"], "Imported")

    def test_conf_file_missing(self):
        s, err = parsing.parse_conf(os.path.join(tempfile.gettempdir(), "no_such_wg.conf"))
        self.assertIsNone(s)
        self.assertTrue(err)


class TestUri(unittest.TestCase):
    def _uri(self, comment="DE Frankfurt"):
        q = lambda v: urllib.parse.quote(v, safe="")
        return ("wireguard://%s@149.36.51.3:51820?publickey=%s&address=%s&mtu=1380#%s"
                % (q(PRIV), q(PUB), q("172.16.0.2/32"), q(comment)))

    def test_valid(self):
        s = parsing.parse_wireguard_uri(self._uri())
        self.assertIsNotNone(s)
        self.assertEqual(s["private_key"], PRIV)
        self.assertEqual(s["public_key"], PUB)
        self.assertEqual(s["endpoint"], "149.36.51.3:51820")
        self.assertEqual(s["address"], "172.16.0.2/32")
        self.assertEqual(s["mtu"], "1380")
        self.assertEqual(s["comment"], "DE Frankfurt")

    def test_default_port(self):
        q = lambda v: urllib.parse.quote(v, safe="")
        # trailing colon -> port defaults to 51820 (original parser behavior)
        s = parsing.parse_wireguard_uri("wireguard://%s@1.2.3.4:?publickey=%s" % (q(PRIV), q(PUB)))
        self.assertEqual(s["endpoint"], "1.2.3.4:51820")
        # no colon at all -> rejected (rpartition yields empty host)
        self.assertIsNone(parsing.parse_wireguard_uri(
            "wireguard://%s@1.2.3.4?publickey=%s" % (q(PRIV), q(PUB))))

    def test_invalid(self):
        for bad in ("", "http://x", "wireguard://no-at-sign",
                    "wireguard://%s@1.2.3.4:51820" % PRIV):  # no publickey
            self.assertIsNone(parsing.parse_wireguard_uri(bad), bad)


class TestCountry(unittest.TestCase):
    def test_ip_literal_guess(self):
        self.assertEqual(parsing._guess_country_from_ip_literal("51.75.1.1"), "DE")
        self.assertEqual(parsing._guess_country_from_ip_literal("147.135.1.1"), "US")
        self.assertEqual(parsing._guess_country_from_ip_literal("8.8.8.8"), "Unknown")

    def test_bundle_keywords(self):
        self.assertEqual(parsing.classify_bundle_country("United States", "1.1.1.1"), "US")
        self.assertEqual(parsing.classify_bundle_country("Germany - Frankfurt", "1.1.1.1"), "DE")
        self.assertEqual(parsing.classify_bundle_country("Deutschland", "1.1.1.1"), "DE")

    def test_bundle_token_match_not_substring(self):
        # historic bug: "abuse" matched "us "
        self.assertEqual(parsing.classify_bundle_country("abuse-mail", "8.8.8.8"), "XX")
        self.assertEqual(parsing.classify_bundle_country("us-east-1", "8.8.8.8"), "US")
        self.assertEqual(parsing.classify_bundle_country("[DE] node", "8.8.8.8"), "DE")

    def test_bundle_ip_ranges(self):
        self.assertEqual(parsing.classify_bundle_country("", "188.114.97.1"), "CF")
        self.assertEqual(parsing.classify_bundle_country("", "162.159.1.1"), "CF")
        self.assertEqual(parsing.classify_bundle_country("", "51.75.1.2"), "DE")
        self.assertEqual(parsing.classify_bundle_country("", "104.244.1.1"), "US")
        self.assertEqual(parsing.classify_bundle_country("", "8.8.8.8"), "XX")


if __name__ == "__main__":
    unittest.main()
