# -*- coding: utf-8 -*-
"""sources.py tests: Proton ZIP parsing, bundle mirror fallback, VPNBook keygen."""
import base64
import io
import unittest
import zipfile
from unittest import mock

from vpnbot import sources

CONF = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.2.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = zcfEQgUoPLK2kvDicsA/4B9F2AI7qfxX5ueDo/Zcjj4=
Endpoint = {ep}:51820
AllowedIPs = 0.0.0.0/0
"""


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


class TestProtonCountry(unittest.TestCase):
    def test_folder(self):
        self.assertEqual(sources._proton_country("us/wg-US-FREE-1.conf"), "US")
        self.assertEqual(sources._proton_country("nl/x.conf"), "NL")

    def test_prefix(self):
        self.assertEqual(sources._proton_country("de-01.conf"), "DE")
        # quirk kept verbatim: bare "wg-XX-..." files classify by first 2 letters;
        # real Proton ZIPs use country folders, which take priority (see below)
        self.assertEqual(sources._proton_country("wg-jp-2.conf"), "WG")
        self.assertEqual(sources._proton_country("jp_3.conf"), "JP")

    def test_unknown(self):
        self.assertEqual(sources._proton_country("random.conf"), "XX")
        self.assertEqual(sources._proton_country(""), "XX")


class TestProtonZip(unittest.TestCase):
    def test_all_countries_stamped_and_named(self):
        z = make_zip([
            ("us/wg-US-FREE-1.conf", CONF.format(ep="1.1.1.1")),
            ("de/wg-DE-FREE-2.conf", CONF.format(ep="2.2.2.2")),
            ("jp/wg-JP-FREE-3.conf", CONF.format(ep="3.3.3.3")),
            ("bad.conf", "[Interface]\nAddress = 10.0.0.2/32\n"),  # unparsable -> skipped
        ])
        out = list(sources.iter_proton_servers(z))
        self.assertEqual(len(out), 3)
        self.assertEqual({s["country"] for s in out}, {"US", "DE", "JP"})
        for s in out:
            self.assertEqual(s["source"], "ProtonVPN")
            self.assertTrue(s["name"].startswith("wg-"))
            self.assertTrue(s["fetched_at"])
            self.assertEqual(s["source_url"], sources.PROTONVPN_ZIP_URL)

    def test_limit(self):
        z = make_zip([("us/a.conf", CONF.format(ep="1.1.1.1")),
                      ("de/b.conf", CONF.format(ep="2.2.2.2"))])
        self.assertEqual(len(list(sources.iter_proton_servers(z, limit=1))), 1)

    def test_corrupt_zip_yields_nothing(self):
        self.assertEqual(list(sources.iter_proton_servers(b"not a zip")), [])


class TestBundleMirrors(unittest.TestCase):
    def test_fallback_to_second_mirror(self):
        resp = mock.MagicMock()
        resp.read.return_value = "wireguard://x".encode()
        resp.__enter__.return_value = resp
        with mock.patch.object(sources.urllib.request, "urlopen",
                               side_effect=[Exception("primary down"), resp]) as u:
            text, used = sources.fetch_bundle_text(timeout=1)
        self.assertEqual(text, "wireguard://x")
        self.assertEqual(used, sources.WIREGUARD_BUNDLE_URLS[1])
        self.assertEqual(u.call_count, 2)

    def test_all_mirrors_fail(self):
        with mock.patch.object(sources.urllib.request, "urlopen",
                               side_effect=Exception("down")):
            text, err = sources.fetch_bundle_text(timeout=1)
        self.assertIsNone(text)
        self.assertIsNotNone(err)


class TestVpnBook(unittest.TestCase):
    def test_known_pubkey(self):
        with mock.patch.object(sources.subprocess, "run", side_effect=Exception("no wg")):
            key = sources.get_vpnbook_pubkey("us16.vpnbook.com")
        self.assertTrue(key)
        self.assertEqual(len(base64.b64decode(key)), 32)

    def test_unknown_host(self):
        with mock.patch.object(sources.subprocess, "run", side_effect=Exception("no wg")):
            self.assertIsNone(sources.get_vpnbook_pubkey("nope.example"))

    def test_keygen_fallback_is_32_bytes(self):
        with mock.patch.object(sources.subprocess, "run", side_effect=Exception("no wg")):
            key = sources.generate_wg_key()
        self.assertEqual(len(base64.b64decode(key)), 32)

    def test_keygen_uses_wg_when_available(self):
        r = mock.MagicMock(returncode=0, stdout="WGKEY\n")
        with mock.patch.object(sources.subprocess, "run", return_value=r):
            self.assertEqual(sources.generate_wg_key(), "WGKEY")


if __name__ == "__main__":
    unittest.main()
