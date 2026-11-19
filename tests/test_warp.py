# -*- coding: utf-8 -*-
"""warp.py tests: X25519, keypair, registration (mocked), endpoint quirks."""
import base64
import unittest
from unittest import mock

from vpnbot import warp

ACC = {
    "id": "test-device-id",
    "config": {
        "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700::1"}},
        "peers": [{"public_key": "PEERPUBKEY=",
                   "endpoint": {"host": "engage.cloudflareclient.com:0",
                                "v4": "162.159.192.5:0"}}],
    },
}


class TestX25519(unittest.TestCase):
    def test_rfc7748_vector(self):
        s = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(warp.x25519(s, u).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_keypair_consistency_and_clamp(self):
        priv, pub = warp.generate_keypair()
        raw = base64.b64decode(priv)
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[0] & 7, 0)          # clamped low bits
        self.assertEqual(raw[31] & 128, 0)       # clamped high bit
        self.assertEqual(raw[31] & 64, 64)       # fixed bit
        self.assertEqual(pub, base64.b64encode(warp.x25519(raw)).decode())

    def test_keypairs_unique(self):
        a, _ = warp.generate_keypair()
        b, _ = warp.generate_keypair()
        self.assertNotEqual(a, b)


class TestRegister(unittest.TestCase):
    def _resp(self, payload):
        r = mock.MagicMock()
        r.read.return_value = payload.encode()
        r.__enter__.return_value = r
        return r

    def test_success_first_api(self):
        import json
        with mock.patch.object(warp.urllib.request, "urlopen",
                               return_value=self._resp(json.dumps(ACC))) as u:
            acc = warp.register("PUB", timeout=1)
        self.assertEqual(acc["id"], "test-device-id")
        self.assertEqual(u.call_count, 1)
        req = u.call_args.args[0]  # urlopen receives the Request object
        body = json.loads(req.data.decode())
        self.assertEqual(body["key"], "PUB")
        self.assertIn("tos", body)

    def test_fallback_second_api(self):
        import json
        with mock.patch.object(warp.urllib.request, "urlopen",
                               side_effect=[Exception("v1 down"),
                                            self._resp(json.dumps(ACC))]) as u:
            acc = warp.register("PUB", timeout=1)
        self.assertEqual(acc["id"], "test-device-id")
        self.assertEqual(u.call_count, 2)

    def test_all_fail_raises(self):
        with mock.patch.object(warp.urllib.request, "urlopen",
                               side_effect=Exception("down")):
            with self.assertRaises(RuntimeError):
                warp.register("PUB", timeout=1)


class TestEndpoints(unittest.TestCase):
    def test_port_zero_quirk_skipped(self):
        cands = warp.endpoint_candidates(ACC)
        self.assertNotIn("engage.cloudflareclient.com:0", cands)
        self.assertNotIn("162.159.192.5:0", cands)
        self.assertIn(warp.WARP_HOST, cands)

    def test_valid_host_kept_first(self):
        acc = {"config": {"peers": [{"endpoint": {
            "host": "engage.cloudflareclient.com:2408", "v4": "162.159.192.1:2408"}}]}}
        cands = warp.endpoint_candidates(acc)
        self.assertEqual(cands[0], "engage.cloudflareclient.com:2408")

    def test_pick_unique(self):
        e1 = warp.pick_warp_endpoint([])
        e2 = warp.pick_warp_endpoint([e1])
        self.assertNotEqual(e1, e2)
        self.assertIn(e1, warp.WARP_ENDPOINT_POOL)

    def test_pick_exhausted_falls_back(self):
        self.assertEqual(warp.pick_warp_endpoint(warp.WARP_ENDPOINT_POOL), warp.WARP_HOST)


class TestBuildServer(unittest.TestCase):
    def test_schema_and_extras(self):
        s = warp.build_server(ACC, "PRIV", "162.159.192.1:2408", index=2)
        for key in ("name", "private_key", "address", "public_key", "endpoint",
                    "dns", "mtu", "country", "source", "fetched_at"):
            self.assertIn(key, s)
        self.assertEqual(s["name"], "WARP-03")
        self.assertEqual(s["address"], "172.16.0.2/32")
        self.assertEqual(s["public_key"], "PEERPUBKEY=")
        self.assertEqual(s["mtu"], "1280")
        self.assertEqual(s["country"], "CF")
        self.assertEqual(s["source"], "WARP-Auto")
        self.assertEqual(s["warp_id"], "test-device-id")
        self.assertIn(warp.WARP_HOST, s["warp_fallbacks"])

    def test_no_peer_key_raises(self):
        with self.assertRaises(ValueError):
            warp.build_server({"config": {"peers": [{}]}}, "PRIV", "e:1")

    def test_top_level_key_fallback(self):
        s = warp.build_server({"key": "TOPKEY", "config": {}}, "PRIV", "e:1")
        self.assertEqual(s["public_key"], "TOPKEY")


class TestFetchWarpServers(unittest.TestCase):
    def test_count_unique_endpoints_and_numbering(self):
        with mock.patch.object(warp, "register", return_value=ACC) as reg:
            out = warp.fetch_warp_servers(count=3, existing_endpoints=["162.159.192.1:2408"],
                                          start_index=5)
        self.assertEqual(reg.call_count, 3)
        self.assertEqual(len(out), 3)
        eps = [s["endpoint"] for s in out]
        self.assertEqual(len(set(eps)), 3)
        self.assertNotIn("162.159.192.1:2408", eps)
        self.assertEqual([s["name"] for s in out], ["WARP-06", "WARP-07", "WARP-08"])
        keys = [s["private_key"] for s in out]
        self.assertEqual(len(set(keys)), 3)

    def test_registration_failure_propagates(self):
        with mock.patch.object(warp, "register", side_effect=RuntimeError("api down")):
            with self.assertRaises(RuntimeError):
                warp.fetch_warp_servers(count=1)


if __name__ == "__main__":
    unittest.main()
