# -*- coding: utf-8 -*-
"""tunnel.py tests: conf generation, DNS cleaning, process-state cache, fast kill."""
import os
import tempfile
import unittest
from unittest import mock

from vpnbot import tunnel

SERVER = {"name": "t", "private_key": "PRIV", "address": "10.0.0.2/32",
          "public_key": "PUB", "endpoint": "1.2.3.4:51820",
          "dns": "1.1.1.1", "mtu": ""}


class TestMakeConf(unittest.TestCase):
    def test_sections_and_keepalive(self):
        text = tunnel.make_conf(SERVER)
        for part in ("[Interface]", "[Peer]", "[Socks5]", "[HTTP]",
                     "PrivateKey = PRIV", "Endpoint = 1.2.3.4:51820",
                     "PersistentKeepalive = 15",
                     "BindAddress = 127.0.0.1:10808", "BindAddress = 127.0.0.1:8080"):
            self.assertIn(part, text)

    def test_mtu_cloudflare_1280(self):
        s = dict(SERVER, endpoint="162.159.1.1:51820")
        self.assertIn("MTU = 1280", tunnel.make_conf(s))

    def test_mtu_legacy_1420_autotuned(self):
        s = dict(SERVER, mtu="1420")
        self.assertIn("MTU = 1380", tunnel.make_conf(s))

    def test_mtu_custom_kept(self):
        s = dict(SERVER, mtu="1400")
        self.assertIn("MTU = 1400", tunnel.make_conf(s))


class TestCleanDns(unittest.TestCase):
    def test_drops_ipv6_and_private(self):
        self.assertEqual(tunnel._clean_dns("10.2.0.1, 2a07:b944::2:1, 1.1.1.1"), "1.1.1.1")

    def test_drops_lan_ranges(self):
        self.assertEqual(tunnel._clean_dns("192.168.1.1, 172.16.0.1, 172.31.9.9, 8.8.8.8"), "8.8.8.8")

    def test_keeps_public_multiple(self):
        self.assertEqual(tunnel._clean_dns("1.1.1.1; 8.8.8.8"), "1.1.1.1, 8.8.8.8")

    def test_fallback(self):
        self.assertEqual(tunnel._clean_dns(""), "1.1.1.1")
        self.assertEqual(tunnel._clean_dns("10.0.0.1"), "1.1.1.1")
        self.assertEqual(tunnel._clean_dns(None), "1.1.1.1")


class TestProcessState(unittest.TestCase):
    def setUp(self):
        self._old = (tunnel._WP_PROC, dict(tunnel._WP_CACHE))
        tunnel._WP_PROC = None
        tunnel._WP_CACHE = {"running": False, "ts": 0.0}

    def tearDown(self):
        tunnel._WP_PROC, cache = self._old
        tunnel._WP_CACHE = cache

    def test_wp_running_cached(self):
        r = mock.MagicMock(stdout="wireproxy.exe  1234  Console")
        with mock.patch.object(tunnel.subprocess, "run", return_value=r) as run:
            self.assertTrue(tunnel.wp_running())
            self.assertTrue(tunnel.wp_running())          # within 1s TTL
            self.assertEqual(run.call_count, 1)
            self.assertTrue(tunnel.wp_running(use_cache=False))
            self.assertEqual(run.call_count, 2)

    def test_wp_running_false(self):
        r = mock.MagicMock(stdout="INFO: No tasks are running which match the specified criteria.")
        with mock.patch.object(tunnel.subprocess, "run", return_value=r):
            self.assertFalse(tunnel.wp_running())

    def test_kill_wp_fast_path_no_taskkill(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        conf = os.path.join(tmp.name, "wireproxy.conf")
        open(conf, "w").close()
        r = mock.MagicMock(stdout="INFO: No tasks are running.")
        with mock.patch.object(tunnel, "WG_CONF", conf), \
             mock.patch.object(tunnel.subprocess, "run", return_value=r) as run:
            tunnel.kill_wp()
        # only tasklist spawned; no blind taskkill when nothing runs
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0], "tasklist")
        self.assertFalse(os.path.exists(conf))  # stale conf removed


if __name__ == "__main__":
    unittest.main()
