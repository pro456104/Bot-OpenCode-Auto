# -*- coding: utf-8 -*-
"""dial() tests: unified write-conf/spawn/wait core (mocked, no real processes)."""
import os
import tempfile
import unittest
from unittest import mock

from vpnbot import paths, tunnel

SERVER = {"name": "t", "private_key": "PRIV", "address": "10.0.0.2/32",
          "public_key": "PUB", "endpoint": "1.2.3.4:51820",
          "dns": "1.1.1.1", "mtu": "1380", "country": "DE", "source": "Custom"}


class TestDial(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.conf = os.path.join(self._tmp.name, "wireproxy.conf")
        self.exe = os.path.join(self._tmp.name, "wireproxy.exe")
        with open(self.exe, "wb") as f:
            f.write(b"MZ")  # fake exe so os.path.isfile passes
        for target, attr, val in ((tunnel, "WG_CONF", self.conf),
                                  (paths, "WG_PROXY", self.exe)):
            p = mock.patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)
        # dial() probes for foreign listeners before spawning; keep tests
        # hermetic (no tasklist/port relocation side effects).
        p = mock.patch.object(tunnel, "proxy_ready", return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def test_success_writes_conf_and_returns_ip(self):
        with mock.patch.object(tunnel, "_spawn_wp", return_value=object()) as sp, \
             mock.patch.object(tunnel, "wait_for_vpn_ready", return_value="9.9.9.9") as w:
            ip = tunnel.dial(SERVER, timeout=5)
        self.assertEqual(ip, "9.9.9.9")
        sp.assert_called_once_with(self.conf)
        w.assert_called_once_with(timeout_total=5)
        with open(self.conf, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("PrivateKey = PRIV", text)
        self.assertIn("Endpoint = 1.2.3.4:51820", text)
        self.assertIn("BindAddress = 127.0.0.1:8080", text)

    def test_missing_exe_raises(self):
        os.remove(self.exe)
        with mock.patch.object(tunnel, "_spawn_wp", return_value=None), \
             mock.patch.object(tunnel, "wait_for_vpn_ready") as w:
            with self.assertRaises(tunnel.WireproxyMissing):
                tunnel.dial(SERVER)
            w.assert_not_called()
        self.assertTrue(os.path.exists(self.conf))  # conf written before spawn

    def test_spawn_fails_but_exe_present_still_waits(self):
        with mock.patch.object(tunnel, "_spawn_wp", return_value=None), \
             mock.patch.object(tunnel, "wait_for_vpn_ready", return_value=None) as w:
            self.assertIsNone(tunnel.dial(SERVER, timeout=3))
            w.assert_called_once_with(timeout_total=3)

    def test_no_ip_returns_none(self):
        with mock.patch.object(tunnel, "_spawn_wp", return_value=object()), \
             mock.patch.object(tunnel, "wait_for_vpn_ready", return_value=None):
            self.assertIsNone(tunnel.dial(SERVER))

    def test_conf_write_error_propagates(self):
        with mock.patch.object(tunnel, "WG_CONF",
                               os.path.join(self._tmp.name, "no_dir", "x.conf")):
            with self.assertRaises(OSError):
                tunnel.dial(SERVER)

    def test_conf_rewritten_each_call(self):
        # kill_wp deletes the conf; dial must recreate it on every attempt
        with mock.patch.object(tunnel, "_spawn_wp", return_value=object()), \
             mock.patch.object(tunnel, "wait_for_vpn_ready", return_value=None):
            tunnel.dial(SERVER)
            os.remove(self.conf)
            tunnel.dial(SERVER)
            self.assertTrue(os.path.exists(self.conf))


if __name__ == "__main__":
    unittest.main()
