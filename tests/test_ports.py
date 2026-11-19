# -*- coding: utf-8 -*-
"""Proxy port handling: dynamic ports, conflict relocation, launch env.

Regression context: wireproxy exits instantly with "bind: Only one usage of
each socket address" when 8080 is owned by another program; the app used to
report a silent connection failure. Ports must relocate and reach OpenCode.
"""
import os
import socket
import unittest
from unittest import mock

from vpnbot import net, paths, tunnel

SERVER = {"name": "t", "private_key": "PRIV", "address": "10.0.0.2/32",
          "public_key": "PUB", "endpoint": "1.2.3.4:51820",
          "dns": "1.1.1.1", "mtu": ""}


class PortPatchMixin:
    def setUp(self):
        self._saved = (paths.PROXY_HTTP_PORT, paths.PROXY_SOCKS_PORT)
        self.addCleanup(paths.set_proxy_ports, *self._saved)
        paths.set_proxy_ports(8080, 10808)


class TestPortFree(unittest.TestCase):
    def test_busy_and_free(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        try:
            self.assertFalse(tunnel.port_free(port))
        finally:
            s.close()
        self.assertTrue(tunnel.port_free(port))


class TestEnsurePorts(PortPatchMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        p = mock.patch.object(paths, "SETTINGS_FILE",
                              os.path.join(self._tmp.name, "settings.json"))
        p.start()
        self.addCleanup(p.stop)

    def test_free_ports_unchanged(self):
        with mock.patch.object(tunnel, "wp_running", return_value=False), \
             mock.patch.object(tunnel, "port_free", return_value=True), \
             mock.patch.object(paths, "save_settings") as save:
            http, socks, changed = tunnel.ensure_proxy_ports()
        self.assertEqual((http, socks), (8080, 10808))
        self.assertFalse(changed)
        save.assert_not_called()

    def test_http_busy_relocates_and_persists(self):
        def free(port):
            return port not in (8080, 8081)

        with mock.patch.object(tunnel, "wp_running", return_value=False), \
             mock.patch.object(tunnel, "port_free", side_effect=free):
            http, socks, changed = tunnel.ensure_proxy_ports()
        self.assertTrue(changed)
        self.assertEqual(http, 8082)
        self.assertEqual(socks, 10808)          # SOCKS stayed free
        self.assertEqual((paths.PROXY_HTTP_PORT, paths.PROXY_SOCKS_PORT), (8082, 10808))
        saved = paths.load_settings()
        self.assertEqual(saved["proxy_http_port"], 8082)
        self.assertEqual(saved["proxy_socks_port"], 10808)

    def test_both_busy_distinct_ports(self):
        busy = {8080, 10808}
        with mock.patch.object(tunnel, "wp_running", return_value=False), \
             mock.patch.object(tunnel, "port_free",
                               side_effect=lambda p: p not in busy):
            http, socks, changed = tunnel.ensure_proxy_ports()
        self.assertTrue(changed)
        self.assertNotEqual(http, socks)
        self.assertNotIn(http, busy)
        self.assertNotIn(socks, busy)

    def test_active_session_untouched(self):
        with mock.patch.object(tunnel, "wp_running", return_value=True), \
             mock.patch.object(tunnel, "port_free", return_value=False):
            http, socks, changed = tunnel.ensure_proxy_ports()
        self.assertEqual((http, socks), (8080, 10808))
        self.assertFalse(changed)


class TestConfUsesPorts(PortPatchMixin, unittest.TestCase):
    def test_dynamic_bind_addresses(self):
        paths.set_proxy_ports(18080, 11080)
        text = tunnel.make_conf(SERVER)
        self.assertIn("BindAddress = 127.0.0.1:18080", text)
        self.assertIn("BindAddress = 127.0.0.1:11080", text)
        self.assertNotIn("127.0.0.1:8080", text)
        self.assertNotIn("127.0.0.1:10808", text)


class TestNetUsesPorts(PortPatchMixin, unittest.TestCase):
    def test_proxy_ready_uses_configured_port(self):
        paths.set_proxy_ports(18081, 11081)
        s = mock.MagicMock()
        s.connect_ex.return_value = 0
        with mock.patch.object(net.socket, "socket", return_value=s):
            self.assertTrue(net.proxy_ready())
        self.assertEqual(s.connect_ex.call_args.args[0], ("127.0.0.1", 18081))

    def test_ip_fetch_proxy_url_uses_configured_port(self):
        paths.set_proxy_ports(18082, 11082)
        opener = mock.MagicMock()
        resp = mock.MagicMock()
        resp.read.return_value = b"9.9.9.9"
        resp.__enter__.return_value = resp
        opener.open.return_value = resp
        with mock.patch.object(net.urllib.request, "build_opener",
                               return_value=opener) as bo:
            self.assertEqual(net._fetch_ip_via_proxy("https://x", timeout=1), "9.9.9.9")
        handler = bo.call_args.args[0]
        self.assertEqual(handler.proxies["http"], "http://127.0.0.1:18082")
        self.assertEqual(handler.proxies["https"], "http://127.0.0.1:18082")


class TestLaunchEnvUsesPorts(PortPatchMixin, unittest.TestCase):
    def _fake_app(self):
        from vpnbot.ui.connect_ui import ConnectMixin

        class Fake(ConnectMixin):
            pass

        a = Fake()
        a.log = mock.MagicMock()
        a.update = mock.MagicMock()
        a.done = mock.MagicMock()
        a.step_status = [mock.MagicMock(), mock.MagicMock()]
        return a

    def test_env_carries_relocated_ports(self):
        from vpnbot.ui import connect_ui
        paths.set_proxy_ports(18083, 11083)
        app = self._fake_app()
        with mock.patch.object(connect_ui.os.path, "exists", return_value=True), \
             mock.patch.object(connect_ui, "any_kernel_up", return_value=False), \
             mock.patch.object(connect_ui.subprocess, "Popen") as popen:
            connect_ui.ConnectMixin.step2_launch(app)
        env = popen.call_args.kwargs["env"]
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:18083")
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:18083")
        self.assertEqual(env["ALL_PROXY"], "socks5h://127.0.0.1:11083")
        self.assertEqual(env["all_proxy"], "socks5h://127.0.0.1:11083")


if __name__ == "__main__":
    unittest.main()
