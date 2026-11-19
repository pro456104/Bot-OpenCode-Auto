# -*- coding: utf-8 -*-
"""UI logic tests without Tk: best-server scoring, row display, protect flags, busy guard.

UI mixin imports are lazy (inside tests) so discovery never loads tkinter
before test_imports' layering check.
"""
import threading
import unittest
from unittest import mock

from vpnbot import gold


def srv(ep, name="n", country="US", **kw):
    d = {"name": name, "endpoint": ep, "country": country, "source": "Custom"}
    d.update(kw)
    return d


class FakeApp:
    def __init__(self, servers):
        self.servers = servers
        self.all_servers = servers
        self.server_status = {}
        self.server_latency = {}
        self.server_checks = {}
        self.failed_servers = set()
        self.active_endpoint = None
        self.log = mock.MagicMock()


class TestBestServer(unittest.TestCase):
    def _best(self, app):
        from vpnbot.ui.connect_ui import ConnectMixin
        return ConnectMixin.get_best_server(app)

    def test_fresh_gold_ranks_first(self):
        a = srv("1.1.1.1:51820", "gold")
        gold.stamp_verified(a, "9.9.9.9")
        b = srv("2.2.2.2:51820", "fast")
        app = FakeApp([b, a])
        app.server_status["2.2.2.2:51820"] = True
        app.server_latency["2.2.2.2:51820"] = 10
        app.server_latency["1.1.1.1:51820"] = 200
        self.assertEqual(self._best(app)["name"], "gold")

    def test_latency_order_within_same_rank(self):
        a, b = srv("1.1.1.1:51820", "slow"), srv("2.2.2.2:51820", "fast")
        app = FakeApp([a, b])
        for s in (a, b):
            app.server_status[s["endpoint"]] = True
        app.server_latency[a["endpoint"]] = 150
        app.server_latency[b["endpoint"]] = 40
        self.assertEqual(self._best(app)["name"], "fast")

    def test_cloudflare_bonus(self):
        cf = srv("188.114.97.1:51820", "cf")
        other = srv("2.2.2.2:51820", "other")
        app = FakeApp([other, cf])
        for s in (cf, other):
            app.server_status[s["endpoint"]] = True
        app.server_latency[cf["endpoint"]] = 80     # 80 - 50 bonus = 30
        app.server_latency[other["endpoint"]] = 50
        self.assertEqual(self._best(app)["name"], "cf")

    def test_failed_excluded(self):
        a, b = srv("1.1.1.1:51820", "failed"), srv("2.2.2.2:51820", "ok")
        app = FakeApp([a, b])
        app.failed_servers.add(a["endpoint"])
        self.assertEqual(self._best(app)["name"], "ok")

    def test_all_failed_falls_back(self):
        a = srv("1.1.1.1:51820", "a")
        app = FakeApp([a])
        app.failed_servers.add(a["endpoint"])
        self.assertIsNotNone(self._best(app))

    def test_empty_returns_none(self):
        self.assertIsNone(self._best(FakeApp([])))


class TestRowDisplay(unittest.TestCase):
    def _call(self, mixin, name, app, *a):
        return getattr(mixin, name)(app, *a)

    def test_ping_text_and_color(self):
        from vpnbot.ui.server_list import ServerListMixin as M
        app = FakeApp([])
        ep = "1.1.1.1:51820"
        app.server_latency[ep] = 45.0
        self.assertEqual(self._call(M, "_ping_text", app, ep), "45ms")
        self.assertEqual(self._call(M, "_ping_color", app, ep), "#3fb950")
        app.server_latency[ep] = 150
        self.assertEqual(self._call(M, "_ping_color", app, ep), "#f0883e")
        app.server_latency[ep] = -1
        app.server_status[ep] = True
        self.assertEqual(self._call(M, "_ping_text", app, ep), "Alive")
        app.server_status[ep] = None
        self.assertEqual(self._call(M, "_ping_text", app, ep), "Silent")
        app.server_status[ep] = False
        self.assertEqual(self._call(M, "_ping_text", app, ep), "Timeout")
        self.assertEqual(self._call(M, "_ping_color", app, ep), "#f85149")
        self.assertEqual(self._call(M, "_ping_text", app, "unknown"), "---")

    def test_row_display_marks(self):
        from vpnbot.ui.server_list import ServerListMixin as M
        app = FakeApp([])
        g = srv("1.1.1.1:51820", "g")
        gold.stamp_verified(g, "9.9.9.9")
        text, fg = self._call(M, "_row_display", app, g)
        self.assertTrue(text.startswith("\u2605 "))
        self.assertEqual(fg, "#ffd866")
        # expired gold -> hollow star
        g["last_verified"] = "2000-01-01T00:00:00"
        text, _ = self._call(M, "_row_display", app, g)
        self.assertTrue(text.startswith("\u2606 "))
        # failed mark
        app.failed_servers.add(g["endpoint"])
        text, fg = self._call(M, "_row_display", app, g)
        self.assertIn("[FAIL]", text)
        self.assertEqual(fg, "#f85149")
        # active mark
        app.failed_servers.clear()
        app.active_endpoint = g["endpoint"]
        text, fg = self._call(M, "_row_display", app, g)
        self.assertIn("[ACTIVE]", text)
        self.assertEqual(fg, "#3fb950")


class TestProtectFlags(unittest.TestCase):
    def _app(self):
        from vpnbot.ui.protect_ui import ProtectMixin

        class ProtectFake(ProtectMixin, FakeApp):
            pass  # mixin methods (_sync_protect_btn/_monitor_loop) must resolve

        a = ProtectFake([])
        a.protect_on = False
        a.monitoring = False
        a.auto_reconnect = False
        a.stop_event = threading.Event()
        a.stop_event.set()
        a.monitor_thread = None
        a.auto_reconnect_thread = None
        a.btn_protect = mock.MagicMock()
        return a

    def test_enable_starts_both_loops(self):
        from vpnbot.ui import protect_ui
        a = self._app()
        with mock.patch.object(protect_ui.threading, "Thread") as T:
            T.return_value.is_alive.return_value = False
            protect_ui.ProtectMixin._protect_enable(a)
        self.assertTrue(a.protect_on)
        self.assertTrue(a.monitoring)
        self.assertTrue(a.auto_reconnect)
        self.assertFalse(a.stop_event.is_set())
        self.assertEqual(T.call_count, 2)  # monitor + auto-reconnect

    def test_disable_sets_stop(self):
        from vpnbot.ui import protect_ui
        a = self._app()
        a.protect_on = a.monitoring = a.auto_reconnect = True
        a.stop_event.clear()
        protect_ui.ProtectMixin._protect_disable(a)
        self.assertFalse(a.protect_on)
        self.assertFalse(a.monitoring)
        self.assertFalse(a.auto_reconnect)
        self.assertTrue(a.stop_event.is_set())


class TestBusyGuard(unittest.TestCase):
    def _app(self, text="Connect"):
        a = FakeApp([])
        a.refreshing = False
        a.rotating = False
        btn = mock.MagicMock()
        btn.cget.return_value = text
        a.step_btns = [btn]
        return a

    def _busy(self, a):
        from vpnbot.ui.connect_ui import ConnectMixin
        return ConnectMixin._busy_vpn(a, "Rotate")

    def test_refresh_blocks(self):
        a = self._app()
        a.refreshing = True
        self.assertTrue(self._busy(a))

    def test_rotate_blocks(self):
        a = self._app()
        a.rotating = True
        self.assertTrue(self._busy(a))

    def test_connecting_blocks(self):
        self.assertTrue(self._busy(self._app("Connecting...")))

    def test_idle_allows(self):
        self.assertFalse(self._busy(self._app("Connect")))


if __name__ == "__main__":
    unittest.main()
