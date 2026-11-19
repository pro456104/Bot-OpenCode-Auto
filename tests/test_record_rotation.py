# -*- coding: utf-8 -*-
"""_record_rotation() tests: unified counters/history/active-endpoint bookkeeping.

UI import is lazy (inside tests) so test discovery never loads tkinter before
test_imports' layering check runs.
"""
import unittest
from unittest import mock


class FakeApp:
    def __init__(self):
        self.rotation_count = 0
        self.total_rotations_today = 0
        self.ip_history = []
        self.active_endpoint = None


class TestRecordRotation(unittest.TestCase):
    def _call(self, app, server, ip, kernel=False):
        from vpnbot.ui.main_window import App
        with mock.patch("vpnbot.ui.main_window.save_history") as sh:
            App._record_rotation(app, server, ip, kernel=kernel)
        return sh

    def test_proxy_rotation(self):
        app = FakeApp()
        sh = self._call(app, {"name": "s1", "endpoint": "e1"}, "1.2.3.4")
        self.assertEqual(app.rotation_count, 1)
        self.assertEqual(app.total_rotations_today, 1)
        self.assertEqual(app.active_endpoint, "e1")
        self.assertEqual(len(app.ip_history), 1)
        e = app.ip_history[0]
        self.assertEqual(e["server"], "s1")
        self.assertEqual(e["ip"], "1.2.3.4")
        self.assertTrue(e["time"])
        sh.assert_called_once_with(app.ip_history)

    def test_kernel_suffix(self):
        app = FakeApp()
        self._call(app, {"name": "s1", "endpoint": "e1"}, "1.2.3.4", kernel=True)
        self.assertEqual(app.ip_history[0]["server"], "s1 [kernel]")

    def test_accumulates(self):
        app = FakeApp()
        self._call(app, {"name": "s1", "endpoint": "e1"}, "1.1.1.1")
        self._call(app, {"name": "s2", "endpoint": "e2"}, "2.2.2.2")
        self.assertEqual(app.rotation_count, 2)
        self.assertEqual(app.total_rotations_today, 2)
        self.assertEqual(len(app.ip_history), 2)
        self.assertEqual(app.active_endpoint, "e2")


if __name__ == "__main__":
    unittest.main()
