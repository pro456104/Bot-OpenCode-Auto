# -*- coding: utf-8 -*-
"""Scheduled-rotation timer tests: tick gating, toggle persistence, loop lifecycle.

UI imports are lazy so discovery never loads tkinter before the layering check.
"""
import threading
import time
import unittest
from unittest import mock


def make_app():
    from vpnbot.ui.protect_ui import ProtectMixin

    class TimerFake(ProtectMixin):
        def __init__(self):
            self.connected = True
            self.rotate_every_min = 1
            self.rotate_timer_on = False
            self.rotate_timer_thread = None
            self._timer_stop = threading.Event()
            self._timer_poll = 0.01
            self.rotate_ip = mock.MagicMock()
            self.log = mock.MagicMock()
            self.btn_timer = mock.MagicMock()
            self._busy_vpn = mock.MagicMock(return_value=False)

        def _safe_after(self, ms, fn, *a, **k):
            fn(*a, **k)

    return TimerFake()


class TestTick(unittest.TestCase):
    def test_rotates_when_due(self):
        a = make_app()
        new = a._rotate_timer_tick(time.time() - 61)
        a.rotate_ip.assert_called_once()
        self.assertGreaterEqual(new, time.time() - 1)

    def test_not_due_yet(self):
        a = make_app()
        last = time.time() - 10
        self.assertEqual(a._rotate_timer_tick(last), last)
        a.rotate_ip.assert_not_called()

    def test_disconnected_never_rotates(self):
        a = make_app()
        a.connected = False
        new = a._rotate_timer_tick(time.time() - 9999)
        a.rotate_ip.assert_not_called()
        self.assertGreaterEqual(new, time.time() - 1)  # interval restarts on reconnect

    def test_busy_yields(self):
        a = make_app()
        a._busy_vpn.return_value = True
        last = time.time() - 9999
        self.assertEqual(a._rotate_timer_tick(last), last)
        a.rotate_ip.assert_not_called()


class TestToggle(unittest.TestCase):
    def test_on_persists_interval(self):
        from vpnbot.ui import protect_ui
        a = make_app()
        with mock.patch.object(protect_ui.simpledialog, "askinteger", return_value=7), \
             mock.patch.object(protect_ui, "load_settings", return_value={}), \
             mock.patch.object(protect_ui, "save_settings") as save, \
             mock.patch.object(protect_ui.threading, "Thread") as T:
            T.return_value.is_alive.return_value = False
            a.toggle_rotate_timer()
        self.assertTrue(a.rotate_timer_on)
        self.assertEqual(a.rotate_every_min, 7)
        save.assert_called_once_with({"rotate_every_min": 7})
        a.btn_timer.config.assert_called()

    def test_off_persists_zero(self):
        from vpnbot.ui import protect_ui
        a = make_app()
        a.rotate_timer_on = True
        with mock.patch.object(protect_ui, "load_settings", return_value={"rotate_every_min": 7}), \
             mock.patch.object(protect_ui, "save_settings") as save:
            a.toggle_rotate_timer()
        self.assertFalse(a.rotate_timer_on)
        self.assertTrue(a._timer_stop.is_set())
        save.assert_called_once_with({"rotate_every_min": 0})

    def test_cancel_dialog_no_change(self):
        from vpnbot.ui import protect_ui
        a = make_app()
        with mock.patch.object(protect_ui.simpledialog, "askinteger", return_value=None):
            a.toggle_rotate_timer()
        self.assertFalse(a.rotate_timer_on)


class TestLoopLifecycle(unittest.TestCase):
    def test_real_thread_starts_and_stops(self):
        from vpnbot.ui import protect_ui
        a = make_app()
        a.connected = False  # tick is a no-op; we only test lifecycle
        with mock.patch.object(protect_ui, "load_settings", return_value={}), \
             mock.patch.object(protect_ui, "save_settings"):
            a._start_rotate_timer()
            self.assertTrue(a.rotate_timer_thread.is_alive())
            time.sleep(0.05)
            a._stop_rotate_timer()
            a.rotate_timer_thread.join(timeout=1)
        self.assertFalse(a.rotate_timer_thread.is_alive())
        a.rotate_ip.assert_not_called()


if __name__ == "__main__":
    unittest.main()
