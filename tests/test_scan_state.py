# -*- coding: utf-8 -*-
"""Scan-state persistence tests: stamps, 24h TTL, startup collection."""
import time
import unittest

from vpnbot import gold


def iso_hours_ago(h):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - h * 3600))


class TestStampScan(unittest.TestCase):
    def test_fields(self):
        s = {}
        gold.stamp_scan(s, True, 42.5)
        self.assertTrue(s["last_scan"])
        self.assertIs(s["last_alive"], True)
        self.assertEqual(s["latency"], 42.5)

    def test_none_alive_preserves_previous(self):
        s = {"last_alive": True}
        gold.stamp_scan(s, None, 10)
        self.assertIs(s["last_alive"], True)
        self.assertEqual(s["latency"], 10)

    def test_silent_alive_stored(self):
        s = {}
        gold.stamp_scan(s, None)
        self.assertNotIn("last_alive", s)  # speed-only run never invents status

    def test_bad_ms_ignored(self):
        s = {}
        gold.stamp_scan(s, False, -1)
        self.assertNotIn("latency", s)
        self.assertIs(s["last_alive"], False)


class TestScanFresh(unittest.TestCase):
    def test_ttl(self):
        self.assertTrue(gold.scan_fresh({"last_scan": iso_hours_ago(1)}))
        self.assertTrue(gold.scan_fresh({"last_scan": iso_hours_ago(23.9)}))
        self.assertFalse(gold.scan_fresh({"last_scan": iso_hours_ago(25)}))

    def test_missing_or_bad(self):
        self.assertFalse(gold.scan_fresh({}))
        self.assertFalse(gold.scan_fresh({"last_scan": ""}))
        self.assertFalse(gold.scan_fresh({"last_scan": "garbage"}))


class TestCollect(unittest.TestCase):
    def test_collect_filters_stale_and_invalid(self):
        servers = [
            {"endpoint": "a:1", "last_scan": iso_hours_ago(1), "last_alive": True, "latency": 30},
            {"endpoint": "b:1", "last_scan": iso_hours_ago(2), "last_alive": False},
            {"endpoint": "c:1", "last_scan": iso_hours_ago(30), "last_alive": True, "latency": 5},
            {"endpoint": "", "last_scan": iso_hours_ago(1), "last_alive": True},
            {"endpoint": "d:1", "last_scan": iso_hours_ago(1), "last_alive": None, "latency": -1},
        ]
        status, latency = gold.collect_scan_state(servers)
        self.assertEqual(status, {"a:1": True, "b:1": False, "d:1": None})
        self.assertEqual(latency, {"a:1": 30})

    def test_empty(self):
        self.assertEqual(gold.collect_scan_state([]), ({}, {}))


if __name__ == "__main__":
    unittest.main()
