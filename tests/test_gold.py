# -*- coding: utf-8 -*-
"""GOLD policy tests: stamps, 3-day TTL boundary, filter helpers."""
import time
import unittest

from vpnbot import gold


def iso_days_ago(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))


class TestStamps(unittest.TestCase):
    def test_stamp_verified_and_fresh(self):
        s = {}
        gold.stamp_verified(s, "1.2.3.4")
        self.assertTrue(s["verified"])
        self.assertEqual(s["exit_ip"], "1.2.3.4")
        self.assertTrue(s["last_verified"])
        self.assertTrue(gold.gold_fresh(s))

    def test_ttl_expired(self):
        s = {"verified": True, "last_verified": iso_days_ago(4)}
        self.assertFalse(gold.gold_fresh(s))

    def test_ttl_boundary_fresh(self):
        s = {"verified": True, "last_verified": iso_days_ago(2.9)}
        self.assertTrue(gold.gold_fresh(s))

    def test_unverified(self):
        self.assertFalse(gold.gold_fresh({"last_verified": iso_days_ago(0)}))
        self.assertFalse(gold.gold_fresh({}))

    def test_missing_or_bad_date(self):
        self.assertFalse(gold.gold_fresh({"verified": True}))
        self.assertFalse(gold.gold_fresh({"verified": True, "last_verified": ""}))
        self.assertFalse(gold.gold_fresh({"verified": True, "last_verified": "garbage"}))

    def test_stamp_fetched(self):
        s = {}
        gold.stamp_fetched(s, "https://example/a")
        first = s["fetched_at"]
        self.assertTrue(first)
        self.assertEqual(s["source_url"], "https://example/a")
        gold.stamp_fetched(s, "https://example/b")
        self.assertEqual(s["fetched_at"], first)  # setdefault: keeps first fetch date
        self.assertEqual(s["source_url"], "https://example/b")

    def test_stamp_fetched_no_url(self):
        s = {}
        gold.stamp_fetched(s, None)
        self.assertTrue(s["fetched_at"])
        self.assertNotIn("source_url", s)


class TestFilters(unittest.TestCase):
    def test_countries_sorted_unique(self):
        servers = [{"country": "US"}, {"country": "DE"}, {"country": "US"}, {}]
        self.assertEqual(gold.get_countries(servers), ["DE", "US", "Unknown"])

    def test_sources_sorted_unique(self):
        servers = [{"source": "VPNBook"}, {"source": "ProtonVPN"}, {"source": "VPNBook"}]
        self.assertEqual(gold.get_sources(servers), ["ProtonVPN", "VPNBook"])

    def test_policy_constants(self):
        self.assertEqual(gold.GOLD_TTL_DAYS, 3)
        self.assertEqual(gold.REFRESH_GOLD_TARGET, 15)


if __name__ == "__main__":
    unittest.main()
