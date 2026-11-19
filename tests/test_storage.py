# -*- coding: utf-8 -*-
"""Storage tests: atomic writes, dedup, corrupt-DB backup, history bound.

All writes go to a temp dir (storage.SERVERS_FILE / IP_HISTORY patched).
"""
import glob
import json
import os
import tempfile
import unittest
from unittest import mock

from vpnbot import storage


def srv(ep="1.2.3.4:51820", pk="KEY", name="t"):
    return {"name": name, "private_key": pk, "address": "10.0.0.2/32",
            "public_key": "PUB", "endpoint": ep, "dns": "1.1.1.1",
            "mtu": "1380", "country": "DE", "source": "Custom"}


class StorageTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.servers_file = os.path.join(self._tmp.name, "servers.json")
        self.history_file = os.path.join(self._tmp.name, "ip_history.json")
        for attr, val in (("SERVERS_FILE", self.servers_file),
                          ("IP_HISTORY", self.history_file)):
            p = mock.patch.object(storage, attr, val)
            p.start()
            self.addCleanup(p.stop)


class TestServers(StorageTestBase):
    def test_roundtrip(self):
        data = [srv(), srv("5.6.7.8:51820", name="t2")]
        self.assertTrue(storage.save_servers(data))
        loaded = storage.load_servers()
        self.assertEqual([s["endpoint"] for s in loaded],
                         ["1.2.3.4:51820", "5.6.7.8:51820"])
        self.assertTrue(all(s.get("fetched_at") for s in loaded))  # choke-point stamp

    def test_dedup_by_endpoint(self):
        storage.save_servers([srv(), srv(pk="OTHER")])
        self.assertEqual(len(storage.load_servers()), 1)

    def test_invalid_entries_dropped(self):
        bad = [{"endpoint": "1.2.3.4:51820"},          # no private key
               {"private_key": "K"},                   # no endpoint
               "not-a-dict", None,
               {"endpoint": "  ", "private_key": "K"}]
        storage.save_servers(bad + [srv()])
        loaded = storage.load_servers()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["endpoint"], "1.2.3.4:51820")

    def test_dict_wrapper(self):
        with open(self.servers_file, "w", encoding="utf-8") as f:
            json.dump({"servers": [srv()]}, f)
        self.assertEqual(len(storage.load_servers()), 1)

    def test_non_list_json(self):
        with open(self.servers_file, "w", encoding="utf-8") as f:
            json.dump(42, f)
        self.assertEqual(storage.load_servers(), [])

    def test_missing_file(self):
        self.assertEqual(storage.load_servers(), [])

    def test_corrupt_file_backed_up_not_wiped(self):
        with open(self.servers_file, "w", encoding="utf-8") as f:
            f.write("{invalid json")
        self.assertEqual(storage.load_servers(), [])
        backups = glob.glob(self.servers_file + ".corrupt_*")
        self.assertEqual(len(backups), 1)
        with open(backups[0], encoding="utf-8") as f:
            self.assertEqual(f.read(), "{invalid json")

    def test_atomic_no_tmp_left(self):
        storage.save_servers([srv()])
        self.assertFalse(os.path.exists(self.servers_file + ".tmp"))
        self.assertTrue(os.path.exists(self.servers_file))


class TestHistory(StorageTestBase):
    def test_roundtrip(self):
        h = [{"time": "t", "server": "s", "ip": "1.2.3.4"}]
        self.assertTrue(storage.save_history(h))
        self.assertEqual(storage.load_history(), h)

    def test_bounded_to_max(self):
        h = [{"i": i} for i in range(storage._HISTORY_MAX + 100)]
        storage.save_history(h)
        loaded = storage.load_history()
        self.assertEqual(len(loaded), storage._HISTORY_MAX)
        self.assertEqual(loaded[-1]["i"], storage._HISTORY_MAX + 99)  # newest kept

    def test_missing_file(self):
        self.assertEqual(storage.load_history(), [])

    def test_non_list(self):
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump({"x": 1}, f)
        self.assertEqual(storage.load_history(), [])


if __name__ == "__main__":
    unittest.main()
