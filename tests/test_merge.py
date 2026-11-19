# -*- coding: utf-8 -*-
"""merge_servers() tests: replace-by-source, dedup, sort, rename numbering."""
import unittest

from vpnbot.storage import merge_servers


def srv(ep, source="Custom", country="US", name="n"):
    return {"name": name, "private_key": "K", "endpoint": ep,
            "source": source, "country": country}


class TestMerge(unittest.TestCase):
    def test_replace_only_target_source(self):
        cur = [srv("1.1.1.1:51820", "URL"), srv("2.2.2.2:51820", "Imported"),
               srv("3.3.3.3:51820", "URL")]
        new = [srv("4.4.4.4:51820", "URL")]
        merged, removed, added, skipped = merge_servers(cur, new, replace_sources=("URL",))
        self.assertEqual(removed, 2)
        self.assertEqual(added, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual([s["endpoint"] for s in merged],
                         ["2.2.2.2:51820", "4.4.4.4:51820"])

    def test_dedup_against_kept(self):
        cur = [srv("1.1.1.1:51820", "Imported")]
        new = [srv("1.1.1.1:51820", "URL"), srv("2.2.2.2:51820", "URL")]
        merged, removed, added, skipped = merge_servers(cur, new, replace_sources=("URL",))
        self.assertEqual((removed, added, skipped), (0, 1, 1))
        self.assertEqual(len(merged), 2)

    def test_dedup_within_new(self):
        new = [srv("1.1.1.1:51820"), srv("1.1.1.1:51820"), srv("2.2.2.2:51820")]
        merged, removed, added, skipped = merge_servers([], new)
        self.assertEqual((removed, added, skipped), (0, 2, 1))

    def test_empty_endpoint_skipped(self):
        merged, _, added, skipped = merge_servers([], [srv(""), srv("1.1.1.1:51820")])
        self.assertEqual((added, skipped), (1, 1))

    def test_current_not_mutated(self):
        cur = [srv("1.1.1.1:51820", "URL")]
        snapshot = list(cur)
        merge_servers(cur, [srv("2.2.2.2:51820", "URL")], replace_sources=("URL",))
        self.assertEqual(cur, snapshot)

    def test_sort_new_by_country_then_endpoint(self):
        new = [srv("9.9.9.9:51820", country="US"), srv("1.1.1.1:51820", country="DE"),
               srv("2.2.2.2:51820", country="DE")]
        merged, _, _, _ = merge_servers([], new, sort_new=True)
        self.assertEqual([s["endpoint"] for s in merged],
                         ["1.1.1.1:51820", "2.2.2.2:51820", "9.9.9.9:51820"])

    def test_rename_by_index_leaves_gaps(self):
        # Bundle/Proton style: index = position in sorted new list (skipped -> gap)
        cur = [srv("1.1.1.1:51820", "Imported")]
        new = [srv("1.1.1.1:51820", "ProtonVPN"), srv("2.2.2.2:51820", "ProtonVPN"),
               srv("3.3.3.3:51820", "ProtonVPN")]
        merged, _, added, skipped = merge_servers(
            cur, new, replace_sources=("ProtonVPN",), sort_new=True,
            rename=lambda s, i, n: f"{i:03d} | {s.get('name')}")
        self.assertEqual((added, skipped), (2, 1))
        self.assertEqual([s["name"] for s in merged[1:]], ["002 | n", "003 | n"])

    def test_rename_by_added_count_no_gaps(self):
        # Fetch ALL style: number = running added count
        cur = [srv("1.1.1.1:51820", "Imported")]
        new = [srv("1.1.1.1:51820", "VPNBook"), srv("2.2.2.2:51820", "VPNBook"),
               srv("3.3.3.3:51820", "VPNBook")]
        merged, _, added, skipped = merge_servers(
            cur, new, replace_sources=("VPNBook",), sort_new=True,
            rename=lambda s, i, n: f"{n:03d} | wg-{s.get('country', 'XX')}-ALL")
        self.assertEqual((added, skipped), (2, 1))
        self.assertEqual([s["name"] for s in merged[1:]],
                         ["001 | wg-US-ALL", "002 | wg-US-ALL"])

    def test_empty_new_keeps_all(self):
        cur = [srv("1.1.1.1:51820", "URL")]
        merged, removed, added, skipped = merge_servers(cur, [], replace_sources=("URL",))
        self.assertEqual((removed, added, skipped), (1, 0, 0))
        self.assertEqual(merged, [])

    def test_no_replace_is_pure_append(self):
        cur = [srv("1.1.1.1:51820")]
        merged, removed, added, skipped = merge_servers(cur, [srv("2.2.2.2:51820")])
        self.assertEqual((removed, added, skipped), (0, 1, 0))
        self.assertEqual(len(merged), 2)


if __name__ == "__main__":
    unittest.main()
