# -*- coding: utf-8 -*-
"""paths.py tests: settings roundtrip, resolution order (manual/bundled/PATH/legacy)."""
import os
import tempfile
import unittest
from unittest import mock

from vpnbot import paths


class TestSettings(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.file = os.path.join(self._tmp.name, "settings.json")
        p = mock.patch.object(paths, "SETTINGS_FILE", self.file)
        p.start()
        self.addCleanup(p.stop)

    def test_roundtrip(self):
        self.assertTrue(paths.save_settings({"wireproxy_path": "X"}))
        self.assertEqual(paths.load_settings(), {"wireproxy_path": "X"})

    def test_missing_file(self):
        self.assertEqual(paths.load_settings(), {})

    def test_corrupt_file(self):
        with open(self.file, "w", encoding="utf-8") as f:
            f.write("{bad")
        self.assertEqual(paths.load_settings(), {})

    def test_non_dict(self):
        with open(self.file, "w", encoding="utf-8") as f:
            f.write("[1,2]")
        self.assertEqual(paths.load_settings(), {})


class TestResolveWireproxy(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.settings = os.path.join(self._tmp.name, "settings.json")
        self.empty_bin = os.path.join(self._tmp.name, "bin")
        os.makedirs(self.empty_bin)
        for attr, val in (("SETTINGS_FILE", self.settings), ("BIN_DIR", self.empty_bin),
                          ("LEGACY_WIREPROXY", os.path.join(self._tmp.name, "no_legacy.exe"))):
            p = mock.patch.object(paths, attr, val)
            p.start()
            self.addCleanup(p.stop)

    def test_manual_wins(self):
        manual = os.path.join(self._tmp.name, "manual.exe")
        open(manual, "wb").close()
        paths.save_settings({"wireproxy_path": manual})
        found, searched = paths.resolve_wireproxy()
        self.assertEqual(found, manual)
        self.assertEqual(searched[0], manual)

    def test_bundled_second(self):
        bundled = os.path.join(self.empty_bin, "wireproxy.exe")
        open(bundled, "wb").close()
        found, _ = paths.resolve_wireproxy()
        self.assertEqual(found, bundled)

    def test_path_third(self):
        with mock.patch.object(paths.shutil, "which", return_value=r"C:\tools\wireproxy.exe"):
            found, _ = paths.resolve_wireproxy()
        self.assertEqual(found, r"C:\tools\wireproxy.exe")

    def test_none_when_all_missing(self):
        with mock.patch.object(paths.shutil, "which", return_value=None):
            found, searched = paths.resolve_wireproxy()
        self.assertIsNone(found)
        self.assertEqual(len(searched), 2)  # bin + legacy (PATH None is not appended)


class TestResolveOpencode(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.settings = os.path.join(self._tmp.name, "settings.json")
        p = mock.patch.object(paths, "SETTINGS_FILE", self.settings)
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(paths, "LEGACY_OPENCODE", os.path.join(self._tmp.name, "no.exe"))
        p2.start()
        self.addCleanup(p2.stop)

    def test_localappdata_found(self):
        lad = self._tmp.name
        exe_dir = os.path.join(lad, "Programs", "@opencode-aidesktop")
        os.makedirs(exe_dir)
        exe = os.path.join(exe_dir, "OpenCode.exe")
        open(exe, "wb").close()
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": lad}), \
             mock.patch.object(paths.shutil, "which", return_value=None):
            found, _ = paths.resolve_opencode()
        self.assertEqual(found, exe)

    def test_manual_wins(self):
        manual = os.path.join(self._tmp.name, "oc.exe")
        open(manual, "wb").close()
        paths.save_settings({"opencode_path": manual})
        found, _ = paths.resolve_opencode()
        self.assertEqual(found, manual)


if __name__ == "__main__":
    unittest.main()
