# -*- coding: utf-8 -*-
"""Structural tests: clean imports, layering contract, no undefined names.

The undefined-name scan is a mini-pyflakes (stdlib only): every Name loaded
in a module must be a builtin, an import, or bound somewhere in that module.
It catches forgotten imports after the mechanical split.
"""
import ast
import builtins
import importlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "vpnbot")

CORE_MODULES = ["vpnbot.util", "vpnbot.paths", "vpnbot.storage", "vpnbot.parsing",
                "vpnbot.gold", "vpnbot.net", "vpnbot.tunnel", "vpnbot.kernel",
                "vpnbot.sources"]
UI_MODULES = ["vpnbot.ui.theme", "vpnbot.ui.server_list", "vpnbot.ui.dialogs",
              "vpnbot.ui.connect_ui", "vpnbot.ui.fetch_ui", "vpnbot.ui.protect_ui",
              "vpnbot.ui.main_window"]

DUNDERS = {"__file__", "__name__", "__doc__", "__package__", "__spec__",
           "__loader__", "__builtins__", "__cached__", "__path__", "__all__",
           "__version__", "__class__", "__dict__"}


def _bound_names(tree):
    allowed = set(dir(builtins)) | DUNDERS
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            allowed.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            allowed.add(n.name)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                for arg in a.posonlyargs + a.args + a.kwonlyargs:
                    allowed.add(arg.arg)
                if a.vararg:
                    allowed.add(a.vararg.arg)
                if a.kwarg:
                    allowed.add(a.kwarg.arg)
        elif isinstance(n, ast.Lambda):
            a = n.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs:
                allowed.add(arg.arg)
            if a.vararg:
                allowed.add(a.vararg.arg)
            if a.kwarg:
                allowed.add(a.kwarg.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                allowed.add((al.asname or al.name).split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            allowed.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            allowed.update(n.names)
    return allowed


def undefined_names(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    allowed = _bound_names(tree)
    return sorted({n.id for n in ast.walk(tree)
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                   and n.id not in allowed})


def module_files():
    files = [os.path.join(PKG, f) for f in sorted(os.listdir(PKG))
             if f.endswith(".py")]
    ui = os.path.join(PKG, "ui")
    if os.path.isdir(ui):
        files += [os.path.join(ui, f) for f in sorted(os.listdir(ui))
                  if f.endswith(".py")]
    return files


class TestImports(unittest.TestCase):
    def test_core_imports_without_tkinter(self):
        # layering contract: core must never pull in the UI toolkit
        for m in CORE_MODULES:
            importlib.import_module(m)
        self.assertNotIn("tkinter", sys.modules)

    def test_paths_base_dir_is_project_root(self):
        from vpnbot import paths
        self.assertEqual(paths.BASE_DIR, ROOT)
        self.assertTrue(os.path.isfile(paths.SERVERS_FILE))
        self.assertTrue(os.path.isfile(os.path.join(paths.BIN_DIR, "wireproxy.exe")))

    def test_mutable_paths_setters(self):
        from vpnbot import paths
        old_wp, old_oc = paths.WG_PROXY, paths.OPENCODE_EXE
        try:
            paths.set_wireproxy_path(r"X:\fake\wireproxy.exe")
            paths.set_opencode_path(r"X:\fake\OpenCode.exe")
            self.assertEqual(paths.WG_PROXY, r"X:\fake\wireproxy.exe")
            self.assertEqual(paths.OPENCODE_EXE, r"X:\fake\OpenCode.exe")
        finally:
            paths.set_wireproxy_path(old_wp)
            paths.set_opencode_path(old_oc)

    def test_no_undefined_names(self):
        for p in module_files():
            missing = undefined_names(p)
            self.assertEqual(missing, [], "%s: undefined %s" % (
                os.path.relpath(p, ROOT), missing))

    def test_no_reverse_imports(self):
        # core modules must not import ui
        for p in module_files():
            if os.path.dirname(p) == PKG:  # core layer
                with open(p, encoding="utf-8") as f:
                    text = f.read()
                self.assertNotIn("vpnbot.ui", text, p)
                self.assertNotIn("from .ui", text, p)
                self.assertNotIn("import tkinter", text, p)

    def test_ui_composition(self):
        if not os.path.isdir(os.path.join(PKG, "ui")):
            self.skipTest("ui stage not built yet")
        for m in UI_MODULES:
            importlib.import_module(m)
        from vpnbot.ui.main_window import App
        from vpnbot.ui.server_list import ServerListMixin
        from vpnbot.ui.dialogs import DialogsMixin
        from vpnbot.ui.connect_ui import ConnectMixin
        from vpnbot.ui.fetch_ui import FetchMixin
        from vpnbot.ui.protect_ui import ProtectMixin
        for mixin in (ServerListMixin, DialogsMixin, ConnectMixin, FetchMixin, ProtectMixin):
            self.assertIn(mixin, App.__mro__)
        for name in ("step1_connect", "step2_launch", "rotate_ip", "random_rotate",
                     "refresh_gold", "fetch_all_fresh", "toggle_protect", "reset",
                     "check_all_servers", "speed_test_all", "pick_paths_dialog",
                     "import_conf", "paste_config", "verify_selected",
                     "kernel_connect_best", "disconnect_vpn", "on_close"):
            self.assertTrue(callable(getattr(App, name, None)), name)

    def test_entry_point(self):
        if not os.path.isdir(os.path.join(PKG, "ui")):
            self.skipTest("ui stage not built yet")
        sys.path.insert(0, ROOT)
        try:
            entry = importlib.import_module("vpn_bot")
            self.assertTrue(callable(entry.App))
        finally:
            sys.path.remove(ROOT)


if __name__ == "__main__":
    unittest.main()
