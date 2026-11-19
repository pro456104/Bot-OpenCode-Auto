# -*- coding: utf-8 -*-
"""Filesystem paths, settings persistence, external-program resolution.

WG_PROXY / OPENCODE_EXE are runtime-mutable (Paths dialog): consumers must
read paths.WG_PROXY / paths.OPENCODE_EXE at call time, never import by name."""

import os
import shutil
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(BASE_DIR, "bin")
SETTINGS_FILE = os.path.join(BASE_DIR, "configs", "settings.json")
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")
WG_CONF = os.path.join(BASE_DIR, "wireproxy.conf")
IP_HISTORY = os.path.join(BASE_DIR, "logs", "ip_history.json")

# Legacy fixed locations (kept as last-resort fallbacks for backward compat)
LEGACY_WIREPROXY = r"C:\Program Files (x86)\wg-opencode\wireproxy.exe"
LEGACY_OPENCODE = r"C:\Users\Admin\AppData\Local\Programs\@opencode-aidesktop\OpenCode.exe"

def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def save_settings(d):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        return True
    except Exception:
        return False


def resolve_wireproxy():
    """Find wireproxy.exe. Order: manual settings -> bundled bin/ -> PATH -> legacy.

    Returns (path_or_None, searched_list). Bundled bin/ makes the project
    independent of the external wg-opencode installation.
    """
    searched = []
    try:
        manual = load_settings().get("wireproxy_path", "")
        if manual:
            searched.append(manual)
            if os.path.isfile(manual):
                return manual, searched
    except Exception:
        pass
    internal = os.path.join(BIN_DIR, "wireproxy.exe")
    searched.append(internal)
    if os.path.isfile(internal):
        return internal, searched
    try:
        which = shutil.which("wireproxy.exe")
        if which:
            searched.append(which)
            return which, searched
    except Exception:
        pass
    searched.append(LEGACY_WIREPROXY)
    if os.path.isfile(LEGACY_WIREPROXY):
        return LEGACY_WIREPROXY, searched
    return None, searched


def resolve_opencode():
    """Find OpenCode.exe. Order: manual settings -> LOCALAPPDATA -> PATH -> legacy."""
    searched = []
    try:
        manual = load_settings().get("opencode_path", "")
        if manual:
            searched.append(manual)
            if os.path.isfile(manual):
                return manual, searched
    except Exception:
        pass
    try:
        lad = os.environ.get("LOCALAPPDATA", "")
        if lad:
            p = os.path.join(lad, "Programs", "@opencode-aidesktop", "OpenCode.exe")
            searched.append(p)
            if os.path.isfile(p):
                return p, searched
    except Exception:
        pass
    for exe in ("OpenCode.exe", "opencode.exe"):
        try:
            which = shutil.which(exe)
        except Exception:
            which = None
        if which:
            searched.append(which)
            return which, searched
    searched.append(LEGACY_OPENCODE)
    if os.path.isfile(LEGACY_OPENCODE):
        return LEGACY_OPENCODE, searched
    return None, searched


def resolve_wireguard_tools():
    """Find official WireGuard client (optional, kernel mode only)."""
    cands_exe, cands_wg = [], []
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        try:
            cands_exe.append(os.path.join(base, "WireGuard", "wireguard.exe"))
            cands_wg.append(os.path.join(base, "WireGuard", "wg.exe"))
        except Exception:
            pass
    cands_exe.append(r"C:\Program Files\WireGuard\wireguard.exe")
    cands_wg.append(r"C:\Program Files\WireGuard\wg.exe")
    exe = next((p for p in cands_exe if p and os.path.isfile(p)), None)
    wg = next((p for p in cands_wg if p and os.path.isfile(p)), None)
    return exe, wg


WG_PROXY, WIREPROXY_SEARCHED = resolve_wireproxy()
if not WG_PROXY:
    WG_PROXY = LEGACY_WIREPROXY  # keeps error messages showing a concrete path
OPENCODE_EXE, OPENCODE_SEARCHED = resolve_opencode()
if not OPENCODE_EXE:
    OPENCODE_EXE = LEGACY_OPENCODE


def set_wireproxy_path(p):
    """Runtime override from the Paths dialog (replaces old `global WG_PROXY`)."""
    global WG_PROXY
    WG_PROXY = p


def set_opencode_path(p):
    """Runtime override from the Paths dialog (replaces old `global OPENCODE_EXE`)."""
    global OPENCODE_EXE
    OPENCODE_EXE = p
