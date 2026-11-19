# -*- coding: utf-8 -*-
"""Servers/history persistence: locked, atomic, dedup-on-load, corrupt-DB backup."""

import threading
import time
import os
import shutil
import json
from .paths import IP_HISTORY, SERVERS_FILE
from .util import _atomic_write_json, now_iso

_SERVERS_LOCK = threading.Lock()
_HISTORY_LOCK = threading.Lock()

_HISTORY_MAX = 500

def load_servers():
    try:
        if os.path.exists(SERVERS_FILE):
            with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
            if isinstance(d, dict):
                d = d.get("servers", [])
            if not isinstance(d, list):
                return []
            # Validate + dedup by endpoint (corrupt entries dropped, not crash)
            seen, clean = set(), []
            for s in d:
                if not isinstance(s, dict):
                    continue
                ep = (s.get("endpoint") or "").strip()
                pk = (s.get("private_key") or "").strip()
                if not ep or not pk:
                    continue
                if ep in seen:
                    continue
                seen.add(ep)
                clean.append(s)
            return clean
    except Exception:
        # Backup corrupt DB instead of wiping it
        try:
            bad = SERVERS_FILE + f".corrupt_{time.strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(SERVERS_FILE, bad)
        except Exception:
            pass
    return []


def save_servers(servers):
    # Choke point: every stored server gets a fetch date (sources-first model).
    # Manual adds keep no source_url (= human-provided, honest provenance).
    try:
        for s in servers:
            if isinstance(s, dict):
                s.setdefault("fetched_at", now_iso())
    except Exception:
        pass
    try:
        with _SERVERS_LOCK:
            return _atomic_write_json(SERVERS_FILE, servers)
    except Exception:
        return False


def load_history():
    try:
        if os.path.exists(IP_HISTORY):
            with open(IP_HISTORY, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        pass
    return []


def save_history(history):
    try:
        # Bound growth: last N rotations only (log file was unbounded)
        if isinstance(history, list) and len(history) > _HISTORY_MAX:
            del history[:-_HISTORY_MAX]
        with _HISTORY_LOCK:
            return _atomic_write_json(IP_HISTORY, history)
    except Exception:
        return False
