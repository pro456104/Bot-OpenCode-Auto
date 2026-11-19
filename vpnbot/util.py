# -*- coding: utf-8 -*-
"""Tiny shared helpers: timestamps and crash-safe atomic JSON writes."""

import time
import os
import json

def _atomic_write_json(path, data):
    """Crash-safe write: tmp + os.replace (never half-written JSON)."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")
