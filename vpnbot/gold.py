# -*- coding: utf-8 -*-
"""GOLD verification policy: stamps, 3-day TTL, refresh targets, filter helpers."""

import time
from .util import now_iso

# Refresh (on-demand only, never at startup): re-verify GOLD, drop dead,
# top up from free sources until GOLD target is met again.
REFRESH_GOLD_TARGET = 15
REFRESH_VERIFY_TIMEOUT = 9
REFRESH_TOPUP_MAX = 25
REFRESH_CAND_CAP = 150
# Sources-first: a GOLD badge is a temp cache, not a permanent title.
# IPs/keys rot (free keys expire, endpoints re-appear under new ports),
# so verified results expire after this many days.
GOLD_TTL_DAYS = 3

def stamp_verified(server, ip):
    server["verified"] = True
    server["last_verified"] = now_iso()
    server["exit_ip"] = ip


def gold_fresh(server):
    """True only if verified AND within TTL. Stale gold is just a rumor."""
    try:
        if not server.get("verified"):
            return False
        lv = server.get("last_verified", "")
        if not lv:
            return False
        age_days = (time.time() - time.mktime(time.strptime(lv, "%Y-%m-%dT%H:%M:%S"))) / 86400.0
        return age_days < GOLD_TTL_DAYS
    except Exception:
        return False


def stamp_fetched(server, source_url):
    server.setdefault("fetched_at", now_iso())
    if source_url:
        server["source_url"] = source_url

def get_countries(servers):
    countries = []
    for s in servers:
        c = s.get("country", "Unknown")
        if c not in countries:
            countries.append(c)
    return sorted(countries)


def get_sources(servers):
    sources = []
    for s in servers:
        src = s.get("source", "Unknown")
        if src not in sources:
            sources.append(src)
    return sorted(sources)


# Scan-state persistence (P3): restore last known UP/DOWN + latency at startup,
# bounded by TTL so stale marks never mislead best-server ranking.
SCAN_TTL_HOURS = 24


def stamp_scan(server, alive, ms=None):
    """Record a scan/speed result on the server entry (persisted schema)."""
    server["last_scan"] = now_iso()
    if alive is not None:
        server["last_alive"] = alive
    if ms and ms > 0:
        server["latency"] = ms


def scan_fresh(server):
    try:
        ls = server.get("last_scan", "")
        if not ls:
            return False
        age_h = (time.time() - time.mktime(time.strptime(ls, "%Y-%m-%dT%H:%M:%S"))) / 3600.0
        return age_h < SCAN_TTL_HOURS
    except Exception:
        return False


def collect_scan_state(servers):
    """(status_dict, latency_dict) from fresh persisted scan marks."""
    status, latency = {}, {}
    for s in servers:
        if not scan_fresh(s):
            continue
        ep = s.get("endpoint", "")
        if not ep:
            continue
        if "last_alive" in s:
            status[ep] = s["last_alive"]
        lat = s.get("latency")
        if lat and lat > 0:
            latency[ep] = lat
    return status, latency
