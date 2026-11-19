# -*- coding: utf-8 -*-
"""wireproxy userspace backend: process tracking, conf generation, readiness polling."""

import time
import os
import re
import subprocess
from .net import get_ip, proxy_ready
from .paths import WG_CONF
from . import paths

_WP_PROC = None          # tracked wireproxy Popen (targeted kill, no blind taskkill)
_WP_CACHE = {"running": False, "ts": 0.0}
_WP_CACHE_TTL = 1.0      # tasklist.exe spawn is ~50-100ms -> cache 1s

def _spawn_wp(conf_path):
    """Launch wireproxy and track the handle for targeted kill."""
    global _WP_PROC
    try:
        proc = subprocess.Popen(
            [paths.WG_PROXY, "-c", conf_path, "-s"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _WP_PROC = proc
        _WP_CACHE["running"] = True
        _WP_CACHE["ts"] = time.time()
        return proc
    except Exception:
        return None


def kill_wp():
    """Targeted kill (tracked PID) + fallback taskkill. No blind 1s sleep.

    The slow taskkill spawn is skipped when nothing is running
    (tracked handle dead + tasklist says no foreign instance), so
    Disconnect/Reset/Close never freeze on an empty kill.
    """
    global _WP_PROC
    killed = False
    proc, _WP_PROC = _WP_PROC, None
    try:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                killed = True
            except Exception:
                pass
    except Exception:
        pass
    if killed or wp_running():
        # Fallback: stray/foreign wireproxy instances (only when needed)
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", "wireproxy.exe"],
                               capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               timeout=6)
            out = (getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")
            if "SUCCESS" in out.upper() or "PID" in out.upper():
                killed = True
        except Exception:
            pass
    _WP_CACHE["running"] = False
    _WP_CACHE["ts"] = time.time()
    if killed:
        time.sleep(0.6)
    if os.path.exists(WG_CONF):
        try:
            os.remove(WG_CONF)
        except Exception:
            pass


def wp_running(use_cache=True):
    """Cached tasklist check (spawn ~50-100ms, so 1s TTL)."""
    try:
        now = time.time()
        if use_cache and (now - _WP_CACHE.get("ts", 0)) < _WP_CACHE_TTL:
            return bool(_WP_CACHE.get("running"))
        # Tracked handle is cheapest truth
        proc = _WP_PROC
        try:
            if proc is not None and proc.poll() is None:
                _WP_CACHE.update(running=True, ts=now)
                return True
        except Exception:
            pass
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq wireproxy.exe"],
                           capture_output=True, text=True, timeout=6,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        running = "wireproxy.exe" in (r.stdout or "")
        # If tracked proc died but a foreign instance lives, still True
        _WP_CACHE.update(running=running, ts=now)
        return running
    except Exception:
        return bool(_WP_CACHE.get("running", False))

def wait_for_vpn_ready(timeout_total=7, poll=0.4):
    """P0 speed: replace fixed sleep(5/6). Poll proxy+IP, return IP on first success.

    Old flow waited 5-6s unconditionally even if handshake finished in 200ms.
    New flow typically returns in 0.5-2s on a good server.
    Proxy-first order: fast TCP check (no spawn) before tasklist spawn.
    """
    deadline = time.time() + timeout_total
    last_ip = None
    while time.time() < deadline:
        # Fast path first (no process spawn)
        if proxy_ready(timeout=0.25):
            last_ip = get_ip(timeout=2)
            if last_ip:
                return last_ip
        elif not wp_running():
            # Proxy down + process gone -> dead, keep polling (caller retries)
            pass
        time.sleep(poll)
    return last_ip

def _auto_mtu_for_endpoint(endpoint):
    """P0 speed: MTU 1280 for Cloudflare/WARP anycast (fragmentation-sensitive),
    1380 for the rest (safer than 1420 on WiFi/PPPoE)."""
    try:
        host = (endpoint or "").split(":")[0]
        if host.startswith("188.114") or host.startswith("162.159"):
            return "1280"
    except Exception:
        pass
    return "1380"


def _clean_dns(dns_text):
    """Keep only public IPv4 DNS servers, else fallback 1.1.1.1.

    Imported configs often carry tunnel-internal DNS (10.x) + IPv6
    (e.g. "10.2.0.1, 2a07:b944::2:1") which may be unreachable, so the
    proxy cannot resolve the IP-check host even when the WireGuard
    handshake itself is fine -> false "connection failed".
    """
    try:
        kept = []
        for part in str(dns_text or "").replace(";", ",").split(","):
            p = part.strip()
            if not p or ":" in p:
                continue  # IPv6 / empty
            if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", p):
                continue  # tunnel-internal / LAN
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", p):
                kept.append(p)
        return ", ".join(kept) if kept else "1.1.1.1"
    except Exception:
        return "1.1.1.1"


def make_conf(s):
    ep = s.get("endpoint", "")
    mtu = s.get("mtu", "")
    # Keep explicit custom MTU, but fix legacy default 1420 -> auto-tuned value
    if not mtu or mtu == "1420":
        mtu = _auto_mtu_for_endpoint(ep)
    dns = _clean_dns(s.get("dns", ""))
    return f"""[Interface]
PrivateKey = {s['private_key']}
Address = {s['address']}
MTU = {mtu}
DNS = {dns}

[Peer]
PublicKey = {s['public_key']}
Endpoint = {s['endpoint']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15

[Socks5]
BindAddress = 127.0.0.1:10808

[HTTP]
BindAddress = 127.0.0.1:8080
"""
