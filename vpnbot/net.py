# -*- coding: utf-8 -*-
"""Network probes (DNS/ICMP/UDP/TCP), server liveness checks, exit-IP fetchers."""

import time
import re
import subprocess
import urllib.request
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

_DNS_CACHE = {}
_DNS_CACHE_TTL = 300

# P0 speed: multiple IP providers, first answer wins (ifconfig.me alone is slow/rate-limited)
IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me",
]

def proxy_ready(host="127.0.0.1", port=8080, timeout=0.3):
    """Fast TCP check that wireproxy HTTP listener is up. No process spawn."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def _fetch_ip_via_proxy(url, timeout=3):
    """Fetch exit IP through local wireproxy HTTP proxy using urllib (no curl.exe spawn)."""
    try:
        proxy = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        })
        opener = urllib.request.build_opener(proxy)
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open(url, timeout=timeout) as resp:
            ip = resp.read().decode("utf-8", errors="ignore").strip()
        # api.ipify/icanhazip may add newline; ifconfig.me returns plain IP
        ip = ip.split()[0] if ip else ""
        if ip and ("." in ip or ":" in ip) and len(ip) < 64:
            return ip
    except Exception:
        pass
    return None


def get_ip(timeout=4):
    """P0 speed: parallel multi-provider IP check. First success wins.

    Old code: single curl.exe -> ifconfig.me with 12s timeout.
    New: 3 providers in parallel via urllib, each ~3s timeout.
    Compatible: get_ip() with no args still works.
    """
    try:
        if not proxy_ready(timeout=0.3):
            # Proxy not even listening yet -> fail fast, caller will retry/poll
            return None
    except Exception:
        pass
    try:
        per_url = max(2, min(4, int(timeout)))
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(_fetch_ip_via_proxy, u, per_url): u for u in IP_CHECK_URLS}
            for fut in as_completed(futures, timeout=timeout):
                try:
                    ip = fut.result()
                except Exception:
                    continue
                if ip:
                    # Cancel stragglers
                    for f in futures:
                        f.cancel()
                    return ip
    except Exception:
        pass
    return None

def resolve_host(host):
    """Resolve hostname to IP with 5-min cache. Returns IP or None on DNS failure."""
    try:
        # Already an IP?
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            return host
        now = time.time()
        hit = _DNS_CACHE.get(host)
        if hit and (now - hit[1]) < _DNS_CACHE_TTL:
            return hit[0]
        ip = socket.gethostbyname(host)
        _DNS_CACHE[host] = (ip, now)
        # Bound cache size (avoid leak with 972 endpoints)
        if len(_DNS_CACHE) > 2000:
            _DNS_CACHE.clear()
            _DNS_CACHE[host] = (ip, now)
        return ip
    except Exception:
        return None


def icmp_ping(host, timeout_ms=1200):
    """ICMP ping via system ping.exe. Returns latency ms or -1.

    Works on Windows regardless of WireGuard protocol - tests if the
    HOST is alive, which TCP-to-WG-port can never do (WG is UDP-only
    and silent to unauthenticated packets).
    """
    try:
        ip = resolve_host(host)
        if not ip:
            return -1
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=(timeout_ms / 1000 + 3),
            creationflags=subprocess.CREATE_NO_WINDOW)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"[Tt]ime[=<]\s*(\d+)\s*ms", out)
        if m:
            return float(m.group(1))
        # "time<1ms" + non-English locales: TTL= line proves reply received
        up = (out or "").upper()
        if "TTL=" in up or "TTL =" in up:
            return 1.0
        return -1
    except Exception:
        return -1


def udp_probe(host, port=51820, timeout=2):
    """Probe the WireGuard UDP port.

    WireGuard never answers unauthenticated packets, so:
      - ICMP port-unreachable (ConnectionReset) => port CLOSED => DOWN
      - timeout (no answer, no ICMP) => OPEN|FILTERED => host may be UP
      - got a reply => OPEN => UP
      - DNS failure => DOWN
    Returns one of: "open", "filtered", "closed", "dns-fail".
    """
    try:
        ip = resolve_host(host)
        if not ip:
            return "dns-fail"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            try:
                s.sendto(b"\x00" * 32, (ip, port))
            except OSError:
                return "closed"
            try:
                s.recvfrom(2048)
                return "open"
            except ConnectionResetError:
                return "closed"
            except socket.timeout:
                return "filtered"
            except OSError as e:
                # Windows WSAECONNRESET (10054) = ICMP port unreachable
                if getattr(e, "winerror", None) == 10054 or "10054" in str(e):
                    return "closed"
                return "filtered"
        finally:
            s.close()
    except Exception:
        return "filtered"


def tcp_alive(host, port, timeout=2):
    """Simple TCP open check (for host-alive fallback on 443/80)."""
    try:
        ip = resolve_host(host)
        if not ip:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_server(host, port=51820, ping_timeout_ms=1200, udp_timeout=2):
    """Accurate WireGuard server check (3-state).

    Order:
      1. DNS must resolve, else DOWN.
      2. UDP CLOSED (ICMP unreachable) => DOWN (definitive).
      3. ICMP ping OK => UP + latency (host alive).
      4. UDP open/filtered + TCP 443/80 open => UP (host alive, ICMP blocked).
      5. Total silence (no ping, no TCP, UDP filtered) => UNKNOWN (None):
         WireGuard is silent by design so we can NOT call it DOWN
         (that was the old false-DOWN bug), but we also must not call
         a possibly-dead host UP. UI shows orange; use Verify for truth.
    Returns (alive: True/False/None, latency_ms, reason: str).
    """
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = 51820

    if not resolve_host(host):
        return False, -1, "DNS fail"

    udp = udp_probe(host, port, timeout=udp_timeout)
    if udp == "dns-fail":
        return False, -1, "DNS fail"
    if udp == "closed":
        return False, -1, "UDP port closed"

    ms = icmp_ping(host, timeout_ms=ping_timeout_ms)
    if ms >= 0:
        return True, round(ms, 1), "Ping OK"

    # Ping blocked/failed but UDP not closed -> check well-known TCP ports
    # to confirm the host itself is alive (Proton hosts have 443 open).
    if tcp_alive(host, 443, timeout=2) or tcp_alive(host, 80, timeout=2):
        return True, -1, "Host alive (ICMP blocked)"

    # Total silence: do NOT mark red (old bug) nor green (dead-host risk).
    if udp in ("open", "filtered"):
        return None, -1, "Silent (unverified)"

    return False, -1, "Unreachable"


DIRECT_IP_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me",
]

def _fetch_direct_ip(url, timeout=3):
    """Direct exit-IP fetch bypassing any proxy env (goes via kernel tunnel if up)."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open(url, timeout=timeout) as resp:
            ip = resp.read().decode("utf-8", errors="ignore").strip()
        ip = ip.split()[0] if ip else ""
        if ip and ("." in ip or ":" in ip) and len(ip) < 64:
            return ip
    except Exception:
        pass
    return None


def fetch_direct_ip(timeout=4):
    """Parallel direct-IP check (no proxy). First answer wins."""
    try:
        per_url = max(2, min(4, int(timeout)))
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(_fetch_direct_ip, u, per_url): u for u in DIRECT_IP_URLS}
            for fut in as_completed(futures, timeout=timeout):
                try:
                    ip = fut.result()
                except Exception:
                    continue
                if ip:
                    for f in futures:
                        f.cancel()
                    return ip
    except Exception:
        pass
    return None
