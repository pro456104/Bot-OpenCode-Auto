# -*- coding: utf-8 -*-
"""Cloudflare WARP auto-registration: free, unlimited, no account/CAPTCHA.

Pure-stdlib X25519 (RFC 7748) + the public device-registration API (the same
flow wgcf uses). Each registration yields a PRIVATE WireGuard device with
stable keys. Devices get unique anycast endpoints from the WARP pool so the
app's endpoint-keyed state (status/latency/failed) keeps working per device.

Proven live: register ~6s -> dial engage.cloudflareclient.com:2408 -> exit IP
changes. API quirk: endpoint port can be ":0" -> use host/fallbacks.
"""
import base64
import json
import os
import time
import urllib.request

from .gold import stamp_fetched

WARP_API_URLS = [
    "https://api.cloudflareclient.com/v0a2158/reg",
    "https://api.cloudflareclient.com/v0a1928/reg",
]
WARP_HOST = "engage.cloudflareclient.com:2408"
# WARP anycast pool: any endpoint accepts any registered device key.
WARP_ENDPOINT_POOL = (
    ["162.159.192.%d:2408" % i for i in range(1, 21)]
    + ["162.159.193.%d:2408" % i for i in range(1, 11)]
    + ["162.159.195.%d:2408" % i for i in range(1, 11)]
    + ["162.159.192.%d:500" % i for i in range(1, 11)]
    + ["162.159.192.%d:4500" % i for i in range(1, 11)]
)

_P = 2**255 - 19


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(scalar, point=9):
    """RFC 7748 Montgomery ladder (pure python, no external crypto deps)."""
    k = int.from_bytes(_clamp(scalar), "little")
    u = int.from_bytes(point, "little") if isinstance(point, (bytes, bytearray)) else point
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % _P
        AA = A * A % _P
        B = (x2 - z2) % _P
        BB = B * B % _P
        E = (AA - BB) % _P
        C = (x3 + z3) % _P
        D = (x3 - z3) % _P
        DA = D * A % _P
        CB = C * B % _P
        x3 = pow(DA + CB, 2, _P)
        z3 = x1 * pow(DA - CB, 2, _P) % _P
        x2 = AA * BB % _P
        z2 = E * (AA + 121665 * E) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def generate_keypair():
    """(private_b64, public_b64) - clamped WireGuard keypair, stdlib only."""
    priv = os.urandom(32)
    return (base64.b64encode(_clamp(priv)).decode(),
            base64.b64encode(x25519(priv)).decode())


def register(pub_b64, timeout=20):
    """Register a WARP device (no account/CAPTCHA). Returns account JSON."""
    body = {
        "key": pub_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "locale": "en_US",
        "model": "PC",
        "type": "Android",
    }
    last = None
    for url in WARP_API_URLS:
        try:
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "okhttp/3.12.1",
                         "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            last = e
    raise RuntimeError("WARP registration failed: %s" % last)


def endpoint_candidates(acc):
    """Ordered dial candidates from the account; skips the ':0' port quirk."""
    peers = acc.get("config", {}).get("peers") or [{}]
    ep = peers[0].get("endpoint", {}) or {}
    out = []
    for key in ("host", "v4"):
        e = ep.get(key)
        if e and not e.endswith(":0"):
            out.append(e)
    if WARP_HOST not in out:
        out.append(WARP_HOST)
    return out


def pick_warp_endpoint(existing):
    """First pool endpoint not already used (keeps per-device state unique)."""
    used = set(existing or ())
    for e in WARP_ENDPOINT_POOL:
        if e not in used:
            return e
    return WARP_HOST  # pool exhausted: shared host (keys still differ)


def build_server(acc, priv_b64, endpoint, index=0):
    """Server dict (app schema + warp_id/warp_fallbacks extras) from account."""
    cfg = acc.get("config", {})
    peer = (cfg.get("peers") or [{}])[0]
    peer_key = peer.get("public_key") or acc.get("key")
    if not peer_key:
        raise ValueError("no peer key in WARP response")
    v4 = cfg.get("interface", {}).get("addresses", {}).get("v4", "172.16.0.2")
    s = {
        "name": "WARP-%02d" % (index + 1),
        "private_key": priv_b64,
        "address": v4 + "/32",
        "public_key": peer_key,
        "endpoint": endpoint,
        "dns": "1.1.1.1",
        "mtu": "1280",
        "country": "CF",
        "source": "WARP-Auto",
        "warp_id": acc.get("id", ""),
        "warp_fallbacks": endpoint_candidates(acc),
    }
    stamp_fetched(s, WARP_API_URLS[0])
    return s


def fetch_warp_servers(count=3, existing_endpoints=(), start_index=0,
                       timeout=20, log=None):
    """Register `count` devices, each with a unique pool endpoint.

    Returns server dicts (unverified). Raises on registration failure.
    """
    out = []
    used = set(existing_endpoints or ())
    for i in range(count):
        priv, pub = generate_keypair()
        acc = register(pub, timeout=timeout)
        ep = pick_warp_endpoint(used)
        used.add(ep)
        s = build_server(acc, priv, ep, index=start_index + i)
        out.append(s)
        if log:
            log("WARP device %d/%d registered (%s)" % (i + 1, count, ep))
    return out
