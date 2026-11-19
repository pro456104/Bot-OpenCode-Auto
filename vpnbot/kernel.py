# -*- coding: utf-8 -*-
"""WireGuard-NT kernel backend: tunnel service install/uninstall, handshake checks."""

import time
import os
import subprocess
from .net import fetch_direct_ip
from .paths import BASE_DIR, resolve_wireguard_tools
from .tunnel import _auto_mtu_for_endpoint

_WG_EXE_FOUND, _WG_TOOL_FOUND = resolve_wireguard_tools()
WIREGUARD_EXE = _WG_EXE_FOUND or r"C:\Program Files\WireGuard\wireguard.exe"
WG_EXE = _WG_TOOL_FOUND or r"C:\Program Files\WireGuard\wg.exe"
KERNEL_TUNNEL = "opencode-kernel"
KERNEL_CONF = os.path.join(BASE_DIR, "wg-kernel.conf")

def make_kernel_conf(s):
    """P2: clean WireGuard-NT config (no proxy sections) for official kernel client.

    Kernel routing (L3) removes the localhost HTTP/SOCKS hop entirely:
    ~15-30% faster + lower latency than wireproxy userspace proxying.
    """
    ep = s.get("endpoint", "")
    mtu = s.get("mtu", "")
    if not mtu or mtu == "1420":
        mtu = _auto_mtu_for_endpoint(ep)
    return f"""[Interface]
PrivateKey = {s['private_key']}
Address = {s['address']}
MTU = {mtu}
DNS = 1.1.1.1

[Peer]
PublicKey = {s['public_key']}
Endpoint = {s['endpoint']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
"""

def kernel_interfaces():
    """List active WireGuard-NT tunnel names (empty list if none / no client)."""
    try:
        r = subprocess.run([WG_EXE, "show", "interfaces"],
                           capture_output=True, text=True, timeout=8,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return (r.stdout or "").split()
    except Exception:
        return []


def kernel_tunnel_up(name=KERNEL_TUNNEL):
    return name in kernel_interfaces()


def any_kernel_up():
    try:
        return len(kernel_interfaces()) > 0
    except Exception:
        return False


def kernel_latest_handshake(name=KERNEL_TUNNEL):
    """Seconds since last handshake, or None (no tunnel / never shook hands)."""
    try:
        r = subprocess.run([WG_EXE, "show", name, "latest-handshakes"],
                           capture_output=True, text=True, timeout=8,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        best = None
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                ts = int(parts[1])
                if ts > 0:
                    age = time.time() - ts
                    best = age if best is None else min(best, age)
        return best
    except Exception:
        return None

def wait_for_kernel_ready(name=KERNEL_TUNNEL, timeout_total=9, poll=0.5):
    """P2: poll kernel handshake + direct IP. Returns exit IP or None."""
    deadline = time.time() + timeout_total
    last_ip = None
    while time.time() < deadline:
        age = kernel_latest_handshake(name)
        if age is not None and age < 150:
            last_ip = fetch_direct_ip(timeout=2)
            if last_ip:
                return last_ip
        time.sleep(poll)
    return last_ip

def kernel_install(conf_path):
    """Install+activate tunnel service via official client. Needs admin."""
    if not os.path.exists(WIREGUARD_EXE):
        return False, "wireguard.exe not found (install official WireGuard first)"
    try:
        r = subprocess.run([WIREGUARD_EXE, "/installtunnelservice", conf_path],
                           capture_output=True, text=True, timeout=20,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            return True, "tunnel installed"
        return False, (r.stderr or r.stdout or "install failed").strip()[:200]
    except Exception as e:
        return False, str(e)[:200]


def kernel_uninstall(name=KERNEL_TUNNEL):
    """Remove our tunnel service only (never touches user's other tunnels).

    Skips the slow service call when no kernel tunnel is up, so
    Disconnect/Reset/Close stay instant in the common proxy-only case.
    """
    if not os.path.exists(WIREGUARD_EXE):
        return
    try:
        if not any_kernel_up():
            return
    except Exception:
        pass
    try:
        subprocess.run([WIREGUARD_EXE, "/uninstalltunnelservice", name],
                       capture_output=True, text=True, timeout=20,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass
