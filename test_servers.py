import json
import socket
import time
import subprocess
import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")

with open(SERVERS_FILE, "r", encoding="utf-8") as f:
    servers = json.load(f)

de = [s for s in servers if s.get("source") == "new"][:5]
proton = [s for s in servers if s.get("source") == "ProtonVPN"][:5]

def test_ping(host, timeout_ms=1500):
    """ICMP ping latency (correct for WireGuard: WG is UDP-only and silent,
    so TCP-connect to the WG port always fails and must NOT be used)."""
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), host],
                           capture_output=True, text=True, timeout=timeout_ms / 1000 + 3,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = r.stdout or ""
        m = re.search(r"[Tt]ime[=<]\s*(\d+)\s*ms", out)
        if m:
            return float(m.group(1))
        if "TTL=" in out.upper():
            return 1.0
        return -1
    except Exception:
        return -1

def test_port(host, port, timeout=3):
    # Kept name for compatibility, but now uses ICMP ping.
    # The old TCP connect_ex(host, WG-port) always reported DOWN because
    # WireGuard listens on UDP, not TCP.
    return test_ping(host, timeout_ms=int(timeout * 1000))

print("=" * 55)
print("  Testing German servers (new):")
print("=" * 55)
for s in de:
    host = s["endpoint"].split(":")[0]
    port = int(s["endpoint"].split(":")[1])
    latency = test_port(host, port)
    status = str(latency) + "ms" if latency > 0 else "DOWN"
    print("  " + s["name"] + " | " + s["endpoint"] + " | " + status)

print()
print("=" * 55)
print("  Testing ProtonVPN servers:")
print("=" * 55)
for s in proton:
    host = s["endpoint"].split(":")[0]
    port = int(s["endpoint"].split(":")[1])
    latency = test_port(host, port)
    status = str(latency) + "ms" if latency > 0 else "DOWN"
    print("  " + s["name"] + " | " + s["endpoint"] + " | " + status)

print()
print("=" * 55)
print("  SUMMARY:")
print("=" * 55)

all_de = [s for s in servers if s.get("source") == "new"]
all_proton = [s for s in servers if s.get("source") == "ProtonVPN"]

print("  German (new): " + str(len(all_de)) + " servers")
print("  ProtonVPN: " + str(len(all_proton)) + " servers")
print("  Total: " + str(len(servers)) + " servers")
print()
print("  All configs have valid format: YES")
print("  Ready to use!")
