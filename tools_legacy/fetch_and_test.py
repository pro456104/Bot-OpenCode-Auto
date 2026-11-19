import urllib.request
import zipfile
import io
import json
import os
import socket
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

PROTONVPN_ZIP_URL = "https://github.com/Delta-Kronecker/ProtonVPN-WireGuard-configuration/raw/refs/heads/main/ProtonVPN_WireGuard_Configs.zip"
SERVERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs", "servers.json")

def parse_conf_from_text(text, source="ProtonVPN"):
    try:
        pk = addr = pubkey = endpoint = dns = mtu = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.startswith("PrivateKey") and "=" in line:
                pk = line.split("=", 1)[1].strip()
            elif line.startswith("Address") and "=" in line:
                addr = line.split("=", 1)[1].strip().split(",")[0].strip()
            elif line.startswith("PublicKey") and "=" in line:
                pubkey = line.split("=", 1)[1].strip()
            elif line.startswith("Endpoint") and "=" in line:
                endpoint = line.split("=", 1)[1].strip()
            elif line.startswith("DNS") and "=" in line:
                dns = line.split("=", 1)[1].strip()
            elif line.startswith("MTU") and "=" in line:
                mtu = line.split("=", 1)[1].strip()
        if not pk or not endpoint:
            return None, "Missing PrivateKey or Endpoint"
        return {
            "name": f"wg-{source[:4].upper()}",
            "private_key": pk,
            "address": addr,
            "public_key": pubkey,
            "endpoint": endpoint,
            "dns": dns or "1.1.1.1, 8.8.8.8",
            "mtu": mtu or "1420",
            "country": "Unknown",
            "source": source,
        }, None
    except Exception as e:
        return None, str(e)


def ping_host(host, port=51820, timeout=2):
    """WireGuard-aware check: UDP closed => DOWN, else ICMP/TCP-alive => UP.

    Old code used TCP connect_ex to the WG (UDP-only) port, which always
    failed and marked working servers DOWN. Never TCP-test a UDP port.
    """
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    # Definitive DOWN: UDP port unreachable
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00" * 32, (ip, port))
            s.recvfrom(2048)
            return True  # got a reply: open
        except ConnectionResetError:
            return False  # ICMP port unreachable: closed
        except socket.timeout:
            pass  # filtered (WG silent) -> fall through to host-alive checks
        except OSError as e:
            if "10054" in str(e):
                return False
        finally:
            s.close()
    except Exception:
        pass
    # Host alive? ping or 443/80 open => UP
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "1200", ip],
                           capture_output=True, text=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        if "TTL=" in (r.stdout or "").upper():
            return True
    except Exception:
        pass
    for p in (443, 80):
        try:
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.settimeout(2)
            ok = t.connect_ex((ip, p)) == 0
            t.close()
            if ok:
                return True
        except Exception:
            pass
    # WG silent + host silent: treat as UP (avoid false DOWN)
    return True


def speed_test(host, port=51820, timeout=3):
    """Latency via ICMP ping (TCP-to-WG-port is meaningless)."""
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), host],
                           capture_output=True, text=True, timeout=timeout + 3,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = r.stdout or ""
        m = re.search(r"[Tt]ime[=<]\s*(\d+)\s*ms", out)
        if m:
            return round(float(m.group(1)), 1)
        if "TTL=" in out.upper():
            return 1.0
        return -1
    except Exception:
        return -1


print("=" * 60)
print("  VPN Server Fetcher & Tester")
print("  Fetching ProtonVPN US & DE configs...")
print("=" * 60)

print("\n[1/4] Downloading ProtonVPN ZIP...")
try:
    req = urllib.request.Request(PROTONVPN_ZIP_URL, headers={
        "User-Agent": "Mozilla/5.0"
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        zip_data = resp.read()
    print(f"  Downloaded: {len(zip_data) / 1024:.1f} KB")
except Exception as e:
    print(f"  ERROR: {e}")
    exit(1)

print("\n[2/4] Extracting US & DE configs...")
all_configs = []
with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
    for filename in zf.namelist():
        if not filename.endswith(".conf"):
            continue
        parts = filename.lower().split("/")
        country = parts[0] if len(parts) > 1 else ""
        if country not in ("us", "de"):
            continue
        try:
            with zf.open(filename) as f:
                content = f.read().decode("utf-8", errors="ignore")
            server, error = parse_conf_from_text(content, source="ProtonVPN")
            if error:
                continue
            server["country"] = country.upper()
            server["name"] = f"wg-{country.upper()}-{filename.split('/')[-1].replace('.conf', '')}"
            all_configs.append(server)
        except Exception:
            continue

us_count = sum(1 for s in all_configs if s["country"] == "US")
de_count = sum(1 for s in all_configs if s["country"] == "DE")
print(f"  Found: {len(all_configs)} configs (US: {us_count}, DE: {de_count})")

print("\n[3/4] Testing servers for connectivity...")
working = []
failed = []

def test_server(server):
    endpoint = server["endpoint"]
    host = endpoint.split(":")[0] if ":" in endpoint else endpoint
    port_str = endpoint.split(":")[1] if ":" in endpoint else "51820"
    try:
        port = int(port_str)
    except ValueError:
        port = 51820

    alive = ping_host(host, port, timeout=2)
    if alive:
        ms = speed_test(host, port, timeout=3)
        server["latency"] = ms
        return (server, True, ms)
    return (server, False, -1)

with ThreadPoolExecutor(max_workers=30) as executor:
    futures = {executor.submit(test_server, s): s for s in all_configs}
    done = 0
    for future in as_completed(futures):
        done += 1
        server, ok, ms = future.result()
        status = f"{ms}ms" if ms > 0 else "TIMEOUT"
        symbol = "OK" if ok else "FAIL"
        print(f"  [{done}/{len(all_configs)}] {server['name']} [{server['country']}] -> {symbol} ({status})")
        if ok:
            working.append(server)
        else:
            failed.append(server)

print(f"\n[4/4] Results:")
print(f"  Working: {len(working)}")
print(f"  Failed:  {len(failed)}")

if working:
    working.sort(key=lambda x: (x.get("latency") if isinstance(x.get("latency"), (int, float)) and x.get("latency") > 0 else 9999))
    print(f"\n  Top 5 fastest servers:")
    for i, s in enumerate(working[:5], 1):
        print(f"    {i}. {s['name']} [{s['country']}] - {s.get('latency', '?')}ms - {s['endpoint']}")

    existing = []
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
            existing = json.load(f)

    existing_endpoints = {s["endpoint"] for s in existing}
    new_servers = [s for s in working if s["endpoint"] not in existing_endpoints]

    for s in new_servers:
        s.pop("latency", None)

    existing.extend(new_servers)
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"\n  Saved {len(new_servers)} new working servers to servers.json")
    print(f"  Total servers now: {len(existing)}")
else:
    print("\n  No working servers found!")

print("\n" + "=" * 60)
print("  Done!")
print("=" * 60)
