import urllib.request
import urllib.parse as urlparse
import json
import os
import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

WIREGUARD_BUNDLE_URL = "https://github.laiyagushi.com/ghraw/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt"
SERVERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs", "servers.json")

KNOWN_RANGES = {
    "188.114": "CF", "162.159": "CF",
    "104.244": "US", "8.6": "US",
    "103.1": "AU", "103.108": "AU",
    "103.107": "SG",
    "51.75": "DE", "147.135": "US",
    "141.98": "DE", "5.189": "DE",
    "185.199": "US", "172.64": "US",
    "66.235": "US", "204.188": "US",
    "23.227": "US", "198.41": "US",
}

COUNTRY_KEYWORDS = {
    "united states": "US", "us ": "US", "america": "US",
    "germany": "DE", "german": "DE", "deutschland": "DE",
    "france": "FR", "canada": "CA", "uk ": "GB",
    "united kingdom": "GB", "netherlands": "NL", "japan": "JP",
    "singapore": "SG", "australia": "AU", "brazil": "BR",
    "india": "IN", "russia": "RU", "turkey": "TR",
    "korea": "KR", "vietnam": "VN", "panama": "PA",
    "sweden": "SE", "switzerland": "CH", "ireland": "IE",
    "italy": "IT", "spain": "ES", "poland": "PL",
    "south africa": "ZA", "iran": "IR",
}


def parse_wireguard_uri(line, index):
    try:
        uri = line[len("wireguard://"):]
        if "#" in uri:
            main_part, comment_raw = uri.rsplit("#", 1)
            comment = urlparse.unquote(comment_raw)
        else:
            main_part = uri
            comment = ""

        if "?" in main_part:
            before_params, params_str = main_part.split("?", 1)
        else:
            before_params = main_part
            params_str = ""

        if "@" in before_params:
            encoded_key, endpoint_raw = before_params.rsplit("@", 1)
            endpoint_raw = urlparse.unquote(endpoint_raw)
        else:
            encoded_key = before_params
            endpoint_raw = ""

        private_key = urlparse.unquote(encoded_key)

        params = {}
        for pair in params_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = urlparse.unquote(v)

        public_key = params.get("publickey", "")
        address = params.get("address", "172.16.0.2/32")
        mtu = params.get("mtu", "1420")

        endpoint_host = ""
        endpoint_port = "51820"
        if ":" in endpoint_raw:
            endpoint_host, endpoint_port = endpoint_raw.rsplit(":", 1)
        else:
            endpoint_host = endpoint_raw

        if not endpoint_host or not public_key or not private_key:
            return None

        endpoint = f"{endpoint_host}:{endpoint_port}"

        country = "Unknown"
        t = comment.lower()
        for kw, code in COUNTRY_KEYWORDS.items():
            if kw in t:
                country = code
                break

        if country == "Unknown":
            ip_prefix = ".".join(endpoint_host.split(".")[:2])
            country = KNOWN_RANGES.get(ip_prefix, "XX")

        return {
            "name": f"wg-{country}-{index:03d}",
            "private_key": private_key,
            "address": address,
            "public_key": public_key,
            "endpoint": endpoint,
            "dns": "1.1.1.1, 8.8.8.8",
            "mtu": mtu,
            "country": country,
            "source": "WireGuard-Bundle",
            "comment": comment,
        }
    except Exception:
        return None


def ping_host(host, port=51820, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def speed_test(host, port=51820, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        if result == 0:
            return round(elapsed, 1)
        return -1
    except Exception:
        return -1


print("=" * 60)
print("  WireGuard VPN Fetcher & Tester")
print("  Source: morpheusadam/v2ray-config")
print("=" * 60)

print("\n[1/4] Downloading WireGuard bundle...")
try:
    req = urllib.request.Request(WIREGUARD_BUNDLE_URL, headers={
        "User-Agent": "Mozilla/5.0"
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read().decode("utf-8", errors="ignore")
    print(f"  Downloaded: {len(data)} bytes")
except Exception as e:
    print(f"  ERROR downloading: {e}")
    exit(1)

print("\n[2/4] Parsing WireGuard configs...")
all_configs = []
for i, line in enumerate(data.splitlines()):
    line = line.strip()
    if not line.startswith("wireguard://"):
        continue
    server = parse_wireguard_uri(line, i)
    if server:
        all_configs.append(server)

us_count = sum(1 for s in all_configs if s["country"] == "US")
de_count = sum(1 for s in all_configs if s["country"] == "DE")
other_count = len(all_configs) - us_count - de_count
print(f"  Found: {len(all_configs)} configs (US: {us_count}, DE: {de_count}, Other: {other_count})")

print("\n[3/4] Testing servers for connectivity (parallel)...")
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


with ThreadPoolExecutor(max_workers=40) as executor:
    futures = {executor.submit(test_server, s): s for s in all_configs}
    done = 0
    for future in as_completed(futures):
        done += 1
        server, ok, ms = future.result()
        status = f"{ms}ms" if ms > 0 else "TIMEOUT"
        symbol = "OK" if ok else "FAIL"
        if done % 50 == 0 or done == len(all_configs):
            print(f"  [{done}/{len(all_configs)}] checked...")
        if ok:
            working.append(server)
            print(f"    + {server['name']} [{server['country']}] {ms}ms - {server['endpoint']}")
        else:
            failed.append(server)

print(f"\n[4/4] Results:")
print(f"  Working: {len(working)}")
print(f"  Failed:  {len(failed)}")

if working:
    working.sort(key=lambda x: (x.get("latency") if isinstance(x.get("latency"), (int, float)) and x.get("latency") > 0 else 9999))

    us_working = [s for s in working if s["country"] == "US"]
    de_working = [s for s in working if s["country"] == "DE"]
    other_working = [s for s in working if s["country"] not in ("US", "DE")]

    print(f"\n  US servers: {len(us_working)}")
    print(f"  DE servers: {len(de_working)}")
    print(f"  Other:      {len(other_working)}")

    print(f"\n  Top 10 fastest servers:")
    for i, s in enumerate(working[:10], 1):
        print(f"    {i}. {s['name']} [{s['country']}] - {s.get('latency', '?')}ms - {s['endpoint']}")

    existing = []
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
            existing = json.load(f)

    existing_endpoints = {s["endpoint"] for s in existing}
    new_servers = [s for s in working if s["endpoint"] not in existing_endpoints]

    for s in new_servers:
        s.pop("latency", None)
        s.pop("comment", None)

    existing.extend(new_servers)
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"\n  Saved {len(new_servers)} new working servers")
    print(f"  Total servers now: {len(existing)}")
else:
    print("\n  No working servers found!")

print("\n" + "=" * 60)
print("  Done!")
print("=" * 60)
