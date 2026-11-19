import urllib.request
import urllib.parse as urlparse
import json
import os
import socket
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
            "endpoint_host": endpoint_host,
            "endpoint_port": int(endpoint_port) if endpoint_port.isdigit() else 51820,
            "dns": "1.1.1.1, 8.8.8.8",
            "mtu": mtu,
            "country": country,
            "source": "WireGuard-Bundle",
            "comment": comment,
        }
    except Exception:
        return None


def test_port(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def test_server_multi_port(server):
    host = server["endpoint_host"]
    ports_to_try = [server["endpoint_port"], 51820, 443, 80, 8080, 2053]
    
    for port in ports_to_try:
        if test_port(host, port, timeout=1):
            return (server, True, port)
    
    dns_alive = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, 53))
        sock.close()
        dns_alive = result == 0
    except Exception:
        pass
    
    return (server, False, -1)


print("=" * 60)
print("  WireGuard VPN Multi-Port Tester")
print("=" * 60)

print("\n[1/3] Downloading WireGuard bundle...")
try:
    req = urllib.request.Request(WIREGUARD_BUNDLE_URL, headers={
        "User-Agent": "Mozilla/5.0"
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read().decode("utf-8", errors="ignore")
    print(f"  Downloaded: {len(data)} bytes")
except Exception as e:
    print(f"  ERROR: {e}")
    exit(1)

print("\n[2/3] Parsing configs...")
all_configs = []
for i, line in enumerate(data.splitlines()):
    line = line.strip()
    if not line.startswith("wireguard://"):
        continue
    server = parse_wireguard_uri(line, i)
    if server:
        all_configs.append(server)

print(f"  Found: {len(all_configs)} configs")

print("\n[3/3] Testing with multiple ports (443, 80, 51820, 8080, 2053)...")
working = []
failed = []

with ThreadPoolExecutor(max_workers=30) as executor:
    futures = {executor.submit(test_server_multi_port, s): s for s in all_configs}
    done = 0
    for future in as_completed(futures):
        done += 1
        server, ok, port = future.result()
        if done % 50 == 0 or done == len(all_configs):
            print(f"  [{done}/{len(all_configs)}] checked...")
        if ok:
            server["open_port"] = port
            working.append(server)
            print(f"    + {server['name']} [{server['country']}] port {port} OPEN - {server['endpoint']}")
        else:
            failed.append(server)

print(f"\nResults:")
print(f"  Working: {len(working)}")
print(f"  Failed:  {len(failed)}")

if working:
    working.sort(key=lambda x: x.get("open_port", 9999))

    us_working = [s for s in working if s["country"] == "US"]
    de_working = [s for s in working if s["country"] == "DE"]

    print(f"\n  US servers: {len(us_working)}")
    print(f"  DE servers: {len(de_working)}")
    print(f"\n  All working servers:")
    for i, s in enumerate(working, 1):
        print(f"    {i}. {s['name']} [{s['country']}] port {s.get('open_port', '?')} - {s['endpoint']}")

    existing = []
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
            existing = json.load(f)

    existing_endpoints = {s["endpoint"] for s in existing}
    new_servers = []
    for s in working:
        if s["endpoint"] not in existing_endpoints:
            s.pop("latency", None)
            s.pop("comment", None)
            s.pop("open_port", None)
            s.pop("endpoint_host", None)
            s.pop("endpoint_port", None)
            new_servers.append(s)

    existing.extend(new_servers)
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"\n  Saved {len(new_servers)} new servers")
    print(f"  Total servers: {len(existing)}")
else:
    print("\n  No working servers found on any port!")

print("\n" + "=" * 60)
print("  Done!")
print("=" * 60)
