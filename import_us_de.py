import urllib.request
import urllib.parse as urlparse
import json
import os
import socket

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
        }
    except Exception:
        return None


def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except:
        return host


def detect_country(host):
    ip = resolve_host(host)
    ip_prefix = ".".join(ip.split(".")[:2])
    
    if ip_prefix in ("188.114", "162.159"):
        return "CF"
    
    ranges = {
        "51.75": "DE", "5.189": "DE", "141.98": "DE", "185.220": "DE",
        "104.244": "US", "8.6": "US", "147.135": "US", "185.199": "US",
        "172.64": "US", "66.235": "US", "204.188": "US", "23.227": "US",
        "198.41": "US", "209.51": "US", "192.168": "US", "10.": "US",
        "103.1": "AU", "103.108": "AU", "103.107": "SG",
        "142.250": "US", "216.58": "US", "35.190": "US", "34.102": "US",
        "34.149": "US", "35.186": "US", "34.85": "US", "34.127": "US",
    }
    return ranges.get(ip_prefix, "Unknown")


print("=" * 60)
print("  WireGuard VPN Importer (US & DE)")
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

print("\n[2/3] Parsing and filtering US & DE configs...")
all_configs = []
us_count = 0
de_count = 0

for i, line in enumerate(data.splitlines()):
    line = line.strip()
    if not line.startswith("wireguard://"):
        continue
    server = parse_wireguard_uri(line, i)
    if not server:
        continue

    host = server["endpoint"].split(":")[0]
    detected = detect_country(host)

    if server["country"] == "Unknown" and detected != "Unknown":
        server["country"] = detected
        server["name"] = f"wg-{detected}-{i:03d}"

    if server["country"] in ("US", "DE"):
        all_configs.append(server)
        if server["country"] == "US":
            us_count += 1
        else:
            de_count += 1

print(f"  US configs: {us_count}")
print(f"  DE configs: {de_count}")
print(f"  Total: {len(all_configs)}")

print("\n[3/3] Saving to servers.json...")
existing = []
if os.path.exists(SERVERS_FILE):
    with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
        existing = json.load(f)

existing_endpoints = {s["endpoint"] for s in existing}
new_servers = [s for s in all_configs if s["endpoint"] not in existing_endpoints]

existing.extend(new_servers)
with open(SERVERS_FILE, "w", encoding="utf-8") as f:
    json.dump(existing, f, indent=2)

print(f"  Added {len(new_servers)} new servers")
print(f"  Total servers: {len(existing)}")

us_total = sum(1 for s in existing if s.get("country") == "US")
de_total = sum(1 for s in existing if s.get("country") == "DE")
print(f"\n  Summary:")
print(f"    US servers: {us_total}")
print(f"    DE servers: {de_total}")
print(f"    Other:      {len(existing) - us_total - de_total}")

print("\n" + "=" * 60)
print("  Done! Run vpn_bot.py and click 'Scan All' to test servers.")
print("=" * 60)
