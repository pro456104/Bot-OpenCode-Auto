import json
import urllib.parse
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_FILE = os.path.join(BASE_DIR, "configs", "wireguard_raw.txt")
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")
CONF_DIR = os.path.join(BASE_DIR, "configs", "imported")
os.makedirs(CONF_DIR, exist_ok=True)

for f in os.listdir(CONF_DIR):
    if f.endswith(".conf"):
        os.remove(os.path.join(CONF_DIR, f))

servers = []
count = 0

KNOWN_RANGES = {
    "188.114": "CF", "162.159": "CF",
    "104.244": "US", "8.6": "US", "149.57": "CA",
    "103.1": "AU", "103.108": "AU", "103.77": "AU", "116.206": "AU",
    "103.107": "SG", "103.62": "SG",
    "138.186": "PA", "197.242": "ZA",
}

def detect_country(text, endpoint=""):
    t = (text + " " + endpoint).lower()
    checks = [
        ("united states", "US"), ("\\U0001f1fa\\U0001f1f8", "US"),
        ("germany", "DE"), ("united kingdom", "UK"),
        ("france", "FR"), ("canada", "CA"), ("toronto", "CA"),
        ("japan", "JP"), ("singapore", "SG"),
        ("australia", "AU"), ("sydney", "AU"), ("melbourne", "AU"),
        ("brisbane", "AU"), ("perth", "AU"), ("adelaide", "AU"),
        ("auckland", "AU"), ("netherlands", "NL"),
        ("korea", "KR"), ("vietnam", "VN"),
        ("panama", "PA"), ("poland", "PL"),
        ("cloudflare", "CF"), ("iran", "IR"),
    ]
    for keyword, code in checks:
        if keyword in t:
            return code
    return None

with open(RAW_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("wireguard://"):
            continue

        try:
            uri = line[len("wireguard://"):]

            # Split at # for comment
            if "#" in uri:
                main_part, comment_raw = uri.rsplit("#", 1)
                comment = urllib.parse.unquote(comment_raw)
            else:
                main_part = uri
                comment = ""

            # Split at ? for params
            if "?" in main_part:
                before_params, params_str = main_part.split("?", 1)
            else:
                before_params = main_part
                params_str = ""

            # before_params = "PRIVATE_KEY@ENDPOINT:PORT"
            # Split at @ to separate key from endpoint
            if "@" in before_params:
                encoded_key, endpoint_raw = before_params.rsplit("@", 1)
                endpoint_raw = urllib.parse.unquote(endpoint_raw)
            else:
                encoded_key = before_params
                endpoint_raw = ""

            # Decode private key
            private_key = urllib.parse.unquote(encoded_key)

            # Parse params
            params = {}
            for pair in params_str.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = urllib.parse.unquote(v)

            public_key = params.get("publickey", "")
            address = params.get("address", "172.16.0.2/32")
            mtu = params.get("mtu", "1420")

            # Parse endpoint
            endpoint_host = ""
            endpoint_port = "51820"
            if ":" in endpoint_raw:
                endpoint_host, endpoint_port = endpoint_raw.rsplit(":", 1)
            else:
                endpoint_host = endpoint_raw

            if not endpoint_host or not public_key or not private_key:
                continue

            private_key = private_key.strip()
            public_key = public_key.strip()

            country = detect_country(comment, endpoint_host)
            if not country:
                ip_prefix = ".".join(endpoint_host.split(".")[:2])
                country = KNOWN_RANGES.get(ip_prefix, "XX")

            conf_content = f"""[Interface]
PrivateKey = {private_key}
Address = {address}
MTU = {mtu}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {public_key}
Endpoint = {endpoint_host}:{endpoint_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:10808

[HTTP]
BindAddress = 127.0.0.1:8080
"""

            conf_name = f"wg-{country}-{count:03d}.conf"
            conf_path = os.path.join(CONF_DIR, conf_name)
            with open(conf_path, "w", encoding="utf-8") as cf:
                cf.write(conf_content)

            servers.append({
                "name": conf_name.replace(".conf", ""),
                "private_key": private_key,
                "address": address,
                "public_key": public_key,
                "endpoint": f"{endpoint_host}:{endpoint_port}",
                "dns": "1.1.1.1, 8.8.8.8",
                "country": country,
                "source": "WireGuard-Bundle"
            })

            count += 1

        except Exception:
            continue

with open(SERVERS_FILE, "w", encoding="utf-8") as f:
    json.dump(servers, f, indent=2)

countries = {}
for s in servers:
    c = s["country"]
    countries[c] = countries.get(c, 0) + 1

print(f"Total imported: {count} servers")
print(f"Countries: {len(countries)}")
for c, n in sorted(countries.items(), key=lambda x: -x[1]):
    print(f"  {c}: {n}")
