import os
import json
import re
import socket
import urllib.request
import urllib.parse
import base64
import struct
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")

KNOWN_GERMAN_RANGES = {
    "51.75": "DE", "141.98": "DE", "5.189": "DE", "85.204": "DE",
    "185.199": "DE", "91.220": "DE", "31.77": "DE", "172.245": "DE",
    "45.14": "DE", "104.244": "DE", "95.216": "DE", "213.202": "DE",
    "89.238": "DE", "176.9": "DE", "185.112": "DE", "45.137": "DE",
    "195.201": "DE", "5.9": "DE", "162.159": "CF",
}

GERMAN_WG_ENDPOINTS = [
    "de1-wg.ssl-tun.xyz:2600",
    "de2-wg.ssl-tun.xyz:2600",
    "de20.vpnbook.com:51820",
    "de220.vpnbook.com:51820",
    "gr1.vpnjantit.com:1024",
    "gr2.vpnjantit.com:1024",
    "gr3.vpnjantit.com:1024",
    "gr4.vpnjantit.com:1024",
    "gr5.vpnjantit.com:1024",
    "gr6.vpnjantit.com:1024",
    "gr7.vpnjantit.com:1024",
    "gr8.vpnjantit.com:1024",
    "gr9.vpnjantit.com:1024",
    "gr10.vpnjantit.com:1024",
    "berlin.cstorm.is:51820",
    "dusseldorf.cstorm.is:51820",
    "frankfurt.cstorm.is:51820",
]

CF_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
CF_DNS = "1.1.1.1, 8.8.8.8"


def load_servers():
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    return []


def save_servers(servers):
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2)


def fetch_url(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None


def parse_wg_uri(uri_line):
    try:
        if not uri_line.startswith("wireguard://"):
            return None
        uri = uri_line[len("wireguard://"):]
        if "#" in uri:
            main_part, comment_raw = uri.rsplit("#", 1)
            comment = urllib.parse.unquote(comment_raw)
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
        else:
            return None

        private_key = urllib.parse.unquote(encoded_key)
        params = {}
        for pair in params_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = urllib.parse.unquote(v)

        public_key = params.get("publickey", "")
        address = params.get("address", "172.16.0.2/32")
        mtu = params.get("mtu", "1280")
        dns = params.get("dns", "1.1.1.1, 8.8.8.8")
        reserved = params.get("reserved", "")
        keepalive = params.get("keepalive", "25")

        endpoint_host = ""
        endpoint_port = "51820"
        if ":" in endpoint_raw:
            endpoint_host, endpoint_port = endpoint_raw.rsplit(":", 1)

        if not endpoint_host or not public_key or not private_key:
            return None

        ep_str = f"{endpoint_host}:{endpoint_port}"

        return {
            "name": f"wg-DE-{hashlib.md5(ep_str.encode()).hexdigest()[:8]}",
            "private_key": private_key,
            "address": address,
            "public_key": public_key,
            "endpoint": ep_str,
            "dns": dns,
            "mtu": mtu,
            "country": "DE",
            "source": "new",
            "reserved": reserved,
            "keepalive": keepalive,
        }
    except Exception:
        return None


def parse_conf_text(text, source="new"):
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
            return None

        name = f"wg-DE-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}"

        return {
            "name": name,
            "private_key": pk,
            "address": addr or "172.16.0.2/32",
            "public_key": pubkey,
            "endpoint": endpoint,
            "dns": dns or "1.1.1.1, 8.8.8.8",
            "mtu": mtu or "1420",
            "country": "DE",
            "source": source,
        }
    except Exception:
        return None


def is_german_endpoint(endpoint):
    host = endpoint.split(":")[0] if ":" in endpoint else endpoint
    for prefix, country in KNOWN_GERMAN_RANGES.items():
        if host.startswith(prefix):
            return country == "DE"
    if any(kw in host.lower() for kw in ["de", "germany", "german", "frankfurt", "berlin", "dusseldorf", "hamburg", "munich", "nuremberg"]):
        return True
    return False


def fetch_from_pog7x():
    configs = []
    urls = [
        f"https://raw.githubusercontent.com/pog7x/vpn-configs/main/githubmirror/{i}.txt"
        for i in range(1, 26)
    ]
    for url in urls:
        data = fetch_url(url, timeout=10)
        if not data:
            continue
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg and is_german_endpoint(cfg["endpoint"]):
                    configs.append(cfg)
            elif "[Interface]" in line and "PrivateKey" in line:
                cfg = parse_conf_text(data, source="new")
                if cfg and is_german_endpoint(cfg["endpoint"]):
                    configs.append(cfg)
    return configs


def fetch_from_free_proxy_list():
    configs = []
    urls = [
        f"https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/{i}.txt"
        for i in range(1, 27)
    ]
    for url in urls:
        data = fetch_url(url, timeout=10)
        if not data:
            continue
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg and is_german_endpoint(cfg["endpoint"]):
                    configs.append(cfg)
    return configs


def fetch_from_gh94():
    configs = []
    url = "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Germany.txt"
    data = fetch_url(url, timeout=15)
    if data:
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg:
                    configs.append(cfg)
            elif line.startswith("wg://"):
                cfg = parse_wg_uri("wireguard://" + line[5:])
                if cfg:
                    configs.append(cfg)
    return configs


def fetch_from_warp_configs():
    configs = []
    url = "https://raw.githubusercontent.com/Delta-Kronecker/WARP-Config/refs/heads/main/ALL.txt"
    data = fetch_url(url, timeout=15)
    if data:
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg and (is_german_endpoint(cfg["endpoint"]) or "DE" in cfg.get("name", "")):
                    configs.append(cfg)
    return configs


def fetch_from_ni_revil():
    configs = []
    url = "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/v2rayng-wg.txt"
    data = fetch_url(url, timeout=15)
    if data:
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg and is_german_endpoint(cfg["endpoint"]):
                    configs.append(cfg)
    return configs


def fetch_from_amin():
    configs = []
    url = "https://raw.githubusercontent.com/amin4139/share_file/main/Wireguard.txt"
    data = fetch_url(url, timeout=15)
    if data:
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg and is_german_endpoint(cfg["endpoint"]):
                    configs.append(cfg)
    return configs


def fetch_from_protonvpn_zip():
    configs = []
    url = "https://github.com/Delta-Kronecker/ProtonVPN-WireGuard-configuration/raw/refs/heads/main/ProtonVPN_WireGuard_Configs.zip"
    try:
        import zipfile
        import io
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            zip_data = resp.read()
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for name in zf.namelist():
                if name.upper().startswith("DE/") and name.endswith(".conf"):
                    with zf.open(name) as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        cfg = parse_conf_text(content, source="new")
                        if cfg:
                            configs.append(cfg)
    except Exception as e:
        print(f"  ProtonVPN ZIP error: {e}")
    return configs


def fetch_from_au1rxx():
    configs = []
    url = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/wg-DE.txt"
    data = fetch_url(url, timeout=15)
    if data:
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("wireguard://"):
                cfg = parse_wg_uri(line)
                if cfg:
                    configs.append(cfg)
            elif "[Interface]" in line:
                cfg = parse_conf_text(data, source="new")
                if cfg:
                    configs.append(cfg)
    return configs


def deduplicate_configs(configs):
    seen = set()
    unique = []
    for cfg in configs:
        ep = cfg.get("endpoint", "")
        pk = cfg.get("private_key", "")
        key = f"{ep}:{pk}"
        if key not in seen:
            seen.add(key)
            unique.append(cfg)
    return unique


def main():
    print("=" * 60)
    print("  GERMAN WireGuard Config Fetcher")
    print("  Searching for DE configs from multiple sources...")
    print("=" * 60)

    all_servers = load_servers()
    existing_endpoints = {s["endpoint"] for s in all_servers}

    all_configs = []

    sources = [
        ("Pog7x Aggregator (25 files)", fetch_from_pog7x),
        ("FreeProxyList (26 files)", fetch_from_free_proxy_list),
        ("Argh94 Germany.txt", fetch_from_gh94),
        ("Delta-Kronecker WARP", fetch_from_warp_configs),
        ("NiREvil v2rayng-wg", fetch_from_ni_revil),
        ("Amin4139 Wireguard.txt", fetch_from_amin),
        ("ProtonVPN ZIP (DE folder)", fetch_from_protonvpn_zip),
        ("Au1rxx wg-DE", fetch_from_au1rxx),
    ]

    for source_name, fetch_func in sources:
        print(f"\n[*] Fetching from: {source_name}")
        try:
            configs = fetch_func()
            print(f"    Found {len(configs)} German configs")
            all_configs.extend(configs)
        except Exception as e:
            print(f"    Error: {e}")

    all_configs = deduplicate_configs(all_configs)
    print(f"\n[*] Total unique German configs found: {len(all_configs)}")

    added = 0
    skipped = 0

    for cfg in all_configs:
        ep = cfg["endpoint"]
        if ep in existing_endpoints:
            skipped += 1
            continue
        all_servers.append(cfg)
        existing_endpoints.add(ep)
        added += 1

    save_servers(all_servers)

    print(f"\n{'=' * 60}")
    print(f"  RESULTS:")
    print(f"  Added: {added} new German servers")
    print(f"  Skipped: {skipped} (already exist)")
    print(f"  Total servers in database: {len(all_servers)}")
    print(f"{'=' * 60}")

    return added


if __name__ == "__main__":
    main()
