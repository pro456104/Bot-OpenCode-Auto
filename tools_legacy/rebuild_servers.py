import os
import json
import re
import socket
import zipfile
import io
import urllib.request
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")
DE_BACKUP = os.path.join(BASE_DIR, "configs", "de_new_backup.json")
PROTONVPN_ZIP = "https://github.com/Delta-Kronecker/ProtonVPN-WireGuard-configuration/raw/refs/heads/main/ProtonVPN_WireGuard_Configs.zip"


def load_servers():
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    return []


def save_servers(servers):
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)


def parse_conf_text(text, source="ProtonVPN"):
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

        country = "Unknown"
        ep_host = endpoint.split(":")[0] if ":" in endpoint else endpoint

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ep_host):
            try:
                host = socket.gethostbyname(ep_host)
                if host.startswith("51.75."):
                    country = "DE"
                elif host.startswith("147.135."):
                    country = "US"
                elif host.startswith("188.114."):
                    country = "CF"
                elif host.startswith("162.159."):
                    country = "CF"
            except Exception:
                pass

        name = f"wg-{country}-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}"

        return {
            "name": name,
            "private_key": pk,
            "address": addr,
            "public_key": pubkey,
            "endpoint": endpoint,
            "dns": dns or "1.1.1.1, 8.8.8.8",
            "mtu": mtu or "1420",
            "country": country,
            "source": source,
        }, None
    except Exception as e:
        return None, str(e)


def get_country_from_filename(filename):
    basename = os.path.splitext(os.path.basename(filename))[0]
    parts = basename.split("-")
    if len(parts) >= 2:
        code = parts[1].upper()
        if len(code) == 2:
            return code
    return "Unknown"


def main():
    print("=" * 60)
    print("  STEP 1: Adding German (DE) configs...")
    print("=" * 60)

    servers = []

    if os.path.exists(DE_BACKUP):
        with open(DE_BACKUP, "r", encoding="utf-8") as f:
            de_configs = json.load(f)
        for cfg in de_configs:
            servers.append(cfg)
        print(f"  Added {len(de_configs)} German configs from backup")
    else:
        print("  No German backup found!")

    print(f"\n{'=' * 60}")
    print("  STEP 2: Downloading ProtonVPN ZIP...")
    print("=" * 60)

    try:
        req = urllib.request.Request(PROTONVPN_ZIP, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=60) as resp:
            zip_data = resp.read()
        print(f"  Downloaded: {len(zip_data) / 1024 / 1024:.1f} MB")
    except Exception as e:
        print(f"  ERROR downloading: {e}")
        save_servers(servers)
        return

    print(f"\n{'=' * 60}")
    print("  STEP 3: Extracting and parsing configs...")
    print("=" * 60)

    existing_endpoints = {s["endpoint"] for s in servers}
    added = 0
    skipped = 0
    errors = 0
    country_count = {}

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        conf_files = [n for n in zf.namelist() if n.endswith(".conf")]
        print(f"  Found {len(conf_files)} .conf files in ZIP")

        for name in conf_files:
            try:
                with zf.open(name) as f:
                    content = f.read().decode("utf-8", errors="ignore")

                country = get_country_from_filename(name)

                server, error = parse_conf_text(content, source="ProtonVPN")
                if error:
                    errors += 1
                    continue

                server["country"] = country
                server["name"] = f"wg-{country}-{hashlib.md5(server['endpoint'].encode()).hexdigest()[:8]}"

                if server["endpoint"] in existing_endpoints:
                    skipped += 1
                    continue

                servers.append(server)
                existing_endpoints.add(server["endpoint"])
                country_count[country] = country_count.get(country, 0) + 1
                added += 1

            except Exception as e:
                errors += 1

    save_servers(servers)

    print(f"\n{'=' * 60}")
    print("  RESULTS:")
    print(f"  German configs added: {len(de_configs) if os.path.exists(DE_BACKUP) else 0}")
    print(f"  ProtonVPN configs added: {added}")
    print(f"  Skipped (duplicates): {skipped}")
    print(f"  Errors: {errors}")
    print(f"  Total servers: {len(servers)}")
    print(f"{'=' * 60}")

    print(f"\n  Countries breakdown:")
    for c in sorted(country_count.keys()):
        print(f"    {c}: {country_count[c]}")

    print(f"\n{'=' * 60}")
    print("  STEP 4: Verifying format...")
    print("=" * 60)

    valid = 0
    invalid = 0
    for s in servers:
        if s.get("private_key") and s.get("endpoint") and s.get("public_key"):
            valid += 1
        else:
            invalid += 1
            print(f"  INVALID: {s.get('name', '?')} - missing fields")

    print(f"  Valid configs: {valid}")
    print(f"  Invalid configs: {invalid}")
    print(f"\n  DONE!")


if __name__ == "__main__":
    main()
