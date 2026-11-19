# -*- coding: utf-8 -*-
"""Online config sources: WG bundle mirrors, ProtonVPN ZIP, VPNBook key generation."""

import re
import subprocess
import urllib.request
from .gold import stamp_fetched
from .parsing import parse_conf_from_text

PROTONVPN_ZIP_URL = "https://github.com/Delta-Kronecker/ProtonVPN-WireGuard-configuration/raw/refs/heads/main/ProtonVPN_WireGuard_Configs.zip"
WIREGUARD_BUNDLE_URL = "https://github.laiyagushi.com/ghraw/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt"
# Mirror is an untrusted proxy (MITM risk) -> prefer official raw, fallback mirror
WIREGUARD_BUNDLE_URLS = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt",
    WIREGUARD_BUNDLE_URL,
]

def fetch_bundle_text(timeout=60):
    """Try bundle mirrors in order. Returns (text, url_used) or (None, None)."""
    last_err = None
    for url in WIREGUARD_BUNDLE_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore"), url
        except Exception as e:
            last_err = e
            continue
    return None, last_err


def fetch_proton_zip(timeout=60):
    """Download ProtonVPN ZIP. Returns bytes or raises."""
    req = urllib.request.Request(PROTONVPN_ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _proton_country(filename):
    """Country code from ZIP path: folder ('us/x.conf') or file prefix ('us-01.conf').

    Returns any 2-letter code (US, NL, JP, CA, DE, ...) so Fetch gets ALL IPs,
    not only US/DE. Falls back to 'XX' when undetectable.
    """
    try:
        parts = (filename or "").lower().split("/")
        if parts and re.match(r"^[a-z]{2}$", parts[0] or ""):
            return parts[0].upper()
        base = parts[-1] if parts else ""
        m = re.match(r"^([a-z]{2})([\-_\.]|\d)", base)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return "XX"


def iter_proton_servers(zdata, source="ProtonVPN", limit=None):
    """Single Proton-ZIP parser (dedup: fetch + refresh shared).

    Yields server dicts for ALL countries (stamped) with clear numbered names.
    Skips unparsable entries only. Country comes from ZIP folder name.
    """
    import zipfile
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            names = sorted([n for n in zf.namelist() if n.endswith(".conf")])
            for filename in names:
                if limit is not None and limit <= 0:
                    break
                country = _proton_country(filename)
                if not country:
                    country = "XX"
                try:
                    with zf.open(filename) as f:
                        content = f.read().decode("utf-8", errors="ignore")
                    server, error = parse_conf_from_text(content, source=source)
                    if error or not server:
                        continue
                    server["country"] = country
                    # Clear section: keep original config name (already like wg-US-FREE-104)
                    base = filename.split("/")[-1].replace(".conf", "")
                    server["name"] = base if base.startswith("wg-") else f"wg-{country}-{base}"
                    stamp_fetched(server, PROTONVPN_ZIP_URL)
                    if limit is not None:
                        limit -= 1
                    yield server
                except Exception:
                    continue
    except Exception:
        return


def get_vpnbook_pubkey(host):
    try:
        result = subprocess.run(
            ["wg", "show", "interfaces"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception:
        pass
    known_keys = {
        "us16.vpnbook.com": "6UQ1vR7kGMe2zOBAp8YCoDQNnQChYFkfGOWh+vsR9nM=",
        "us178.vpnbook.com": "6UQ1vR7kGMe2zOBAp8YCoDQNnQChYFkfGOWh+vsR9nM=",
        "de20.vpnbook.com": "6UQ1vR7kGMe2zOBAp8YCoDQNnQChYFkfGOWh+vsR9nM=",
        "de220.vpnbook.com": "6UQ1vR7kGMe2zOBAp8YCoDQNnQChYFkfGOWh+vsR9nM=",
    }
    return known_keys.get(host)


def generate_wg_key():
    try:
        result = subprocess.run(
            ["wg", "genkey"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    import base64
    import os as _os
    key = _os.urandom(32)
    return base64.b64encode(key).decode()
