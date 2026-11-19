# -*- coding: utf-8 -*-
"""WireGuard config parsers: .conf text/file, wireguard:// URI, country classification."""

import os
import re

def _parse_wg_lines(text):
    """Single .conf parser (dedup: parse_conf + parse_conf_from_text shared)."""
    pk = addr = pubkey = endpoint = dns = mtu = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "privatekey":
            pk = val
        elif key == "address":
            addr = val.split(",")[0].strip()
        elif key == "publickey":
            pubkey = val
        elif key == "endpoint":
            endpoint = val
        elif key == "dns":
            dns = val
        elif key == "mtu":
            mtu = val
    return pk, addr, pubkey, endpoint, dns, mtu


def _guess_country_from_ip_literal(ep_host):
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ep_host or ""):
        if ep_host.startswith("51.75."):
            return "DE"
        if ep_host.startswith("147.135."):
            return "US"
    return "Unknown"


def parse_conf(filepath):
    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            content = f.read()
        pk, addr, pubkey, endpoint, dns, mtu = _parse_wg_lines(content)
        if not pk or not endpoint:
            return None, "Missing PrivateKey or Endpoint"
        ep_host = endpoint.split(":")[0] if ":" in endpoint else endpoint
        name = os.path.splitext(os.path.basename(filepath))[0]
        return {
            "name": name, "private_key": pk, "address": addr,
            "public_key": pubkey, "endpoint": endpoint,
            "dns": dns or "1.1.1.1, 8.8.8.8", "mtu": mtu or "1420",
            "country": _guess_country_from_ip_literal(ep_host),
            "source": "Imported",
        }, None
    except Exception as e:
        return None, str(e)

def parse_wireguard_uri(line):
    """Single wireguard:// URI parser (bundle/import helpers shared).

    Returns dict(server) or None. Fixes historic endpoint_raw bug where
    endpoint was decoded from the private-key part.
    """
    try:
        import urllib.parse as urlparse
        line = (line or "").strip()
        if not line.startswith("wireguard://"):
            return None
        uri = line[len("wireguard://"):]
        comment = urlparse.unquote(uri.rsplit("#", 1)[1]) if "#" in uri else ""
        main = uri.rsplit("#", 1)[0]
        before, _, params_str = main.partition("?")
        priv_enc, sep, ep_enc = before.rpartition("@")
        if not sep:
            return None
        priv = urlparse.unquote(priv_enc)
        ep_raw = urlparse.unquote(ep_enc)
        host, _, port = ep_raw.rpartition(":")
        if not host:
            return None
        port = port or "51820"
        pm = {}
        for pair in (params_str or "").split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                pm[k] = urlparse.unquote(v)
        if not pm.get("publickey") or not priv:
            return None
        return {
            "private_key": priv,
            "address": pm.get("address", "172.16.0.2/32"),
            "public_key": pm["publickey"],
            "endpoint": f"{host}:{port}",
            "mtu": pm.get("mtu", "1380"),
            "comment": comment,
        }
    except Exception:
        return None

_BUNDLE_RANGES = {
    "188.114": "CF", "162.159": "CF",
    "51.75": "DE", "141.98": "DE", "5.189": "DE",
    "104.244": "US", "8.6": "US", "147.135": "US",
    "185.199": "US", "172.64": "US", "66.235": "US",
}
_BUNDLE_KW = {
    "united states": "US", "america": "US",
    "germany": "DE", "german": "DE", "deutschland": "DE",
}


def classify_bundle_country(comment, host):
    """Shared US/DE/CF classifier for wireguard:// bundle lines."""
    try:
        t = (comment or "").lower()
        for kw, code in _BUNDLE_KW.items():
            if kw in t:
                return code
        # Token match on separators (old "us " matched "abuse " etc.)
        if re.search(r"(^|[\s\-_\[\]\(\)])us($|[\s\-_\[\]\(\)\d])", t):
            return "US"
        if re.search(r"(^|[\s\-_\[\]\(\)])de($|[\s\-_\[\]\(\)\d])", t):
            return "DE"
        prefix = ".".join((host or "").split(".")[:2])
        return _BUNDLE_RANGES.get(prefix, "XX")
    except Exception:
        return "XX"

def parse_conf_from_text(text, source="Custom"):
    try:
        pk, addr, pubkey, endpoint, dns, mtu = _parse_wg_lines(text)
        if not pk or not endpoint:
            return None, "Missing PrivateKey or Endpoint"
        ep_host = endpoint.split(":")[0] if ":" in endpoint else endpoint
        country = _guess_country_from_ip_literal(ep_host)
        name = f"wg-{country}-{source[:4].upper()}"
        return {
            "name": name, "private_key": pk, "address": addr,
            "public_key": pubkey, "endpoint": endpoint,
            "dns": dns or "1.1.1.1, 8.8.8.8", "mtu": mtu or "1420",
            "country": country, "source": source,
        }, None
    except Exception as e:
        return None, str(e)
