"""
harvest_ips.py - Deep multi-source WireGuard harvester for DE / NL / FR.

IMPORTANT - what this program actually consumes:
    vpn_bot.py is a WireGuard-only client. Its input to servers.json is exactly
    these 9 keys (vpn_bot.py:364-370 / 1084-1097):
        name, private_key, address, public_key, endpoint, dns, mtu, country, source
    and its bulk-import format is a .conf with [Interface] PrivateKey/Address/
    DNS/MTU + [Peer] PublicKey/Endpoint/AllowedIPs/PersistentKeepalive.
    The HTTP/SOCKS proxies on 127.0.0.1:8080 / :10808 are wireproxy's *output*
    (wireproxy.conf:13-17), NOT input. So "IPs" here means WireGuard ENDPOINT
    IPs (public UDP ip:port), never http/socks proxy lists.

Pipeline:
    1. download every public config mirror / bundle
    2. parse wireguard:// URIs, inline .conf blocks and base64 sub payloads
    3. geolocate the endpoint IP with a local DB-IP country table (accurate, no
       rate limit) so DE/NL/FR filtering is real and not prefix guessing
    4. verify with a genuine WireGuard handshake probe: mac1 is computed with
       the config's own public key, so the responder decrypts, sees an unknown
       sender index and answers with a 92-byte handshake response. That proves
       the endpoint is reachable AND the public key belongs to a live server.
    5. re-validate every output entry against vpn_bot.py's own parsing rules,
       then write .conf files + a merge-ready servers.json into ips-new/

Usage:
    python harvest_ips.py                      # DE NL FR
    python harvest_ips.py DE NL FR US GB       # any ISO2 codes
    python harvest_ips.py --no-probe           # skip handshake verification
"""

import base64
import bisect
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import random
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse as up
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "ips-new")
RAW_DIR = os.path.join(OUT_DIR, "raw")
GEO_CACHE = os.path.join(OUT_DIR, "geo_cache.json")

UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "*/*",
}

PORT_RE = re.compile(r"^\d{1,5}$")

MISS = "\x00miss"  # sentinel: "looked up, no country" - never retry online


# ----------------------------------------------------------------------------
# SOURCES  --  where the IPs actually come from
# ----------------------------------------------------------------------------
def build_sources(countries):
    """(name, url, country_hint_or_None) - WireGuard config sources only."""
    src = []

    # --- global config bundles (need per-IP geo lookup) ---------------------
    for name, url in [
        ("morpheusadam-v2ray-wireguard",
         "https://github.laiyagushi.com/ghraw/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt"),
        ("Delta-Kronecker-WARP",
         "https://raw.githubusercontent.com/Delta-Kronecker/WARP-Config/refs/heads/main/ALL.txt"),
        ("NiREvil-vless-wg",
         "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/v2rayng-wg.txt"),
        ("amin4139-Wireguard",
         "https://raw.githubusercontent.com/amin4139/share_file/main/Wireguard.txt"),
        ("mahdibland-V2RayAggregator-Eternity",
         "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt"),
        ("Epodonios-v2ray-configs-all",
         "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"),
        ("barry-far-V2ray-Configs",
         "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"),
        ("TarikJaber-erothu",
         "https://raw.githubusercontent.com/TarikJaber/Proxy-Sub/main/Online%20Proxy/Eternity.txt"),
        ("Epodonios-sub",
         "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub%20Configs%20Combined.txt"),
        ("10ium-SUB",
         "https://raw.githubusercontent.com/10ium/SUB/main/Config%20List/All.txt"),
        ("10ium-WG",
         "https://raw.githubusercontent.com/10ium/SUB/main/Config%20List/wireguard.txt"),
        ("iboxz-freevpn",
         "https://raw.githubusercontent.com/iboxz/free-vpn-collector/main/wireguard.txt"),
        ("Darkx7-vpnconfigs",
         "https://raw.githubusercontent.com/Darkx7/vpnconfigs/main/wireguard.txt"),
        ("freevpn-tech",
         "https://raw.githubusercontent.com/freevpn-tech/freevpn-configs/main/wireguard.txt"),
    ]:
        src.append((name, url, None))

    # --- paginated mirrors -------------------------------------------------
    for i in range(1, 61):
        src.append((f"nikita29a-mirror-{i}",
                    f"https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/{i}.txt",
                    None))
    for i in range(1, 61):
        src.append((f"pog7x-mirror-{i}",
                    f"https://raw.githubusercontent.com/pog7x/vpn-configs/main/githubmirror/{i}.txt",
                    None))

    # --- per-country files --------------------------------------------------
    long_names = {"DE": "Germany", "NL": "Netherlands", "FR": "France",
                  "GB": "England", "US": "United States", "CA": "Canada",
                  "SE": "Sweden", "CH": "Switzerland", "PL": "Poland",
                  "FI": "Finland", "AT": "Austria", "BE": "Belgium",
                  "ES": "Spain", "IT": "Italy", "RU": "Russia", "TR": "Turkey",
                  "IN": "India", "JP": "Japan", "SG": "Singapore",
                  "AU": "Australia", "BR": "Brazil", "CZ": "Czechia",
                  "NO": "Norway", "DK": "Denmark", "IE": "Ireland",
                  "PT": "Portugal", "UA": "Ukraine", "AE": "UnitedArabEmirates",
                  "IL": "Israel", "ZA": "SouthAfrica", "CN": "China",
                  "RO": "Romania", "HU": "Hungary", "UA2": "Ukraine"}

    for cc in countries:
        long_name = long_names.get(cc, cc)
        # per-country files (hint is advisory, real filter is DB-IP)
        src.append((f"Argh94-{long_name}",
                    f"https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/{long_name}.txt",
                    cc))
        src.append((f"Au1rxx-wg-{cc}",
                    f"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/wg-{cc}.txt",
                    cc))
        src.append((f"AbbasMaHRdi-{cc}",
                    f"https://raw.githubusercontent.com/AbbasMaHRdi/free-vpn-servers/main/{cc}.txt",
                    cc))
        src.append((f"proxifly-wg-{cc}",
                    f"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{cc}/data.txt",
                    cc))
        # ProtonVPN official per-country WireGuard config zip
        src.append((f"ProtonVPN-ZIP-{cc}",
                    "https://github.com/Delta-Kronecker/ProtonVPN-WireGuard-configuration/raw/refs/heads/main/ProtonVPN_WireGuard_Configs.zip",
                    cc))
    return src


# ----------------------------------------------------------------------------
# HTTP with retries
# ----------------------------------------------------------------------------
def http_get(url, timeout=45, retries=3, raw=False):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if data[:4] == b"PK\x03\x04":
                return _unzip_confs(data)
            return data if raw else data.decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            if e.code in (404, 401, 403, 410):
                return None
            time.sleep(1.2 * (attempt + 1))
        except Exception:
            time.sleep(1.2 * (attempt + 1))
    return None


def _unzip_confs(blob):
    """ProtonVPN-style zip of per-country .conf folders -> flat conf text.
    Only the folders named in COUNTRY_DIRS are kept so the archive stays small."""
    import io
    import zipfile
    try:
        parts = []
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".conf"):
                    continue
                head = name.split("/", 1)[0].strip().upper()[:2]
                if head not in COUNTRY_DIRS:
                    continue
                parts.append(zf.read(name).decode("utf-8", "ignore"))
        return "\n\n".join(parts) if parts else None
    except Exception:
        return None


COUNTRY_DIRS = set()


def _init_country_dirs(countries):
    global COUNTRY_DIRS
    alias = {"UK": "GB", "GB": "GB"}
    COUNTRY_DIRS = {alias.get(c, c) for c in countries}


_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


# ----------------------------------------------------------------------------
# GEOLOCATION  --  local DB-IP country table (no rate limit), cached
# ----------------------------------------------------------------------------
class Geo:
    """IP -> ISO2 country via a local DB-IP country-lite table.

    DB-IP rows are VARIABLE size CIDRs ('start,end,cc'), e.g.
    1.0.0.0-1.255.255.255=AU next to 1.0.0.0..1.0.0.255 style blocks, so an exact
    /24 or /16 dict lookup silently misses most addresses. The table is loaded
    into two sorted int arrays and searched with bisect on the IP as a 32-bit
    integer - O(log n) and always correct."""

    def __init__(self):
        self.starts = []
        self.ends = []
        self.ccs = []
        self.cache = {}
        self.lock = threading.Lock()
        if os.path.exists(GEO_CACHE):
            try:
                self.cache = json.load(open(GEO_CACHE, encoding="utf-8"))
            except Exception:
                self.cache = {}
        self._load_dbip()

    def _load_dbip(self):
        for month in _recent_months(4):
            url = f"https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
            blob = http_get(url, timeout=120, retries=2, raw=True)
            if not blob:
                continue
            try:
                txt = gzip.decompress(blob).decode("utf-8", "ignore")
            except Exception:
                continue
            rows = []
            for line in txt.splitlines():
                p = line.split(",")
                if len(p) < 3 or not p[0][0].isdigit():
                    continue
                try:
                    rows.append((_ip2int(p[0]), _ip2int(p[1]), p[2].strip().upper()))
                except ValueError:
                    continue
            rows.sort()
            self.starts = [r[0] for r in rows]
            self.ends = [r[1] for r in rows]
            self.ccs = [r[2] for r in rows]
            log(f"  geo: DB-IP {month} -> {len(rows):,} CIDR blocks")
            return
        log("  geo: WARNING DB-IP unavailable, online fallback only")

    def lookup_many(self, ips):
        """Warm nothing - the local DB-IP table is the authority and is far more
        reliable than the online fallback, so pre-filling the cache with online
        results (or None) would poison every later code() call. Only flush."""
        try:
            json.dump(self.cache, open(GEO_CACHE, "w", encoding="utf-8"))
        except Exception:
            pass
        return {ip: self.code(ip) for ip in ips}

    @staticmethod
    def _online(chunk):
        try:
            body = json.dumps(chunk).encode()
            req = urllib.request.Request(
                "https://ipwho.is/batch?fields=success,country_code",
                data=body,
                headers={"Content-Type": "application/json", **UA})
            with urllib.request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode("utf-8", "ignore"))
            out = {}
            for ip, row in zip(chunk, rows):
                cc = row.get("country_code") if isinstance(row, dict) and row.get("success") else None
                out[ip] = cc.upper()[:2] if cc else MISS
            return out
        except Exception:
            return {ip: MISS for ip in chunk}

    def code(self, ip):
        """Local CIDR table first; online lookup only for genuine table misses
        (IPv6, or an address DB-IP does not carry). MISS is cached so a failing
        fallback is never retried."""
        if ip in self.cache:
            v = self.cache[ip]
            return None if v is MISS or not v else v

        cc = None
        if _valid_ip(ip) and self.starts:
            try:
                n = _ip2int(ip)
                # last block whose start <= n
                i = bisect.bisect_right(self.starts, n) - 1
                if i >= 0 and n <= self.ends[i] and self.ccs[i] not in ("ZZ", ""):
                    cc = self.ccs[i]
            except ValueError:
                cc = None
        if cc is None:
            cc = self._online([ip]).get(ip) or None

        with self.lock:
            self.cache[ip] = cc if cc else MISS
        return cc


def _valid_ip(ip):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip or ""))


def _ip2int(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _recent_months(n):
    import datetime
    now = datetime.datetime.now()
    out = []
    y, m = now.year, now.month
    for _ in range(n):
        out.append(f"{y}-{m:02d}")
        m -= 1
        if m == 0:
            m, y = 12, y - 1
    return out


# ----------------------------------------------------------------------------
# PARSERS
# ----------------------------------------------------------------------------
WG_URI_RE = re.compile(r"^(wireguard|wg)://", re.I)
B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{60,}$")


def parse_wireguard_uri(line, source):
    if not WG_URI_RE.match(line):
        return None
    uri = line[line.index("://") + 3:]
    comment = ""
    if "#" in uri:
        uri, comment = uri.rsplit("#", 1)
        comment = up.unquote(comment)
    uri = uri.split("?", 1)
    before = uri[0]
    params = {}
    if len(uri) > 1:
        for pair in uri[1].split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.lower()] = up.unquote(v)
    if "@" not in before:
        return None
    key_enc, endpoint_raw = before.rsplit("@", 1)
    private_key = up.unquote(key_enc)
    endpoint_raw = up.unquote(endpoint_raw)

    if ":" in endpoint_raw:
        host, port_s = endpoint_raw.rsplit(":", 1)
    else:
        host, port_s = endpoint_raw, "51820"
    if not PORT_RE.match(port_s):
        port_s = "51820"

    public_key = params.get("publickey") or params.get("pubkey") or params.get("peerkey") or ""
    address = params.get("address", "172.16.0.2/32")
    mtu = params.get("mtu", "1420")
    dns = params.get("dns", "1.1.1.1, 8.8.8.8")
    keepalive = params.get("keepalive", "25")

    if not host or not public_key or not private_key:
        return None
    return {
        "private_key": private_key,
        "address": address,
        "public_key": public_key,
        "endpoint": f"{host}:{port_s}",
        "host": host,
        "port": int(port_s),
        "dns": dns,
        "mtu": mtu,
        "keepalive": keepalive,
        "comment": comment,
        "source": source,
    }


def parse_conf_block(text, source):
    """Parse a [Interface]/[Peer] wireguard .conf into the same dict."""
    pk = addr = pub = endpoint = dns = mtu = keepalive = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        low = k.lower()
        if low == "privatekey":
            pk = v
        elif low == "address":
            addr = v.split(",")[0].strip()
        elif low == "publickey":
            pub = v
        elif low == "endpoint":
            endpoint = v
        elif low == "dns":
            dns = v
        elif low == "mtu":
            mtu = v
        elif low == "persistentkeepalive":
            keepalive = v
    if not pk or not pub or not endpoint:
        return None
    if ":" in endpoint:
        host, port_s = endpoint.rsplit(":", 1)
    else:
        host, port_s = endpoint, "51820"
    if not PORT_RE.match(port_s):
        port_s = "51820"
    if not host or ":" in host:
        return None
    return {
        "private_key": pk, "address": addr or "172.16.0.2/32", "public_key": pub,
        "endpoint": f"{host}:{port_s}", "host": host, "port": int(port_s),
        "dns": dns or "1.1.1.1, 8.8.8.8", "mtu": mtu or "1420",
        "keepalive": keepalive or "25", "comment": "", "source": source,
    }


PROTO_RE = re.compile(r"^(https?|socks4a?|socks5h?)://", re.I)


def extract_payloads(text, depth=0):
    """Find raw configs inside base64 subscription blobs."""
    payloads = [text]
    if depth > 2:
        return payloads
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 80 or "://" in line or "[" in line:
            continue
        if not B64_RE.match(line):
            continue
        try:
            dec = base64.b64decode(line + "=" * (-len(line) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if "://" in dec or "[Interface]" in dec:
            payloads.extend(extract_payloads(dec, depth + 1))
    return payloads


# ----------------------------------------------------------------------------
# VERIFIERS
# ----------------------------------------------------------------------------
def wg_handshake_probe(host, port, public_key_b64, timeout=3.0):
    """True only if a real WireGuard responder answers.
    mac1 = BLAKE2s(peer_public_key, packet[0:116]) -> responder decrypts, sees an
    unknown sender index, replies 92-byte handshake response (type 2)."""
    try:
        pub = base64.b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
    except Exception:
        return False, "badkey"
    if len(pub) != 32:
        return False, "badkeylen"
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = bytearray(struct.pack("<II", 1, 1) + os.urandom(32) + b"\x00" * 48 + b"\x00" * 28)
        mac = hashlib.blake2s(digest_size=16)
        mac.update(pub)
        mac.update(bytes(pkt[:116]))
        pkt += mac.digest() + b"\x00" * 16
        sock.sendto(bytes(pkt), (host, port))
        data, _ = sock.recvfrom(256)
        if len(data) == 92 and struct.unpack("<I", data[:4])[0] == 2:
            return True, "handshake-ok"
        return False, f"reply{len(data)}B"
    except socket.timeout:
        return False, "timeout"
    except Exception as e:
        return False, type(e).__name__
    finally:
        if sock:
            sock.close()


def verify_wg(cfg, attempts=2):
    for i in range(attempts):
        t0 = time.time()
        ok, why = wg_handshake_probe(cfg["host"], cfg["port"], cfg["public_key"])
        if ok:
            return True, round((time.time() - t0) * 1000, 1)
        time.sleep(0.35 * (i + 1))
    return False, -1


# ----------------------------------------------------------------------------
# OUTPUT  --  byte-compatible with vpn_bot.py's parsers
# ----------------------------------------------------------------------------
SERVER_KEYS = ("name", "private_key", "address", "public_key", "endpoint",
               "dns", "mtu", "country", "source")


def bot_parse_conf_text(text):
    """Byte-for-byte reimplementation of vpn_bot.py _parse_wg_lines +
    parse_conf() so anything written here is guaranteed loadable by the app."""
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


def validate_for_bot(cfg):
    """Run the entry back through the app's own .conf parser + wireproxy field
    rules. Returns (ok, reason)."""
    pk, addr, pub, endpoint, dns, mtu = bot_parse_conf_text(conf_text(cfg, "validate"))
    if not pk:
        return False, "no PrivateKey"
    if not endpoint:
        return False, "no Endpoint"
    if not pub:
        return False, "no PublicKey"
    host, _, port = endpoint.rpartition(":")
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        return False, f"bad endpoint {endpoint}"
    try:
        if len(base64.b64decode(pk + "=" * (-len(pk) % 4))) != 32:
            return False, "PrivateKey not 32 bytes"
    except Exception:
        return False, "PrivateKey not base64"
    try:
        if len(base64.b64decode(pub + "=" * (-len(pub) % 4))) != 32:
            return False, "PublicKey not 32 bytes"
    except Exception:
        return False, "PublicKey not base64"
    if "/" not in addr:
        return False, f"bad Address {addr}"
    return True, "ok"


def conf_text(cfg, tag):
    """Same field set wireproxy consumes, matching vpn_bot.py's generator."""
    return (
        f"[Interface]\n"
        f"PrivateKey = {cfg['private_key']}\n"
        f"Address = {cfg['address']}\n"
        f"DNS = {cfg['dns']}\n"
        f"MTU = {cfg['mtu']}\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {cfg['public_key']}\n"
        f"Endpoint = {cfg['endpoint']}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = {cfg['keepalive']}\n"
        f"# {tag}\n"
    )


def main():
    args = [a.upper() for a in sys.argv[1:] if not a.startswith("-")]
    do_probe = "--no-probe" not in sys.argv
    countries = args[:12] if args else ["DE", "NL", "FR"]
    _init_country_dirs(countries)

    os.makedirs(RAW_DIR, exist_ok=True)

    log("=" * 70)
    log(f"  WIREGUARD HARVEST   countries={','.join(countries)}")
    log(f"  output -> {OUT_DIR}")
    log(f"  output type: vpn_bot.py servers.json schema (9 keys) + .conf")
    log("=" * 70)

    # ---------------- 1. download ----------------
    log("\n[1/6] Downloading WireGuard sources ...")
    sources = build_sources(countries)
    fetched = {}

    def grab(item):
        name, url, hint = item
        return item, http_get(url, timeout=90, retries=3)

    with cf.ThreadPoolExecutor(20) as ex:
        for (name, url, hint), text in ex.map(grab, sources):
            if text and len(text) > 120:
                fetched[name] = (url, hint, text)
                safe = up.quote(name, safe="")
                try:
                    with open(os.path.join(RAW_DIR, safe + ".txt"), "w", encoding="utf-8") as fh:
                        fh.write(f"# source: {url}\n{text}")
                except Exception:
                    pass
    log(f"  alive sources: {len(fetched)} / {len(sources)}")

    # ---------------- 2. parse ----------------
    log("\n[2/6] Parsing wireguard:// URIs and .conf blocks ...")
    cands, per_source = [], []

    for name, (url, hint, text) in fetched.items():
        before = len(cands)
        for payload in extract_payloads(text):
            if "[Interface]" in payload and "PrivateKey" in payload:
                for block in re.split(r"\n\s*\n(?=\[Interface\])", payload):
                    cfg = parse_conf_block(block, name)
                    if cfg:
                        cands.append(cfg)
            for line in payload.splitlines():
                line = line.strip()
                if WG_URI_RE.match(line):
                    cfg = parse_wireguard_uri(line, name)
                    if cfg:
                        cands.append(cfg)
        per_source.append({"source": name, "url": url, "country_hint": hint,
                           "configs": len(cands) - before,
                           "alive": False})

    seen, uniq = set(), []
    for c in cands:
        k = (c["endpoint"], c["public_key"])
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    log(f"  parsed {len(cands)} -> {len(uniq)} unique (endpoint+pubkey)")

    # ---------------- 3. geolocate ----------------
    log("\n[3/6] Geolocating endpoint IPs with local DB-IP table ...")
    geo = Geo()
    ips = [c["host"] for c in uniq if re.match(r"^\d+\.\d+\.\d+\.\d+$", c["host"])]
    hosts = [c["host"] for c in uniq if not re.match(r"^\d+\.\d+\.\d+\.\d+$", c["host"])]
    geo.lookup_many(list(set(ips)))
    if hosts:
        log(f"  {len(set(hosts))} hostname endpoints -> resolved at connect time")
    for c in uniq:
        c["country"] = geo.code(c["host"])

    by_cc = {}
    for c in uniq:
        if c.get("country") in countries:
            by_cc.setdefault(c["country"], []).append(c)
    for cc in countries:
        log(f"  {cc}: {len(by_cc.get(cc, []))} candidates")

    # ---------------- 4. verify ----------------
    flat = [c for cc in countries for c in by_cc.get(cc, [])]
    live = []
    if do_probe:
        log(f"\n[4/6] Verifying {len(flat)} endpoints with a real WireGuard handshake ...")

        def wg_job(cfg):
            return cfg, verify_wg(cfg)

        with cf.ThreadPoolExecutor(150) as ex:
            done = 0
            for cfg, (ok, ms) in ex.map(wg_job, flat):
                done += 1
                if done % 200 == 0:
                    log(f"    {done}/{len(flat)} probed, live={len(live)}")
                if ok:
                    cfg["latency_ms"] = ms
                    live.append(cfg)
    else:
        log("\n[4/6] Probe skipped (--no-probe)")
        for c in flat:
            c["latency_ms"] = -1
        live = flat
    log(f"  LIVE: {len(live)} / {len(flat)}")

    # ---------------- 5. validate against the app's own parser -------------
    log("\n[5/6] Re-validating every entry with vpn_bot.py's .conf parser ...")
    good, rejected = [], {}
    for c in live:
        ok, why = validate_for_bot(c)
        if ok:
            good.append(c)
        else:
            rejected[why] = rejected.get(why, 0) + 1
    log(f"  accepted {len(good)}, rejected {len(live) - len(good)}")
    for why, n in sorted(rejected.items(), key=lambda x: -x[1]):
        log(f"    {n:>4}  {why}")

    # ---------------- 6. write ----------------
    log("\n[6/6] Writing ...")
    summary = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
               "type": "wireguard",
               "schema_keys": list(SERVER_KEYS),
               "countries": countries, "per_country": {}}
    servers_out = []

    for cc in countries:
        cdir = os.path.join(OUT_DIR, cc)
        os.makedirs(cdir, exist_ok=True)

        wgs = sorted([c for c in good if c["country"] == cc],
                     key=lambda x: x.get("latency_ms", 1e9))

        # combined .conf (multi-block, drop-in for Bulk Import / Paste Config)
        if wgs:
            with open(os.path.join(cdir, f"wireguard_{cc}.conf"), "w", encoding="utf-8") as fh:
                for c in wgs:
                    fh.write(conf_text(c, f"{c['endpoint']} {c.get('latency_ms')}ms "
                                         f"src={c['source']} {c['comment'] or ''}".strip()))
                    fh.write("\n")

        # one .conf per server
        sub = os.path.join(cdir, "wireguard")
        os.makedirs(sub, exist_ok=True)
        for i, c in enumerate(wgs, 1):
            c["name"] = f"wg-{cc}-{i:03d}"
            servers_out.append({
                "name": c["name"],
                "private_key": c["private_key"],
                "address": c["address"],
                "public_key": c["public_key"],
                "endpoint": c["endpoint"],
                "dns": c["dns"],
                "mtu": c["mtu"],
                "country": cc,
                "source": c["source"],
            })
            with open(os.path.join(sub, f"{c['name']}.conf"), "w", encoding="utf-8") as fh:
                fh.write(conf_text(c, f"{c['endpoint']} {c.get('latency_ms')}ms src={c['source']}"))

        with open(os.path.join(cdir, f"endpoints_{cc}.txt"), "w", encoding="utf-8") as fh:
            for c in wgs:
                fh.write(f"{c['endpoint']}\t{c.get('latency_ms')}ms\t{c['source']}\n")

        summary["per_country"][cc] = {
            "live": len(wgs),
            "candidates": len(by_cc.get(cc, [])),
            "endpoints": [c["endpoint"] for c in wgs],
        }
        log(f"  {cc}: {len(wgs)} live -> {cc}/wireguard/ + wireguard_{cc}.conf")

    with open(os.path.join(OUT_DIR, "servers.json"), "w", encoding="utf-8") as fh:
        json.dump(servers_out, fh, indent=2)
    with open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    with open(os.path.join(OUT_DIR, "sources.json"), "w", encoding="utf-8") as fh:
        json.dump(sorted(per_source, key=lambda r: -r["configs"]), fh, indent=2)

    # merge helper
    with open(os.path.join(OUT_DIR, "merge_into_servers.py"), "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os\n"
            "HERE = os.path.dirname(os.path.abspath(__file__))\n"
            "main_p = os.path.join(HERE, '..', 'configs', 'servers.json')\n"
            "cur = json.load(open(main_p, encoding='utf-8-sig')) if os.path.exists(main_p) else []\n"
            "add = json.load(open(os.path.join(HERE, 'servers.json'), encoding='utf-8'))\n"
            "have = {s.get('endpoint') for s in cur}\n"
            "before = len(cur)\n"
            "for s in add:\n"
            "    if s['endpoint'] not in have:\n"
            "        cur.append(s)\n"
            "        have.add(s['endpoint'])\n"
            "json.dump(cur, open(main_p, 'w', encoding='utf-8'), indent=2)\n"
            "print(f'configs/servers.json: {before} -> {len(cur)} (+{len(cur)-before})')\n"
        )

    log("\n" + "=" * 70)
    log("  DONE")
    for cc in countries:
        s = summary["per_country"][cc]
        log(f"  {cc}: {s['live']} live / {s['candidates']} candidates")
    log(f"  servers.json ({len(servers_out)} entries) + .conf files in {OUT_DIR}")
    log("  merge with:  python ips-new\\merge_into_servers.py")
    log("=" * 70)


if __name__ == "__main__":
    main()