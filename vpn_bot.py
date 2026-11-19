import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import subprocess
import threading
import os
import time
import json
import atexit
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, "bin")
SETTINGS_FILE = os.path.join(BASE_DIR, "configs", "settings.json")
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")
WG_CONF = os.path.join(BASE_DIR, "wireproxy.conf")
IP_HISTORY = os.path.join(BASE_DIR, "logs", "ip_history.json")
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

# Legacy fixed locations (kept as last-resort fallbacks for backward compat)
LEGACY_WIREPROXY = r"C:\Program Files (x86)\wg-opencode\wireproxy.exe"
LEGACY_OPENCODE = r"C:\Users\Admin\AppData\Local\Programs\@opencode-aidesktop\OpenCode.exe"

# ---- Backend hardening: shared locks / caches (no new deps) ----
_SERVERS_LOCK = threading.Lock()
_HISTORY_LOCK = threading.Lock()
_WP_PROC = None          # tracked wireproxy Popen (targeted kill, no blind taskkill)
_WP_CACHE = {"running": False, "ts": 0.0}
_WP_CACHE_TTL = 1.0      # tasklist.exe spawn is ~50-100ms -> cache 1s
_LOG_MAX_LINES = 800
_HISTORY_MAX = 500


def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def save_settings(d):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        return True
    except Exception:
        return False


def resolve_wireproxy():
    """Find wireproxy.exe. Order: manual settings -> bundled bin/ -> PATH -> legacy.

    Returns (path_or_None, searched_list). Bundled bin/ makes the project
    independent of the external wg-opencode installation.
    """
    searched = []
    try:
        manual = load_settings().get("wireproxy_path", "")
        if manual:
            searched.append(manual)
            if os.path.isfile(manual):
                return manual, searched
    except Exception:
        pass
    internal = os.path.join(BIN_DIR, "wireproxy.exe")
    searched.append(internal)
    if os.path.isfile(internal):
        return internal, searched
    try:
        which = shutil.which("wireproxy.exe")
        if which:
            searched.append(which)
            return which, searched
    except Exception:
        pass
    searched.append(LEGACY_WIREPROXY)
    if os.path.isfile(LEGACY_WIREPROXY):
        return LEGACY_WIREPROXY, searched
    return None, searched


def resolve_opencode():
    """Find OpenCode.exe. Order: manual settings -> LOCALAPPDATA -> PATH -> legacy."""
    searched = []
    try:
        manual = load_settings().get("opencode_path", "")
        if manual:
            searched.append(manual)
            if os.path.isfile(manual):
                return manual, searched
    except Exception:
        pass
    try:
        lad = os.environ.get("LOCALAPPDATA", "")
        if lad:
            p = os.path.join(lad, "Programs", "@opencode-aidesktop", "OpenCode.exe")
            searched.append(p)
            if os.path.isfile(p):
                return p, searched
    except Exception:
        pass
    for exe in ("OpenCode.exe", "opencode.exe"):
        try:
            which = shutil.which(exe)
        except Exception:
            which = None
        if which:
            searched.append(which)
            return which, searched
    searched.append(LEGACY_OPENCODE)
    if os.path.isfile(LEGACY_OPENCODE):
        return LEGACY_OPENCODE, searched
    return None, searched


def resolve_wireguard_tools():
    """Find official WireGuard client (optional, kernel mode only)."""
    cands_exe, cands_wg = [], []
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        try:
            cands_exe.append(os.path.join(base, "WireGuard", "wireguard.exe"))
            cands_wg.append(os.path.join(base, "WireGuard", "wg.exe"))
        except Exception:
            pass
    cands_exe.append(r"C:\Program Files\WireGuard\wireguard.exe")
    cands_wg.append(r"C:\Program Files\WireGuard\wg.exe")
    exe = next((p for p in cands_exe if p and os.path.isfile(p)), None)
    wg = next((p for p in cands_wg if p and os.path.isfile(p)), None)
    return exe, wg


WG_PROXY, WIREPROXY_SEARCHED = resolve_wireproxy()
if not WG_PROXY:
    WG_PROXY = LEGACY_WIREPROXY  # keeps error messages showing a concrete path
OPENCODE_EXE, OPENCODE_SEARCHED = resolve_opencode()
if not OPENCODE_EXE:
    OPENCODE_EXE = LEGACY_OPENCODE

def _atomic_write_json(path, data):
    """Crash-safe write: tmp + os.replace (never half-written JSON)."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def load_servers():
    try:
        if os.path.exists(SERVERS_FILE):
            with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
            if isinstance(d, dict):
                d = d.get("servers", [])
            if not isinstance(d, list):
                return []
            # Validate + dedup by endpoint (corrupt entries dropped, not crash)
            seen, clean = set(), []
            for s in d:
                if not isinstance(s, dict):
                    continue
                ep = (s.get("endpoint") or "").strip()
                pk = (s.get("private_key") or "").strip()
                if not ep or not pk:
                    continue
                if ep in seen:
                    continue
                seen.add(ep)
                clean.append(s)
            return clean
    except Exception:
        # Backup corrupt DB instead of wiping it
        try:
            bad = SERVERS_FILE + f".corrupt_{time.strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(SERVERS_FILE, bad)
        except Exception:
            pass
    return []


def save_servers(servers):
    # Choke point: every stored server gets a fetch date (sources-first model).
    # Manual adds keep no source_url (= human-provided, honest provenance).
    try:
        for s in servers:
            if isinstance(s, dict):
                s.setdefault("fetched_at", now_iso())
    except Exception:
        pass
    try:
        with _SERVERS_LOCK:
            return _atomic_write_json(SERVERS_FILE, servers)
    except Exception:
        return False


def load_history():
    try:
        if os.path.exists(IP_HISTORY):
            with open(IP_HISTORY, "r", encoding="utf-8-sig") as f:
                d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        pass
    return []


def save_history(history):
    try:
        # Bound growth: last N rotations only (log file was unbounded)
        if isinstance(history, list) and len(history) > _HISTORY_MAX:
            del history[:-_HISTORY_MAX]
        with _HISTORY_LOCK:
            return _atomic_write_json(IP_HISTORY, history)
    except Exception:
        return False


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


def _spawn_wp(conf_path):
    """Launch wireproxy and track the handle for targeted kill."""
    global _WP_PROC
    try:
        proc = subprocess.Popen(
            [WG_PROXY, "-c", conf_path, "-s"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _WP_PROC = proc
        _WP_CACHE["running"] = True
        _WP_CACHE["ts"] = time.time()
        return proc
    except Exception:
        return None


def kill_wp():
    """Targeted kill (tracked PID) + fallback taskkill. No blind 1s sleep.

    The slow taskkill spawn is skipped when nothing is running
    (tracked handle dead + tasklist says no foreign instance), so
    Disconnect/Reset/Close never freeze on an empty kill.
    """
    global _WP_PROC
    killed = False
    proc, _WP_PROC = _WP_PROC, None
    try:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                killed = True
            except Exception:
                pass
    except Exception:
        pass
    if killed or wp_running():
        # Fallback: stray/foreign wireproxy instances (only when needed)
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", "wireproxy.exe"],
                               capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               timeout=6)
            out = (getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")
            if "SUCCESS" in out.upper() or "PID" in out.upper():
                killed = True
        except Exception:
            pass
    _WP_CACHE["running"] = False
    _WP_CACHE["ts"] = time.time()
    if killed:
        time.sleep(0.6)
    if os.path.exists(WG_CONF):
        try:
            os.remove(WG_CONF)
        except Exception:
            pass


def wp_running(use_cache=True):
    """Cached tasklist check (spawn ~50-100ms, so 1s TTL)."""
    try:
        now = time.time()
        if use_cache and (now - _WP_CACHE.get("ts", 0)) < _WP_CACHE_TTL:
            return bool(_WP_CACHE.get("running"))
        # Tracked handle is cheapest truth
        proc = _WP_PROC
        try:
            if proc is not None and proc.poll() is None:
                _WP_CACHE.update(running=True, ts=now)
                return True
        except Exception:
            pass
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq wireproxy.exe"],
                           capture_output=True, text=True, timeout=6,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        running = "wireproxy.exe" in (r.stdout or "")
        # If tracked proc died but a foreign instance lives, still True
        _WP_CACHE.update(running=running, ts=now)
        return running
    except Exception:
        return bool(_WP_CACHE.get("running", False))


_DNS_CACHE = {}
_DNS_CACHE_TTL = 300

# P0 speed: multiple IP providers, first answer wins (ifconfig.me alone is slow/rate-limited)
IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me",
]


def proxy_ready(host="127.0.0.1", port=8080, timeout=0.3):
    """Fast TCP check that wireproxy HTTP listener is up. No process spawn."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def _fetch_ip_via_proxy(url, timeout=3):
    """Fetch exit IP through local wireproxy HTTP proxy using urllib (no curl.exe spawn)."""
    try:
        proxy = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        })
        opener = urllib.request.build_opener(proxy)
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open(url, timeout=timeout) as resp:
            ip = resp.read().decode("utf-8", errors="ignore").strip()
        # api.ipify/icanhazip may add newline; ifconfig.me returns plain IP
        ip = ip.split()[0] if ip else ""
        if ip and ("." in ip or ":" in ip) and len(ip) < 64:
            return ip
    except Exception:
        pass
    return None


def get_ip(timeout=4):
    """P0 speed: parallel multi-provider IP check. First success wins.

    Old code: single curl.exe -> ifconfig.me with 12s timeout.
    New: 3 providers in parallel via urllib, each ~3s timeout.
    Compatible: get_ip() with no args still works.
    """
    try:
        if not proxy_ready(timeout=0.3):
            # Proxy not even listening yet -> fail fast, caller will retry/poll
            return None
    except Exception:
        pass
    try:
        per_url = max(2, min(4, int(timeout)))
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(_fetch_ip_via_proxy, u, per_url): u for u in IP_CHECK_URLS}
            for fut in as_completed(futures, timeout=timeout):
                try:
                    ip = fut.result()
                except Exception:
                    continue
                if ip:
                    # Cancel stragglers
                    for f in futures:
                        f.cancel()
                    return ip
    except Exception:
        pass
    return None


def wait_for_vpn_ready(timeout_total=7, poll=0.4):
    """P0 speed: replace fixed sleep(5/6). Poll proxy+IP, return IP on first success.

    Old flow waited 5-6s unconditionally even if handshake finished in 200ms.
    New flow typically returns in 0.5-2s on a good server.
    Proxy-first order: fast TCP check (no spawn) before tasklist spawn.
    """
    deadline = time.time() + timeout_total
    last_ip = None
    while time.time() < deadline:
        # Fast path first (no process spawn)
        if proxy_ready(timeout=0.25):
            last_ip = get_ip(timeout=2)
            if last_ip:
                return last_ip
        elif not wp_running():
            # Proxy down + process gone -> dead, keep polling (caller retries)
            pass
        time.sleep(poll)
    return last_ip


def resolve_host(host):
    """Resolve hostname to IP with 5-min cache. Returns IP or None on DNS failure."""
    try:
        # Already an IP?
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            return host
        now = time.time()
        hit = _DNS_CACHE.get(host)
        if hit and (now - hit[1]) < _DNS_CACHE_TTL:
            return hit[0]
        ip = socket.gethostbyname(host)
        _DNS_CACHE[host] = (ip, now)
        # Bound cache size (avoid leak with 972 endpoints)
        if len(_DNS_CACHE) > 2000:
            _DNS_CACHE.clear()
            _DNS_CACHE[host] = (ip, now)
        return ip
    except Exception:
        return None


def icmp_ping(host, timeout_ms=1200):
    """ICMP ping via system ping.exe. Returns latency ms or -1.

    Works on Windows regardless of WireGuard protocol - tests if the
    HOST is alive, which TCP-to-WG-port can never do (WG is UDP-only
    and silent to unauthenticated packets).
    """
    try:
        ip = resolve_host(host)
        if not ip:
            return -1
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=(timeout_ms / 1000 + 3),
            creationflags=subprocess.CREATE_NO_WINDOW)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"[Tt]ime[=<]\s*(\d+)\s*ms", out)
        if m:
            return float(m.group(1))
        # "time<1ms" + non-English locales: TTL= line proves reply received
        up = (out or "").upper()
        if "TTL=" in up or "TTL =" in up:
            return 1.0
        return -1
    except Exception:
        return -1


def udp_probe(host, port=51820, timeout=2):
    """Probe the WireGuard UDP port.

    WireGuard never answers unauthenticated packets, so:
      - ICMP port-unreachable (ConnectionReset) => port CLOSED => DOWN
      - timeout (no answer, no ICMP) => OPEN|FILTERED => host may be UP
      - got a reply => OPEN => UP
      - DNS failure => DOWN
    Returns one of: "open", "filtered", "closed", "dns-fail".
    """
    try:
        ip = resolve_host(host)
        if not ip:
            return "dns-fail"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            try:
                s.sendto(b"\x00" * 32, (ip, port))
            except OSError:
                return "closed"
            try:
                s.recvfrom(2048)
                return "open"
            except ConnectionResetError:
                return "closed"
            except socket.timeout:
                return "filtered"
            except OSError as e:
                # Windows WSAECONNRESET (10054) = ICMP port unreachable
                if getattr(e, "winerror", None) == 10054 or "10054" in str(e):
                    return "closed"
                return "filtered"
        finally:
            s.close()
    except Exception:
        return "filtered"


def tcp_alive(host, port, timeout=2):
    """Simple TCP open check (for host-alive fallback on 443/80)."""
    try:
        ip = resolve_host(host)
        if not ip:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_server(host, port=51820, ping_timeout_ms=1200, udp_timeout=2):
    """Accurate WireGuard server check (3-state).

    Order:
      1. DNS must resolve, else DOWN.
      2. UDP CLOSED (ICMP unreachable) => DOWN (definitive).
      3. ICMP ping OK => UP + latency (host alive).
      4. UDP open/filtered + TCP 443/80 open => UP (host alive, ICMP blocked).
      5. Total silence (no ping, no TCP, UDP filtered) => UNKNOWN (None):
         WireGuard is silent by design so we can NOT call it DOWN
         (that was the old false-DOWN bug), but we also must not call
         a possibly-dead host UP. UI shows orange; use Verify for truth.
    Returns (alive: True/False/None, latency_ms, reason: str).
    """
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = 51820

    if not resolve_host(host):
        return False, -1, "DNS fail"

    udp = udp_probe(host, port, timeout=udp_timeout)
    if udp == "dns-fail":
        return False, -1, "DNS fail"
    if udp == "closed":
        return False, -1, "UDP port closed"

    ms = icmp_ping(host, timeout_ms=ping_timeout_ms)
    if ms >= 0:
        return True, round(ms, 1), "Ping OK"

    # Ping blocked/failed but UDP not closed -> check well-known TCP ports
    # to confirm the host itself is alive (Proton hosts have 443 open).
    if tcp_alive(host, 443, timeout=2) or tcp_alive(host, 80, timeout=2):
        return True, -1, "Host alive (ICMP blocked)"

    # Total silence: do NOT mark red (old bug) nor green (dead-host risk).
    if udp in ("open", "filtered"):
        return None, -1, "Silent (unverified)"

    return False, -1, "Unreachable"


def ping_host(host, port=51820, timeout=2):
    """Backwards-compatible wrapper: True only when confirmed usable."""
    alive, _, _ = check_server(host, port)
    return alive is True


def speed_test(host, port=51820, timeout=3):
    """Backwards-compatible wrapper: latency via ICMP ping.

    NOTE: old code measured TCP-connect time to a UDP-only port, which
    always failed. Latency must come from ICMP, not TCP.
    """
    ms = icmp_ping(host, timeout_ms=int(timeout * 1000))
    return round(ms, 1) if ms >= 0 else -1


def _auto_mtu_for_endpoint(endpoint):
    """P0 speed: MTU 1280 for Cloudflare/WARP anycast (fragmentation-sensitive),
    1380 for the rest (safer than 1420 on WiFi/PPPoE)."""
    try:
        host = (endpoint or "").split(":")[0]
        if host.startswith("188.114") or host.startswith("162.159"):
            return "1280"
    except Exception:
        pass
    return "1380"


def _clean_dns(dns_text):
    """Keep only public IPv4 DNS servers, else fallback 1.1.1.1.

    Imported configs often carry tunnel-internal DNS (10.x) + IPv6
    (e.g. "10.2.0.1, 2a07:b944::2:1") which may be unreachable, so the
    proxy cannot resolve the IP-check host even when the WireGuard
    handshake itself is fine -> false "connection failed".
    """
    try:
        kept = []
        for part in str(dns_text or "").replace(";", ",").split(","):
            p = part.strip()
            if not p or ":" in p:
                continue  # IPv6 / empty
            if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", p):
                continue  # tunnel-internal / LAN
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", p):
                kept.append(p)
        return ", ".join(kept) if kept else "1.1.1.1"
    except Exception:
        return "1.1.1.1"


def make_conf(s):
    ep = s.get("endpoint", "")
    mtu = s.get("mtu", "")
    # Keep explicit custom MTU, but fix legacy default 1420 -> auto-tuned value
    if not mtu or mtu == "1420":
        mtu = _auto_mtu_for_endpoint(ep)
    dns = _clean_dns(s.get("dns", ""))
    return f"""[Interface]
PrivateKey = {s['private_key']}
Address = {s['address']}
MTU = {mtu}
DNS = {dns}

[Peer]
PublicKey = {s['public_key']}
Endpoint = {s['endpoint']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15

[Socks5]
BindAddress = 127.0.0.1:10808

[HTTP]
BindAddress = 127.0.0.1:8080
"""


_WG_EXE_FOUND, _WG_TOOL_FOUND = resolve_wireguard_tools()
WIREGUARD_EXE = _WG_EXE_FOUND or r"C:\Program Files\WireGuard\wireguard.exe"
WG_EXE = _WG_TOOL_FOUND or r"C:\Program Files\WireGuard\wg.exe"
KERNEL_TUNNEL = "opencode-kernel"
KERNEL_CONF = os.path.join(BASE_DIR, "wg-kernel.conf")

DIRECT_IP_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me",
]


def make_kernel_conf(s):
    """P2: clean WireGuard-NT config (no proxy sections) for official kernel client.

    Kernel routing (L3) removes the localhost HTTP/SOCKS hop entirely:
    ~15-30% faster + lower latency than wireproxy userspace proxying.
    """
    ep = s.get("endpoint", "")
    mtu = s.get("mtu", "")
    if not mtu or mtu == "1420":
        mtu = _auto_mtu_for_endpoint(ep)
    return f"""[Interface]
PrivateKey = {s['private_key']}
Address = {s['address']}
MTU = {mtu}
DNS = 1.1.1.1

[Peer]
PublicKey = {s['public_key']}
Endpoint = {s['endpoint']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
"""


def kernel_interfaces():
    """List active WireGuard-NT tunnel names (empty list if none / no client)."""
    try:
        r = subprocess.run([WG_EXE, "show", "interfaces"],
                           capture_output=True, text=True, timeout=8,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return (r.stdout or "").split()
    except Exception:
        return []


def kernel_tunnel_up(name=KERNEL_TUNNEL):
    return name in kernel_interfaces()


def any_kernel_up():
    try:
        return len(kernel_interfaces()) > 0
    except Exception:
        return False


def kernel_latest_handshake(name=KERNEL_TUNNEL):
    """Seconds since last handshake, or None (no tunnel / never shook hands)."""
    try:
        r = subprocess.run([WG_EXE, "show", name, "latest-handshakes"],
                           capture_output=True, text=True, timeout=8,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        best = None
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                ts = int(parts[1])
                if ts > 0:
                    age = time.time() - ts
                    best = age if best is None else min(best, age)
        return best
    except Exception:
        return None


def _fetch_direct_ip(url, timeout=3):
    """Direct exit-IP fetch bypassing any proxy env (goes via kernel tunnel if up)."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open(url, timeout=timeout) as resp:
            ip = resp.read().decode("utf-8", errors="ignore").strip()
        ip = ip.split()[0] if ip else ""
        if ip and ("." in ip or ":" in ip) and len(ip) < 64:
            return ip
    except Exception:
        pass
    return None


def fetch_direct_ip(timeout=4):
    """Parallel direct-IP check (no proxy). First answer wins."""
    try:
        per_url = max(2, min(4, int(timeout)))
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(_fetch_direct_ip, u, per_url): u for u in DIRECT_IP_URLS}
            for fut in as_completed(futures, timeout=timeout):
                try:
                    ip = fut.result()
                except Exception:
                    continue
                if ip:
                    for f in futures:
                        f.cancel()
                    return ip
    except Exception:
        pass
    return None


def wait_for_kernel_ready(name=KERNEL_TUNNEL, timeout_total=9, poll=0.5):
    """P2: poll kernel handshake + direct IP. Returns exit IP or None."""
    deadline = time.time() + timeout_total
    last_ip = None
    while time.time() < deadline:
        age = kernel_latest_handshake(name)
        if age is not None and age < 150:
            last_ip = fetch_direct_ip(timeout=2)
            if last_ip:
                return last_ip
        time.sleep(poll)
    return last_ip


def kernel_install(conf_path):
    """Install+activate tunnel service via official client. Needs admin."""
    if not os.path.exists(WIREGUARD_EXE):
        return False, "wireguard.exe not found (install official WireGuard first)"
    try:
        r = subprocess.run([WIREGUARD_EXE, "/installtunnelservice", conf_path],
                           capture_output=True, text=True, timeout=20,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            return True, "tunnel installed"
        return False, (r.stderr or r.stdout or "install failed").strip()[:200]
    except Exception as e:
        return False, str(e)[:200]


def kernel_uninstall(name=KERNEL_TUNNEL):
    """Remove our tunnel service only (never touches user's other tunnels).

    Skips the slow service call when no kernel tunnel is up, so
    Disconnect/Reset/Close stay instant in the common proxy-only case.
    """
    if not os.path.exists(WIREGUARD_EXE):
        return
    try:
        if not any_kernel_up():
            return
    except Exception:
        pass
    try:
        subprocess.run([WIREGUARD_EXE, "/uninstalltunnelservice", name],
                       capture_output=True, text=True, timeout=20,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass


# Refresh (on-demand only, never at startup): re-verify GOLD, drop dead,
# top up from free sources until GOLD target is met again.
REFRESH_GOLD_TARGET = 15
REFRESH_VERIFY_TIMEOUT = 9
REFRESH_TOPUP_MAX = 25
REFRESH_CAND_CAP = 150
# Sources-first: a GOLD badge is a temp cache, not a permanent title.
# IPs/keys rot (free keys expire, endpoints re-appear under new ports),
# so verified results expire after this many days.
GOLD_TTL_DAYS = 3


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def stamp_verified(server, ip):
    server["verified"] = True
    server["last_verified"] = now_iso()
    server["exit_ip"] = ip


def gold_fresh(server):
    """True only if verified AND within TTL. Stale gold is just a rumor."""
    try:
        if not server.get("verified"):
            return False
        lv = server.get("last_verified", "")
        if not lv:
            return False
        age_days = (time.time() - time.mktime(time.strptime(lv, "%Y-%m-%dT%H:%M:%S"))) / 86400.0
        return age_days < GOLD_TTL_DAYS
    except Exception:
        return False


def stamp_fetched(server, source_url):
    server.setdefault("fetched_at", now_iso())
    if source_url:
        server["source_url"] = source_url


def get_countries(servers):
    countries = []
    for s in servers:
        c = s.get("country", "Unknown")
        if c not in countries:
            countries.append(c)
    return sorted(countries)


def get_sources(servers):
    sources = []
    for s in servers:
        src = s.get("source", "Unknown")
        if src not in sources:
            sources.append(src)
    return sorted(sources)


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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OpenCode VPN Bot v2.0")
        self.geometry("1040x900")
        self.minsize(900, 760)
        self.configure(bg="#0d1117")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.all_servers = load_servers()
        self.servers = list(self.all_servers)
        self.current = 0
        self.rotation_count = 0
        self.ip_history = load_history()
        self.monitoring = False
        self.monitor_thread = None
        self.protect_on = False
        self.stop_event = threading.Event()
        self.steps_done = [False, False]
        self.connected = False
        self.server_status = {}
        self.server_latency = {}
        self.server_checks = {}
        self.checking = False
        self.speed_testing = False
        self.refreshing = False
        # Dedicated cancel flags for one-shot jobs (scan/speed).
        # The global stop_event is ONLY for monitor/auto-reconnect/reset/close:
        # it stays SET after Reset/Protect-OFF, so one-shot jobs must NEVER
        # consult it (old bug: scan aborted instantly with 0/0/0 and every
        # connect failed right after any Reset).
        self._scan_stop = threading.Event()
        self._speed_stop = threading.Event()
        self._refresh_stop = threading.Event()
        # Race guards: parallel Rotate/refresh/fetch/connect threads used to
        # fight over wireproxy.conf + all_servers (stuck/dead states).
        self.fetching = False   # any Fetch thread owns all_servers
        self.rotating = False   # a Rotate/Random thread owns wireproxy
        # Session generation: bumped on Reset/Disconnect so late threads
        # from an older session can never flip the UI back to "Connected".
        self._sess = 0
        self._updating_info = False
        self._selected_row = None
        self.active_endpoint = None
        self._animating = False
        self.server_var = tk.StringVar(value="")
        self.auto_reconnect = False
        self.auto_reconnect_thread = None
        self.failed_servers = set()
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_server_list())
        self.total_rotations_today = 0
        self.start_time = time.time()

        atexit.register(self.cleanup)
        self.build()
        self._check_deps()
        self.update_timer()

    def update_timer(self):
        elapsed = int(time.time() - self.start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        self.lbl_uptime.config(text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        self.after(1000, self.update_timer)

    def build(self):
        title_frame = tk.Frame(self, bg="#0d1117")
        title_frame.pack(fill="x", padx=20, pady=(8, 3))
        tk.Label(title_frame, text="OpenCode VPN Bot", bg="#0d1117", fg="#58a6ff",
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(title_frame, text="v2.0", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 10)).pack(side="left", padx=(8, 0), pady=(5, 0))

        info_frame = tk.Frame(self, bg="#0d1117")
        info_frame.pack(fill="x", padx=20, pady=(0, 3))

        self.lbl_status = tk.Label(info_frame, text="Disconnected", bg="#0d1117",
                                    fg="#f85149", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side="left")

        self.lbl_rotations = tk.Label(info_frame, text="Rotations: 0", bg="#0d1117",
                                       fg="#8b949e", font=("Consolas", 9))
        self.lbl_rotations.pack(side="left", padx=(15, 0))

        self.lbl_uptime = tk.Label(info_frame, text="Uptime: 00:00:00", bg="#0d1117",
                                    fg="#8b949e", font=("Consolas", 9))
        self.lbl_uptime.pack(side="left", padx=(15, 0))

        self.lbl_ip = tk.Label(info_frame, text="IP: ---", bg="#0d1117",
                                fg="#f0883e", font=("Consolas", 9))
        self.lbl_ip.pack(side="right")

        self.lbl_count = tk.Label(info_frame, text="Servers: 0", bg="#0d1117",
                                   fg="#8b949e", font=("Consolas", 9))
        self.lbl_count.pack(side="right", padx=(0, 15))

        # ---- Single toolbar row: Search + Country + Source (left) | Scan (right) ----
        # One row only (no empty gap), right side has safe margin so buttons
        # are never cut off at the window edge.
        toolbar = tk.Frame(self, bg="#0d1117")
        toolbar.pack(fill="x", padx=20, pady=(3, 3))
        toolbar.columnconfigure(0, weight=1)
        toolbar.columnconfigure(1, weight=0)

        left_bar = tk.Frame(toolbar, bg="#0d1117")
        left_bar.grid(row=0, column=0, sticky="w")
        right_bar = tk.Frame(toolbar, bg="#0d1117")
        right_bar.grid(row=0, column=1, sticky="e", padx=(10, 0))

        tk.Label(left_bar, text="Search:", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).pack(side="left")
        self.search_entry = tk.Entry(left_bar, textvariable=self.search_var,
                                      bg="#161b22", fg="#c9d1d9", insertbackground="#c9d1d9",
                                      font=("Consolas", 9), width=18, bd=0,
                                      highlightthickness=1, highlightcolor="#1f6feb")
        self.search_entry.pack(side="left", padx=(5, 10))

        tk.Label(left_bar, text="Country:", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9)).pack(side="left")

        self.country_var = tk.StringVar(value="All")
        countries = ["All"] + get_countries(self.all_servers)
        self.country_menu = tk.OptionMenu(left_bar, self.country_var, *countries,
                                           command=self.filter_changed)
        self.country_menu.config(bg="#161b22", fg="#c9d1d9", font=("Segoe UI", 9),
                                  highlightthickness=0, width=6)
        self.country_menu["menu"].config(bg="#161b22", fg="#c9d1d9")
        self.country_menu.pack(side="left", padx=(5, 0))

        tk.Label(left_bar, text="Source:", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9)).pack(side="left", padx=(10, 0))

        self.source_var = tk.StringVar(value="All")
        sources = ["All"] + get_sources(self.all_servers)
        self.source_menu = tk.OptionMenu(left_bar, self.source_var, *sources,
                                          command=self.filter_changed)
        self.source_menu.config(bg="#161b22", fg="#c9d1d9", font=("Segoe UI", 9),
                                highlightthickness=0, width=14)
        self.source_menu["menu"].config(bg="#161b22", fg="#c9d1d9")
        self.source_menu.pack(side="left", padx=(5, 0))

        self.lbl_checked = tk.Label(right_bar, text="", bg="#0d1117", fg="#8b949e",
                                     font=("Segoe UI", 8))
        self.lbl_checked.pack(side="left", padx=(0, 6))

        # Top-right scan actions: Scan All + Speed side by side.
        # Both toggle into a red Stop while running (second click cancels).
        self.btn_check_all = tk.Button(right_bar, text="Scan All", bg="#1f6feb",
                                        fg="white", font=("Segoe UI", 9, "bold"),
                                        width=10, command=self.check_all_servers)
        self.btn_check_all.pack(side="left", padx=(2, 2))
        self.btn_speed_top = tk.Button(right_bar, text="Speed", bg="#0a7ea4",
                                       fg="white", font=("Segoe UI", 9, "bold"),
                                       width=8, command=self.speed_test_all)
        self.btn_speed_top.pack(side="left", padx=(2, 2))
        # Historical name used by speed methods -> points at the top button
        # (the bottom-bar Speed was moved up here).
        self.btn_speed = self.btn_speed_top

        list_outer = tk.Frame(self, bg="#161b22", relief="raised", bd=1)
        list_outer.pack(fill="both", expand=True, padx=20, pady=(3, 3))

        list_header = tk.Frame(list_outer, bg="#161b22")
        list_header.pack(fill="x", padx=8, pady=(4, 2))

        tk.Label(list_header, text="Servers", bg="#161b22", fg="#c9d1d9",
                 font=("Segoe UI", 9, "bold")).pack(side="left")

        sel_frame = tk.Frame(list_header, bg="#161b22")
        sel_frame.pack(side="right", padx=(0, 2))

        # Merged: 6 micro-buttons -> 2 dropdowns (Select / Delete).
        # Verify moved to bottom secondary bar (deep check, infrequent).
        self._select_mb = tk.Menubutton(sel_frame, text="Select \u25be",
                                        bg="#21262d", fg="#c9d1d9",
                                        font=("Segoe UI", 8, "bold"),
                                        relief="raised", bd=1)
        self._select_mb.pack(side="left", padx=1)
        select_menu = tk.Menu(self._select_mb, tearoff=0,
                              bg="#161b22", fg="#c9d1d9")
        select_menu.add_command(label="Select All", command=self.select_all)
        select_menu.add_command(label="Select None", command=self.deselect_all)
        select_menu.add_command(label="Select Active (UP + silent)",
                                command=self.select_active)
        self._select_mb.configure(menu=select_menu)

        self._delete_mb = tk.Menubutton(sel_frame, text="Delete \u25be",
                                        bg="#3a1d1d", fg="#ff9d97",
                                        font=("Segoe UI", 8, "bold"),
                                        relief="raised", bd=1)
        self._delete_mb.pack(side="left", padx=(6, 0))
        delete_menu = tk.Menu(self._delete_mb, tearoff=0,
                              bg="#161b22", fg="#c9d1d9")
        delete_menu.add_command(label="Delete Selected",
                                command=self.delete_selected)
        delete_menu.add_command(label="Delete DOWN (red only)",
                                command=self.delete_inactive)
        self._delete_mb.configure(menu=delete_menu)

        # Table header: # | Status | Server | Ping (English only)
        table_header = tk.Frame(list_outer, bg="#21262d")
        table_header.pack(fill="x", padx=5, pady=(2, 0))
        tk.Label(table_header, text="#", bg="#21262d", fg="#8b949e",
                 font=("Consolas", 8, "bold"), width=5).pack(side="left")
        tk.Label(table_header, text="", bg="#21262d", width=2).pack(side="left")
        tk.Label(table_header, text="o", bg="#21262d", fg="#8b949e",
                 font=("Consolas", 8, "bold"), width=2).pack(side="left")
        tk.Label(table_header, text="Server  (Name [Country] Endpoint / Source)",
                 bg="#21262d", fg="#8b949e",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(side="left", fill="x", expand=True, padx=(4, 0))
        tk.Label(table_header, text="Ping", bg="#21262d", fg="#8b949e",
                 font=("Segoe UI", 8, "bold"), width=10).pack(side="right", padx=(0, 10))

        list_canvas_frame = tk.Frame(list_outer, bg="#161b22")
        list_canvas_frame.pack(fill="both", expand=True, padx=5, pady=(2, 5))

        self.server_canvas = tk.Canvas(list_canvas_frame, bg="#0d1117",
                                        highlightthickness=0)
        scrollbar = tk.Scrollbar(list_canvas_frame, orient="vertical",
                                  command=self.server_canvas.yview)
        self.server_list_frame = tk.Frame(self.server_canvas, bg="#0d1117")

        self.server_list_frame.bind(
            "<Configure>",
            lambda e: self.server_canvas.configure(scrollregion=self.server_canvas.bbox("all"))
        )
        # CRITICAL FIX: inner frame must stretch to full canvas width,
        # otherwise the list looks narrow with empty black space on the right.
        self._list_window = self.server_canvas.create_window(
            (0, 0), window=self.server_list_frame, anchor="nw")
        self.server_canvas.bind(
            "<Configure>",
            lambda e: self.server_canvas.itemconfig(self._list_window, width=e.width)
        )
        self.server_canvas.configure(yscrollcommand=scrollbar.set)
        self.server_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # B1 fix: wheel must work over rows too (events go to the widget under
        # the cursor, children never propagate to the canvas binding).
        self.bind_all("<MouseWheel>", self._on_mousewheel_global)
        # Linux / extra bindings
        self.server_canvas.bind("<Button-4>", lambda e: self.server_canvas.yview_scroll(-1, "units"))
        self.server_canvas.bind("<Button-5>", lambda e: self.server_canvas.yview_scroll(1, "units"))

        self.refresh_server_list()

        steps_frame = tk.Frame(self, bg="#0d1117")
        steps_frame.pack(fill="x", padx=20, pady=(3, 0))
        # Side-by-side (was stacked vertically): saves ~60px vertical space
        # so the server list + log below get more room.
        steps_frame.columnconfigure(0, weight=1, uniform="steps")
        steps_frame.columnconfigure(1, weight=1, uniform="steps")

        self.step_labels = []
        self.step_status = []
        self.step_btns = []

        steps = [
            ("1. Kill & Connect to VPN", self.step1_connect, "Connect"),
            ("2. Launch OpenCode", self.step2_launch, "Launch"),
        ]

        for i, (text, cmd, btn_text) in enumerate(steps):
            frame = tk.Frame(steps_frame, bg="#161b22", relief="raised", bd=1)
            frame.grid(row=0, column=i, sticky="nsew", padx=3, pady=2)
            left = tk.Frame(frame, bg="#161b22")
            left.pack(side="left", fill="x", expand=True, padx=8, pady=3)
            lbl = tk.Label(left, text=text, bg="#161b22", fg="#c9d1d9",
                           font=("Segoe UI", 9, "bold"), anchor="w")
            lbl.pack(anchor="w")
            status = tk.Label(left, text="Waiting...", bg="#161b22", fg="#8b949e",
                              font=("Segoe UI", 8), anchor="w")
            status.pack(anchor="w")
            btn = tk.Button(frame, text=btn_text,
                            bg="#238636" if i == 0 else "#21262d", fg="white",
                            font=("Segoe UI", 11, "bold"), width=12,
                            command=cmd, state="disabled")
            btn.pack(side="right", padx=8, pady=6, ipady=4)
            self.step_labels.append(lbl)
            self.step_status.append(status)
            self.step_btns.append(btn)

        # ---- Primary control row: only daily actions, BIG ----
        ctrl_frame = tk.Frame(self, bg="#0d1117")
        ctrl_frame.pack(fill="x", padx=20, pady=(5, 3))

        self.btn_rotate = tk.Button(ctrl_frame, text="Rotate", bg="#1f6feb", fg="white",
                  font=("Segoe UI", 11, "bold"), width=16,
                  command=self.rotate_ip)
        self.btn_rotate.pack(side="left", padx=(0, 6), pady=2, ipady=4)
        tk.Button(ctrl_frame, text="Random", bg="#f0883e", fg="white",
                  font=("Segoe UI", 10, "bold"), width=10,
                  command=self.random_rotate).pack(side="left", padx=(0, 2), pady=2, ipady=4)

        # ---- Bottom secondary bar (packed BEFORE log so it is never pushed off-screen) ----
        # Daily add actions are explicit here: Import (file/files/folder) + Tunnel (manual).
        bottom_bar = tk.Frame(self, bg="#161b22", relief="raised", bd=1)
        bottom_bar.pack(side="bottom", fill="x", padx=0, pady=0)

        log_frame = tk.Frame(self, bg="#0d1117")
        log_frame.pack(fill="x", padx=20, pady=(3, 3))

        log_header = tk.Frame(log_frame, bg="#0d1117")
        log_header.pack(fill="x")
        tk.Label(log_header, text="Log:", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 8), anchor="w").pack(side="left")
        # Clear moved to bottom secondary bar (keeps log header clean).

        bottom_inner = tk.Frame(bottom_bar, bg="#161b22")
        bottom_inner.pack(fill="x", padx=10, pady=5)

        left_sec = tk.Frame(bottom_inner, bg="#161b22")
        left_sec.pack(side="left")
        right_sec = tk.Frame(bottom_inner, bg="#161b22")
        right_sec.pack(side="right")

        # Primary add actions (always visible, not hidden): file(s) + manual tunnel.
        tk.Button(left_sec, text="Import", bg="#238636", fg="white",
                  font=("Segoe UI", 8, "bold"), width=8,
                  command=self.import_conf).pack(side="left", padx=(0, 2))
        tk.Button(left_sec, text="+ Tunnel", bg="#238636", fg="white",
                  font=("Segoe UI", 8, "bold"), width=8,
                  command=self.add_tunnel_dialog).pack(side="left", padx=2)
        # Fetch dropdown: online sources only (files live in Import/+Tunnel above).
        self._fetch_mb = tk.Menubutton(left_sec, text="Fetch \u25be",
                                       bg="#1f6feb", fg="white",
                                       font=("Segoe UI", 8, "bold"),
                                       relief="raised", bd=1)
        self._fetch_mb.pack(side="left", padx=(4, 3))
        fetch_menu = tk.Menu(self._fetch_mb, tearoff=0,
                             bg="#161b22", fg="#c9d1d9")
        fetch_menu.add_command(label="Paste Config", command=self.paste_config)
        fetch_menu.add_command(label="Fetch URL", command=self.fetch_from_url)
        fetch_menu.add_command(label="Bulk Fetch URLs", command=self.fetch_bulk_urls)
        fetch_menu.add_separator()
        fetch_menu.add_command(label="Import .conf file(s)...", command=self.import_conf)
        fetch_menu.add_command(label="Bulk Import folder...", command=self.bulk_import)
        fetch_menu.add_separator()
        fetch_menu.add_command(label="Fetch WG Bundle", command=self.fetch_bundle)
        fetch_menu.add_command(label="ProtonVPN", command=self.fetch_protonvpn)
        fetch_menu.add_command(label="VPNBook", command=self.fetch_vpnbook)
        fetch_menu.add_separator()
        fetch_menu.add_command(label="Fetch ALL Fresh (1-click)", command=self.fetch_all_fresh)
        self._fetch_mb.configure(menu=fetch_menu)

        self.btn_verify = tk.Button(left_sec, text="Verify", bg="#1f6feb", fg="white",
                  font=("Segoe UI", 8, "bold"), width=7,
                  command=self.verify_selected)
        self.btn_verify.pack(side="left", padx=2)
        # (Speed lives top-right next to Scan All; self.btn_speed aliases it.)
        self.btn_refresh = tk.Button(left_sec, text="Refresh", bg="#bf8700", fg="white",
                  font=("Segoe UI", 8, "bold"), width=8,
                  command=self.refresh_gold)
        self.btn_refresh.pack(side="left", padx=2)
        tk.Button(left_sec, text="Kernel", bg="#8957e5", fg="white",
                  font=("Segoe UI", 8, "bold"), width=7,
                  command=self.kernel_connect_best).pack(side="left", padx=2)

        # Merged protection: Monitor + Auto Reconn -> ONE toggle.
        self.protect_on = False
        self.btn_protect = tk.Button(left_sec, text="Protect OFF", bg="#6e7681",
                                     fg="white", font=("Segoe UI", 8, "bold"),
                                     width=11, command=self.toggle_protect)
        self.btn_protect.pack(side="left", padx=(6, 2))
        # Aliases so legacy methods (toggle_monitor / toggle_auto_reconnect /
        # reset) keep working without AttributeError.
        self.btn_monitor = self.btn_protect
        self.btn_auto_reconnect = self.btn_protect

        tk.Button(right_sec, text="Paths", bg="#21262d", fg="#c9d1d9",
                  font=("Segoe UI", 8, "bold"), width=7,
                  command=self.pick_paths_dialog).pack(side="left", padx=2)
        tk.Button(right_sec, text="Clear", bg="#21262d", fg="#8b949e",
                  font=("Segoe UI", 8), width=6,
                  command=self.clear_log).pack(side="left", padx=2)
        tk.Button(right_sec, text="Reset", bg="#5a1f1f", fg="#ff9d97",
                  font=("Segoe UI", 8, "bold"), width=7,
                  command=self.reset).pack(side="left", padx=(8, 0))

        self.log_text = tk.Text(log_frame, bg="#0d1117", fg="#c9d1d9",
                                font=("Consolas", 8), height=8, wrap="word",
                                state="disabled", bd=0, highlightthickness=0)
        log_scrollbar = tk.Scrollbar(log_frame, orient="vertical",
                                      command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")

        self.step_btns[0].config(state="normal")
        self.step_status[0].config(text="Ready", fg="#f0883e")
        try:
            gold_n = sum(1 for s in self.all_servers if gold_fresh(s))
            self.log(f"Loaded {len(self.all_servers)} servers ({gold_n} fresh GOLD). "
                     "Double-click a row for instant connect.")
        except Exception:
            pass

    def _on_mousewheel_global(self, event):
        """Scroll the server list iff pointer is over it; else let event pass
        (log box keeps its own scrolling). Returning 'break' only inside."""
        try:
            x, y = event.x_root, event.y_root
            cx, cy = self.server_canvas.winfo_rootx(), self.server_canvas.winfo_rooty()
            cw, ch = self.server_canvas.winfo_width(), self.server_canvas.winfo_height()
            if cx <= x <= cx + cw and cy <= y <= cy + ch:
                self.server_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                return "break"
        except Exception:
            pass

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _check_deps(self):
        # Startup check: searched paths shown so user knows where we looked.
        if not os.path.isfile(WG_PROXY or ""):
            paths = "\n  ".join(dict.fromkeys(WIREPROXY_SEARCHED or [WG_PROXY]))
            msg = ("wireproxy.exe not found!\n\nSearched in:\n  " + paths +
                   "\n\nFix: copy wireproxy.exe into the project's bin folder, "
                   "install wg-opencode, or set the path manually via the Paths button.")
            self.log("WARNING: wireproxy missing!")
            messagebox.showwarning("Missing Files", msg)
        if not os.path.isfile(OPENCODE_EXE or ""):
            paths = "\n  ".join(dict.fromkeys(OPENCODE_SEARCHED or [OPENCODE_EXE]))
            msg = ("OpenCode.exe not found!\n\nSearched in:\n  " + paths +
                   "\n\nFix: install OpenCode Desktop or pick its exe via the Paths button.")
            self.log("WARNING: OpenCode missing!")
            messagebox.showwarning("Missing Files", msg)
        if not os.path.isfile(WIREGUARD_EXE or ""):
            self.log("Note: official WireGuard client not installed - kernel mode off, proxy works.")

    def pick_paths_dialog(self):
        """Manual override for exe paths -> saved in configs/settings.json."""
        global WG_PROXY, OPENCODE_EXE
        d = tk.Toplevel(self)
        d.title("Program Paths")
        d.geometry("560x220")
        d.configure(bg="#0d1117")
        d.transient(self)
        d.grab_set()
        s = load_settings()

        tk.Label(d, text="wireproxy path (proxy engine):", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=15, pady=(12, 2))
        wp_var = tk.StringVar(value=s.get("wireproxy_path", "") or (WG_PROXY or ""))
        tk.Entry(d, textvariable=wp_var, bg="#161b22", fg="#c9d1d9",
                 font=("Consolas", 8), width=70).pack(padx=15, fill="x")

        tk.Label(d, text="OpenCode path:", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        oc_var = tk.StringVar(value=s.get("opencode_path", "") or (OPENCODE_EXE or ""))
        tk.Entry(d, textvariable=oc_var, bg="#161b22", fg="#c9d1d9",
                 font=("Consolas", 8), width=70).pack(padx=15, fill="x")

        def browse(var):
            p = filedialog.askopenfilename(title="Select exe file",
                                           filetypes=[("Executable", "*.exe"), ("All", "*.*")])
            if p:
                var.set(p)

        btns = tk.Frame(d, bg="#0d1117")
        btns.pack(fill="x", padx=15, pady=12)
        tk.Button(btns, text="Browse wireproxy", bg="#21262d", fg="#c9d1d9",
                  font=("Segoe UI", 8), command=lambda: browse(wp_var)).pack(side="left")
        tk.Button(btns, text="Browse OpenCode", bg="#21262d", fg="#c9d1d9",
                  font=("Segoe UI", 8), command=lambda: browse(oc_var)).pack(side="left", padx=(6, 0))

        def save():
            ns = load_settings()
            if wp_var.get().strip():
                ns["wireproxy_path"] = wp_var.get().strip()
            elif "wireproxy_path" in ns:
                del ns["wireproxy_path"]
            if oc_var.get().strip():
                ns["opencode_path"] = oc_var.get().strip()
            elif "opencode_path" in ns:
                del ns["opencode_path"]
            save_settings(ns)
            new_wp, _ = resolve_wireproxy()
            new_oc, _ = resolve_opencode()
            # Never degrade to None: keep last working path if resolve fails
            if new_wp:
                global WG_PROXY
                WG_PROXY = new_wp
            if new_oc:
                global OPENCODE_EXE
                OPENCODE_EXE = new_oc
            self.log(f"saved paths -> wireproxy: {WG_PROXY} | opencode: {OPENCODE_EXE}")
            messagebox.showinfo("Done", "Paths saved to configs/settings.json")
            d.destroy()

        tk.Button(btns, text="Save", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=10, command=save).pack(side="right")

    def filter_changed(self, *args):
        self.refresh_server_list()

    def _refresh_filter_menus(self):
        countries = get_countries(self.all_servers)
        self.country_menu["menu"].delete(0, "end")
        for c in ["All"] + countries:
            self.country_menu["menu"].add_command(
                label=c,
                command=lambda v=c: (self.country_var.set(v), self.filter_changed()))
        # After clean (empty list) reset stale selection to All
        try:
            if self.country_var.get() not in (["All"] + countries):
                self.country_var.set("All")
        except Exception:
            pass
        sources = get_sources(self.all_servers)
        self.source_menu["menu"].delete(0, "end")
        for s in ["All"] + sources:
            self.source_menu["menu"].add_command(
                label=s,
                command=lambda v=s: (self.source_var.set(v), self.filter_changed()))
        try:
            if self.source_var.get() not in (["All"] + sources):
                self.source_var.set("All")
        except Exception:
            pass

    def refresh_server_list(self):
        country = self.country_var.get()
        source = self.source_var.get()
        search = self.search_var.get().lower().strip()

        self.servers = list(self.all_servers)

        if country != "All":
            self.servers = [s for s in self.servers if s.get("country") == country]
        if source != "All":
            self.servers = [s for s in self.servers if s.get("source") == source]
        if search:
            self.servers = [s for s in self.servers if
                           search in s.get("name", "").lower() or
                           search in s.get("endpoint", "").lower() or
                           search in s.get("country", "").lower()]

        self.lbl_count.config(text=f"Servers: {len(self.servers)}")
        # B2 fix: keep checkbox selection + scroll position across rebuilds
        # (search keystroke used to wipe both).
        try:
            kept_checks = {w.server_data.get("endpoint", "") for w in
                           self.server_list_frame.winfo_children()
                           if getattr(w, "checked", None) is not None and w.checked.get()}
        except Exception:
            kept_checks = set()
        try:
            kept_scroll = self.server_canvas.yview()[0]
        except Exception:
            kept_scroll = 0.0
        for widget in self.server_list_frame.winfo_children():
            widget.destroy()
        for i, server in enumerate(self.servers):
            self._create_server_row(i, server)
        if kept_checks:
            for w in self.server_list_frame.winfo_children():
                try:
                    if w.server_data.get("endpoint", "") in kept_checks:
                        w.checked.set(True)
                except Exception:
                    pass
        try:
            self.update_idletasks()
            self.server_canvas.yview_moveto(kept_scroll)
        except Exception:
            pass

    def _ping_text(self, endpoint):
        """Short text for the Ping column (max ~10 chars so it never clips).

        Shows numeric ping when available, else a short status word.
        Full reason stays in the log / server_checks, not in this column.
        """
        try:
            lat = self.server_latency.get(endpoint)
            if lat and lat > 0:
                try:
                    return f"{float(lat):g}ms"
                except Exception:
                    return f"{lat}ms"
            st = self.server_status.get(endpoint, "unscanned")
            if st is True:
                return "Alive"
            if st is None:
                return "Silent"
            if st is False:
                return "Timeout"
            return "---"
        except Exception:
            return "---"

    def _ping_color(self, endpoint):
        try:
            lat = self.server_latency.get(endpoint)
            if lat and lat > 0:
                if lat < 100:
                    return "#3fb950"
                if lat < 300:
                    return "#f0883e"
                return "#f0883e"
            if endpoint in self.server_status:
                st = self.server_status.get(endpoint)
                if st is True:
                    return "#3fb950"
                if st is None:
                    return "#f0883e"
                return "#f85149"
            return "#8b949e"
        except Exception:
            return "#8b949e"

    def _create_server_row(self, index, server):
        row = tk.Frame(self.server_list_frame, bg="#0d1117")
        row.pack(fill="x", expand=True, padx=2, pady=1)

        # Column 1: row number (1-based, follows visible order)
        num_label = tk.Label(row, text=f"{index + 1}", bg="#0d1117", fg="#8b949e",
                             font=("Consolas", 8), width=5, anchor="e")
        num_label.pack(side="left")

        checked = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(row, variable=checked, bg="#0d1117",
                             fg="#c9d1d9", selectcolor="#161b22",
                             activebackground="#0d1117", activeforeground="#c9d1d9",
                             highlightthickness=0, bd=0, width=2)
        cb.pack(side="left")

        status_color = "#8b949e"
        status_text = "\u25cb"  # empty circle = not scanned yet
        endpoint = server.get("endpoint", "")
        if endpoint in self.server_status:
            st = self.server_status[endpoint]
            if st is True:
                status_color = "#3fb950"
                status_text = "\u25cf"
            elif st is None:
                status_color = "#f0883e"
                status_text = "\u25cf"
            else:
                status_color = "#f85149"
                status_text = "\u25cf"

        status_label = tk.Label(row, text=status_text, bg="#0d1117", fg=status_color,
                                 font=("Consolas", 11), width=2)
        status_label.pack(side="left")

        display, fg = self._row_display(server)
        lbl = tk.Label(row, text=display, bg="#0d1117", fg=fg,
                        font=("Consolas", 9), anchor="w", justify="left")
        lbl.pack(side="left", fill="x", expand=True)

        # Column 5: Ping (filled by Scan All / Speed, merged ping check)
        # Fixed width 10 + right margin 10 keeps it clear of the scrollbar
        # so short values ("177ms", "Alive", "Timeout") are never clipped.
        ping_label = tk.Label(row, text=self._ping_text(endpoint),
                              bg="#0d1117", fg=self._ping_color(endpoint),
                              font=("Consolas", 9, "bold"), width=10, anchor="center")
        ping_label.pack(side="right", padx=(4, 10))

        row.server_data = server
        row.num_label = num_label
        row.status_label = status_label
        row.lbl = lbl
        row.ping_label = ping_label
        row.checked = checked
        row.cb = cb

        def on_click(e, r=row):
            self.select_server_row(r)

        def _paint(r, bg):
            try:
                r.configure(bg=bg)
            except Exception:
                pass
            for w in (getattr(r, "num_label", None), getattr(r, "lbl", None),
                      getattr(r, "status_label", None), getattr(r, "ping_label", None)):
                try:
                    if w is not None:
                        w.configure(bg=bg)
                except Exception:
                    pass

        def on_enter(e, r=row):
            try:
                if self._selected_row is None or self.servers.index(r.server_data) != self._selected_row:
                    _paint(r, "#161b22")
            except Exception:
                pass

        def on_leave(e, r=row):
            try:
                if self._selected_row is None or self.servers.index(r.server_data) != self._selected_row:
                    _paint(r, "#0d1117")
            except Exception:
                pass

        row.bind("<Button-1>", on_click)
        lbl.bind("<Button-1>", on_click)
        status_label.bind("<Button-1>", on_click)
        num_label.bind("<Button-1>", on_click)
        ping_label.bind("<Button-1>", on_click)
        cb.bind("<Button-1>", on_click)
        # Double-click = select + connect immediately (fastest UX path)
        row.bind("<Double-Button-1>", lambda e, r=row: self._dbl_connect(r))
        lbl.bind("<Double-Button-1>", lambda e, r=row: self._dbl_connect(r))
        status_label.bind("<Double-Button-1>", lambda e, r=row: self._dbl_connect(r))
        num_label.bind("<Double-Button-1>", lambda e, r=row: self._dbl_connect(r))
        ping_label.bind("<Double-Button-1>", lambda e, r=row: self._dbl_connect(r))
        row.bind("<Enter>", on_enter)
        row.bind("<Leave>", on_leave)
        lbl.bind("<Enter>", on_enter)
        lbl.bind("<Leave>", on_leave)

        if self._selected_row is not None and index == self._selected_row:
            _paint(row, "#1c2333")

    def select_server_row(self, row):
        for widget in self.server_list_frame.winfo_children():
            try:
                widget.configure(bg="#0d1117")
                for sub in (getattr(widget, "num_label", None), getattr(widget, "lbl", None),
                            getattr(widget, "status_label", None), getattr(widget, "ping_label", None)):
                    try:
                        if sub is not None:
                            sub.configure(bg="#0d1117")
                    except Exception:
                        pass
            except Exception:
                pass

        server = row.server_data
        self.server_var.set(f"{server['name']} ({server['endpoint']})")
        try:
            self._selected_row = self.servers.index(server)
        except ValueError:
            self._selected_row = None

        row.configure(bg="#1c2333")
        for sub in (getattr(row, "num_label", None), getattr(row, "lbl", None),
                    getattr(row, "status_label", None), getattr(row, "ping_label", None)):
            try:
                if sub is not None:
                    sub.configure(bg="#1c2333")
            except Exception:
                pass

    def _row_display(self, server):
        """Single source of row text: GOLD star + FAIL + ACTIVE.

        Ping/latency lives in its own Ping column (see _ping_text),
        so the main text stays clean and readable (English only).
        """
        endpoint = server.get("endpoint", "")
        name = server.get("name", "Unknown")
        country = server.get("country", "?")
        source = server.get("source", "?")
        is_failed = endpoint in self.failed_servers
        fail_mark = " [FAIL]" if is_failed else ""
        if gold_fresh(server):
            gold_mark = "\u2605 "
        elif server.get("verified"):
            gold_mark = "\u2606 "  # verified once, now expired -> needs refresh
        else:
            gold_mark = ""
        active_mark = " [ACTIVE]" if endpoint and endpoint == self.active_endpoint else ""
        display = f"{gold_mark}{name} [{country}] {endpoint} ({source}){fail_mark}{active_mark}"
        if endpoint and endpoint == self.active_endpoint and not is_failed:
            fg = "#3fb950"
        elif is_failed:
            fg = "#f85149"
        elif gold_fresh(server):
            fg = "#ffd866"
        else:
            fg = "#c9d1d9"
        return display, fg

    def _dbl_connect(self, row):
        self.select_server_row(row)
        # Double-click always force-connects to that row (switches even if up)
        self.step1_connect(force=True)

    def _mark_active_row(self):
        for w in self.server_list_frame.winfo_children():
            if hasattr(w, "server_data"):
                try:
                    text, fg = self._row_display(w.server_data)
                    w.lbl.config(text=text, fg=fg)
                except Exception:
                    pass
                try:
                    ep = w.server_data.get("endpoint", "")
                    if hasattr(w, "ping_label"):
                        w.ping_label.config(text=self._ping_text(ep), fg=self._ping_color(ep))
                except Exception:
                    pass

    def select_all(self):
        for widget in self.server_list_frame.winfo_children():
            if hasattr(widget, 'checked'):
                widget.checked.set(True)

    def deselect_all(self):
        for widget in self.server_list_frame.winfo_children():
            if hasattr(widget, 'checked'):
                widget.checked.set(False)

    def select_active(self):
        for widget in self.server_list_frame.winfo_children():
            if hasattr(widget, 'checked') and hasattr(widget, 'server_data'):
                endpoint = widget.server_data.get("endpoint", "")
                # UP (True) + UNKNOWN (None, silent) are both worth trying;
                # only definitive DOWN (False) is excluded.
                st = self.server_status.get(endpoint, None)
                widget.checked.set(st is not False)

    def verify_selected(self):
        """Deep verify: real WireGuard handshake via wireproxy + IP check.

        This is the ground truth. Fast scan (ping/UDP) can say UP while the
        actual WG keys are expired, or vice versa. Verify connects for real
        and reports the obtained exit IP.
        """
        server = self._get_selected_from_list()
        if not server:
            # fall back to checked servers
            checked = self.get_checked_servers()
            if checked:
                server = checked[0]
            else:
                self.log("Select a server first (click a row), then Verify.")
                messagebox.showinfo("Verify", "Click a server row first, then press Verify.")
                return
        if self._busy_vpn("Verify"):
            return
        self.log(f"Verifying {server.get('name', '?')} (real VPN handshake)...")
        # Same visual pattern as Scan: disable while working (deep-check button).
        try:
            self.btn_verify.config(state="disabled", text="Verifying...")
        except Exception:
            pass
        # Remember active session so Verify never kills a live VPN
        # (old bug: Verify did kill_wp() and left the red Disconnect button on a dead tunnel).
        was_connected = self._is_vpn_up()
        was_endpoint = self.active_endpoint
        was_server = None
        try:
            if was_connected and was_endpoint:
                for s in (self.all_servers or []):
                    if s.get("endpoint") == was_endpoint:
                        was_server = s
                        break
        except Exception:
            was_server = None
        threading.Thread(target=self._verify_thread,
                         args=(server, was_connected, was_endpoint, was_server, self._sess),
                         daemon=True).start()

    def _verify_thread(self, server, was_connected=False, was_endpoint=None, was_server=None, sess=None):
        endpoint = server.get("endpoint", "")
        try:
            kill_wp()
            try:
                kernel_uninstall()
            except Exception:
                pass
            with open(WG_CONF, "w", encoding="utf-8") as f:
                f.write(make_conf(server))
            _spawn_wp(WG_CONF)
            ip = wait_for_vpn_ready(timeout_total=7)
            if not ip:
                self._safe_after(0, lambda: self.log(f"Verify {server.get('name')}: FAIL (tunnel down)"))
                self.server_status[endpoint] = False
                self.server_checks[endpoint] = "Real handshake failed"
                self.failed_servers.add(endpoint)
                self._safe_after(0, lambda: self._update_server_status(endpoint, False))
                kill_wp()
                # Restore the previous live session if we interrupted one.
                self._verify_restore(was_connected, was_endpoint, was_server, sess)
                return
            kill_wp()
            if ip:
                self._safe_after(0, lambda: self.log(f"Verify {server.get('name')}: OK, exit IP = {ip}"))
                self.server_status[endpoint] = True
                self.server_checks[endpoint] = f"Verified {ip}"
                self.failed_servers.discard(endpoint)
                stamp_verified(server, ip)
                save_servers(self.all_servers)
                self._safe_after(0, lambda: self._update_server_status(endpoint, True))
                # Restore the previous live session if we interrupted one.
                self._verify_restore(was_connected, was_endpoint, was_server, sess)
            else:
                self._safe_after(0, lambda: self.log(f"Verify {server.get('name')}: FAIL (no exit IP)"))
                self.server_status[endpoint] = False
                self.server_checks[endpoint] = "No exit IP"
                self._safe_after(0, lambda: self._update_server_status(endpoint, False))
                self._verify_restore(was_connected, was_endpoint, was_server, sess)
        except Exception as e:
            try:
                kill_wp()
            except Exception:
                pass
            self._safe_after(0, lambda: self.log(f"Verify error: {e}"))
            try:
                self._verify_restore(was_connected, was_endpoint, was_server, sess)
            except Exception:
                pass
        finally:
            self._safe_after(0, lambda: self.btn_verify.config(state="normal", text="Verify"))

    def _verify_restore(self, was_connected, was_endpoint, was_server, sess=None):
        """Reconnect the session Verify interrupted (if any), keep button truthful.

        Skipped when the session changed meanwhile (Reset/Disconnect during
        Verify): resurrecting a killed tunnel was a classic stuck state.
        """
        try:
            if sess is not None and sess != self._sess:
                self._safe_after(0, lambda: self.log("Verify done - session changed, no restore."))
                return
            if not was_connected or not was_server:
                # Nothing to restore: make sure the main button shows
                # the real state (disconnected -> green Connect).
                if not self._is_vpn_up():
                    self._safe_after(0, lambda: self._set_btn_disconnected(msg="Ready"))
                return
            self._safe_after(0, lambda: self.log(f"Verify done - restoring {was_server.get('name', '?')}..."))
            try:
                with open(WG_CONF, "w", encoding="utf-8") as f:
                    f.write(make_conf(was_server))
            except Exception:
                return
            _spawn_wp(WG_CONF)
            ip = wait_for_vpn_ready(timeout_total=7)
            if ip:
                self.active_endpoint = was_endpoint
                self._safe_after(0, lambda: self._mark_active_row())
                self._safe_after(0, lambda: self._set_btn_connected())
                self._safe_after(0, lambda: self.log(f"Restored VPN ({ip})"))
                self._safe_after(0, self.update_info)
            else:
                # Restore failed -> show real state (green Connect), not stale red.
                self._safe_after(0, lambda: self._set_btn_disconnected(msg="Ready"))
        except Exception:
            pass

    def get_checked_servers(self):
        checked = []
        for widget in self.server_list_frame.winfo_children():
            if hasattr(widget, 'checked') and widget.checked.get():
                checked.append(widget.server_data)
        return checked

    def delete_selected(self):
        to_delete = self.get_checked_servers()
        if not to_delete:
            self.log("No servers selected!")
            return

        if not messagebox.askyesno("Confirm Delete",
                                    f"Delete {len(to_delete)} selected server(s)?"):
            return

        endpoints = {s["endpoint"] for s in to_delete}
        self.all_servers = [s for s in self.all_servers if s["endpoint"] not in endpoints]
        save_servers(self.all_servers)

        self._refresh_filter_menus()

        self.refresh_server_list()
        self.log(f"Deleted {len(to_delete)} server(s)")

    def delete_inactive(self):
        inactive = []
        for s in self.all_servers:
            ep = s.get("endpoint", "")
            # Only definitive DOWN (False). UNKNOWN (None, silent) is kept:
            # WireGuard silence is not proof of death (old bug deleted those).
            if ep in self.server_status and self.server_status[ep] is False:
                inactive.append(s)

        if not inactive:
            self.log("No DOWN servers found. Run Scan All first. (UNKNOWN/silent servers are kept.)")
            return

        if not messagebox.askyesno("Confirm Delete",
                                    f"Delete {len(inactive)} DOWN server(s)?\n"
                                    f"(Only red DOWN servers. Orange UNKNOWN/silent are kept.)"):
            return

        endpoints = {s["endpoint"] for s in inactive}
        self.all_servers = [s for s in self.all_servers if s["endpoint"] not in endpoints]
        save_servers(self.all_servers)

        self._refresh_filter_menus()

        self.refresh_server_list()
        self.log(f"Deleted {len(inactive)} inactive server(s)")

    def _get_selected_from_list(self):
        try:
            sel_text = self.server_var.get()
        except Exception:
            return None
        for s in (self.servers or []):
            try:
                label = f"{s['name']} ({s['endpoint']})"
                if label == sel_text:
                    return s
            except Exception:
                continue
        # Fall back to full list (filter may hide the previously picked row).
        for s in (self.all_servers or []):
            try:
                label = f"{s['name']} ({s['endpoint']})"
                if label == sel_text:
                    return s
            except Exception:
                continue
        return None

    def _resolve_server_for_connect(self):
        """Connect target: clicked row -> single checked box -> best server.

        One-click Connect must work with no manual selection: fall back to
        get_best_server() (fastest verified, failed skipped) instead of a
        blocking popup. Popup helper is kept but no longer blocks Connect.
        """
        server = self._get_selected_from_list()
        if server:
            return server
        # Highlighted row fallback: single-click sets _selected_row; if the
        # server_var string ever desyncs (filter/search rebuild, rename),
        # the highlight index is still the user's explicit choice and must
        # win over auto-pick (fixes "Connect ignores my click" reports).
        try:
            idx = getattr(self, "_selected_row", None)
            if isinstance(idx, int) and 0 <= idx < len(self.servers or []):
                hl = (self.servers or [])[idx]
                if isinstance(hl, dict) and hl.get("endpoint"):
                    try:
                        self.server_var.set(f"{hl['name']} ({hl['endpoint']})")
                    except Exception:
                        pass
                    return hl
        except Exception:
            pass
        # A single checked checkbox counts as an explicit choice
        # (users tick the box thinking it selects the row).
        try:
            checked = self.get_checked_servers()
        except Exception:
            checked = []
        if len(checked) == 1:
            try:
                self._apply_popup_choice(checked[0])
            except Exception:
                pass
            return checked[0]
        if len(checked) > 1:
            # Several boxes ticked: dial the best of them, no popup.
            try:
                best = self.get_best_server()
                if best and best in checked:
                    self._apply_popup_choice(best)
                    return best
            except Exception:
                pass
            try:
                self._apply_popup_choice(checked[0])
            except Exception:
                pass
            return checked[0]
        # Nothing selected at all -> auto-pick best (never block Connect).
        try:
            best = self.get_best_server()
            if best:
                try:
                    self._apply_popup_choice(best)
                except Exception:
                    pass
                self.log(f"Auto-picked: {best.get('name', '?')} ({best.get('endpoint', '?')})")
                return best
        except Exception:
            pass
        return None

    def _apply_popup_choice(self, server):
        """Reflect a popup/checkbox choice in the main list (highlight + var)."""
        try:
            ep = (server or {}).get("endpoint", "")
            if not ep:
                return
            self.server_var.set(f"{server['name']} ({server['endpoint']})")
            try:
                self._selected_row = self.servers.index(server)
            except ValueError:
                try:
                    # Same endpoint object from all_servers (filter hides it).
                    for i, s in enumerate(self.servers):
                        if s.get("endpoint") == ep:
                            self._selected_row = i
                            server = s
                            break
                except Exception:
                    pass
            for w in self.server_list_frame.winfo_children():
                try:
                    if hasattr(w, "server_data") and w.server_data.get("endpoint") == ep:
                        self.select_server_row(w)
                        break
                except Exception:
                    continue
        except Exception:
            pass

    def _popup_choose_server(self, prefill=None):
        """Small modal list: user must pick an IP, then Connect dials it.

        Returns the chosen server dict or None if cancelled/empty.
        """
        cands = list(prefill) if prefill else list(self.servers or self.all_servers or [])
        if not cands:
            self.log("No servers available! Fetch or Import first.")
            messagebox.showinfo("Choose Server", "No servers available!\nFetch or Import first.")
            return None
        result = {"server": None}

        d = tk.Toplevel(self)
        d.title("Choose Server")
        d.geometry("540x430")
        d.configure(bg="#0d1117")
        d.transient(self)
        d.grab_set()

        tk.Label(d, text="Choose an IP to connect:",
                 bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 10, "bold")).pack(pady=(12, 4))

        search_v = tk.StringVar()
        se = tk.Entry(d, textvariable=search_v, bg="#161b22", fg="#c9d1d9",
                      insertbackground="#c9d1d9", font=("Consolas", 9), width=60)
        se.pack(padx=15, fill="x", pady=(0, 6))
        se.focus_set()

        lb_frame = tk.Frame(d, bg="#0d1117")
        lb_frame.pack(padx=15, fill="both", expand=True)
        lb = tk.Listbox(lb_frame, bg="#161b22", fg="#c9d1d9",
                        font=("Consolas", 9), selectmode="single",
                        highlightthickness=0, activestyle="none")
        sb = tk.Scrollbar(lb_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        shown = {"items": []}

        def refresh_lb(*a):
            q = (search_v.get() or "").lower().strip()
            lb.delete(0, "end")
            items = []
            for s in cands:
                try:
                    txt = f"{s.get('name','?')} [{s.get('country','?')}] {s.get('endpoint','?')} ({s.get('source','?')})"
                except Exception:
                    continue
                if q and q not in txt.lower():
                    continue
                items.append((txt, s))
            # UP first so a usable IP is on top (no silent auto-pick though).
            def rank(item):
                _, s = item
                st = self.server_status.get(s.get("endpoint", ""), "unscanned")
                return 0 if st is True else (1 if st is None else (2 if st == "unscanned" else 3))
            items.sort(key=rank)
            shown["items"] = items
            for txt, _ in items:
                lb.insert("end", txt)
            if items:
                lb.selection_set(0)
                lb.see(0)

        try:
            search_v.trace_add("write", refresh_lb)
        except Exception:
            pass
        refresh_lb()

        btns = tk.Frame(d, bg="#0d1117")
        btns.pack(fill="x", padx=15, pady=12)

        def on_ok(*a):
            try:
                sel = lb.curselection()
                idx = sel[0] if sel else (0 if shown["items"] else None)
                if idx is None:
                    return
                result["server"] = shown["items"][idx][1]
            except Exception:
                result["server"] = None
            try:
                d.grab_release()
            except Exception:
                pass
            d.destroy()

        def on_cancel():
            result["server"] = None
            try:
                d.grab_release()
            except Exception:
                pass
            d.destroy()

        lb.bind("<Double-Button-1>", on_ok)
        d.bind("<Return>", on_ok)
        d.bind("<Escape>", lambda e: on_cancel())
        tk.Button(btns, text="Connect", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=14,
                  command=on_ok).pack(side="right", padx=(5, 0))
        tk.Button(btns, text="Cancel", bg="#6e7681", fg="white",
                  font=("Segoe UI", 9, "bold"), width=10,
                  command=on_cancel).pack(side="right")
        try:
            self.wait_window(d)
        except Exception:
            pass
        chosen = result.get("server")
        if chosen:
            try:
                self._apply_popup_choice(chosen)
            except Exception:
                pass
            self.log(f"Picked: {chosen.get('name', '?')} ({chosen.get('endpoint', '?')})")
        else:
            self.log("Choose cancelled - no server picked.")
        return chosen

    def get_best_server(self):
        """P0: fastest verified server first (UP + lowest latency + not failed).

        Old rotate picked next-in-list regardless of speed. This sorts by:
        1) verified UP, 2) latency asc, 3) UNKNOWN-silent, 4) rest. Failed excluded.
        """
        cands = [s for s in (self.servers or self.all_servers)
                 if s.get("endpoint") not in self.failed_servers]
        if not cands:
            cands = list(self.servers or self.all_servers)
        if not cands:
            return None

        def score(s):
            ep = s.get("endpoint", "")
            st = self.server_status.get(ep, "unscanned")
            lat = self.server_latency.get(ep, 9999)
            try:
                lat = float(lat) if lat and lat > 0 else 9999
            except Exception:
                lat = 9999
            # Prefer Cloudflare/WARP anycast (lowest routing distance)
            try:
                host = (ep or "").split(":")[0]
                cf_bonus = -50 if host.startswith("188.114") or host.startswith("162.159") else 0
            except Exception:
                cf_bonus = 0
            # Sources-first: only FRESH gold (verified within TTL) ranks top.
            # Stale gold is demoted to normal candidacy until re-verified.
            if gold_fresh(s):
                rank = -1
            elif st is True:
                rank = 0
            elif st == "unscanned":
                rank = 1
            elif st is None:
                rank = 2
            else:
                rank = 3
            return (rank, lat + cf_bonus)

        cands.sort(key=score)
        return cands[0]

    def _safe_after(self, ms, func, *args, **kwargs):
        """after() that never crashes on closed/destroyed widgets."""
        try:
            return self.after(ms, func, *args, **kwargs)
        except Exception:
            try:
                func(*args, **kwargs)
            except Exception:
                pass
            return None

    def log(self, msg):
        try:
            ts = time.strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{ts}] {msg}\n")
            # Bound widget growth (was unbounded -> Tk slowdown / RAM leak)
            try:
                count = int(self.log_text.index("end-1c").split(".")[0])
                if count > _LOG_MAX_LINES:
                    self.log_text.delete("1.0", f"{count - _LOG_MAX_LINES}.0")
            except Exception:
                pass
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass

    def done(self, i, ok=True):
        self._animating = False
        self.steps_done[i] = True
        if i == 0 and ok:
            # Same button flips: green Connect -> red Disconnect
            self.step_btns[i].config(state="normal", text="Disconnect",
                                     bg="#da3633", fg="white")
            self.step_status[i].config(text="Connected", fg="#3fb950")
            if i + 1 < 2 and not self.steps_done[i + 1]:
                self.step_btns[i + 1].config(state="normal", bg="#238636")
            return
        self.step_btns[i].config(state="disabled", bg="#21262d")
        self.step_status[i].config(
            text="Done" if ok else "Failed",
            fg="#3fb950" if ok else "#f85149")
        if ok and i + 1 < 2:
            self.step_btns[i + 1].config(state="normal", bg="#238636")

    def _set_btn_connected(self):
        """Flip step-1 button to red Disconnect (same button)."""
        try:
            self.connected = True
            self.steps_done[0] = True
            self._animating = False
            self.step_btns[0].config(state="normal", text="Disconnect",
                                     bg="#da3633", fg="white")
            self.step_status[0].config(text="Connected", fg="#3fb950")
            if len(self.step_btns) > 1 and not self.steps_done[1]:
                self.step_btns[1].config(state="normal", bg="#238636")
        except Exception:
            pass

    def _set_btn_disconnected(self, msg="Ready"):
        """Flip step-1 button back to green Connect (same button)."""
        try:
            self.connected = False
            self.steps_done[0] = False
            self._animating = False
            self.active_endpoint = None
            try:
                self._mark_active_row()
            except Exception:
                pass
            self.step_btns[0].config(state="normal", text="Connect",
                                     bg="#238636", fg="white")
            self.step_status[0].config(text=msg, fg="#f0883e")
            # If OpenCode not launched yet, lock Launch again until next connect
            try:
                if len(self.step_btns) > 1 and not self.steps_done[1]:
                    self.step_btns[1].config(state="disabled", bg="#21262d")
            except Exception:
                pass
            self.lbl_status.config(text="Disconnected", fg="#f85149")
            self.lbl_ip.config(text="IP: ---")
        except Exception:
            pass

    def disconnect_vpn(self):
        """Disconnect both proxy and kernel tunnels, flip button back.

        UI flips instantly; the (sometimes slow: taskkill/service) kills run
        in the background so the button never looks frozen. Bumps the session
        so in-flight connect/rotate threads can no longer resurrect the UI.
        """
        try:
            self._sess += 1
        except Exception:
            pass
        try:
            was_up = bool(getattr(self, "connected", False) and getattr(self, "active_endpoint", None))
        except Exception:
            was_up = False
        # Stray check: flag can be False while OUR stray wireproxy / our
        # kernel tunnel is still alive (e.g. transient IP-check failure
        # cleared the flag). Those strays must still be killed, otherwise
        # they linger forever (old path skipped kills when was_up=False).
        try:
            stray_wp = wp_running(use_cache=True)
        except Exception:
            stray_wp = False
        try:
            stray_kernel = kernel_tunnel_up()
        except Exception:
            stray_kernel = False
        need_kill = bool(was_up or stray_wp or stray_kernel)
        self._set_btn_disconnected(msg="Ready")
        try:
            self.update_idletasks()
        except Exception:
            pass
        # Avoid misleading "Disconnected." spam when nothing was connected
        # (old bug: every stray Connect press logged Disconnected).
        self.log("Disconnecting..." if need_kill else "Ready (already disconnected).")
        if need_kill:
            threading.Thread(target=self._disconnect_kills, args=(was_up,), daemon=True).start()

    def _disconnect_kills(self, was_up):
        try:
            kill_wp()
        except Exception:
            pass
        try:
            kernel_uninstall()
        except Exception:
            pass
        try:
            if os.path.exists(KERNEL_CONF):
                os.remove(KERNEL_CONF)
        except Exception:
            pass
        if was_up:
            self._safe_after(0, lambda: self.log("Disconnected."))

    def _is_our_session(self):
        """True only if WE own an active session (flag + endpoint).

        Foreign wireproxy.exe / foreign WireGuard tunnels must NEVER
        count as 'our VPN up' - otherwise a stray process bricks the
        green Connect button (single-click swallowed, double-click works
        because force=True bypasses the toggle).
        """
        try:
            return bool(getattr(self, "connected", False) and getattr(self, "active_endpoint", None))
        except Exception:
            return False

    def _is_vpn_up(self, fresh=True):
        """True only if OUR session is active AND our tunnel is live.

        OUR-session-gated (fixes single-click Connect bug):
          - flag False (Disconnected UI) -> ALWAYS False, even if a stray
            wireproxy.exe or a foreign kernel tunnel is up. A green Connect
            press must then proceed to connect (its thread kills strays),
            never mis-fire as Disconnect.
          - flag True (we connected) -> confirm with OUR processes:
            tracked/live wireproxy OR our opencode-kernel tunnel only
            (kernel_tunnel_up, NOT any_kernel_up which includes foreign).
        fresh=True uses a live tasklist check (no 1s cache) so the
        Connect toggle never mistakes a stale cache for a live tunnel.
        Button text "Connecting..." is BUSY, not UP (handled separately).
        """
        try:
            if not self._is_our_session():
                return False
        except Exception:
            return False
        try:
            if wp_running(use_cache=(not fresh)):
                return True
        except Exception:
            pass
        try:
            # OURS only: foreign tunnels (any_kernel_up) must not flip
            # the Connect button. One wg.exe spawn only (perf).
            if kernel_tunnel_up():
                return True
        except Exception:
            pass
        # Flag says up but no live OUR tunnel -> stale (crashed/killed
        # externally). Report down so a red-button press resets and
        # reconnects in the SAME click instead of needing two clicks.
        return False

    def _is_any_vpn_up(self):
        """System-wide check (ours + foreign), for status/refresh guards only.

        NEVER use for the Connect/Disconnect toggle - that must be
        _is_vpn_up() (ours only).
        """
        try:
            if self._is_vpn_up(fresh=False):
                return True
        except Exception:
            pass
        try:
            if wp_running():
                return True
        except Exception:
            pass
        try:
            if any_kernel_up():
                return True
        except Exception:
            pass
        return False

    def _pulse_step(self, i, base, dots=0):
        """Progress dots while a step runs (stops when done()/failed)."""
        try:
            if not self._animating or (i < len(self.steps_done) and self.steps_done[i]):
                return
            self.step_status[i].config(text=base + "." * (dots % 4 or 1))
            self.after(400, lambda: self._pulse_step(i, base, dots + 1))
        except Exception:
            pass

    def update_info(self):
        """Non-blocking: network I/O in background, labels via after.

        Old version ran get_ip()/fetch_direct_ip() (up to ~4-8s) on the Tk
        main thread -> full UI freeze after every connect/rotate.
        """
        try:
            self.lbl_rotations.config(text=f"Rotations: {self.rotation_count}")
        except Exception:
            pass
        if getattr(self, "_updating_info", False):
            return
        self._updating_info = True
        threading.Thread(target=self._update_info_bg, daemon=True).start()

    def _update_info_bg(self):
        try:
            if any_kernel_up():
                ip = fetch_direct_ip(timeout=4)
                self._safe_after(0, lambda: self._apply_info_result(ip, True))
            else:
                ip = get_ip()
                self._safe_after(0, lambda: self._apply_info_result(ip, False))
        except Exception:
            self._safe_after(0, lambda: self._apply_info_result(None, False))
        finally:
            self._safe_after(0, lambda: setattr(self, "_updating_info", False))

    def _apply_info_result(self, ip, is_kernel):
        # NOTE: transient IP-check failure must NOT clear the session flag
        # (old bug: providers blocked -> connected=False while wireproxy was
        # still running + button red -> next Connect press saw wp_running and
        # mis-fired as Disconnect, bricking single-click Connect forever).
        try:
            if is_kernel:
                self.lbl_ip.config(text=f"IP: {ip or '---'} (kernel)")
                if ip:
                    self.connected = True
                    self.lbl_status.config(text="Kernel Direct", fg="#3fb950")
                    if not self._animating:
                        self._set_btn_connected()
                else:
                    # Keep OUR session alive if OUR kernel tunnel is still up
                    # (transient provider/DNS failure, not a dead tunnel).
                    try:
                        ours_up = kernel_tunnel_up()
                    except Exception:
                        ours_up = False
                    if ours_up and self._is_our_session():
                        self.lbl_status.config(text="Kernel? (IP check failed)", fg="#f0883e")
                    else:
                        self.connected = False
                        self.lbl_status.config(text="Kernel?", fg="#f0883e")
                return
            self.lbl_ip.config(text=f"IP: {ip or '---'}")
            if ip:
                self.connected = True
                self.lbl_status.config(text="Connected", fg="#3fb950")
                if not self._animating:
                    self._set_btn_connected()
            else:
                try:
                    ours_up = wp_running(use_cache=True) or kernel_tunnel_up()
                except Exception:
                    ours_up = False
                if ours_up and self._is_our_session():
                    # Tunnel alive, only the IP providers failed -> do NOT
                    # desync the flag/button; next Connect still toggles right.
                    self.lbl_status.config(text="Connected? (IP check failed)", fg="#f0883e")
                else:
                    # No live OUR tunnel (or no session) -> truly down.
                    # Only clear the flag when there is no session to protect;
                    # an in-flight connect (animating) owns the flag.
                    if not self._animating:
                        self.connected = False
                    self.lbl_status.config(text="Disconnected", fg="#f85149")
        except Exception:
            pass

    def check_all_servers(self):
        # Toggle: while scanning the SAME button is a red Stop.
        if self.checking:
            try:
                self._scan_stop.set()
            except Exception:
                pass
            self.log("Stopping scan...")
            return
        if self.speed_testing:
            self.log("Speed test running - stop it first.")
            return
        targets = list(self.servers)
        if not targets:
            self.log("Nothing to scan (empty list). Fetch or Import first.")
            return
        self.checking = True
        try:
            self._scan_stop.clear()
        except Exception:
            pass
        # Stay enabled so the user can press Stop; red = cancellable.
        self.btn_check_all.config(state="normal", text="Stop", bg="#da3633")
        self.log(f"Scanning {len(targets)} servers (parallel)... (press Stop to cancel)")
        self.lbl_checked.config(text="Scanning...")
        threading.Thread(target=self._check_all_thread, args=(targets,), daemon=True).start()

    def _check_all_thread(self, targets):
        total = len(targets)
        done_count = 0
        lock = threading.Lock()
        cancelled = False
        _SKIP = object()

        def check_one(server):
            nonlocal done_count
            if self._scan_stop.is_set():
                return _SKIP
            endpoint = server.get("endpoint", "")
            host = endpoint.split(":")[0] if ":" in endpoint else endpoint
            port_str = endpoint.split(":")[1] if ":" in endpoint else "51820"
            try:
                port = int(str(port_str).strip())
            except (ValueError, TypeError):
                port = 51820
            alive, ms, reason = check_server(host, port)
            # Merged ping check: Scan All also fills the Ping column.
            # check_server returns ms only when ICMP answered; otherwise do
            # one explicit ICMP ping so the Ping column still shows a value.
            ping_ms = ms
            if not (ping_ms and ping_ms > 0):
                try:
                    ping_ms = icmp_ping(host, timeout_ms=1200)
                    ping_ms = round(ping_ms, 1) if ping_ms and ping_ms > 0 else -1
                except Exception:
                    ping_ms = -1
            self.server_status[endpoint] = alive
            self.server_checks[endpoint] = reason
            if ping_ms and ping_ms > 0:
                self.server_latency[endpoint] = ping_ms
                ms = ping_ms
            elif ms and ms > 0:
                self.server_latency[endpoint] = ms
            with lock:
                done_count += 1
                n = done_count
            if alive is True:
                status = "UP"
            elif alive is None:
                status = "UNKNOWN"
            else:
                status = "DOWN"
            extra = f" ({ms}ms)" if ms and ms > 0 else f" ({reason})"
            name = server.get("name", "?")
            self._safe_after(0, lambda n=n, name=name, status=status, extra=extra:
                             self.log(f"[{n}/{total}] {name} -> {status}{extra}"))
            self._safe_after(0, lambda endpoint=endpoint, alive=alive, ms=ms:
                             self._update_server_status(endpoint, alive, ms))
            return alive

        active = 0
        unknown = 0
        inactive = 0

        # 20 workers: 50 ping.exe spawns thrashed weak machines (no speedup past ~20)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_one, s): s for s in targets}
            for future in as_completed(futures):
                if self._scan_stop.is_set():
                    for f in futures:
                        try:
                            f.cancel()
                        except Exception:
                            pass
                    cancelled = True
                    break
                try:
                    res = future.result()
                except Exception:
                    continue
                if res is _SKIP:
                    continue
                if res is True:
                    active += 1
                elif res is None:
                    unknown += 1
                else:
                    inactive += 1

        self._safe_after(0, lambda: self._check_done(active, unknown, inactive, total, cancelled))

    def _update_server_status(self, endpoint, alive, latency=None):
        try:
            if latency and latency > 0:
                self.server_latency[endpoint] = latency
            for widget in self.server_list_frame.winfo_children():
                if hasattr(widget, 'server_data') and widget.server_data.get("endpoint") == endpoint:
                    # 3-state dot: green=UP, orange=UNKNOWN(silent), red=DOWN
                    if alive is True:
                        widget.status_label.config(fg="#3fb950", text="\u25cf")
                    elif alive is None:
                        widget.status_label.config(fg="#f0883e", text="\u25cf")
                    else:
                        widget.status_label.config(fg="#f85149", text="\u25cf")
                    self._refresh_row_text(widget)
                    break
        except Exception:
            pass

    def _refresh_row_text(self, widget):
        try:
            text, fg = self._row_display(widget.server_data)
            widget.lbl.config(text=text, fg=fg)
        except Exception:
            pass
        try:
            ep = widget.server_data.get("endpoint", "")
            if hasattr(widget, "ping_label"):
                widget.ping_label.config(text=self._ping_text(ep), fg=self._ping_color(ep))
        except Exception:
            pass

    def _check_done(self, active, unknown, inactive, total, cancelled=False):
        self.checking = False
        try:
            self._scan_stop.clear()
        except Exception:
            pass
        self.btn_check_all.config(state="normal", text="Scan All", bg="#1f6feb")
        suffix = " (stopped)" if cancelled else ""
        self.lbl_checked.config(text=f"UP: {active} | ??: {unknown} | DOWN: {inactive}{suffix}")
        self.log(f"Scan {'stopped' if cancelled else 'complete'}: {active} UP, {unknown} UNKNOWN, {inactive} DOWN / {total}{suffix} "
                 f"(green=alive, orange=silent/unverified->use Verify, red=dead)")
        if not cancelled and active > 0:
            self.log("Tip: double-click a GREEN row for instant connect (dead rows are skipped by Rotate).")

    def step1_connect(self, force=False):
        # Same button toggles (like deep-verify): green Connect <-> red Disconnect.
        # After a successful connect the SAME button turns red and cancels on next press.
        # force=True (double-click / auto-resume) bypasses toggle and connects.
        # Refresh owns WG_CONF+wireproxy while running -> refuse ALL connects
        # meanwhile (even double-click: it would corrupt refresh checks AND
        # the connect). Refresh-resume clears the flag before dialing.
        if getattr(self, "refreshing", False):
            self.log("Refresh running... stop it first, then connect.")
            messagebox.showinfo("Busy", "GOLD refresh is running.\nStop it first, then connect.")
            return
        if getattr(self, "rotating", False):
            self.log("Rotate in progress - wait, then connect.")
            return
        DISCONNECT_TEXTS = ("disconnect", "cancel", "disconnected")
        if not force:
            try:
                cur_text = (self.step_btns[0].cget("text") or "").strip().lower()
            except Exception:
                cur_text = "connect"
            # Busy (connect already running) -> ignore extra clicks.
            if cur_text == "connecting...":
                self.log("Connecting... please wait.")
                return
            really_up = self._is_vpn_up(fresh=True)
            if cur_text in DISCONNECT_TEXTS or really_up:
                if really_up:
                    self.disconnect_vpn()
                    return
                # Stale red button with no live tunnel -> reset to green
                # and CONTINUE to connect (old bug just logged "Disconnected").
                try:
                    self._set_btn_disconnected(msg="Ready")
                except Exception:
                    pass
        server = self._resolve_server_for_connect()
        if not server:
            # Empty list (nothing to auto-pick) -> stay idle.
            self.step_status[0].config(text="No server - Fetch or Import first!", fg="#f85149")
            self.log("Connect: empty list, nothing to dial. Fetch or Import first.")
            return
        endpoint = server.get("endpoint", "")
        st = self.server_status.get(endpoint, "unscanned")
        if st is False:
            if not messagebox.askyesno("Server DOWN",
                                        f"{server['name']} is DOWN (UDP closed / DNS fail).\nTry anyway?"):
                return
        elif st is None:
            if not messagebox.askyesno("Server unverified",
                                        f"{server['name']} is SILENT (no ping reply).\n"
                                        f"It may still work (WireGuard is silent by design).\n"
                                        f"Use Verify for certainty. Connect anyway?"):
                return
        self.log(f"Connecting to {server['name']}...")
        self.step_status[0].config(text="Running...", fg="#f0883e")
        # Connecting state: disabled + clear label so user sees progress
        # (old code kept text "Connect" while disabled -> looked broken/stuck).
        self.step_btns[0].config(state="disabled", text="Connecting...")
        self._animating = True
        self.after(100, lambda: self._pulse_step(0, "Connecting"))
        self.update()
        sess = self._sess  # late completions from an older session are ignored
        threading.Thread(target=self._step1_thread, args=(server, sess), daemon=True).start()

    def _step1_thread(self, server, sess):
        try:
            kill_wp()
            # Proxy mode owns routing: drop OUR kernel tunnel first so a
            # leftover opencode-kernel does not hijack wireproxy's traffic
            # (dual tunnels -> wrong exit IP / false "connection failed").
            try:
                kernel_uninstall()
            except Exception:
                pass
            try:
                with open(WG_CONF, "w", encoding="utf-8") as f:
                    f.write(make_conf(server))
            except Exception as e:
                self._safe_after(0, lambda: self.log(f"Conf write failed: {e}"))
                self._safe_after(0, self._step1_failed)
                return
            success_ip = None
            for attempt in range(3):
                # NOTE: no stop_event check here on purpose. The global
                # stop_event stays SET after Reset/Protect-OFF, which used to
                # abort every future connect instantly ("failed after 3
                # attempts" without trying). Reset/close kills wireproxy, so
                # this loop still exits naturally via failed polls.
                # Stale session (Reset/Disconnect meanwhile) -> abort quietly,
                # but never leave the button stuck on disabled "Connecting...".
                if sess != self._sess:
                    self._safe_after(0, self._step1_failed_if_connecting)
                    return
                self._safe_after(0, lambda a=attempt: self.log(f"Attempt {a + 1}/3..."))
                if _spawn_wp(WG_CONF) is None and not os.path.isfile(WG_PROXY or ""):
                    self._safe_after(0, lambda: self.log("wireproxy.exe not found! Use Paths button."))
                    break
                # P0: fast poll (returns in ~0.5-2s on good server) instead of fixed sleep(5)
                ip = wait_for_vpn_ready(timeout_total=7)
                if ip:
                    success_ip = ip
                    break
                self._safe_after(0, lambda a=attempt: self.log(f"Attempt {a + 1} failed, retrying..."))
                kill_wp()
                time.sleep(1)
            if success_ip:
                self._safe_after(0, lambda: self._step1_done(server, success_ip, sess))
            else:
                # Remember the dead endpoint so Rotate/best-server skips it.
                try:
                    self.failed_servers.add(server.get("endpoint", ""))
                except Exception:
                    pass
                self._safe_after(0, lambda: self.log(
                    f"{server.get('name', '?')} seems dead (3/3 failed) - "
                    f"marked [FAIL], try a GREEN (scanned UP) row."))
                self._safe_after(0, self._step1_failed)
        except Exception as e:
            try:
                kill_wp()
            except Exception:
                pass
            self._safe_after(0, lambda: self.log(f"Connect thread error: {e}"))
            self._safe_after(0, self._step1_failed)

    def _step1_done(self, server, ip, sess=None):
        # Stale session (Reset/Disconnect meanwhile) -> never touch the UI:
        # the old bug flipped the button back to red Disconnect after reset.
        if sess is not None and sess != self._sess:
            self.log(f"Ignored late success for {server.get('name', '?')} (session changed).")
            return
        # Guarantee the button flips to red Disconnect even if
        # history/log/row-marking throws (old bug left it grey disabled).
        try:
            self.rotation_count += 1
            self.total_rotations_today += 1
            self.ip_history.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "server": server["name"], "ip": ip,
            })
            save_history(self.ip_history)
            self.log(f"Connected to {server['name']} | IP: {ip}")
            self.active_endpoint = server.get("endpoint", "")
            try:
                self._mark_active_row()
            except Exception:
                pass
        finally:
            # Same-button flip: green Connect -> red Disconnect (cancel).
            try:
                self.done(0)
            except Exception:
                try:
                    self._set_btn_connected()
                except Exception:
                    pass
            try:
                self.update_info()
            except Exception:
                pass

    def _step1_failed(self):
        self._animating = False
        self.log("Connection failed after 3 attempts!")
        self.step_status[0].config(text="Failed - Click Connect to retry", fg="#f85149")
        self.step_btns[0].config(state="normal", text="Connect",
                                 bg="#238636", fg="white")

    def _step1_failed_if_connecting(self):
        """Safety net: stale abort must not leave button disabled forever.

        Only restores when the button is still in the transient
        "Connecting..." state (i.e. Reset/Disconnect did NOT already fix
        it). Otherwise it does nothing, so a newer session is never hurt.
        """
        try:
            cur = (self.step_btns[0].cget("text") or "").strip().lower()
        except Exception:
            return
        if cur == "connecting...":
            try:
                self._step1_failed()
            except Exception:
                pass

    def step2_launch(self):
        if not os.path.exists(OPENCODE_EXE):
            self.log("OpenCode.exe not found!")
            self.step_status[1].config(text="Not found!", fg="#f85149")
            return
        self.log("Launching OpenCode...")
        self.step_status[1].config(text="Running...", fg="#f0883e")
        self.update()
        env = os.environ.copy()
        # One check only (any includes ours) - two wg.exe spawns froze Launch.
        if any_kernel_up():
            # P2: kernel tunnel active -> direct routing, NO proxy hop (fastest).
            # Remove any proxy vars so OpenCode goes direct via WireGuard-NT.
            for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                      "https_proxy", "http_proxy", "all_proxy"):
                env.pop(k, None)
            env["NO_PROXY"] = "localhost,127.0.0.1,::1"
            env["no_proxy"] = "localhost,127.0.0.1,::1"
            self.log("Kernel direct mode: OpenCode WITHOUT proxy (via WireGuard-NT).")
        else:
            env["HTTPS_PROXY"] = "http://127.0.0.1:8080"
            env["HTTP_PROXY"] = "http://127.0.0.1:8080"
            # P0: SOCKS5 handshake is ~15-20% faster than HTTP CONNECT; expose both
            # so OpenCode/electron-net can pick the fastest path.
            env["ALL_PROXY"] = "socks5h://127.0.0.1:10808"
            env["all_proxy"] = "socks5h://127.0.0.1:10808"
            env["NO_PROXY"] = "localhost,127.0.0.1,::1"
            env["no_proxy"] = "localhost,127.0.0.1,::1"
        subprocess.Popen([OPENCODE_EXE], env=env)
        self.log("OpenCode launched!")
        self.done(1)
        self.step_status[1].config(text="Running!", fg="#3fb950")

    def import_conf(self):
        """Import: pick ONE file or MANY files from disk, review, then add."""
        filepaths = filedialog.askopenfilenames(
            title="Import .conf File(s) - select one or many",
            filetypes=[("WireGuard Config", "*.conf"), ("All Files", "*.*")],
        )
        if not filepaths:
            return
        # Normalize: single string (old behavior) or tuple of paths
        if isinstance(filepaths, str):
            filepaths = (filepaths,)
        parsed, errors = [], 0
        existing_eps = {s.get("endpoint") for s in self.all_servers}
        for fp in filepaths:
            server, error = parse_conf(fp)
            if error or not server:
                errors += 1
                continue
            if server.get("endpoint") in existing_eps:
                continue  # skip duplicates silently, reported in review
            parsed.append(server)
            existing_eps.add(server.get("endpoint"))
        if not parsed:
            self.log(f"Import: nothing new ({errors} errors, rest duplicates).")
            messagebox.showinfo("Import", f"No new servers.\nErrors: {errors}\n(duplicates skipped)")
            return
        # ---- Review step before adding ----
        self._import_review_dialog(parsed, errors)

    def _import_review_dialog(self, parsed, errors=0):
        """Show parsed file(s) for review, user confirms Add."""
        d = tk.Toplevel(self)
        d.title(f"Review Import ({len(parsed)} servers)")
        d.geometry("620x420")
        d.configure(bg="#0d1117")
        d.transient(self)
        d.grab_set()
        tk.Label(d, text=f"Found {len(parsed)} new server(s) - review then Add:",
                 bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))
        txt = scrolledtext.ScrolledText(d, bg="#161b22", fg="#c9d1d9",
                                        font=("Consolas", 9), height=16, width=70)
        txt.pack(padx=15, pady=5, fill="both", expand=True)
        for s in parsed:
            txt.insert("end", f"{s.get('name')} [{s.get('country')}] "
                              f"{s.get('endpoint')} ({s.get('source')})\n")
        if errors:
            txt.insert("end", f"\n({errors} file(s) failed to parse)")
        txt.configure(state="disabled")

        btns = tk.Frame(d, bg="#0d1117")
        btns.pack(fill="x", padx=15, pady=(0, 10))

        def do_add():
            if self._adds_busy("Import"):
                return
            for s in parsed:
                self.all_servers.append(s)
            save_servers(self.all_servers)
            self._refresh_filter_menus()
            self.refresh_server_list()
            self.log(f"Imported {len(parsed)} server(s) from file(s).")
            messagebox.showinfo("Success", f"Added {len(parsed)} server(s).")
            d.destroy()

        tk.Button(btns, text=f"Add {len(parsed)}", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=12,
                  command=do_add).pack(side="right", padx=(5, 0))
        tk.Button(btns, text="Cancel", bg="#6e7681", fg="white",
                  font=("Segoe UI", 9, "bold"), width=8,
                  command=d.destroy).pack(side="right")

    def add_tunnel_dialog(self):
        """Manual '+ Tunnel': type or paste fields, review live, then Add."""
        d = tk.Toplevel(self)
        d.title("Add Tunnel (manual)")
        d.geometry("520x560")
        d.configure(bg="#0d1117")
        d.transient(self)
        d.grab_set()

        tk.Label(d, text="Add WireGuard Tunnel manually:",
                 bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))

        form = tk.Frame(d, bg="#0d1117")
        form.pack(fill="x", padx=15)

        def row(label):
            tk.Label(form, text=label, bg="#0d1117", fg="#8b949e",
                     font=("Segoe UI", 9), width=14, anchor="w").pack(anchor="w", pady=(6, 0))
            var = tk.StringVar()
            tk.Entry(form, textvariable=var, bg="#161b22", fg="#c9d1d9",
                     font=("Consolas", 9), width=60).pack(fill="x")
            return var

        name_v = row("Name (optional):")
        priv_v = row("PrivateKey *:")
        addr_v = row("Address:")
        pub_v = row("PublicKey *:")
        ep_v = row("Endpoint * (ip:port):")
        dns_v = row("DNS:")
        addr_v.set("10.0.0.2/32")
        dns_v.set("1.1.1.1")

        cf = tk.Frame(d, bg="#0d1117")
        cf.pack(fill="x", padx=15, pady=(6, 0))
        tk.Label(cf, text="Country:", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).pack(side="left")
        country_v = tk.StringVar(value="DE")
        tk.OptionMenu(cf, country_v, *["DE", "US", "UK", "FR", "NL",
                                      "CA", "SG", "JP", "AU", "XX"]).pack(side="left", padx=(5, 0))
        tk.Label(cf, text="Source:", bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 9)).pack(side="left", padx=(15, 0))
        source_v = tk.StringVar(value="Manual")
        tk.Entry(cf, textvariable=source_v, bg="#161b22", fg="#c9d1d9",
                 font=("Segoe UI", 9), width=14).pack(side="left", padx=(5, 0))

        preview = tk.Label(d, text="", bg="#0d1117", fg="#f0883e",
                           font=("Consolas", 8), wraplength=480, justify="left")
        preview.pack(padx=15, pady=(8, 0), anchor="w")

        def refresh_preview(*a):
            preview.config(text=f"Review: {name_v.get() or 'wg-...'} | "
                                f"{ep_v.get() or '?'} | key: "
                                f"{'OK' if priv_v.get().strip() and pub_v.get().strip() else 'MISSING'}")
        for v in (name_v, priv_v, pub_v, ep_v):
            v.trace_add("write", refresh_preview)
        refresh_preview()

        btns = tk.Frame(d, bg="#0d1117")
        btns.pack(fill="x", padx=15, pady=12)

        def do_add():
            if self._adds_busy("+ Tunnel"):
                return
            priv, pub, ep = priv_v.get().strip(), pub_v.get().strip(), ep_v.get().strip()
            if not priv or not pub or not ep:
                messagebox.showwarning("Missing", "PrivateKey + PublicKey + Endpoint are required!")
                return
            exists = any(s.get("endpoint") == ep for s in self.all_servers)
            if exists:
                messagebox.showinfo("Exists", f"Endpoint already in list:\n{ep}")
                return
            name = name_v.get().strip() or f"wg-{country_v.get()}-MAN"
            server = {
                "name": name,
                "private_key": priv,
                "address": addr_v.get().strip() or "10.0.0.2/32",
                "public_key": pub,
                "endpoint": ep,
                "dns": dns_v.get().strip() or "1.1.1.1",
                "mtu": "1380",
                "country": country_v.get().strip() or "XX",
                "source": source_v.get().strip() or "Manual",
            }
            self.all_servers.append(server)
            save_servers(self.all_servers)
            self._refresh_filter_menus()
            self.refresh_server_list()
            self.log(f"Manual tunnel added: {name} ({ep})")
            messagebox.showinfo("Success", f"Tunnel added:\n{name}")
            d.destroy()

        tk.Button(btns, text="Add Tunnel", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=12,
                  command=do_add).pack(side="right", padx=(5, 0))
        tk.Button(btns, text="Cancel", bg="#6e7681", fg="white",
                  font=("Segoe UI", 9, "bold"), width=8,
                  command=d.destroy).pack(side="right")

    def bulk_import(self):
        folder = filedialog.askdirectory(title="Select Folder with .conf Files")
        if not folder:
            return
        conf_files = []
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.endswith(".conf"):
                    conf_files.append(os.path.join(root, f))
        if not conf_files:
            self.log("No .conf files found!")
            messagebox.showinfo("Nothing", "No .conf files found in this folder.")
            return
        self.log(f"Found {len(conf_files)} config files...")
        if self._adds_busy("Bulk import"):
            return
        imported = skipped = errors = 0
        for filepath in conf_files:
            server, error = parse_conf(filepath)
            if error:
                errors += 1
                continue
            exists = any(s["endpoint"] == server["endpoint"] for s in self.all_servers)
            if exists:
                skipped += 1
                continue
            self.all_servers.append(server)
            imported += 1
        save_servers(self.all_servers)
        self._refresh_filter_menus()
        self.refresh_server_list()
        self.log(f"Bulk import: {imported} added, {skipped} skipped, {errors} errors")
        messagebox.showinfo("Bulk Import",
                             f"Imported: {imported}\nSkipped: {skipped}\nErrors: {errors}")

    def paste_config(self):
        dialog = tk.Toplevel(self)
        dialog.title("Paste WireGuard Config")
        dialog.geometry("500x400")
        dialog.configure(bg="#0d1117")
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Paste WireGuard .conf content below:",
                 bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))

        tk.Label(dialog, text="Format: [Interface] + PrivateKey + Address + [Peer] + PublicKey + Endpoint",
                 bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 8)).pack()

        text_area = scrolledtext.ScrolledText(dialog, bg="#161b22", fg="#c9d1d9",
                                               font=("Consolas", 9), height=15, width=55)
        text_area.pack(padx=15, pady=10, fill="both", expand=True)

        source_var = tk.StringVar(value="Pasted")
        src_frame = tk.Frame(dialog, bg="#0d1117")
        src_frame.pack(fill="x", padx=15, pady=(0, 5))
        tk.Label(src_frame, text="Source:", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9)).pack(side="left")
        tk.Entry(src_frame, textvariable=source_var, bg="#161b22", fg="#c9d1d9",
                 font=("Segoe UI", 9), width=15).pack(side="left", padx=(5, 0))

        def do_paste():
            if self._adds_busy("Paste"):
                return
            text = text_area.get("1.0", "end").strip()
            if not text:
                messagebox.showwarning("Empty", "Please paste config text!")
                return
            server, error = parse_conf_from_text(text, source=source_var.get())
            if error:
                messagebox.showerror("Parse Error", f"Cannot parse config:\n{error}")
                return
            exists = any(s["endpoint"] == server["endpoint"] for s in self.all_servers)
            if exists:
                messagebox.showinfo("Exists", f"Server already exists:\n{server['endpoint']}")
                return
            self.all_servers.append(server)
            save_servers(self.all_servers)
            self._refresh_filter_menus()
            self.refresh_server_list()
            self.log(f"Pasted: {server['name']} ({server['endpoint']})")
            messagebox.showinfo("Success", f"Server added:\n{server['name']}")
            dialog.destroy()

        btn_frame = tk.Frame(dialog, bg="#0d1117")
        btn_frame.pack(fill="x", padx=15, pady=(0, 10))
        tk.Button(btn_frame, text="Add Server", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=12,
                  command=do_paste).pack(side="right", padx=(5, 0))
        tk.Button(btn_frame, text="Cancel", bg="#6e7681", fg="white",
                  font=("Segoe UI", 9, "bold"), width=8,
                  command=dialog.destroy).pack(side="right")

    def _fetch_begin(self, kind):
        """Single-flight guard: two Fetch threads mutating all_servers (or a
        Fetch racing GOLD-refresh's replace) silently lost entries. Returns
        True when this fetch owns the flag."""
        if getattr(self, "fetching", False):
            self.log(f"{kind}: a fetch is already running - wait for it.")
            return False
        if getattr(self, "refreshing", False):
            self.log(f"{kind}: GOLD refresh is running - stop it first.")
            return False
        self.fetching = True
        return True

    def _fetch_wrap(self, fn, *args):
        try:
            fn(*args)
        finally:
            try:
                self.fetching = False
            except Exception:
                pass

    def _adds_busy(self, what):
        """Manual adds race Fetch/Refresh list replaces -> entries silently lost."""
        if getattr(self, "fetching", False) or getattr(self, "refreshing", False):
            messagebox.showwarning("Busy", f"{what}: a Fetch/Refresh is running.\nWait for it, then add again.")
            return True
        return False

    def fetch_from_url(self):
        url = simpledialog.askstring("Fetch Config",
                                      "Enter URL to .conf file or config list:",
                                      parent=self)
        if not url:
            return
        url = url.strip()
        if not self._fetch_begin("Fetch URL"):
            return
        self.log(f"Fetching from: {url}")
        threading.Thread(target=self._fetch_wrap, args=(self._fetch_url_thread, url), daemon=True).start()

    def _fetch_url_thread(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read().decode("utf-8", errors="ignore")

            new_servers = []
            configs_found = 0

            blocks = re.split(r'(?=\[Interface\])', data)
            for block in blocks:
                if "[Interface]" in block and "PrivateKey" in block:
                    configs_found += 1
                    server, error = parse_conf_from_text(block, source="URL")
                    if server:
                        server["source_url"] = url
                        server["fetched_at"] = now_iso()
                        new_servers.append(server)

            if configs_found == 0:
                self._safe_after(0, lambda: self.log("No WireGuard configs found at URL! Old kept."))
                self._safe_after(0, lambda: messagebox.showwarning("Not Found", "No WireGuard configs found."))
                return

            # Replace mode: drop old URL source only (fresh copy from this URL).
            removed = sum(1 for s in self.all_servers if s.get("source") == "URL")
            self.all_servers = [s for s in self.all_servers if s.get("source") != "URL"]
            existing = {s.get("endpoint") for s in self.all_servers}

            added = 0
            skipped = 0
            for server in new_servers:
                if server.get("endpoint") in existing:
                    skipped += 1
                    continue
                self.all_servers.append(server)
                existing.add(server.get("endpoint"))
                added += 1

            save_servers(self.all_servers)
            self._safe_after(0, self._refresh_filter_menus)
            self._safe_after(0, self.refresh_server_list)
            msg = f"URL fresh: {removed} old URL removed, {configs_found} found, {added} added, {skipped} dup-in-other-source"
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("Fetch Done", msg))
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"Fetch error: {e}"))
            self._safe_after(0, lambda: messagebox.showerror("Fetch Error", str(e)))

    def fetch_bulk_urls(self):
        dialog = tk.Toplevel(self)
        dialog.title("Bulk Fetch from URLs")
        dialog.geometry("550x350")
        dialog.configure(bg="#0d1117")
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Enter URLs (one per line):",
                 bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))

        tk.Label(dialog, text="Each URL should point to a .conf file or list of configs",
                 bg="#0d1117", fg="#8b949e",
                 font=("Segoe UI", 8)).pack()

        text_area = scrolledtext.ScrolledText(dialog, bg="#161b22", fg="#c9d1d9",
                                               font=("Consolas", 9), height=12, width=60)
        text_area.pack(padx=15, pady=10, fill="both", expand=True)
        text_area.insert("1.0", "# Paste URLs below (one per line)\n# Example:\n# https://example.com/config.conf")

        def do_fetch():
            urls_text = text_area.get("1.0", "end").strip()
            if not urls_text:
                messagebox.showwarning("Empty", "Please enter URLs!")
                return
            urls = [u.strip() for u in urls_text.splitlines() if u.strip() and u.strip().startswith("http")]
            if not urls:
                messagebox.showwarning("No URLs", "No valid URLs found!")
                return
            dialog.destroy()
            if not self._fetch_begin("Bulk fetch"):
                return
            self.log(f"Bulk fetching from {len(urls)} URLs...")
            threading.Thread(target=self._fetch_wrap, args=(self._bulk_fetch_thread, urls), daemon=True).start()

        btn_frame = tk.Frame(dialog, bg="#0d1117")
        btn_frame.pack(fill="x", padx=15, pady=(0, 10))
        tk.Button(btn_frame, text="Fetch All", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=10,
                  command=do_fetch).pack(side="right", padx=(5, 0))
        tk.Button(btn_frame, text="Cancel", bg="#6e7681", fg="white",
                  font=("Segoe UI", 9, "bold"), width=8,
                  command=dialog.destroy).pack(side="right")

    def _bulk_fetch_thread(self, urls):
        new_servers = []
        total_found = 0
        for i, url in enumerate(urls):
            self._safe_after(0, lambda u=url, n=i: self.log(f"[{n+1}/{len(urls)}] Fetching: {u}"))
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = resp.read().decode("utf-8", errors="ignore")

                blocks = re.split(r'(?=\[Interface\])', data)
                for block in blocks:
                    if "[Interface]" in block and "PrivateKey" in block:
                        total_found += 1
                        server, error = parse_conf_from_text(block, source="BulkURL")
                        if server:
                            server["source_url"] = url
                            server["fetched_at"] = now_iso()
                            new_servers.append(server)
            except Exception as e:
                self._safe_after(0, lambda u=url, err=str(e): self.log(f"  Error: {u} -> {err}"))

        if not new_servers:
            self._safe_after(0, lambda: self.log("Bulk fetch: nothing found, old BulkURL kept."))
            self._safe_after(0, lambda: messagebox.showwarning("Bulk Fetch", "No configs found, old list kept."))
            return

        # Replace mode: drop old BulkURL only.
        removed = sum(1 for s in self.all_servers if s.get("source") == "BulkURL")
        self.all_servers = [s for s in self.all_servers if s.get("source") != "BulkURL"]
        existing = {s.get("endpoint") for s in self.all_servers}

        total_added = 0
        total_skipped = 0
        seen_new = set()
        for server in new_servers:
            ep = server.get("endpoint")
            if ep in seen_new:
                total_skipped += 1
                continue
            seen_new.add(ep)
            if ep in existing:
                total_skipped += 1
                continue
            self.all_servers.append(server)
            existing.add(ep)
            total_added += 1

        save_servers(self.all_servers)
        self._safe_after(0, self._refresh_filter_menus)
        self._safe_after(0, self.refresh_server_list)
        msg = f"Bulk fresh: {removed} old removed, {total_found} found, {total_added} added, {total_skipped} dup"
        self._safe_after(0, lambda: self.log(msg))
        self._safe_after(0, lambda: messagebox.showinfo("Bulk Fetch Done", msg))

    def fetch_bundle(self):
        if not self._fetch_begin("Bundle"):
            return
        self.log("Fetching WireGuard bundle (ALL countries)...")
        threading.Thread(target=self._fetch_wrap, args=(self._fetch_bundle_thread,), daemon=True).start()

    def _fetch_bundle_thread(self):
        try:
            data, used = fetch_bundle_text(timeout=60)
            if not data:
                raise RuntimeError(f"bundle fetch failed: {used}")
            self._safe_after(0, lambda: self.log(f"Bundle source: {used}"))

            new_servers = []
            seen_new = set()

            for line in data.splitlines():
                parsed = parse_wireguard_uri(line)
                if not parsed:
                    continue
                try:
                    endpoint = parsed["endpoint"]
                    host = endpoint.split(":")[0]
                    country = classify_bundle_country(parsed.get("comment", ""), host)
                    if not country:
                        country = "XX"
                    if endpoint in seen_new:
                        continue
                    seen_new.add(endpoint)
                    server = {
                        "name": f"wg-{country}-BUN{len(new_servers):03d}",
                        "private_key": parsed["private_key"],
                        "address": parsed.get("address", "172.16.0.2/32"),
                        "public_key": parsed["publickey"] if "publickey" in parsed else parsed["public_key"],
                        "endpoint": endpoint,
                        "dns": "1.1.1.1, 8.8.8.8",
                        "mtu": parsed.get("mtu", "1380"),
                        "country": country,
                        "source": "WireGuard-Bundle",
                        "source_url": used if isinstance(used, str) else WIREGUARD_BUNDLE_URL,
                        "fetched_at": now_iso(),
                    }
                    new_servers.append(server)
                except Exception:
                    continue

            if not new_servers:
                self._safe_after(0, lambda: self.log("Bundle: no configs in fresh download, keeping old."))
                self._safe_after(0, lambda: messagebox.showwarning("Bundle", "No configs found, old list kept."))
                return

            # New clearly-numbered section: sort by country then endpoint
            from collections import Counter as _Counter
            new_servers.sort(key=lambda s: (s.get("country", "XX"), s.get("endpoint", "")))
            per_country = _Counter(s.get("country", "XX") for s in new_servers)

            # Replace mode: drop old Bundle sources only, keep other sources.
            bundle_sources = ("WireGuard-Bundle", "Refresh-Bundle")
            removed = sum(1 for s in self.all_servers if s.get("source") in bundle_sources)
            self.all_servers = [s for s in self.all_servers if s.get("source") not in bundle_sources]
            existing = {s.get("endpoint") for s in self.all_servers}

            added = 0
            skipped = 0
            for i, server in enumerate(new_servers, 1):
                if server.get("endpoint") in existing:
                    skipped += 1
                    continue
                server["name"] = f"{i:03d} | wg-{server.get('country')}-BUN"
                self.all_servers.append(server)
                existing.add(server.get("endpoint"))
                added += 1

            save_servers(self.all_servers)
            def _show_bundle_section():
                try:
                    self.country_var.set("All")
                except Exception:
                    pass
                try:
                    self.source_var.set("WireGuard-Bundle")
                except Exception:
                    pass
                try:
                    self._refresh_filter_menus()
                except Exception:
                    pass
                try:
                    self.refresh_server_list()
                except Exception:
                    pass
            self._safe_after(0, _show_bundle_section)
            breakdown = ", ".join(f"{c}:{n}" for c, n in sorted(per_country.items()))
            msg = f"Bundle fresh: {removed} old removed, {added} added (ALL: {breakdown}), {skipped} dup-in-other-source"
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("Bundle Done", msg))

        except Exception as e:
            self._safe_after(0, lambda: self.log(f"Bundle error: {e}"))
            self._safe_after(0, lambda: messagebox.showerror("Bundle Error", str(e)))

    def fetch_protonvpn(self):
        if not self._fetch_begin("ProtonVPN"):
            return
        self.log("Fetching ProtonVPN configs (ALL countries)...")
        threading.Thread(target=self._fetch_wrap, args=(self._fetch_protonvpn_thread,), daemon=True).start()

    def _fetch_protonvpn_thread(self):
        try:
            zip_data = fetch_proton_zip(timeout=60)

            new_servers = []
            seen_new = set()
            errors = 0

            for server in iter_proton_servers(zip_data, source="ProtonVPN"):
                try:
                    ep = server.get("endpoint")
                    if not ep or ep in seen_new:
                        continue
                    seen_new.add(ep)
                    new_servers.append(server)
                except Exception:
                    errors += 1

            if not new_servers:
                self._safe_after(0, lambda: self.log("ProtonVPN: fresh ZIP has no configs, keeping old."))
                self._safe_after(0, lambda: messagebox.showwarning("ProtonVPN", "No configs in fresh ZIP, old list kept."))
                return

            # Replace mode: drop old Proton sources only, keep other sources.
            proton_sources = ("ProtonVPN", "Refresh-Proton")
            removed = sum(1 for s in self.all_servers if s.get("source") in proton_sources)
            self.all_servers = [s for s in self.all_servers if s.get("source") not in proton_sources]
            existing = {s.get("endpoint") for s in self.all_servers}

            # New clearly-numbered section: sort by country then endpoint,
            # renumber 001..N so the fresh block is ordered and easy to read.
            from collections import Counter
            new_servers.sort(key=lambda s: (s.get("country", "XX"), s.get("endpoint", "")))
            per_country = Counter(s.get("country", "XX") for s in new_servers)

            added = 0
            skipped = 0
            for i, server in enumerate(new_servers, 1):
                if server.get("endpoint") in existing:
                    skipped += 1
                    continue
                # Numbered clear section: "001 | wg-US-FREE-104"
                server["name"] = f"{i:03d} | {server.get('name', 'Proton')}"
                self.all_servers.append(server)
                existing.add(server.get("endpoint"))
                added += 1

            save_servers(self.all_servers)
            # Show the fresh section clearly: reset filters so new IPs are visible
            def _show_proton_section():
                try:
                    self.country_var.set("All")
                except Exception:
                    pass
                try:
                    self.source_var.set("ProtonVPN")
                except Exception:
                    pass
                try:
                    self._refresh_filter_menus()
                except Exception:
                    pass
                try:
                    self.refresh_server_list()
                except Exception:
                    pass
            self._safe_after(0, _show_proton_section)
            breakdown = ", ".join(f"{c}:{n}" for c, n in sorted(per_country.items()))
            msg = (f"ProtonVPN fresh: {removed} old removed, {added} added (ALL: {breakdown}), "
                   f"{skipped} dup-in-other-source, {errors} errors")
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("ProtonVPN Done", msg))

        except Exception as e:
            self._safe_after(0, lambda: self.log(f"ProtonVPN error: {e}"))
            self._safe_after(0, lambda: messagebox.showerror("ProtonVPN Error", str(e)))

    def fetch_vpnbook(self):
        if not self._fetch_begin("VPNBook"):
            return
        self.log("Fetching VPNBook configs (US & DE)...")
        threading.Thread(target=self._fetch_wrap, args=(self._fetch_vpnbook_thread,), daemon=True).start()

    def _fetch_vpnbook_thread(self):
        try:
            servers_to_fetch = [
                ("us16.vpnbook.com", "US", "VPNBook-US1"),
                ("us178.vpnbook.com", "US", "VPNBook-US2"),
                ("de20.vpnbook.com", "DE", "VPNBook-DE1"),
                ("de220.vpnbook.com", "DE", "VPNBook-DE2"),
            ]

            new_servers = []
            errors = 0

            for host, country, name in servers_to_fetch:
                try:
                    wg_pubkey = self._get_vpnbook_pubkey(host)
                    if not wg_pubkey:
                        errors += 1
                        continue

                    private_key = self._generate_wg_key()
                    if not private_key:
                        errors += 1
                        continue

                    config_text = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {wg_pubkey}
Endpoint = {host}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
                    server, error = parse_conf_from_text(config_text, source="VPNBook")
                    if error:
                        errors += 1
                        continue
                    server["country"] = country
                    server["name"] = f"wg-{country}-{name}"
                    server["fetched_at"] = now_iso()
                    new_servers.append(server)
                except Exception:
                    errors += 1

            if not new_servers:
                self._safe_after(0, lambda: self.log("VPNBook: generation failed, keeping old."))
                return

            # Replace mode: drop old VPNBook only.
            removed = sum(1 for s in self.all_servers if s.get("source") == "VPNBook")
            self.all_servers = [s for s in self.all_servers if s.get("source") != "VPNBook"]
            existing = {s.get("endpoint") for s in self.all_servers}

            added = 0
            skipped = 0
            for server in new_servers:
                if server.get("endpoint") in existing:
                    skipped += 1
                    continue
                self.all_servers.append(server)
                existing.add(server.get("endpoint"))
                added += 1

            save_servers(self.all_servers)
            self._safe_after(0, self._refresh_filter_menus)
            self._safe_after(0, self.refresh_server_list)
            msg = f"VPNBook fresh: {removed} old removed, {added} added (US+DE), {skipped} dup, {errors} errors"
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("VPNBook Done", msg))

        except Exception as e:
            self._safe_after(0, lambda: self.log(f"VPNBook error: {e}"))
            self._safe_after(0, lambda: messagebox.showerror("VPNBook Error", str(e)))

    def _get_vpnbook_pubkey(self, host):
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

    def _generate_wg_key(self):
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

    def fetch_all_fresh(self):
        """One-click: fresh download from ALL web sources, replace same-source old."""
        if not self._fetch_begin("Fetch ALL"):
            return
        self.log("Fetch ALL: Bundle + ProtonVPN + VPNBook (fresh, 1-click)...")
        threading.Thread(target=self._fetch_wrap, args=(self._fetch_all_thread,), daemon=True).start()

    def _fetch_all_thread(self):
        try:
            all_new = []
            report = {}
            # --- 1) Bundle ---
            try:
                data, used = fetch_bundle_text(timeout=60)
                if data:
                    seen = set()
                    n = 0
                    for line in data.splitlines():
                        parsed = parse_wireguard_uri(line)
                        if not parsed:
                            continue
                        try:
                            ep = parsed["endpoint"]
                            host = ep.split(":")[0]
                            country = classify_bundle_country(parsed.get("comment", ""), host)
                            if not country:
                                country = "XX"
                            if ep in seen:
                                continue
                            seen.add(ep)
                            all_new.append({
                                "private_key": parsed["private_key"],
                                "address": parsed.get("address", "172.16.0.2/32"),
                                "public_key": parsed["publickey"] if "publickey" in parsed else parsed["public_key"],
                                "endpoint": ep,
                                "dns": "1.1.1.1, 8.8.8.8",
                                "mtu": parsed.get("mtu", "1380"),
                                "country": country,
                                "source": "WireGuard-Bundle",
                                "source_url": used if isinstance(used, str) else WIREGUARD_BUNDLE_URL,
                                "fetched_at": now_iso(),
                            })
                            n += 1
                        except Exception:
                            continue
                    report["bundle"] = f"{n} dl"
                    self._safe_after(0, lambda: self.log(f"  ALL[1/3] Bundle: {n} fresh"))
                else:
                    report["bundle"] = "fail"
            except Exception as e:
                report["bundle"] = f"fail:{e}"[:60]
            # --- 2) Proton ---
            try:
                zdata = fetch_proton_zip(timeout=60)
                n0 = len(all_new)
                seen_p = set()
                for server in iter_proton_servers(zdata, source="ProtonVPN"):
                    ep = server.get("endpoint")
                    if ep and ep not in seen_p:
                        seen_p.add(ep)
                        all_new.append(server)
                report["proton"] = f"{len(all_new)-n0} dl"
                self._safe_after(0, lambda: self.log(f"  ALL[2/3] Proton: {len(all_new)-n0} fresh"))
            except Exception as e:
                report["proton"] = f"fail:{e}"[:60]
            # --- 3) VPNBook (local regen) ---
            try:
                n0 = len(all_new)
                for host, country, name in [
                    ("us16.vpnbook.com", "US", "VPNBook-US1"),
                    ("us178.vpnbook.com", "US", "VPNBook-US2"),
                    ("de20.vpnbook.com", "DE", "VPNBook-DE1"),
                    ("de220.vpnbook.com", "DE", "VPNBook-DE2"),
                ]:
                    pub = self._get_vpnbook_pubkey(host)
                    priv = self._generate_wg_key()
                    if not pub or not priv:
                        continue
                    srv, err = parse_conf_from_text(
                        f"[Interface]\nPrivateKey = {priv}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n\n"
                        f"[Peer]\nPublicKey = {pub}\nEndpoint = {host}:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n",
                        source="VPNBook")
                    if not err and srv:
                        srv["country"] = country
                        srv["name"] = f"wg-{country}-{name}"
                        srv["fetched_at"] = now_iso()
                        all_new.append(srv)
                report["vpnbook"] = f"{len(all_new)-n0} gen"
            except Exception:
                report["vpnbook"] = "fail"

            if not all_new:
                self._safe_after(0, lambda: self.log("Fetch ALL: all sources failed, old kept."))
                self._safe_after(0, lambda: messagebox.showwarning("Fetch ALL", "All downloads failed, old kept."))
                return

            # Replace all three source families at once, keep Manual/Imported/URL etc.
            replace_sources = ("WireGuard-Bundle", "Refresh-Bundle", "ProtonVPN", "Refresh-Proton", "VPNBook")
            removed = sum(1 for s in self.all_servers if s.get("source") in replace_sources)
            self.all_servers = [s for s in self.all_servers if s.get("source") not in replace_sources]
            existing = {s.get("endpoint") for s in self.all_servers}
            # Clearly-numbered fresh section: sort ALL by country then endpoint
            try:
                all_new.sort(key=lambda s: (s.get("country", "XX"), s.get("endpoint", "")))
            except Exception:
                pass
            added = skipped = 0
            seen_all = set()
            num = 0
            for srv in all_new:
                ep = srv.get("endpoint")
                if not ep or ep in seen_all:
                    skipped += 1
                    continue
                seen_all.add(ep)
                if ep in existing:
                    skipped += 1
                    continue
                num += 1
                srv["name"] = f"{num:03d} | wg-{srv.get('country', 'XX')}-ALL"
                self.all_servers.append(srv)
                existing.add(ep)
                added += 1

            save_servers(self.all_servers)
            def _show_all_section():
                try:
                    self.country_var.set("All")
                except Exception:
                    pass
                try:
                    self.source_var.set("All")
                except Exception:
                    pass
                try:
                    self._refresh_filter_menus()
                except Exception:
                    pass
                try:
                    self.refresh_server_list()
                except Exception:
                    pass
            self._safe_after(0, _show_all_section)
            msg = f"Fetch ALL fresh: {removed} old removed, {added} added (ALL countries), {skipped} dup | {report}"
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("Fetch ALL Done", msg))
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"Fetch ALL error: {e}"))
            self._safe_after(0, lambda: messagebox.showerror("Fetch ALL Error", str(e)))

    def refresh_gold(self):
        """On-demand GOLD refresh: re-verify, drop dead, top up from free sources.

        Never runs at startup. Temporarily uses wireproxy, so an active
        connection is paused (and resumed to the new best at the end).
        Second click = Stop (red): aborts between handshake checks.
        """
        # Toggle: while refreshing the SAME button is a red Stop.
        if getattr(self, "refreshing", False):
            try:
                self._refresh_stop.set()
            except Exception:
                pass
            self.log("Stopping refresh... (finishes the current check)")
            return
        if getattr(self, "fetching", False):
            self.log("Fetch running - wait for it or stop it first.")
            messagebox.showinfo("Busy", "A Fetch is running.\nWait for it to finish.")
            return
        if wp_running() or any_kernel_up():
            if not messagebox.askyesno(
                    "Refresh GOLD",
                    "Refresh will briefly disconnect the VPN to re-verify servers.\n"
                    "It reconnects automatically to the new best afterwards.\n\nContinue?"):
                return
        self.refreshing = True
        try:
            self._refresh_stop.clear()
        except Exception:
            pass
        # Stay enabled so the user can press Stop; red = cancellable.
        self.btn_refresh.config(state="normal", text="Stop", bg="#da3633")
        was = self._get_selected_from_list()
        resume = was if (self.connected and was) else None
        self.log("Refresh started: [1] re-verify GOLD, [2] drop dead, [3] top up free.")
        threading.Thread(target=self._refresh_thread, args=(resume,), daemon=True).start()

    def _handshake_check(self, server, timeout=REFRESH_VERIFY_TIMEOUT):
        """Single real-handshake check. Returns exit IP or None. Self-cleaning."""
        try:
            with open(WG_CONF, "w", encoding="utf-8") as f:
                f.write(make_conf(server))
            _spawn_wp(WG_CONF)
            return wait_for_vpn_ready(timeout_total=timeout)
        except Exception:
            return None
        finally:
            try:
                kill_wp()
            except Exception:
                pass

    def _refresh_thread(self, resume_server):
        # Sources-first: fresh pull from websites BEFORE trusting stored servers.
        # Fresh verified gold (within TTL) is counted as-is, no re-verify.
        try:
            try:
                bdir = os.path.join(BASE_DIR, "configs", "backups")
                os.makedirs(bdir, exist_ok=True)
                if os.path.exists(SERVERS_FILE):
                    ts = time.strftime("%Y%m%d_%H%M%S")
                    shutil.copy2(SERVERS_FILE,
                                 os.path.join(bdir, f"servers_pre_refresh_{ts}.json"))
                    # Rotation: keep last 3 only (backups were unbounded bloat)
                    try:
                        snaps = sorted(
                            f for f in os.listdir(bdir)
                            if f.startswith("servers_pre_refresh_") and f.endswith(".json"))
                        for old in snaps[:-3]:
                            try:
                                os.remove(os.path.join(bdir, old))
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            kill_wp()
            kernel_uninstall()

            fresh = [s for s in self.all_servers if gold_fresh(s)]
            stale = [s for s in self.all_servers
                     if s.get("verified") and not gold_fresh(s)]
            for s in stale:
                s["verified"] = False  # demote: expired badge, kept as candidate
            alive = len(fresh)
            self._safe_after(0, lambda: self.log(
                f"[1/3] Fresh GOLD kept: {alive} (no re-verify), "
                f"expired demoted: {len(stale)}."))

            def promote(s, ip):
                stamp_verified(s, ip)
                self.server_status[s.get("endpoint", "")] = True
                self.server_checks[s.get("endpoint", "")] = f"Verified {ip}"
                self.failed_servers.discard(s.get("endpoint", ""))

            dead_eps = set()
            added = 0
            tried = 0
            need = max(0, REFRESH_GOLD_TARGET - alive)
            if need > 0:
                cands = self._refresh_fetch_candidates()
                self._safe_after(0, lambda: self.log(
                    f"[2/3] {len(cands)} fresh website candidates, need {need} "
                    f"(cap {REFRESH_TOPUP_MAX} checks)..."))
                for s in cands:
                    if self._refresh_stop.is_set():
                        break
                    if alive + added >= REFRESH_GOLD_TARGET or tried >= REFRESH_TOPUP_MAX:
                        break
                    tried += 1
                    ip = self._handshake_check(s)
                    if self._refresh_stop.is_set():
                        break
                    if ip:
                        promote(s, ip)
                        self.all_servers.append(s)
                        added += 1
                        self._safe_after(0, lambda s=s, ip=ip:
                                   self.log(f"  NEW GOLD {s['name']} ({s.get('country')}) <- website -> {ip}"))
                # Still short? Re-verify demoted old gold as last resort.
                if alive + added < REFRESH_GOLD_TARGET and stale:
                    left = REFRESH_GOLD_TARGET - (alive + added)
                    self._safe_after(0, lambda: self.log(
                        f"[2b/3] Re-verifying {len(stale)} demoted old servers (need {left})..."))
                    for s in list(stale):
                        if self._refresh_stop.is_set():
                            break
                        if alive + added >= REFRESH_GOLD_TARGET or tried >= REFRESH_TOPUP_MAX:
                            break
                        tried += 1
                        ip = self._handshake_check(s)
                        if self._refresh_stop.is_set():
                            break
                        if ip:
                            promote(s, ip)
                            added += 1
                            self._safe_after(0, lambda s=s, ip=ip:
                                       self.log(f"  RE-GOLD {s['name']} -> {ip}"))
                        else:
                            dead_eps.add(s.get("endpoint", ""))
                            self._safe_after(0, lambda s=s:
                                       self.log(f"  DEAD {s['name']}"))
                self._safe_after(0, lambda: self.log(f"[3/3] Top-up done: +{added} GOLD ({tried} checked)"))
            else:
                self._safe_after(0, lambda: self.log("[2/3] GOLD target already met, no top-up needed."))

            if dead_eps:
                self.all_servers = [s for s in self.all_servers
                                    if s.get("endpoint") not in dead_eps]
                for ep in dead_eps:
                    self.server_status.pop(ep, None)
                    self.server_latency.pop(ep, None)

            save_servers(self.all_servers)
            gold_n = sum(1 for s in self.all_servers if gold_fresh(s))
            self._safe_after(0, self._refresh_filter_menus)
            self._safe_after(0, self.refresh_server_list)
            stopped = self._refresh_stop.is_set()
            if stopped:
                msg = (f"Refresh stopped: {gold_n} GOLD kept (+{added} new, "
                       f"{tried} checked), total {len(self.all_servers)} servers.")
                self._safe_after(0, lambda: self.log(msg))
                # No auto-resume after a manual stop: the tunnel is really
                # down -> show green Connect, not a stale red Disconnect.
                self.connected = False
                self.active_endpoint = None
                self._safe_after(0, lambda: self._set_btn_disconnected(msg="Ready"))
                return
            msg = (f"Refresh done: {gold_n} GOLD (alive {alive} + new {added}), "
                   f"dropped {len(dead_eps)}, total {len(self.all_servers)} servers.")
            self._safe_after(0, lambda: self.log(msg))
            self._safe_after(0, lambda: messagebox.showinfo("Refresh Done", msg))
            # Resume previous session on the new best server.
            # If nothing to resume, the tunnel is really down -> the main
            # button must show green Connect, not a stale red Disconnect.
            if resume_server is not None:
                self._safe_after(0, self._refresh_resume)
            else:
                self.connected = False
                self.active_endpoint = None
                self._safe_after(0, lambda: self._set_btn_disconnected(msg="Ready"))
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"Refresh error: {e}"))
        finally:
            try:
                kill_wp()
            except Exception:
                pass
            self.refreshing = False
            try:
                self._refresh_stop.clear()
            except Exception:
                pass
            self._safe_after(0, lambda: self.btn_refresh.config(state="normal", text="Refresh", bg="#bf8700"))

    def _refresh_resume(self):
        # Refresh work is done: release the lock BEFORE reconnecting so the
        # resume connect is never refused as "refresh running".
        self.refreshing = False
        best = self.get_best_server()
        if best:
            self.server_var.set(f"{best['name']} ({best['endpoint']})")
            self.log(f"Resuming on new best: {best['name']}...")
            # Force-connect: refresh already killed the tunnel, so reset the
            # toggle first (else step1_connect would see Disconnect and stop).
            try:
                self.connected = False
                self.active_endpoint = None
                self.step_btns[0].config(state="normal", text="Connect",
                                         bg="#238636", fg="white")
                self.step_status[0].config(text="Ready", fg="#f0883e")
            except Exception:
                pass
            self.step1_connect(force=True)
        else:
            self.log("Nothing to resume with (empty list).")

    def _refresh_fetch_candidates(self):
        """Fresh ALL-country candidates from free sources, fastest-first. No writes."""
        seen = {s.get("endpoint") for s in self.all_servers}
        cands = []

        def want_country(c):
            return bool(c)  # accept ALL countries (fix: old filter dropped 70%+ of Proton/Bundle)

        # --- Source 1: WireGuard bundle (shared parser, no duplication) ---
        try:
            data, _ = fetch_bundle_text(timeout=60)
            if not data:
                raise RuntimeError("bundle mirrors unreachable")
            for line in data.splitlines():
                if len(cands) >= REFRESH_CAND_CAP:
                    break
                parsed = parse_wireguard_uri(line)
                if not parsed:
                    continue
                try:
                    ep = parsed["endpoint"]
                    if ep in seen:
                        continue
                    host = ep.split(":")[0]
                    country = classify_bundle_country(parsed.get("comment", ""), host)
                    if not want_country(country):
                        continue
                    cands.append({
                        "name": f"wg-{country}-RF{len(cands):03d}",
                        "private_key": parsed["private_key"],
                        "address": parsed.get("address", "172.16.0.2/32"),
                        "public_key": parsed["public_key"],
                        "endpoint": ep,
                        "dns": "1.1.1.1",
                        "mtu": parsed.get("mtu", "1380"),
                        "country": country,
                        "source": "Refresh-Bundle",
                        "source_url": WIREGUARD_BUNDLE_URL,
                        "fetched_at": now_iso(),
                    })
                    seen.add(ep)
                except Exception:
                    continue
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"  bundle fetch note: {e}"))

        # --- Source 2: ProtonVPN ZIP (US/DE folders, shared parser) ---
        try:
            zdata = fetch_proton_zip(timeout=60)
            for server in iter_proton_servers(
                    zdata, source="Refresh-Proton",
                    limit=(REFRESH_CAND_CAP + 60 - len(cands))):
                try:
                    if server.get("endpoint") in seen:
                        continue
                    cands.append(server)
                    seen.add(server.get("endpoint"))
                except Exception:
                    continue
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"  proton fetch note: {e}"))

        # --- Fast pre-scan: UP + lowest latency first ---
        def probe(s):
            ep = s.get("endpoint", "")
            host = ep.split(":")[0] if ":" in ep else ep
            try:
                port = int(str(ep.split(":")[1]).strip()) if ":" in ep else 51820
            except (ValueError, TypeError):
                port = 51820
            alive, ms, _ = check_server(host, port)
            return (s, alive, ms if ms and ms > 0 else 99999)

        ordered = []
        try:
            with ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(probe, s): s for s in cands}
                for f in as_completed(futs):
                    try:
                        ordered.append(f.result())
                    except Exception:
                        pass
        except Exception:
            return cands
        ordered.sort(key=lambda x: (0 if x[1] is True else 1, x[2]))
        return [s for s, alive, _ in ordered if alive is True] or [s for s, _, _ in ordered[:20]]

    def _busy_vpn(self, what="Rotate"):
        """Refuse overlapping VPN jobs (all share wireproxy.conf+wireproxy).

        Parallel Rotate/Connect/Kernel threads used to race: last-writer-wins
        on the conf, stray processes, and a stuck red/green button.
        """
        if getattr(self, "refreshing", False):
            self.log(f"{what}: Refresh running - stop it first.")
            return True
        try:
            cur = (self.step_btns[0].cget("text") or "").strip().lower()
        except Exception:
            cur = "connect"
        if cur == "connecting...":
            self.log(f"{what}: connect in progress - wait.")
            return True
        if getattr(self, "rotating", False):
            self.log(f"{what}: rotate already in progress - wait.")
            return True
        return False

    def _clear_rotating(self):
        try:
            self.rotating = False
        except Exception:
            pass

    def rotate_ip(self):
        if not self.servers:
            self.log("No servers available!")
            return
        if self._busy_vpn("Rotate"):
            return
        # P0: prefer fastest verified server (skip known-failed), fall back to round-robin
        best = self.get_best_server()
        if best and best.get("endpoint") not in self.failed_servers:
            server = best
            try:
                self.current = self.servers.index(server)
            except ValueError:
                pass
            self.log(f"Rotating to fastest: {server['name']}...")
        else:
            self.log("Rotating IP...")
            self.current = (self.current + 1) % len(self.servers)
            server = self.servers[self.current]
        self.server_var.set(f"{server['name']} ({server['endpoint']})")
        self.rotating = True
        sess = self._sess
        threading.Thread(target=self._rotate_thread, args=(server, sess), daemon=True).start()

    def random_rotate(self):
        if not self.servers:
            self.log("No servers available!")
            return
        if self._busy_vpn("Random"):
            return
        available = [s for s in self.servers
                     if s.get("endpoint") not in self.failed_servers]
        if not available:
            available = self.servers
        server = random.choice(available)
        self.log(f"Random rotate to {server['name']}...")
        self.server_var.set(f"{server['name']} ({server['endpoint']})")
        self.rotating = True
        sess = self._sess
        threading.Thread(target=self._rotate_thread, args=(server, sess), daemon=True).start()

    def _rotate_thread(self, server, sess):
        try:
            if sess != self._sess:
                self._safe_after(0, self._clear_rotating)
                return
            kill_wp()
            try:
                kernel_uninstall()
            except Exception:
                pass
            try:
                with open(WG_CONF, "w", encoding="utf-8") as f:
                    f.write(make_conf(server))
            except Exception as e:
                self._safe_after(0, lambda: self.log(f"Rotate conf failed: {e}"))
                self._safe_after(0, self._clear_rotating)
                return
            _spawn_wp(WG_CONF)
            ip = wait_for_vpn_ready(timeout_total=7)
            if sess != self._sess:
                self._safe_after(0, self._clear_rotating)
                return
            if ip:
                self._safe_after(0, lambda: self._rotate_done(server, ip, sess))
            else:
                self.failed_servers.add(server.get("endpoint", ""))
                self._safe_after(0, lambda: self.log(f"Rotation failed for {server['name']}!"))
                self._safe_after(0, self._clear_rotating)
        except Exception as e:
            self._safe_after(0, lambda: self.log(f"Rotate error: {e}"))
            self._safe_after(0, self._clear_rotating)

    def _rotate_done(self, server, ip, sess=None):
        if sess is not None and sess != self._sess:
            self._safe_after(0, self._clear_rotating)
            self.log(f"Ignored late rotate for {server.get('name', '?')} (session changed).")
            return
        # Guarantee red Disconnect flip (same-button toggle) even if logging fails.
        try:
            self.rotation_count += 1
            self.total_rotations_today += 1
            self.ip_history.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "server": server["name"], "ip": ip,
            })
            save_history(self.ip_history)
            self.log(f"Rotated to {server['name']} | IP: {ip}")
            self.active_endpoint = server.get("endpoint", "")
            try:
                self._mark_active_row()
            except Exception:
                pass
        finally:
            try:
                self._clear_rotating()
            except Exception:
                pass
            try:
                self._set_btn_connected()
            except Exception:
                pass
            try:
                self.update_info()
            except Exception:
                pass

    def kernel_connect_best(self):
        """P2: connect best server via official WireGuard-NT kernel (fastest path)."""
        if self._busy_vpn("Kernel"):
            return
        # Same main button toggles: red Disconnect cancels.
        DISCONNECT_TEXTS = ("disconnect", "cancel", "disconnected")
        try:
            cur = (self.step_btns[0].cget("text") or "").strip().lower()
        except Exception:
            cur = "connect"
        if cur == "connecting...":
            self.log("Connecting... please wait.")
            return
        really_up = self._is_vpn_up(fresh=True)
        if cur in DISCONNECT_TEXTS or really_up:
            if really_up:
                self.disconnect_vpn()
                return
            try:
                self._set_btn_disconnected(msg="Ready")
            except Exception:
                pass
        server = self._resolve_server_for_connect()
        if not server:
            self.step_status[0].config(text="No server - choose one!", fg="#f85149")
            return
        self.log(f"Kernel connect: {server['name']} (WireGuard-NT, no proxy hop)...")
        self.step_status[0].config(text="Running (kernel)...", fg="#f0883e")
        self.step_btns[0].config(state="disabled", text="Connecting...")
        self._animating = True
        self.after(100, lambda: self._pulse_step(0, "Kernel connecting"))
        self.update()
        sess = self._sess
        threading.Thread(target=self._kernel_connect_thread, args=(server, sess), daemon=True).start()

    def _kernel_connect_thread(self, server, sess):
        others = [t for t in kernel_interfaces() if t != KERNEL_TUNNEL]
        if others:
            self._animating = False
            self._safe_after(0, lambda: self.log(f"Kernel blocked: tunnel(s) {others} already active. "
                                           "Disconnect them in WireGuard app first (two full tunnels conflict)."))
            self._safe_after(0, lambda: self.step_status[0].config(text="Blocked - other tunnel up", fg="#f85149"))
            self._safe_after(0, lambda: self.step_btns[0].config(state="normal", text="Connect",
                                                           bg="#238636", fg="white"))
            return
        kill_wp()
        kernel_uninstall()
        try:
            with open(KERNEL_CONF, "w", encoding="utf-8") as f:
                f.write(make_kernel_conf(server))
        except Exception as e:
            self._animating = False
            self._safe_after(0, lambda: self.log(f"Kernel conf write failed: {e}"))
            self._safe_after(0, lambda: self.step_btns[0].config(state="normal", text="Connect",
                                                           bg="#238636", fg="white"))
            return
        ok, msg = kernel_install(KERNEL_CONF)
        if not ok:
            self._animating = False
            self._safe_after(0, lambda: self.log(f"Kernel install failed: {msg} (need Admin?)"))
            self._safe_after(0, lambda: self.step_status[0].config(text="Kernel failed", fg="#f85149"))
            self._safe_after(0, lambda: self.step_btns[0].config(state="normal", text="Connect",
                                                           bg="#238636", fg="white"))
            return
        ip = wait_for_kernel_ready(timeout_total=10)
        if sess != self._sess:
            # Reset/Disconnect meanwhile: leave the tunnel alone (a newer
            # session may own it) and never touch the UI.
            self._safe_after(0, lambda: self.log("Ignored late kernel result (session changed)."))
            return
        if ip:
            self._safe_after(0, lambda: self._kernel_done(server, ip, sess))
        else:
            self._animating = False
            kernel_uninstall()
            self._safe_after(0, lambda: self.log("Kernel handshake failed (no handshake/IP). Tunnel removed."))
            self._safe_after(0, lambda: self.step_status[0].config(text="Failed - retry", fg="#f85149"))
            self._safe_after(0, lambda: self.step_btns[0].config(state="normal", text="Connect",
                                                           bg="#238636", fg="white"))

    def _kernel_done(self, server, ip, sess=None):
        if sess is not None and sess != self._sess:
            self.log(f"Ignored late kernel success for {server.get('name', '?')} (session changed).")
            return
        # Guarantee red Disconnect flip even if logging fails.
        try:
            self.rotation_count += 1
            self.total_rotations_today += 1
            self.ip_history.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "server": server["name"] + " [kernel]", "ip": ip,
            })
            save_history(self.ip_history)
            self.log(f"Kernel connected: {server['name']} | exit IP: {ip} (direct, no proxy)")
            self.active_endpoint = server.get("endpoint", "")
            try:
                self._mark_active_row()
            except Exception:
                pass
        finally:
            try:
                self.done(0)
            except Exception:
                try:
                    self._set_btn_connected()
                except Exception:
                    pass
            try:
                self.update_info()
            except Exception:
                pass

    def kernel_disconnect_ours(self):
        kernel_uninstall()
        self.log("Kernel tunnel (ours) removed")

    # ---- Merged protection: ONE toggle for Monitor + Auto Reconnect ----
    def _sync_protect_btn(self):
        try:
            on = bool(getattr(self, "protect_on", False))
            if hasattr(self, "btn_protect"):
                self.btn_protect.config(
                    text="Protect ON" if on else "Protect OFF",
                    bg="#238636" if on else "#6e7681")
        except Exception:
            pass

    def toggle_protect(self):
        if getattr(self, "protect_on", False):
            self._protect_disable()
        else:
            self._protect_enable()

    def _protect_enable(self):
        self.protect_on = True
        self.stop_event.clear()
        # Monitor part
        self.monitoring = True
        self.log("Protect ON: monitor (10s) + auto-reconnect (15s)")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        # Auto-reconnect part
        self.auto_reconnect = True
        self.failed_servers.clear()
        if not self.auto_reconnect_thread or not self.auto_reconnect_thread.is_alive():
            self.auto_reconnect_thread = threading.Thread(
                target=self._auto_reconnect_loop, daemon=True)
            self.auto_reconnect_thread.start()
        self._sync_protect_btn()

    def _protect_disable(self):
        self.protect_on = False
        self.monitoring = False
        self.auto_reconnect = False
        self.stop_event.set()
        self.log("Protect OFF")
        self._sync_protect_btn()

    def toggle_monitor(self):
        # Legacy entry (kept for compat) -> delegates to unified toggle.
        self.toggle_protect()

    def start_monitor(self):
        if not getattr(self, "protect_on", False):
            self._protect_enable()
        else:
            self.monitoring = True
            self.stop_event.clear()
            if not self.monitor_thread or not self.monitor_thread.is_alive():
                self.monitor_thread = threading.Thread(
                    target=self._monitor_loop, daemon=True)
                self.monitor_thread.start()
            self._sync_protect_btn()
            self.log("Monitor started (10s interval)")

    def stop_monitor(self):
        self._protect_disable()

    def _monitor_loop(self):
        # B5 fix: labels updated from here too (status used to go stale).
        # Network work stays in this background thread; after() only paints.
        while not self.stop_event.is_set():
            if any_kernel_up():
                ip = fetch_direct_ip(timeout=3)
                kern = True
            elif not wp_running():
                ip, kern = None, False
                self._safe_after(0, lambda: self.log("wireproxy down! Rotating..."))
                self._safe_after(0, self.rotate_ip)
            else:
                ip = get_ip(timeout=3)
                kern = False
                if not ip:
                    self._safe_after(0, lambda: self.log("No IP! Rotating..."))
                    self._safe_after(0, self.rotate_ip)
            self._safe_after(0, lambda ip=ip, kern=kern: self._show_monitor_status(ip, kern))
            self.stop_event.wait(10)

    def _show_monitor_status(self, ip, kern):
        # Same rule as _apply_info_result: transient IP failure with a live
        # OUR tunnel must NOT clear the session flag (else single-click
        # Connect bricks). Only mark down when OUR tunnel is really gone.
        try:
            self.lbl_rotations.config(text=f"Rotations: {self.rotation_count}")
            self.lbl_ip.config(text=f"IP: {ip or '---'}" + (" (kernel)" if kern else ""))
            if ip:
                self.connected = True
                self.lbl_status.config(text="Kernel Direct" if kern else "Connected", fg="#3fb950")
                return
            try:
                ours_up = kernel_tunnel_up() if kern else wp_running(use_cache=True)
            except Exception:
                ours_up = False
            if ours_up and self._is_our_session():
                self.lbl_status.config(
                    text=("Kernel? (IP check failed)" if kern else "Connected? (IP check failed)"),
                    fg="#f0883e")
                return
            if kern:
                self.connected = False
                self.lbl_status.config(text="Kernel?", fg="#f0883e")
            elif not wp_running():
                self.connected = False
                self.lbl_status.config(text="Reconnecting...", fg="#f0883e")
            else:
                self.lbl_status.config(text="Connected? (IP check failed)", fg="#f0883e")
        except Exception:
            pass

    def speed_test_all(self):
        # Toggle: while testing the SAME button is a red Stop.
        if self.speed_testing:
            try:
                self._speed_stop.set()
            except Exception:
                pass
            self.log("Stopping speed test...")
            return
        if self.checking:
            self.log("Scan already running, wait...")
            return
        targets = list(self.servers)
        if not targets:
            self.log("Nothing to test (empty list). Fetch or Import first.")
            return
        self.speed_testing = True
        try:
            self._speed_stop.clear()
        except Exception:
            pass
        self.btn_speed.config(state="normal", text="Stop", bg="#da3633")
        self.log(f"Speed testing {len(targets)} servers... (press Stop to cancel)")
        threading.Thread(target=self._speed_test_thread, args=(targets,), daemon=True).start()

    def _speed_test_thread(self, targets):
        total = len(targets)
        done_count = 0
        results = []
        lock = threading.Lock()
        _SKIP = object()

        def test_one(server):
            nonlocal done_count
            if self._speed_stop.is_set():
                return _SKIP
            endpoint = server.get("endpoint", "")
            host = endpoint.split(":")[0] if ":" in endpoint else endpoint
            # Latency = ICMP ping (TCP-to-WG-port is meaningless: WG is UDP-only)
            ms = icmp_ping(host, timeout_ms=2500)
            ms = round(ms, 1) if ms and ms > 0 else -1
            self.server_latency[endpoint] = ms
            with lock:
                done_count += 1
                n = done_count
            name = server.get('name', '?')
            if ms > 0:
                self._safe_after(0, lambda n=n, name=name, ms=ms:
                                 self.log(f"[{n}/{total}] {name} -> {ms}ms"))
            else:
                self._safe_after(0, lambda n=n, name=name:
                                 self.log(f"[{n}/{total}] {name} -> TIMEOUT"))
            self._safe_after(0, lambda endpoint=endpoint, ms=ms:
                             self._update_server_latency(endpoint, ms))
            return (server, ms)

        cancelled = False
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(test_one, s): s for s in targets}
            for future in as_completed(futures):
                if self._speed_stop.is_set():
                    for f in futures:
                        try:
                            f.cancel()
                        except Exception:
                            pass
                    cancelled = True
                    break
                try:
                    r = future.result()
                except Exception:
                    continue
                if r is _SKIP:
                    continue
                results.append(r)

        fast = sorted([r for r in results if r[1] > 0], key=lambda x: x[1])
        self._safe_after(0, lambda: self._speed_test_done(fast, total, cancelled))

    def _update_server_latency(self, endpoint, ms):
        try:
            for widget in self.server_list_frame.winfo_children():
                if hasattr(widget, 'server_data') and widget.server_data.get("endpoint") == endpoint:
                    try:
                        text, fg = self._row_display(widget.server_data)
                        widget.lbl.config(text=text, fg=fg)
                    except Exception:
                        pass
                    try:
                        if hasattr(widget, "ping_label"):
                            widget.ping_label.config(text=self._ping_text(endpoint),
                                                     fg=self._ping_color(endpoint))
                    except Exception:
                        pass
                    if ms > 0 and ms < 100:
                        widget.status_label.config(fg="#3fb950", text="\u25cf")
                    elif ms > 0 and ms < 300:
                        widget.status_label.config(fg="#f0883e", text="\u25cf")
                    else:
                        widget.status_label.config(fg="#f85149", text="\u25cf")
                    break
        except Exception:
            pass

    def _speed_test_done(self, fast, total, cancelled=False):
        self.speed_testing = False
        try:
            self._speed_stop.clear()
        except Exception:
            pass
        self.btn_speed.config(state="normal", text="Speed", bg="#0a7ea4")
        if cancelled:
            self.log(f"Speed test stopped ({total} servers, partial results).")
            return
        if fast:
            top3 = fast[:3]
            names = ", ".join([f"{s.get('name', '?')} ({m}ms)" for s, m in top3])
            self.log(f"Speed test done! Top 3: {names}")
        else:
            self.log(f"Speed test done! {total} servers tested")

    def toggle_auto_reconnect(self):
        # Legacy entry (kept for compat) -> delegates to unified toggle.
        self.toggle_protect()

    def _auto_reconnect_loop(self):
        while self.auto_reconnect and not self.stop_event.is_set():
            if self.connected:
                try:
                    ours_kernel = kernel_tunnel_up()
                except Exception:
                    ours_kernel = False
                if ours_kernel:
                    # OUR kernel tunnel is a valid connection - no proxy
                    # reconnect (old path spawned proxy alongside kernel).
                    pass
                elif not wp_running():
                    self._safe_after(0, lambda: self.log("AUTO: wireproxy down, reconnecting..."))
                    self._auto_reconnect_action()
                else:
                    ip = get_ip()
                    if not ip:
                        self._safe_after(0, lambda: self.log("AUTO: No IP, reconnecting..."))
                        self._auto_reconnect_action()
            self.stop_event.wait(15)

    def _auto_reconnect_action(self):
        active_servers = [s for s in self.all_servers
                         if self.server_status.get(s.get("endpoint", ""), False)
                         and s.get("endpoint", "") not in self.failed_servers]
        if not active_servers:
            active_servers = [s for s in self.all_servers
                             if s.get("endpoint", "") not in self.failed_servers]
        if not active_servers:
            active_servers = self.all_servers

        for server in active_servers:
            if not self.auto_reconnect:
                return
            # Yield to manual jobs (quietly: retry next cycle instead of
            # racing wireproxy.conf with the user's Rotate/Connect).
            if getattr(self, "rotating", False):
                return
            try:
                _cur = (self.step_btns[0].cget("text") or "").strip().lower()
            except Exception:
                _cur = ""
            if _cur == "connecting...":
                return
            sess = self._sess
            self.log(f"AUTO: Trying {server.get('name', '?')}...")
            kill_wp()
            with open(WG_CONF, "w", encoding="utf-8") as f:
                f.write(make_conf(server))
            _spawn_wp(WG_CONF)
            ip = wait_for_vpn_ready(timeout_total=7)
            if sess != self._sess or not self.auto_reconnect:
                # Reset/Disconnect/Protect-OFF meanwhile: do NOT resurrect.
                try:
                    kill_wp()
                except Exception:
                    pass
                return
            if ip:
                self.rotation_count += 1
                self.total_rotations_today += 1
                self.ip_history.append({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "server": server["name"], "ip": ip,
                })
                save_history(self.ip_history)
                # Keep main button truthful: AUTO connect must also turn it red.
                self.active_endpoint = server.get("endpoint", "")
                try:
                    self.failed_servers.discard(server.get("endpoint", ""))
                except Exception:
                    pass
                self._safe_after(0, lambda: self.log(f"AUTO: Connected to {server['name']} | IP: {ip}"))
                self._safe_after(0, lambda: self._mark_active_row())
                self._safe_after(0, lambda: self._set_btn_connected())
                self._safe_after(0, self.update_info)
                return
            self.failed_servers.add(server.get("endpoint", ""))
            kill_wp()
            time.sleep(1)

        self._safe_after(0, lambda: self.log("AUTO: All servers failed, will retry..."))
        self.failed_servers.clear()

    def reset(self):
        self.stop_event.set()
        self.monitoring = False
        self.auto_reconnect = False
        self.protect_on = False
        # New session: late connect/rotate/verify threads are ignored.
        try:
            self._sess += 1
        except Exception:
            pass
        # Cancel any running scan/speed/refresh and restore their buttons
        # (their threads exit on the cancel flag and repaint via after()).
        try:
            self._scan_stop.set()
        except Exception:
            pass
        try:
            self._speed_stop.set()
        except Exception:
            pass
        try:
            self._refresh_stop.set()
        except Exception:
            pass
        self.checking = False
        self.speed_testing = False
        self.refreshing = False
        self.rotating = False
        try:
            self.btn_check_all.config(state="normal", text="Scan All", bg="#1f6feb")
        except Exception:
            pass
        try:
            self.btn_speed.config(state="normal", text="Speed", bg="#0a7ea4")
        except Exception:
            pass
        try:
            self.btn_refresh.config(state="normal", text="Refresh", bg="#bf8700")
        except Exception:
            pass
        try:
            self._sync_protect_btn()
        except Exception:
            pass
        # Legacy aliases point at btn_protect; guard in case build not run.
        for _alias in ("btn_monitor", "btn_auto_reconnect"):
            try:
                w = getattr(self, _alias, None)
                if w is not None and w is not getattr(self, "btn_protect", None):
                    w.config(text="Monitor", bg="#238636")
            except Exception:
                pass
        # Slow kills (taskkill/service) run in the background: Reset must
        # never freeze the UI, and late threads are already session-blocked.
        threading.Thread(target=self._reset_kills, daemon=True).start()
        self.current = 0
        self.rotation_count = 0
        self.connected = False
        self.steps_done = [False, False]
        self._selected_row = None
        self.active_endpoint = None
        self._animating = False
        self.server_var.set("")
        self.server_latency.clear()
        self.failed_servers.clear()
        for i in range(2):
            self.step_btns[i].config(state="disabled", bg="#21262d")
            self.step_status[i].config(text="Waiting...", fg="#8b949e")
        self.step_btns[0].config(state="normal", text="Connect",
                                 bg="#238636", fg="white")
        self.step_status[0].config(text="Ready", fg="#f0883e")
        self.lbl_rotations.config(text="Rotations: 0")
        self.lbl_ip.config(text="IP: ---")
        self.lbl_status.config(text="Disconnected", fg="#f85149")
        self.refresh_server_list()
        self.log("Reset complete")

    def _reset_kills(self):
        try:
            kill_wp()
        except Exception:
            pass
        try:
            kernel_uninstall()
        except Exception:
            pass
        try:
            if os.path.exists(KERNEL_CONF):
                os.remove(KERNEL_CONF)
        except Exception:
            pass

    def cleanup(self):
        try:
            kill_wp()
        except Exception:
            pass
        try:
            kernel_uninstall()
        except Exception:
            pass

    def on_close(self):
        self.stop_event.set()
        self.monitoring = False
        self.auto_reconnect = False
        self.cleanup()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
