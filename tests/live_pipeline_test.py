# -*- coding: utf-8 -*-
"""LIVE end-to-end pipeline test (real network + real wireproxy process).

Flow: fetch sources -> parse -> merge -> save -> parallel scan -> dial best
(real VPN connect) -> verify exit IP via proxy vs direct -> stamp GOLD -> cleanup.

Safety: aborts if a wireproxy session is already running; try/finally kill_wp.
Run: python tests/live_pipeline_test.py   (takes ~1-3 minutes)
"""
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpnbot import gold, net, parsing, sources, storage, tunnel  # noqa: E402


def log(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m))


def fetch_candidates():
    cands, seen = [], set()
    # 1) WG bundle
    try:
        data, used = sources.fetch_bundle_text(timeout=45)
        if data:
            for line in data.splitlines():
                p = parsing.parse_wireguard_uri(line)
                if not p:
                    continue
                ep = p["endpoint"]
                if ep in seen:
                    continue
                seen.add(ep)
                host = ep.split(":")[0]
                country = parsing.classify_bundle_country(p.get("comment", ""), host)
                cands.append({"name": "wg-%s-BUN%03d" % (country, len(cands)),
                              "private_key": p["private_key"],
                              "address": p.get("address", "172.16.0.2/32"),
                              "public_key": p["public_key"], "endpoint": ep,
                              "dns": "1.1.1.1, 8.8.8.8", "mtu": p.get("mtu", "1380"),
                              "country": country, "source": "WireGuard-Bundle",
                              "source_url": used if isinstance(used, str) else sources.WIREGUARD_BUNDLE_URL,
                              "fetched_at": gold.now_iso()})
            log("bundle: %d candidates (via %s)" % (len(cands), used))
    except Exception as e:
        log("bundle fetch failed: %s" % e)
    # 2) Proton ZIP
    try:
        z = sources.fetch_proton_zip(timeout=45)
        n0 = len(cands)
        for s in sources.iter_proton_servers(z, source="ProtonVPN"):
            if s.get("endpoint") not in seen:
                seen.add(s["endpoint"])
                cands.append(s)
        log("proton: +%d candidates" % (len(cands) - n0))
    except Exception as e:
        log("proton fetch failed: %s" % e)
    # 3) VPNBook fallback (local generation, known pubkeys)
    if not cands:
        for host, country, name in [("us16.vpnbook.com", "US", "VPNBook-US1"),
                                    ("de20.vpnbook.com", "DE", "VPNBook-DE1")]:
            pub = sources.get_vpnbook_pubkey(host)
            priv = sources.generate_wg_key()
            if not pub or not priv:
                continue
            s, err = parsing.parse_conf_from_text(
                "[Interface]\nPrivateKey = %s\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n"
                "[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\n"
                % (priv, pub, host), source="VPNBook")
            if not err and s:
                s["country"] = country
                s["name"] = "wg-%s-%s" % (country, name)
                cands.append(s)
        log("vpnbook fallback: %d candidates" % len(cands))
    return cands


def main():
    if tunnel.wp_running(use_cache=False):
        log("ABORT: a wireproxy session is already running - not disturbing it.")
        return 2

    cands = fetch_candidates()
    if not cands:
        log("FAIL: no candidates from any source (network blocked?)")
        return 1

    merged, removed, added, skipped = storage.merge_servers([], cands)
    ok = storage.save_servers(merged)
    log("merge+save: %d servers persisted (save=%s)" % (len(merged), ok))
    assert ok and len(storage.load_servers()) == len(merged)

    # parallel liveness scan (cap 60 for speed)
    targets = merged[:60]
    alive = []
    def probe(s):
        ep = s.get("endpoint", "")
        host, port = net.split_endpoint(ep)
        a, ms, reason = net.check_server(host, port)
        return s, a, ms, reason
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(probe, s) for s in targets]
        for f in as_completed(futs):
            s, a, ms, reason = f.result()
            if a is True:
                alive.append((s, ms if ms and ms > 0 else 9999))
    alive.sort(key=lambda x: x[1])
    log("scan: %d/%d alive" % (len(alive), len(targets)))
    if not alive:
        log("FAIL: no alive server found among %d candidates" % len(targets))
        return 1

    best, ms = alive[0]
    log("dialing best: %s (%s, %sms)" % (best["name"], best["endpoint"], ms))
    exit_ip = None
    try:
        exit_ip = tunnel.dial(best, timeout=12)
        if not exit_ip:
            # one retry on a different alive server
            if len(alive) > 1:
                best, ms = alive[1]
                log("retry dial: %s" % best["name"])
                exit_ip = tunnel.dial(best, timeout=12)
        if exit_ip:
            log("CONNECTED via proxy: exit IP = %s" % exit_ip)
            again = net.get_ip(timeout=4)
            log("get_ip() recheck: %s (match=%s)" % (again, again == exit_ip))
            direct = net.fetch_direct_ip(timeout=4)
            log("direct (no proxy) IP: %s | VPN changes exit: %s"
                % (direct, bool(direct and direct != exit_ip)))
            gold.stamp_verified(best, exit_ip)
            storage.save_servers(merged)
            log("stamped GOLD: %s (fresh=%s)" % (best["name"], gold.gold_fresh(best)))
            log("LIVE PIPELINE: PASS")
            return 0
        log("FAIL: dial returned no exit IP (handshake failed on tried servers)")
        return 1
    finally:
        tunnel.kill_wp()
        time.sleep(0.3)
        log("cleanup: wireproxy killed, proxy listening=%s, conf exists=%s"
            % (net.proxy_ready(), os.path.exists(tunnel.WG_CONF)))


if __name__ == "__main__":
    sys.exit(main())
