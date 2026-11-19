# -*- coding: utf-8 -*-
"""Fetch/import handlers and the GOLD refresh pipeline (threads + UI glue)."""

import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import scrolledtext
import threading
import time
import os
import re
import shutil
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..gold import REFRESH_CAND_CAP, REFRESH_GOLD_TARGET, REFRESH_TOPUP_MAX, REFRESH_VERIFY_TIMEOUT, gold_fresh, stamp_verified
from ..kernel import any_kernel_up, kernel_uninstall
from ..net import check_server
from ..parsing import classify_bundle_country, parse_conf_from_text, parse_wireguard_uri
from ..paths import BASE_DIR, SERVERS_FILE, WG_CONF
from ..sources import WIREGUARD_BUNDLE_URL, fetch_bundle_text, fetch_proton_zip, generate_wg_key, get_vpnbook_pubkey, iter_proton_servers
from ..storage import save_servers
from ..tunnel import _spawn_wp, kill_wp, make_conf, wait_for_vpn_ready, wp_running
from ..util import now_iso

class FetchMixin:
    """Fetch/import handlers and the GOLD refresh pipeline (threads + UI glue)."""

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
                    wg_pubkey = get_vpnbook_pubkey(host)
                    if not wg_pubkey:
                        errors += 1
                        continue

                    private_key = generate_wg_key()
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
                    pub = get_vpnbook_pubkey(host)
                    priv = generate_wg_key()
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
