# -*- coding: utf-8 -*-
"""Server table: rows, filters, selection, delete, scan & speed-test UI."""

import tkinter as tk
from tkinter import messagebox
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..gold import get_countries, get_sources, gold_fresh
from ..net import check_server, icmp_ping
from ..storage import save_servers

class ServerListMixin:
    """Server table: rows, filters, selection, delete, scan & speed-test UI."""

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
