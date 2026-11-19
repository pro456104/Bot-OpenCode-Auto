# -*- coding: utf-8 -*-
"""App(tk.Tk) composed of feature mixins - the only Tk root."""

import tkinter as tk
from tkinter import messagebox
import threading
import time
import os
import atexit
from ..gold import get_countries, get_sources, gold_fresh
from ..kernel import KERNEL_CONF, WIREGUARD_EXE, any_kernel_up, kernel_tunnel_up, kernel_uninstall
from ..net import fetch_direct_ip, get_ip
from ..paths import OPENCODE_SEARCHED, WIREPROXY_SEARCHED
from ..storage import load_history, load_servers
from ..tunnel import kill_wp, wp_running
from .. import paths
from .server_list import ServerListMixin
from .dialogs import DialogsMixin
from .connect_ui import ConnectMixin
from .fetch_ui import FetchMixin
from .protect_ui import ProtectMixin

_LOG_MAX_LINES = 800


class App(ServerListMixin, DialogsMixin, ConnectMixin, FetchMixin, ProtectMixin, tk.Tk):
    """Main window: state, layout, log, status strip, reset/cleanup.

    Feature methods live in the mixins; all cross-calls stay self.*.
    Session-generation guards and race flags are preserved verbatim.
    """

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
        if not os.path.isfile(paths.WG_PROXY or ""):
            searched_txt = "\n  ".join(dict.fromkeys(WIREPROXY_SEARCHED or [paths.WG_PROXY]))
            msg = ("wireproxy.exe not found!\n\nSearched in:\n  " + searched_txt +
                   "\n\nFix: copy wireproxy.exe into the project's bin folder, "
                   "install wg-opencode, or set the path manually via the Paths button.")
            self.log("WARNING: wireproxy missing!")
            messagebox.showwarning("Missing Files", msg)
        if not os.path.isfile(paths.OPENCODE_EXE or ""):
            searched_txt = "\n  ".join(dict.fromkeys(OPENCODE_SEARCHED or [paths.OPENCODE_EXE]))
            msg = ("OpenCode.exe not found!\n\nSearched in:\n  " + searched_txt +
                   "\n\nFix: install OpenCode Desktop or pick its exe via the Paths button.")
            self.log("WARNING: OpenCode missing!")
            messagebox.showwarning("Missing Files", msg)
        if not os.path.isfile(WIREGUARD_EXE or ""):
            self.log("Note: official WireGuard client not installed - kernel mode off, proxy works.")

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
