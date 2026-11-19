# -*- coding: utf-8 -*-
"""Modal dialogs: program paths, server chooser, import review, tunnel editor, paste."""

import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import scrolledtext
import os
import json
from ..parsing import parse_conf, parse_conf_from_text
from ..paths import load_settings, resolve_opencode, resolve_wireproxy, save_settings, set_opencode_path, set_wireproxy_path
from ..storage import save_servers
from .. import paths

class DialogsMixin:
    """Modal dialogs: program paths, server chooser, import review, tunnel editor, paste."""

    def pick_paths_dialog(self):
        """Manual override for exe paths -> saved in configs/settings.json."""
        d = tk.Toplevel(self)
        d.title("Program Paths")
        d.geometry("560x220")
        d.configure(bg="#0d1117")
        d.transient(self)
        d.grab_set()
        s = load_settings()

        tk.Label(d, text="wireproxy path (proxy engine):", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=15, pady=(12, 2))
        wp_var = tk.StringVar(value=s.get("wireproxy_path", "") or (paths.WG_PROXY or ""))
        tk.Entry(d, textvariable=wp_var, bg="#161b22", fg="#c9d1d9",
                 font=("Consolas", 8), width=70).pack(padx=15, fill="x")

        tk.Label(d, text="OpenCode path:", bg="#0d1117", fg="#c9d1d9",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        oc_var = tk.StringVar(value=s.get("opencode_path", "") or (paths.OPENCODE_EXE or ""))
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
                paths.set_wireproxy_path(new_wp)
            if new_oc:
                paths.set_opencode_path(new_oc)
            self.log(f"saved paths -> wireproxy: {paths.WG_PROXY} | opencode: {paths.OPENCODE_EXE}")
            messagebox.showinfo("Done", "Paths saved to configs/settings.json")
            d.destroy()

        tk.Button(btns, text="Save", bg="#238636", fg="white",
                  font=("Segoe UI", 9, "bold"), width=10, command=save).pack(side="right")

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
