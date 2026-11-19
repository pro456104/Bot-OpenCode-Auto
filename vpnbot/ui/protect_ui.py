# -*- coding: utf-8 -*-
"""Protect toggle: monitor watchdog + auto-reconnect loops."""

import threading
import time
from ..kernel import any_kernel_up, kernel_tunnel_up
from ..net import fetch_direct_ip, get_ip
from ..tunnel import dial, kill_wp, wp_running

class ProtectMixin:
    """Protect toggle: monitor watchdog + auto-reconnect loops."""

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
            try:
                ip = dial(server, timeout=7)
            except Exception:
                ip = None
            if sess != self._sess or not self.auto_reconnect:
                # Reset/Disconnect/Protect-OFF meanwhile: do NOT resurrect.
                try:
                    kill_wp()
                except Exception:
                    pass
                return
            if ip:
                self._record_rotation(server, ip)
                # Keep main button truthful: AUTO connect must also turn it red.
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
