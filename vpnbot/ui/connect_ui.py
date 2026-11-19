# -*- coding: utf-8 -*-
"""Connect/disconnect, deep verify, rotate, kernel mode, OpenCode launch."""

from tkinter import messagebox
import threading
import time
import os
import random
import subprocess
from ..gold import gold_fresh, stamp_scan, stamp_verified
from ..kernel import KERNEL_CONF, KERNEL_TUNNEL, any_kernel_up, kernel_install, kernel_interfaces, kernel_tunnel_up, kernel_uninstall, make_kernel_conf, wait_for_kernel_ready
from ..storage import save_servers
from ..tunnel import WireproxyMissing, dial, kill_wp, wp_running
from .. import paths

class ConnectMixin:
    """Connect/disconnect, deep verify, rotate, kernel mode, OpenCode launch."""

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
            try:
                ip = dial(server, timeout=7)
            except WireproxyMissing:
                ip = None
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
                stamp_scan(server, True)
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
                ip = dial(was_server, timeout=7)
            except WireproxyMissing:
                ip = None
            except Exception:
                return
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
                # dial() rewrites the conf each attempt: kill_wp() deletes it on
                # retry, so the old write-once loop could never actually recover.
                try:
                    ip = dial(server, timeout=7)
                except WireproxyMissing:
                    self._safe_after(0, lambda: self.log("wireproxy.exe not found! Use Paths button."))
                    break
                except OSError as e:
                    self._safe_after(0, lambda e=e: self.log(f"Conf write failed: {e}"))
                    self._safe_after(0, self._step1_failed)
                    return
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
            self._record_rotation(server, ip)
            self.log(f"Connected to {server['name']} | IP: {ip}")
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
        if not os.path.exists(paths.OPENCODE_EXE):
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
            http_proxy = "http://127.0.0.1:%d" % paths.PROXY_HTTP_PORT
            socks_proxy = "socks5h://127.0.0.1:%d" % paths.PROXY_SOCKS_PORT
            env["HTTPS_PROXY"] = http_proxy
            env["HTTP_PROXY"] = http_proxy
            # P0: SOCKS5 handshake is ~15-20% faster than HTTP CONNECT; expose both
            # so OpenCode/electron-net can pick the fastest path.
            env["ALL_PROXY"] = socks_proxy
            env["all_proxy"] = socks_proxy
            env["NO_PROXY"] = "localhost,127.0.0.1,::1"
            env["no_proxy"] = "localhost,127.0.0.1,::1"
        subprocess.Popen([paths.OPENCODE_EXE], env=env)
        self.log("OpenCode launched!")
        self.done(1)
        self.step_status[1].config(text="Running!", fg="#3fb950")

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
                ip = dial(server, timeout=7)
            except WireproxyMissing:
                ip = None
            except OSError as e:
                self._safe_after(0, lambda e=e: self.log(f"Rotate conf failed: {e}"))
                self._safe_after(0, self._clear_rotating)
                return
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
            self._record_rotation(server, ip)
            self.log(f"Rotated to {server['name']} | IP: {ip}")
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
            self._record_rotation(server, ip, kernel=True)
            self.log(f"Kernel connected: {server['name']} | exit IP: {ip} (direct, no proxy)")
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
