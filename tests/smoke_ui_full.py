# -*- coding: utf-8 -*-
"""FULL UI smoke: real server data, every dialog, filters, selection, reset.

All writes go to a TEMP copy of servers.json/history/settings (real data safe).
No network calls, no wireproxy spawn. Run: python tests/smoke_ui_full.py
"""
import os
import shutil
import sys
import tempfile
import time
from unittest import mock

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk  # noqa: E402
from tkinter import messagebox, filedialog, simpledialog  # noqa: E402

for fn in ("showwarning", "showinfo", "showerror"):
    setattr(messagebox, fn, lambda *a, _f=fn, **k: None)
messagebox.askyesno = lambda *a, **k: True
filedialog.askopenfilenames = lambda *a, **k: ()
filedialog.askdirectory = lambda *a, **k: ""
simpledialog.askstring = lambda *a, **k: None

from vpnbot import paths, storage  # noqa: E402
from vpnbot.ui.main_window import App  # noqa: E402

SAMPLE = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.9.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = zcfEQgUoPLK2kvDicsA/4B9F2AI7qfxX5ueDo/Zcjj4=
Endpoint = 203.0.113.99:51820
AllowedIPs = 0.0.0.0/0
"""

results = []


def check(name, fn):
    try:
        fn()
        results.append((name, True, ""))
        print("  PASS  %s" % name)
    except Exception as e:
        import traceback
        results.append((name, False, str(e)))
        print("  FAIL  %s -> %r" % (name, e))
        traceback.print_exc()


def tops(app):
    return [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]


def close_tops(app):
    for w in tops(app):
        w.destroy()


def rows(app):
    return [w for w in app.server_list_frame.winfo_children() if hasattr(w, "server_data")]


def main():
    tmp = tempfile.TemporaryDirectory()
    servers_tmp = os.path.join(tmp.name, "servers.json")
    shutil.copy2(paths.SERVERS_FILE, servers_tmp)
    for target, attr, val in ((storage, "SERVERS_FILE", servers_tmp),
                              (storage, "IP_HISTORY", os.path.join(tmp.name, "h.json")),
                              (paths, "SETTINGS_FILE", os.path.join(tmp.name, "s.json"))):
        mock.patch.object(target, attr, val).start()

    t0 = time.time()
    app = App()
    app.update()
    build_s = time.time() - t0
    n = len(app.all_servers)
    print("built App with %d real servers in %.2fs" % (n, build_s))

    check("rows match servers", lambda: (
        len(rows(app)) == n or (_ for _ in ()).throw(AssertionError("rows %d != %d" % (len(rows(app)), n)))))

    def best():
        b = app.get_best_server()
        assert b is not None, "no best server"
        print("        best = %s (%s)" % (b["name"], b["endpoint"]))
    check("get_best_server on real data", best)

    def filters():
        us = [s for s in app.all_servers if s.get("country") == "US"]
        app.country_var.set("US"); app.filter_changed(); app.update()
        assert len(rows(app)) == len(us), "US filter %d != %d" % (len(rows(app)), len(us))
        app.country_var.set("All"); app.filter_changed()
        app.source_var.set("ProtonVPN"); app.filter_changed(); app.update()
        pr = [s for s in app.all_servers if s.get("source") == "ProtonVPN"]
        assert len(rows(app)) == len(pr), "Proton filter %d != %d" % (len(rows(app)), len(pr))
        app.source_var.set("All"); app.filter_changed()
        app.search_var.set("BUN"); app.update()
        assert 0 < len(rows(app)) < n, "search filter"
        app.search_var.set(""); app.update()
        assert len(rows(app)) == n
    check("country/source/search filters", filters)

    def selection():
        app.select_all()
        assert len(app.get_checked_servers()) == n
        app.deselect_all()
        assert len(app.get_checked_servers()) == 0
        app.select_active()
        app.deselect_all()
        r = rows(app)[0]
        app.select_server_row(r)
        assert app.server_var.get() != ""
        assert app._resolve_server_for_connect() is not None
    check("selection + resolve-for-connect", selection)

    def status_paint():
        ep = rows(app)[0].server_data["endpoint"]
        app.server_status[ep] = True  # scan thread sets this; painting only reads
        app._update_server_status(ep, True, 42.0)
        app._update_server_latency(ep, 42.0)
        app._refresh_row_text(rows(app)[0])
        assert app.server_latency[ep] == 42.0, "latency not stored"
        assert rows(app)[0].status_label.cget("fg") == "#3fb950", "dot not green"
    check("status/latency row painting", status_paint)

    def delete_path():
        before = len(app.all_servers)
        r = rows(app)[0]
        r.checked.set(True)
        app.delete_selected()
        app.update()
        assert len(app.all_servers) == before - 1, "delete_selected"
    check("delete_selected (temp data)", delete_path)

    def paste_dialog():
        app.paste_config()
        app.update()
        assert tops(app), "no paste dialog created"
        d = tops(app)[-1]
        kids = d.winfo_children()
        # ScrolledText registers its container Frame as the dialog child;
        # the real Text widget lives inside that frame.
        txt = None
        for w in kids:
            if isinstance(w, tk.Frame):
                for c in w.winfo_children():
                    if isinstance(c, tk.Text):
                        txt = c
                        break
            if txt is not None:
                break
        assert txt is not None, "Text widget not found in %s" % [w.__class__.__name__ for w in kids]
        txt.insert("1.0", SAMPLE)
        btn = None
        for w in kids:
            if isinstance(w, tk.Frame):
                for b in w.winfo_children():
                    if isinstance(b, tk.Button) and "Add" in b.cget("text"):
                        btn = b
        assert btn is not None, "Add button not found"
        before = len(app.all_servers)
        btn.invoke()
        app.update()
        assert len(app.all_servers) == before + 1, "paste add: %d -> %d" % (before, len(app.all_servers))
        assert any(s.get("endpoint") == "203.0.113.99:51820" for s in app.all_servers), "endpoint missing"
    check("paste_config dialog + real add", paste_dialog)

    def review_dialog():
        parsed = [{"name": "rev", "endpoint": "203.0.113.100:51820", "country": "DE",
                   "source": "Imported", "private_key": "K", "public_key": "P",
                   "address": "10.0.0.2/32", "dns": "1.1.1.1", "mtu": "1380"}]
        before = len(app.all_servers)
        app._import_review_dialog(parsed, errors=1)
        app.update()
        d = tops(app)[-1]
        assert "Review Import" in d.title()
        btn = next(b for b in d.winfo_children()[-1].winfo_children()
                   if isinstance(b, tk.Button) and b.cget("text").startswith("Add"))
        btn.invoke()
        app.update()
        assert len(app.all_servers) == before + 1
    check("import review dialog + add", review_dialog)

    def tunnel_dialog():
        app.add_tunnel_dialog()
        app.update()
        d = tops(app)[-1]
        assert d.title() == "Add Tunnel (manual)"
        close_tops(app)
    check("add_tunnel dialog builds", tunnel_dialog)

    def paths_dialog():
        app.pick_paths_dialog()
        app.update()
        d = tops(app)[-1]
        assert d.title() == "Program Paths"
        close_tops(app)
    check("paths dialog builds", paths_dialog)

    def bulk_dialog():
        app.fetch_bulk_urls()
        app.update()
        d = tops(app)[-1]
        assert "Bulk Fetch" in d.title()
        close_tops(app)
    check("bulk URLs dialog builds", bulk_dialog)

    def chooser_dialog():
        app.after(300, lambda: close_tops(app))
        chosen = app._popup_choose_server()  # blocks in wait_window until auto-close
        assert chosen is None, "auto-cancel should return None"
    check("popup chooser (auto-cancel)", chooser_dialog)

    def launch_negative():
        if os.path.isfile(paths.OPENCODE_EXE):
            print("        (OpenCode present - skipping negative launch test)")
            return
        app.step2_launch()
        app.update()
        assert app.step_status[1].cget("text") == "Not found!"
    check("step2_launch missing-exe guard", launch_negative)

    def disconnect_idle():
        app.disconnect_vpn()
        app.update()
        assert app.step_btns[0].cget("text") == "Connect"
    check("disconnect when idle", disconnect_idle)

    def reset_flow():
        app.reset()
        app.update()
        assert app.rotation_count == 0
        assert app.connected is False
        assert app.step_btns[0].cget("text") == "Connect"
        assert len(rows(app)) == len(app.servers)
    check("reset flow", reset_flow)

    def protect_button():
        app._sync_protect_btn()
        assert app.btn_protect.cget("text") == "Protect OFF"
    check("protect button sync", protect_button)

    app.destroy()
    tmp.cleanup()
    failed = [r for r in results if not r[1]]
    print("\nFULL UI SMOKE: %d/%d passed%s" % (
        len(results) - len(failed), len(results),
        "" if not failed else " - FAILURES: " + ", ".join(f[0] for f in failed)))
    sys.stdout.flush()
    os._exit(1 if failed else 0)


if __name__ == "__main__":
    main()
