# -*- coding: utf-8 -*-
"""UI smoke test: build the real App window, verify widgets, destroy.

Run manually:  python tests/smoke_ui.py
Safety: messagebox patched (no modal blocks), os._exit skips atexit cleanup
so a running wireproxy session is NEVER killed by this test. No network calls.
"""
import os
import sys
import tempfile
from unittest import mock

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tkinter import messagebox  # noqa: E402

# No modal dialogs during smoke (missing-dep warnings etc.)
for fn in ("showwarning", "showinfo", "showerror"):
    setattr(messagebox, fn,
            lambda *a, _fn=fn, **k: print("  [messagebox.%s suppressed] %s" % (_fn, a[:1])))

from vpnbot import paths  # noqa: E402

# App startup may relocate proxy ports (writes settings.json): keep the real
# user settings untouched by pointing at a temp file.
_tmp = tempfile.TemporaryDirectory()
mock.patch.object(paths, "SETTINGS_FILE",
                  os.path.join(_tmp.name, "settings.json")).start()

from vpnbot.ui.main_window import App  # noqa: E402
from vpnbot import gold  # noqa: E402


def main():
    app = App()
    app.update()

    # --- structural assertions -------------------------------------------
    rows = [w for w in app.server_list_frame.winfo_children()
            if hasattr(w, "server_data")]
    assert len(rows) == len(app.servers), "rows %d != servers %d" % (len(rows), len(app.servers))
    assert app.step_btns[0].cget("text") == "Connect", app.step_btns[0].cget("text")
    assert app.step_btns[1].cget("state") == "disabled"
    assert app.lbl_status.cget("text") == "Disconnected"
    assert app.log_text.index("end-1c") != "1.0", "log empty"
    print("  built: %d server rows, steps/log/status OK" % len(rows))

    # --- exercise pure-UI mixin paths (no network) ------------------------
    us = [s for s in app.all_servers if s.get("country") == "US"]
    app.country_var.set("US")
    app.filter_changed()  # OptionMenu fires command on user pick; .set() alone doesn't
    app.update()
    rows_us = [w for w in app.server_list_frame.winfo_children()
               if hasattr(w, "server_data")]
    assert len(rows_us) == len(us), "US filter: %d != %d" % (len(rows_us), len(us))
    app.country_var.set("All")
    app.filter_changed()
    app.update()

    app.select_all()
    app.deselect_all()
    app.select_active()
    app.deselect_all()

    app.search_var.set("wg-")
    app.update()
    app.search_var.set("")
    app.update()

    app.clear_log()
    assert app.log_text.index("end-1c") == "1.0"
    app.log("smoke test log line")
    assert "smoke test log line" in app.log_text.get("1.0", "end")
    print("  filters/search/select/log exercised OK")

    gold_n = sum(1 for s in app.all_servers if gold.gold_fresh(s))
    print("  data: %d servers (%d fresh GOLD)" % (len(app.all_servers), gold_n))

    app.destroy()
    print("SMOKE UI: PASS")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)  # skip atexit cleanup -> never touches a live wireproxy


if __name__ == "__main__":
    main()
