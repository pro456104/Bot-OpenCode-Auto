# -*- coding: utf-8 -*-
"""OpenCode VPN Bot v2.0 - entry point.

Modular monolith: all logic lives in the vpnbot/ package.
Run: python vpn_bot.py  (or double-click start.bat)
"""
from vpnbot.ui.main_window import App

if __name__ == "__main__":
    app = App()
    app.mainloop()
