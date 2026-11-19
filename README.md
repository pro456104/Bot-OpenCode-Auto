# OpenCode VPN Bot

## Project Overview
A Python Tkinter GUI app that manages WireGuard VPN connections for OpenCode Desktop. Step-by-step interface that runs before OpenCode.

v2.0 is a **modular monolith**: one process, one portable folder, but the code is split into the `vpnbot/` package with strict layer boundaries. `vpn_bot.py` is now a thin entry point.

## File Structure
```
bot opencode auto/
├── vpn_bot.py              # Entry point only (~11 lines)
├── start.bat               # Double-click to launch
├── vpnbot/                 # The application package
│   ├── paths.py            # BASE_DIR, file paths, settings.json, exe resolution (+ runtime path setters)
│   ├── util.py             # now_iso, atomic JSON write
│   ├── storage.py          # servers/history persistence (locks, dedup, corrupt-DB backup)
│   ├── parsing.py          # .conf / wireguard:// URI parsers, country classification
│   ├── gold.py             # GOLD stamps, 3-day TTL, refresh policy constants
│   ├── net.py              # DNS/ICMP/UDP/TCP probes, check_server, exit-IP fetchers
│   ├── tunnel.py           # wireproxy userspace backend (spawn/kill/conf/readiness)
│   ├── kernel.py           # WireGuard-NT kernel backend (tunnel service, handshakes)
│   ├── sources.py          # WG bundle mirrors, ProtonVPN ZIP, VPNBook keygen
│   └── ui/
│       ├── theme.py        # Palette reference (GitHub-dark)
│       ├── main_window.py  # App(tk.Tk): state, layout, log, status, reset/cleanup
│       ├── server_list.py  # ServerListMixin: rows, filters, selection, scan, speed
│       ├── dialogs.py      # DialogsMixin: paths, chooser, import review, tunnel, paste
│       ├── connect_ui.py   # ConnectMixin: connect/verify/rotate/kernel/launch
│       ├── fetch_ui.py     # FetchMixin: fetch handlers + GOLD refresh pipeline
│       └── protect_ui.py   # ProtectMixin: monitor + auto-reconnect loops
├── tests/                  # stdlib unittest suite + UI smoke test
├── bin/wireproxy.exe       # Bundled proxy engine
├── configs/
│   ├── servers.json        # VPN server list (with source tags)
│   ├── settings.json       # Optional manual path overrides
│   └── backups/            # Auto backups (pre-refresh/clean/migrate)
├── logs/                   # ip_history.json + archive
└── *.py helpers            # Standalone CLI harvesters/importers (unchanged, independent)
```

## Architecture (Modular Monolith)
Dependency direction (strict, no reverse imports, no cycles):
```
ui  →  core (tunnel / kernel / net / parsing / storage / sources / gold)  →  paths / util
```
- **No `tkinter` outside `vpnbot/ui/`** — the core is UI-agnostic.
- **No `subprocess` outside core** (net/tunnel/kernel/sources/paths).
- **All file writes are atomic** (`util._atomic_write_json`) under storage locks.
- **Mutable runtime state** lives in exactly one module each: `paths.WG_PROXY` /
  `paths.OPENCODE_EXE` (read at call time, updated via `paths.set_*_path`),
  and the tracked wireproxy handle inside `tunnel.py`.
- **UI composition**: `App(ServerListMixin, DialogsMixin, ConnectMixin, FetchMixin, ProtectMixin, tk.Tk)`.
  All cross-calls remain `self.*`; session-generation guards (`_sess`), race flags
  (`fetching/rotating/refreshing`) and dedicated cancel events are preserved verbatim.
- **Threading rule**: background threads call core only; widgets are touched
  exclusively on the Tk main thread via `_safe_after`.

## Key Paths (auto-detected, override in `configs/settings.json`)
- Program: `vpn_bot.py` (portable - copy the folder anywhere)
- wireproxy: `bin\wireproxy.exe` (bundled) -> PATH -> `C:\Program Files (x86)\wg-opencode\wireproxy.exe`
- OpenCode: `%LOCALAPPDATA%\Programs\@opencode-aidesktop\OpenCode.exe` -> PATH
- Official WireGuard (optional, kernel mode only): `%ProgramFiles%\WireGuard\`
- Proxy: `127.0.0.1:8080` (HTTP) / `127.0.0.1:10808` (SOCKS5)

## How It Works
1. Step 1: Kill old wireproxy processes
2. Step 2: Connect to VPN server (picks from servers.json)
3. Step 3: Test VPN IP via parallel IP providers
4. Step 4: Launch OpenCode with HTTPS_PROXY env vars

## Features

### Server Management
- **Country Filter**: Filter servers by country (DE, US, CA, NL, JP, etc.)
- **Source Filter**: Filter servers by source (VPNBook, FreeVPN, Custom, URL, Pasted, BulkURL)
- **Scan All**: Parallel ping check on port 51820
- **Speed Test**: Measure latency for all servers
- **Selection**: Select All / None / Active servers
- **Delete**: Remove selected or inactive servers

### Fetch & Import
- **Import**: Import single .conf file
- **Bulk Import**: Import all .conf files from a folder
- **Paste Config**: Paste WireGuard config text directly
- **Fetch URL**: Download config from a URL
- **Fetch Bulk URLs**: Fetch from multiple URLs at once
- **Refresh**: On-demand: pulls fresh servers from websites first, GOLD is temp cache (3-day TTL), drops dead (never auto)
- **Open VPNBook**: Opens VPNBook website (generate config, then paste it)

### Connection
- **Rotate IP**: Switch to next server
- **Monitor**: Watchdog that auto-rotates on failure
- **Auto Reconnect**: Auto-rotate on wireproxy/IP failure
- **Protect**: One toggle combining Monitor + Auto Reconnect
- **Kernel**: Optional WireGuard-NT direct routing (no proxy hop)

## Environment Variables for OpenCode
```
HTTPS_PROXY=http://127.0.0.1:8080
HTTP_PROXY=http://127.0.0.1:8080
ALL_PROXY=socks5h://127.0.0.1:10808
NO_PROXY=localhost,127.0.0.1,::1
```
(Kernel mode: proxy vars removed — OpenCode routes directly via WireGuard-NT.)

## Adding New Servers

### Method 1: Paste Config
1. Go to vpnbook.com/freevpn/wireguard-vpn
2. Generate a WireGuard config (select server, port, solve CAPTCHA)
3. Copy the config text
4. Click "Paste Config" in the app
5. Paste and click "Add Server"

### Method 2: Fetch from URL
1. Get a URL to a .conf file
2. Click "Fetch URL"
3. Enter the URL
4. Configs are auto-parsed and added

### Method 3: Import File
1. Click "Import" or "Bulk Import"
2. Select .conf file(s)

## Important Notes
- Only OpenCode uses VPN proxy, all other programs unaffected
- wireproxy converts WireGuard tunnel to local HTTP/SOCKS5 proxy
- No system routing table changes needed (proxy mode)
- VPNBook configs expire after 7 days
- Rate limit is per-IP on "muse spark 1.3 free" model

## Testing
```powershell
# Unit tests (stdlib only, no network, temp dirs)
python -m unittest discover -s tests -t .

# UI smoke test (builds the real window, no network, never kills wireproxy)
python tests\smoke_ui.py

# Run the app
python "C:\Users\Admin\Desktop\bot opencode auto\vpn_bot.py"
```
Manual checklist after changes: Connect / double-click row / Rotate / Random /
Kernel / Scan All / Speed / Verify / Fetch (each source) / Refresh + Stop /
Protect ON-OFF / Reset / Paths / clean close.

## Dependencies
- Python 3.10+ with Tkinter (stdlib only — no pip packages)
- wireproxy.exe (bundled in bin/)
- OpenCode Desktop
- Optional: official WireGuard client (kernel mode)
