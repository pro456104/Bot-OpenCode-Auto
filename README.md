# OpenCode VPN Bot

## Project Overview
A Python Tkinter GUI app that manages WireGuard VPN connections for OpenCode Desktop. Step-by-step interface that runs before OpenCode.

## File Structure
```
bot opencode auto/
├── vpn_bot.py          # Main program (Python 3.14.5, Tkinter)
├── start.bat           # Double-click to launch
├── configs/
│   └── servers.json    # VPN server list (with source tags)
└── logs/
```

## Key Paths (auto-detected, override in `configs/settings.json`)
- Program: `vpn_bot.py` (portable - copy the folder anywhere)
- wireproxy: `bin\wireproxy.exe` (bundled) -> PATH -> `C:\Program Files (x86)\wg-opencode\wireproxy.exe`
- OpenCode: `%LOCALAPPDATA%\Programs\@opencode-aidesktop\OpenCode.exe` -> PATH
- Official WireGuard (optional, kernel mode only): `%ProgramFiles%\WireGuard\`
- Proxy: `127.0.0.1:8080` (HTTP) / `127.0.0.1:10808` (SOCKS5)

## How It Works
1. Step 1: Kill old wireproxy processes
2. Step 2: Connect to VPN server (picks from servers.json)
3. Step 3: Test VPN IP via curl
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
- **Monitor**: Watchdog (30s) that auto-rotates on failure
- **Auto Reconnect**: Auto-rotate on wireproxy/IP failure

## Environment Variables for OpenCode
```
HTTPS_PROXY=http://127.0.0.1:8080
HTTP_PROXY=http://127.0.0.1:8080
NO_PROXY=localhost,127.0.0.1,::1
```

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
- No system routing table changes needed
- VPNBook configs expire after 7 days
- Rate limit is per-IP on "muse spark 1.3 free" model

## Testing
```powershell
# Kill processes
Get-Process wireproxy -ErrorAction SilentlyContinue | Stop-Process -Force

# Run program
python "C:\Users\Admin\Desktop\bot opencode auto\vpn_bot.py"
```

## Dependencies
- Python 3.14.5
- wireproxy.exe
- OpenCode Desktop
