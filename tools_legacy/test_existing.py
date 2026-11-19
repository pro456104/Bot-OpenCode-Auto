import socket
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(BASE_DIR, "configs", "servers.json")
with open(SERVERS_FILE, "r", encoding="utf-8-sig") as f:
    servers = json.load(f)

print(f"Testing {len(servers)} existing servers...")
working = 0
for s in servers[:100]:
    endpoint = s.get("endpoint", "")
    host = endpoint.split(":")[0] if ":" in endpoint else endpoint
    port_str = endpoint.split(":")[1] if ":" in endpoint else "51820"
    try:
        port = int(port_str)
    except:
        port = 51820

    name = s.get("name", "?")
    country = s.get("country", "?")

    found = False
    for p in [port, 443, 80, 8080]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, p))
            sock.close()
            if result == 0:
                print(f"  OK: {name} [{country}] port {p} - {host}")
                working += 1
                found = True
                break
        except:
            pass
    if not found:
        print(f"  FAIL: {name} [{country}] - {host}")

print(f"\nWorking: {working}/{min(100, len(servers))}")
