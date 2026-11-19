# tools_legacy — archived standalone scripts

These 10 scripts predate the modular app. Their functionality now lives
inside the application itself:

| Script | Superseded by |
|---|---|
| fetch_and_test.py / fetch_wireguard.py / fetch_multiport.py / fetch_germany.py / import_us_de.py | Fetch ▾ → WG Bundle / Fetch ALL Fresh |
| harvest_ips.py | Fetch ALL Fresh + Refresh (GOLD verification) |
| import_configs.py | Import / Bulk Import / Paste Config |
| rebuild_servers.py | Refresh (re-verify + top-up) |
| test_servers.py / test_existing.py | Scan All / Speed / Verify |

**Path warning:** each script computes `BASE_DIR` from its own location and
expects to sit in the project root (next to `configs/`). Archived here, those
relative paths no longer resolve. To reuse one, move it back to the root or
adjust its `BASE_DIR`. They are kept for reference only; the git history
(baseline commit `4ae45c4`) preserves their original context.
