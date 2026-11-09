<p align="center">
  <img src="assets/banner.svg" alt="netpeek" width="720">
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.7%2B-2dd4bf">
  <img alt="deps" src="https://img.shields.io/badge/dependencies-none-4ade80">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-f472b6">
</p>

**netpeek** is a single-file, zero-dependency Python tool that scans your local network and shows every connected device: IP, MAC, vendor, hostname and when it was last seen.

<p align="center">
  <img src="assets/demo.svg" alt="netpeek demo" width="720">
</p>

## Features

- **One file, stdlib only.** Copy `netpeek.py` anywhere and run it.
- **Vendor lookup** from a small built-in OUI table (about 120 prefixes, 38 popular vendors). No network calls.
- **Watch mode** that alerts (and rings the terminal bell) when a new device joins.
- **JSON output** for scripts and dashboards.
- **Cross-platform:** reads `/proc/net/arp` on Linux, falls back to `arp -a` on macOS and Windows.
- Colored table, graceful `Ctrl+C`.

## Usage

```bash
python netpeek.py                      # scan once, print a table
python netpeek.py --watch              # rescan every 10s, alert on new devices
python netpeek.py --watch 30           # ...every 30s
python netpeek.py --json               # JSON array of devices
python netpeek.py --subnet 10.0.0.0/24 # scan a specific network
python netpeek.py --no-dns             # skip hostname lookups (faster)
```

Example JSON:

```json
[
  {
    "ip": "192.168.1.23",
    "mac": "A4:83:E7:AA:BB:CC",
    "vendor": "Apple",
    "hostname": "macbook.lan",
    "last_seen": "2026-11-10T21:04:12"
  }
]
```

With `--watch --json`, netpeek prints one JSON line per new device:
`{"event": "new_device", "ip": "...", ...}`

## Options

| Flag | Description |
| --- | --- |
| `-w, --watch [SECS]` | Keep scanning every `SECS` seconds (default 10). The first scan is the baseline, so only devices that appear afterwards trigger an alert. |
| `-j, --json` | Output JSON instead of a table. |
| `-s, --subnet CIDR` | Network to scan. Default: your local `/24`. |
| `--no-dns` | Skip reverse-DNS hostname lookups. |

Set `NO_COLOR=1` to disable colors.

## How it works

1. Sends one empty UDP packet to every host in the subnet, which forces the OS to ARP for each address.
2. Reads the OS ARP cache (`/proc/net/arp` or `arp -a`).
3. Matches the first 3 MAC bytes against the built-in vendor table. MACs with the "locally administered" bit set (typical for phones using private Wi-Fi addresses) are labeled `Private (random MAC)`.
4. Resolves hostnames in parallel via reverse DNS.

## Notes

- Only devices on your **own subnet** that answer ARP are visible. Devices in deep sleep may be missed on a single scan.
- "Last seen" is tracked in memory during a run (most useful with `--watch`); nothing is written to disk.
- The vendor table is intentionally small and best effort. Unknown prefixes show `Unknown`; add yours to the `VENDORS` dict.
- Only scan networks you own or are authorized to scan.

## License

[MIT](LICENSE)
