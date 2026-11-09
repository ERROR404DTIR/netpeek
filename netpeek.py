#!/usr/bin/env python3
"""netpeek - see every device on your local network. Python stdlib only.

    python netpeek.py                 one-shot table
    python netpeek.py --watch [SECS]  keep scanning, alert when a NEW device joins
    python netpeek.py --json          machine-readable output
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# --------------------------------------------------------------------------
# Vendor lookup: small built-in OUI table (first 3 MAC bytes -> vendor).
# Best effort, no network calls. Add your own prefixes freely.
# --------------------------------------------------------------------------
VENDORS = {
    "Apple": "3C0754 A483E7 F01898 DCA904 28CFE9 ACBC32 88665A 001CB3 14109F F45C89",
    "Samsung": "001247 001599 8C7712 5C0A5B 30074D 94350A",
    "Google": "3C5AB4 F4F5D8 546009 A47733 1CF29A",
    "Amazon": "74C246 44650D FC65DE 6854FD 40B4CD F0272D",
    "Raspberry Pi": "B827EB DCA632 E45F01 D83ADD",
    "Intel": "001B21 001E64 3CA9F4 8C8D28 A434D9",
    "Microsoft": "00155D 0050F2 281878 7C1E52",
    "Cisco": "00000C 001AA1 001B54 F872EA",
    "TP-Link": "50C7BF 14CC20 F4F26D 98DAC4 60E327 C025E9",
    "Netgear": "00095B 00146C A06391 204E7F",
    "D-Link": "00055D 00179A 1CBDB9",
    "ASUS": "000C6E 001A92 04D4C4 2C56DC",
    "Huawei": "00E0FC 00259E 286ED4 4846FB",
    "Xiaomi": "640980 286C07 34CE00 7811DC",
    "Sony": "00014A 0013A9 30F9ED",
    "LG": "001C62 10683F A816B2",
    "Dell": "001422 180373 F8BC12",
    "HP": "001B78 3CD92B 9CB654",
    "Lenovo": "28D244 98FA9B",
    "Espressif (IoT)": "240AC4 30AEA4 84CCA8 A4CF12 3C71BF",
    "Ubiquiti": "002722 24A43C 44D9E7 788A20 FCECDA",
    "Roku": "000D4B B0A737 D83134",
    "Nintendo": "0009BF 0017AB 98B6E9",
    "Sonos": "000E58 5CAAFD 7828CA",
    "Philips Hue": "001788 ECB5FA",
    "Synology": "001132",
    "VMware": "000C29 005056 000569",
    "VirtualBox": "080027",
    "QEMU/KVM": "525400",
    "AVM FRITZ!": "3CA62F 00040E C80E14 444E6D",
    "Belkin": "94103E 08863B",
    "Brother": "008077 30055C",
    "Canon": "000085 180CAC",
    "Epson": "000048 64EB8C",
    "MikroTik": "000C42 4C5E0C 6C3B6B",
    "Hikvision": "4CBD8F 2857BE",
    "Zyxel": "001349 00A0C5",
    "OnePlus": "C0EEFB 94652D",
    "Realtek": "00E04C",
}
# Flip into {prefix: vendor} for O(1) lookups.
OUI = {prefix: vendor for vendor, prefixes in VENDORS.items() for prefix in prefixes.split()}


def vendor_of(mac):
    """Vendor name for a MAC like 'AA:BB:CC:DD:EE:FF'."""
    known = OUI.get(mac[:8].replace(":", ""))
    if known:
        return known
    # Bit 1 of the first byte set => locally administered (phones randomize MACs).
    return "Private (random MAC)" if int(mac[:2], 16) & 0x02 else "Unknown"


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def local_network():
    """Guess our LAN as a /24. A UDP connect() sends nothing; it just picks a route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "192.168.1.1"
    finally:
        s.close()
    return ipaddress.ip_network(ip + "/24", strict=False)


def poke(ip):
    """Send one empty UDP packet; the OS must ARP for the host, filling the ARP cache."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"\0", (ip, 9))
    except OSError:
        pass


def norm_mac(mac):
    """macOS drops leading zeros ('a:b:c'), Windows uses dashes; normalize both."""
    return ":".join(x.zfill(2) for x in re.split(r"[:-]", mac)).upper()


def read_arp():
    """Return {ip: mac} from the OS ARP cache."""
    entries = {}
    if os.path.exists("/proc/net/arp"):  # Linux
        with open("/proc/net/arp") as f:
            next(f)  # header
            for line in f:
                cols = line.split()
                if len(cols) >= 4 and cols[2] != "0x0":  # 0x0 = incomplete entry
                    entries[cols[0]] = norm_mac(cols[3])
    else:  # macOS / Windows: parse `arp -a`
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
        except FileNotFoundError:
            sys.exit("netpeek: could not find the 'arp' command")
        pattern = r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})"
        for ip, mac in re.findall(pattern, out):
            entries[ip] = norm_mac(mac)
    return entries


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def scan(net, resolve=True):
    """Wake up the ARP cache, read it, and return a list of device dicts."""
    with ThreadPoolExecutor(64) as pool:
        list(pool.map(poke, [str(h) for h in net.hosts()]))
    time.sleep(1.5)  # give hosts a moment to answer ARP

    devices = []
    for ip, mac in read_arp().items():
        addr = ipaddress.ip_address(ip)
        junk = addr.is_multicast or addr in (net.network_address, net.broadcast_address)
        if addr not in net or junk or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        devices.append({"ip": ip, "mac": mac, "vendor": vendor_of(mac), "hostname": ""})

    if resolve and devices:  # reverse DNS can be slow, so do it in parallel
        with ThreadPoolExecutor(32) as pool:
            for dev, name in zip(devices, pool.map(hostname, [d["ip"] for d in devices])):
                dev["hostname"] = name
    return devices


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if os.name == "nt":
    os.system("")  # enables ANSI escape codes in the Windows console


def color(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR and code else text


def ago(seconds):
    s = int(seconds)
    if s < 5:
        return "just now"
    if s < 60:
        return f"{s}s ago"
    return f"{s // 60}m ago" if s < 3600 else f"{s // 3600}h ago"


def render(rows, online, new, net):
    """Print the device table. Green = just joined, dim = currently offline."""
    heads = ("IP", "MAC", "VENDOR", "HOSTNAME", "LAST SEEN")
    now = time.time()
    body = [(d["ip"], d["mac"], d["vendor"], d["hostname"] or "-", ago(now - d["last_seen"]))
            for d in rows]
    widths = [max(len(r[i]) for r in [heads] + body) for i in range(5)]
    fmt = lambda cells: "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    print(color(f"netpeek | {net} | {len(online)} online | {datetime.now():%H:%M:%S}", "1;36"))
    print(color(fmt(heads), "1"))
    for dev, cells in zip(rows, body):
        if dev["mac"] in new:
            print(color(fmt(cells) + "  NEW", "1;32"))
        else:
            print(color(fmt(cells), "" if dev["mac"] in online else "2"))


def export(dev):
    """Device dict with a human-readable ISO timestamp, for JSON output."""
    out = dict(dev)
    out["last_seen"] = datetime.fromtimestamp(dev["last_seen"]).isoformat(timespec="seconds")
    return out


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(prog="netpeek", description="Show every device on your local network.")
    p.add_argument("-w", "--watch", nargs="?", type=int, const=10, metavar="SECS",
                   help="rescan every SECS seconds (default 10) and alert on new devices")
    p.add_argument("-j", "--json", action="store_true", help="output JSON")
    p.add_argument("-s", "--subnet", help="CIDR to scan, e.g. 192.168.1.0/24 (default: your /24)")
    p.add_argument("--no-dns", action="store_true", help="skip hostname lookups (faster)")
    args = p.parse_args()

    net = ipaddress.ip_network(args.subnet, strict=False) if args.subnet else local_network()
    watching = args.watch is not None
    seen = {}      # mac -> device dict (kept across scans so we can show 'last seen')
    alerts = []    # log of new-device alerts (watch mode)
    first = True   # the first scan is the baseline, so nothing is 'new' yet

    if sys.stderr.isatty():
        print(f"Scanning {net} ...", file=sys.stderr)
    try:
        while True:
            found = scan(net, resolve=not args.no_dns)
            now = time.time()
            online = {d["mac"] for d in found}
            new = set()
            for dev in found:
                if dev["mac"] not in seen and not first:
                    new.add(dev["mac"])
                    alerts.append(f"[{datetime.now():%H:%M:%S}] NEW DEVICE  {dev['ip']}  "
                                  f"{dev['mac']}  {dev['vendor']}  {dev['hostname']}".rstrip())
                seen[dev["mac"]] = {**dev, "last_seen": now}

            rows = sorted(seen.values(), key=lambda d: ipaddress.ip_address(d["ip"]))
            if args.json:
                if watching:  # one JSON line per new device
                    for mac in new:
                        print(json.dumps({"event": "new_device", **export(seen[mac])}), flush=True)
                else:
                    print(json.dumps([export(d) for d in rows], indent=2))
            else:
                if watching and sys.stdout.isatty():
                    print("\033[H\033[J", end="")  # clear screen
                render(rows, online, new, net)
                for line in alerts[-5:]:
                    print(color(line, "1;33"))
                if new:
                    print("\a", end="", flush=True)  # terminal bell

            if not watching:
                return 0
            first = False
            time.sleep(max(1, args.watch))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
