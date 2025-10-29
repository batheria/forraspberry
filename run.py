#!/usr/bin/env python3
"""
scan_net.py
Escanea la red local y lista dispositivos (IP, MAC, Vendor, Hostname).
Uso:
  sudo python3 scan_net.py 192.168.18.0/24
Si no pasás rango, intenta detectar la red local desde hostname -I.
"""

import subprocess, sys, csv, re, shutil, socket, time
from datetime import datetime

def run(cmd, shell=False):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, shell=shell)
        return out
    except subprocess.CalledProcessError as e:
        return e.output
    except FileNotFoundError:
        return None

def detect_local_network():
    out = run(["hostname", "-I"])
    if out:
        ips = out.strip().split()
        if ips:
            ip = ips[0]
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # fallback common ranges
    return "192.168.1.0/24"

def parse_arp_scan(output):
    # arp-scan lines: IP<TAB>MAC<TAB>VENDOR
    devices = []
    if not output:
        return devices
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"^([\d\.]+)\s+([0-9a-f:]{17})\s+(.+)$", line, re.I)
        if m:
            devices.append({"ip": m.group(1), "mac": m.group(2).lower(), "vendor": m.group(3).strip(), "host": ""})
    return devices

def parse_nmap_grepable(output):
    devices = []
    if not output:
        return devices
    # Nmap -sn -oG format: Host: 192.168.18.45 ()   Status: Up
    # and later "MAC: xx:xx:xx (Vendor)"
    current = {}
    for line in output.splitlines():
        if line.startswith("Host:"):
            parts = line.split()
            ip = parts[1]
            current = {"ip": ip, "mac": "", "vendor": "", "host": ""}
            devices.append(current)
        elif "MAC Address:" in line or "MAC:" in line:
            m = re.search(r"MAC (?:Address:)?\s*([0-9A-Fa-f:]{17})\s*\(?([^\)]*)\)?", line)
            if m and current:
                current["mac"] = m.group(1).lower()
                current["vendor"] = m.group(2).strip()
        elif "Nmap scan report for" in line:
            m = re.search(r"Nmap scan report for (.+?) \(([\d\.]+)\)", line)
            if m:
                name = m.group(1).strip()
                ip = m.group(2).strip()
                for d in devices:
                    if d["ip"] == ip:
                        d["host"] = name
    return devices

def parse_arp_a(output):
    devices = []
    if not output:
        return devices
    # lines like: ? (192.168.18.1) at a4:7c:c9:08:c0:ad [ether] on wlp2s0
    for line in output.splitlines():
        m = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-f:]{17})\s+\[", line, re.I)
        if m:
            ip = m.group(1)
            mac = m.group(2).lower()
            devices.append({"ip": ip, "mac": mac, "vendor": "", "host": ""})
    return devices

def ping_sweep(range_cidr):
    # range like 192.168.18.0/24 -> generate ips .1 to .254
    base = ".".join(range_cidr.split(".")[:3])
    devices = []
    for i in range(1,255):
        ip = f"{base}.{i}"
        p = subprocess.run(["ping","-c","1","-W","1",ip], stdout=subprocess.DEVNULL)
        if p.returncode == 0:
            devices.append({"ip": ip, "mac": "", "vendor": "", "host": ""})
    return devices

def uniq_devices(devs):
    seen = {}
    out = []
    for d in devs:
        ip = d.get("ip")
        if ip not in seen:
            seen[ip] = True
            out.append(d)
    return out

def mac_lookup_oui(mac):
    # fast OUI lookup using local cache file (optional). If no cache/online, return empty.
    # For simplicity, return empty here. User can integrate IEEE oui lookup if wants.
    return ""

def save_csv(devices, fname="scan_results.csv"):
    with open(fname, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","mac","vendor","host"])
        writer.writeheader()
        for d in devices:
            writer.writerow({"ip": d.get("ip",""), "mac": d.get("mac",""), "vendor": d.get("vendor",""), "host": d.get("host","")})
    print(f"Saved {len(devices)} devices to {fname}")

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else detect_local_network()
    print(f"[+] Target network: {target}")
    devices = []

    # 1) try arp-scan
    if shutil.which("arp-scan"):
        print("[*] Running arp-scan (requires sudo)...")
        out = run(["sudo","arp-scan","--localnet"])
        devices = parse_arp_scan(out)
    else:
        print("[-] arp-scan not found")

    # 2) if none or partial, try nmap -sn
    if (not devices) and shutil.which("nmap"):
        print("[*] Running nmap ping-scan (requires sudo)...")
        out = run(["sudo","nmap","-sn", target, "-oG","-"])
        devices = parse_nmap_grepable(out)
    elif (shutil.which("nmap") and devices):
        # try complement nmap to enrich data
        print("[*] Enriching with nmap...")
        out = run(["sudo","nmap","-sn", target, "-oG","-"])
        more = parse_nmap_grepable(out)
        # merge by IP, prefer mac/vendor if present
        ips = {d["ip"]: d for d in devices}
        for m in more:
            ip = m["ip"]
            if ip in ips:
                if not ips[ip].get("mac") and m.get("mac"):
                    ips[ip]["mac"] = m["mac"]
                    ips[ip]["vendor"] = m.get("vendor","")
                if not ips[ip].get("host") and m.get("host"):
                    ips[ip]["host"] = m.get("host")
            else:
                ips[ip] = m
        devices = list(ips.values())

    # 3) fallback to arp -a
    if (not devices):
        print("[*] Trying arp -a ...")
        out = run(["arp","-a"])
        devices = parse_arp_a(out)

    # 4) final fallback ping sweep (slow)
    if (not devices):
        print("[*] Falling back to ping sweep (slow)...")
        devices = ping_sweep(target)

    devices = uniq_devices(devices)

    # try reverse DNS for hostnames if empty
    for d in devices:
        if not d.get("host"):
            try:
                d["host"] = socket.gethostbyaddr(d["ip"])[0]
            except Exception:
                d["host"] = ""

    # print nicely
    print("\nFound devices:")
    print(f"{'IP':<16} {'MAC':<20} {'VENDOR':<30} {'HOST'}")
    for d in devices:
        print(f"{d.get('ip',''):<16} {d.get('mac',''):<20} {d.get('vendor',''):<30} {d.get('host','')}")

    # save csv
    save_csv(devices)

if __name__ == "__main__":
    main()
