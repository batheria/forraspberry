

import os
import sys
import subprocess
import shutil
import time
import csv
from datetime import datetime
from monitor import MonitorManager
import re
from shutil import which

PCAP_FILE = "capture.pcap"

# ---------------- PARCEAR IP Y MAC ----------------
def is_ip(s):
    parts = s.split('.')
    return len(parts) == 4 and all(p.isdigit() and 0<=int(p)<=255 for p in parts)

def is_mac(s):
    import re
    return bool(re.match(r"^[0-9a-f:]{17}$", s.lower()))

# ---------------- GUARDA LA INFORMACION EN UN CSV ----------------
def save_csv(devices, fname):
    fieldnames = ["ip","mac","vendor","host"]
    with open(fname, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow({"ip": d.get("ip",""), "mac": d.get("mac",""), "vendor": d.get("vendor",""), "host": d.get("host","")})



# ---------------- PING MONITOR ----------------
def monitor_ping(target=None, interval=2):
    if not target:
        target = input("IP objetivo para monitor (ej. 192.168.18.161): ").strip()
        if not target:
            print("Cancelado.")
            return
    print(f"Monitoreando {target}. Ctrl+C para detener.")
   
    try:
        while True:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rc, out = run(["ping", "-c", "1", "-W", "1", target])
            reachable = rc == 0
            rtt = ""
            if reachable:
                import re
                m = re.search(r"time=([\d\.]+) ms", out)
                if m:
                    rtt = m.group(1)
            print(ts, target, "UP" if reachable else "DOWN", rtt)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario. Saliendo monitor.")

def clear():
    os.system("clear" if os.name != "nt" else "cls")
# ---------------- MENÚ ----------------

# ---------------- RUN CMD TODOS LOS COMANDOS VAN POR ACA ----------------
def run(cmd, capture=True, shell=False):
    try:
        if capture:
            res = subprocess.run(cmd if isinstance(cmd, list) else cmd, shell=shell,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return res.returncode, (res.stdout or "").strip()
        else:
            res = subprocess.run(cmd if isinstance(cmd, list) else cmd, shell=shell)
            return res.returncode, ""
    except FileNotFoundError as e:
        return 127, str(e)


# ---------------- SCAN WIRELESS ----------------

def parse_iwlist_scan(output):
    """Parsea la salida de `iwlist <iface> scan`."""
    networks = []
    # split by 'Cell'
    cells = re.split(r"\n\s*Cell\s+\d+\s+-\s+Address:\s+", output)
    for cell in cells[1:]:
        net = {"raw": cell.strip(), "ssid": None, "bssid": None, "channel": None, "signal_dbm": None, "encryption": "OPEN"}
        # BSSID
        m = re.match(r"([0-9A-Fa-f:]{17})", cell)
        if m:
            net["bssid"] = m.group(1).lower()

        ess = re.search(r'ESSID:"(.*)"', cell)
        if ess:
            net["ssid"] = ess.group(1) or "<hidden>"

        ch = re.search(r"Channel:(\d+)", cell)
        if ch:
            net["channel"] = int(ch.group(1))
        else:
            freq = re.search(r"Frequency:(\d+\.\d+)", cell)
            if freq:
                # not converting freq to channel here
                net["channel"] = freq.group(1)

        sig = re.search(r"Signal level[=\-: ]+([-0-9]+) dBm", cell)
        if not sig:
            sig = re.search(r"Quality=.*Signal level[=\-: ]*([-0-9]+) dBm", cell)
        if sig:
            try:
                net["signal_dbm"] = int(sig.group(1))
            except:
                net["signal_dbm"] = sig.group(1)

        enc_on = re.search(r"Encryption key:(on|off)", cell)
        if enc_on and enc_on.group(1) == "on":
            # look for WPA/RSN
            if re.search(r"WPA2|WPA|RSN", cell, re.IGNORECASE):
                net["encryption"] = "WPA/WPA2"
            else:
                net["encryption"] = "Encrypted"
        else:
            net["encryption"] = "OPEN"

        networks.append(net)
    return networks

def detect_wireless_interface():
    """Detecta la primera interfaz wireless usando `iw dev` o lista /sys/class/net."""
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        if out.returncode == 0:
            m = re.search(r"Interface\s+(\w+)", out.stdout)
            if m:
                return m.group(1)
    except FileNotFoundError:
        pass

    # Fallback: buscar interfaces en /sys/class/net que tengan /wireless
    import os
    for iface in os.listdir("/sys/class/net"):
        if os.path.exists(f"/sys/class/net/{iface}/wireless"):
            return iface
    return None

def parse_iw_scan(output):
    """Parsea la salida de `iw dev <iface> scan`."""
    networks = []
    # Split entries by "BSS " which starts each block
    blocks = re.split(r"\nBSS\s+", "\n" + output)
    for block in blocks[1:]:
        net = {"raw": block.strip(), "ssid": None, "bssid": None, "channel": None, "signal_dbm": None, "encryption": "OPEN"}
        # BSSID is first token on the block (MAC)
        m = re.match(r"([0-9a-fA-F:]{17})", block)
        if m:
            net["bssid"] = m.group(1).lower()

        ssid = re.search(r"\n\s*SSID:\s*(.*)\n", block)
        if ssid:
            net["ssid"] = ssid.group(1).strip() or "<hidden>"

        sig = re.search(r"signal:\s*([-0-9.]+)\s*dBm", block)
        if sig:
            try:
                net["signal_dbm"] = int(float(sig.group(1)))
            except:
                net["signal_dbm"] = sig.group(1)

        ch = re.search(r"DS Parameter set: channel (\d+)", block)
        if ch:
            net["channel"] = int(ch.group(1))
        else:
            ch2 = re.search(r"freq:\s*(\d+)", block)  # freq in MHz
            if ch2:
                freq = int(ch2.group(1))
                # convert common 2.4GHz channels; basic conversion:
                if 2412 <= freq <= 2472:
                    net["channel"] = (freq - 2407) // 5
                elif freq == 2484:
                    net["channel"] = 14
                else:
                    net["channel"] = freq

        # encryption detection
        if re.search(r"\n\s*RSN:\s*", block) or "WPA" in block or re.search(r"IE:\s*WPA", block):
            net["encryption"] = "WPA/WPA2"
        elif re.search(r"privacy", block, re.IGNORECASE) or re.search(r"cipher", block, re.IGNORECASE):
            net["encryption"] = "Encrypted"
        else:
            net["encryption"] = "OPEN"

        networks.append(net)
    return networks

def scan_networks(interface=None):
    """Detecta interfaz (si no se pasa) y escanea redes retornando una lista de dicts."""
    if interface is None:
        interface = detect_wireless_interface()
        if interface is None:
            raise RuntimeError("No se detectó interfaz inalámbrica. Conecta un adaptador y prueba de nuevo.")

    # Preferir 'iw' si existe
    if which("iw"):
        cmd = ["sudo", "iw", "dev", interface, "scan"]
        rc, out = run(cmd)
        if rc == 0 and out.strip():
            return parse_iw_scan(out)
        # si falla, no panic: intentar iwlist
    # Fallback a iwlist
    if which("iwlist"):
        cmd = ["sudo", "iwlist", interface, "scan"]
        rc, out = run(cmd)
        if rc == 0 and out.strip():
            return parse_iwlist_scan(out)

    raise RuntimeError("No se pudo ejecutar scan. Asegúrate de tener 'iw' o 'iwlist' instalado y ejecutar con permisos (sudo).")

#------------------- SCAN PUERTOS --------------------------------

def scan_network_auto(target=None):
    """
    Intenta usar arp-scan, sino nmap, sino arp -a, y guarda resultados en CSV simple.
    """
    if not target:
        # intentar detectar automáticamente
        rc, ipout = run(["hostname", "-I"])
        if rc == 0 and ipout.strip():
            ip = ipout.strip().split()[0]
            parts = ip.split('.')
            if len(parts) == 4:
                target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    if not target:
        target = input("Ingresá la red CIDR a escanear (ej. 192.168.18.0/24): ").strip()
        if not target:
            print("Cancelado.")
            return

    devices = []
    print(f"[+] Scan objetivo: {target}")

    # 1) arp-scan
    if shutil.which("arp-scan"):
        print("[*] Ejecutando arp-scan --localnet (requiere sudo)...")
        rc, out = run(["sudo", "arp-scan", "--localnet"])
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and is_ip(parts[0]) and is_mac(parts[1]):
                    devices.append({"ip": parts[0], "mac": parts[1].lower(), "vendor": " ".join(parts[2:]), "host": ""})
    # 2) nmap fallback / complemento
    if shutil.which("nmap"):
        print("[*] Ejecutando nmap -sn para completar información...")
        rc, out = run(["sudo", "nmap", "-sn", target, "-oG", "-"])
        if rc == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Host:"):
                    # Host: 192.168.18.45 ()    Status: Up
                    parts = line.split()
                    ip = parts[1] if len(parts) > 1 else ""
                    if is_ip(ip):
                        # añadir si no está
                        if not any(d["ip"] == ip for d in devices):
                            devices.append({"ip": ip, "mac": "", "vendor": "", "host": ""})
                if "MAC Address:" in line or "MAC:" in line:
                    import re
                    m = re.search(r"([0-9A-Fa-f:]{17})\s*\(?([^\)]*)\)?", line)
                    if m:
                        mac = m.group(1).lower()
                        vendor = m.group(2).strip()
                        # buscar dispositivo por IP cercano (último añadido)
                        for d in reversed(devices):
                            if d.get("mac") == "" or d.get("vendor") == "":
                                d["mac"] = mac
                                d["vendor"] = vendor
                                break

    # 3) arp -a fallback


# ---------------- TCPDUMP CAPTURE ----------------
def capture_traffic(interface=None, duration=None):
    if not shutil.which("tcpdump"):
        print("tcpdump no instalado. Instalar: sudo apt install tcpdump")
        return
    if not interface:
        interface = input("Interfaz a usar para captura (ej. wlan0mon o wlan0): ").strip()
        if not interface:
            print("Cancelado.")
            return
    cmd = ["sudo", "tcpdump", "-i", interface, "-w", PCAP_FILE]
    if duration:
        print(f"Capturando en {interface} por {duration} segundos -> {PCAP_FILE}")
        try:
            p = subprocess.Popen(cmd)
            time.sleep(duration)
            p.terminate()
            print(f"Captura guardada en {PCAP_FILE}")
        except KeyboardInterrupt:
            p.terminate()
            print("Captura interrumpida, archivo guardado.")
    else:
        print(f"Iniciando captura en {interface}. Ctrl+C para detener. Archivo: {PCAP_FILE}")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nCaptura interrumpida por usuario.")

def placeholder_attack():
    print("ATACANDO")

def menu():
    while True:
        
        print("\n=== RPi SAFE TOOLBOX ===")
        print("1) Scanear Red Wifi")
        print("2) Monitorizar host (ping log)")
        print("3) Capturar tráfico (tcpdump -> pcap)")
        print("4) (PLACEHOLDER) Atacar tal usuario (NO ejecuta ataque)")
        print("5) Placa de red Monitor")
        print("6) Salir")

        choice = input("Elegí una opción [1-6]: ").strip()

        clear()
        if choice == "1":
            iface = None
            if len(sys.argv) > 1:
                iface = sys.argv[1]
            nets = scan_networks(iface)
            if not nets:
                print("No se encontraron redes.")
            else:
                # imprimir resumen simple
                print(f"{'SSID':40} {'BSSID':17} {'CH':>3} {'SIG(dBm)':>8} {'ENC':>10}")
                print("-"*86)
                for n in nets:
                    ssid = (n['ssid'] or "<hidden>")[:40]
                    bssid = n['bssid'] or "?"
                    ch = str(n['channel']) if n['channel'] else "?"
                    sig = str(n['signal_dbm']) if n['signal_dbm'] is not None else "?"
                    enc = n['encryption']
                    print(f"{ssid:40} {bssid:17} {ch:>3} {sig:>8} {enc:>10}")
                # también guardamos raw en JSON si quieres
                # print(json.dumps(nets, indent=2))
            """network = input("Red CIDR (enter para autodetectar): ").strip() or None
            scan_network_auto(network)"""

        elif choice == "2":
            target = input("IP objetivo (enter para preguntar después): ").strip() or None
            interval = input("Intervalo entre pings (segundos, default 2): ").strip()
            try:
                interval = int(interval) if interval else 2
            except:
                interval = 2
            monitor_ping(target, interval)
        elif choice == "3":
            interface = input("Interfaz para captura (enter para preguntar): ").strip() or None
            dur = input("Duración en segundos (enter para captura hasta Ctrl+C): ").strip()
            try:
                dur = int(dur) if dur else None
            except:
                dur = None
            capture_traffic(interface, dur)

        elif choice == "5":
            interface = input("Introduce la interfaz (ej: wlan0): ").strip()
            manager_monitor = MonitorManager(interface)
            print("1) Activar el modo monitor")
            print("2) Desactivar el modo monitor")

            choice = input("Elegí una opción [1-2]: ").strip()

            if choice == '1':
                manager_monitor.enable_monitor_mode()
            if choice == '2':
                manager_monitor.disable_monitor_mode()

            run(f"sudo iwconfig")


        elif choice == "6":
            print("Saliendo. Buenas pruebas controladas.")
            break
        else:
            print("Opción inválida.")


if __name__ == "__main__":
    menu()
