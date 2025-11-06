

import os
import sys
import subprocess
import shutil
import time
import csv
from datetime import datetime
from monitor import MonitorManager
import moduls
from wireless import Wireless

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
            rc, out = moduls.run(["ping", "-c", "1", "-W", "1", target])
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



#------------------- SCAN PUERTOS --------------------------------

def scan_network_auto(target=None):
    """
    Intenta usar arp-scan, sino nmap, sino arp -a, y guarda resultados en CSV simple.
    """
    if not target:
        # intentar detectar automáticamente
        rc, ipout = moduls.run(["hostname", "-I"])
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
        rc, out = moduls.run(["sudo", "arp-scan", "--localnet"])
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and is_ip(parts[0]) and is_mac(parts[1]):
                    devices.append({"ip": parts[0], "mac": parts[1].lower(), "vendor": " ".join(parts[2:]), "host": ""})
    # 2) nmap fallback / complemento
    if shutil.which("nmap"):
        print("[*] Ejecutando nmap -sn para completar información...")
        rc, out = moduls.run(["sudo", "nmap", "-sn", target, "-oG", "-"])
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

# ---------------- MENÚ ----------------



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

                nets = Wireless.main()

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

            moduls.run(f"sudo iwconfig")


        elif choice == "6":
            print("Saliendo. Buenas pruebas controladas.")
            break
        else:
            print("Opción inválida.")


if __name__ == "__main__":
    menu()
