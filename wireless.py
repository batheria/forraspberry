import subprocess, tempfile, time, glob, csv, os, shutil, argparse

class Wireless:

    def __init__(self):
        pass

    def run_airodump(self,interface, duration, tmpdir):
        prefix = os.path.join(tmpdir, "scan")
        cmd = ["sudo", "airodump-ng", "--write", prefix, "--output-format", "csv", interface]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(duration)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def find_csv(tmpdir):
        matches = glob.glob(os.path.join(tmpdir, "*.csv"))
        if not matches:
            return None
        return max(matches, key=os.path.getmtime)

    def parse_airodump_csv(self,path):
        networks = []
        with open(path, newline='', errors='ignore') as fh:
            reader = csv.reader(fh)
            section = "pre"
            headers = []
            for row in reader:
                # normalize empty-row separation
                if not row or all(not col.strip() for col in row):
                    if section == "networks":
                        section = "clients"
                    continue

                first = row[0].strip().upper()
                if first.startswith("BSSID"):
                    section = "networks"
                    headers = [h.strip() for h in row]
                    continue
                if first.startswith("STATION MAC") or first.startswith("STATION") :
                    section = "clients"
                    continue

                if section == "networks":
                    # defensive parsing: many airodump versions have columns:
                    # BSSID, First time seen, Last time seen, channel, speed, privacy, cipher, auth, power, beacons, #IV, LAN IP, ID-length, ESSID
                    try:
                        bssid = row[0].strip()
                        ssid = row[-1].strip() if len(row) >= 1 else "<hidden>"
                        channel = row[3].strip() if len(row) > 3 and row[3].strip() else None
                        power = None
                        if len(row) > 8 and row[8].strip() != '':
                            try:
                                power = int(row[8].strip())
                            except:
                                power = row[8].strip()
                        privacy = row[5].strip() if len(row) > 5 else ""
                        cipher = row[6].strip() if len(row) > 6 else ""
                        auth = row[7].strip() if len(row) > 7 else ""
                        encryption = " ".join(x for x in (privacy, cipher, auth) if x).strip() or "UNKNOWN"
                        networks.append({
                            "bssid": bssid,
                            "ssid": ssid if ssid != "" else "<hidden>",
                            "channel": channel or "?",
                            "power": power if power is not None else "?",
                            "encryption": encryption
                        })
                    except Exception:
                        # fallback: keep raw line if parsing falla
                        networks.append({"bssid": row[0] if row else "", "ssid": row[-1] if row else "", "channel":"?", "power":"?", "encryption":"?"})
        return networks

    def save_txt(networks, outpath):
        with open(outpath, "w", encoding="utf-8") as fh:
            fh.write(f"{'BSSID':20}\t{'SSID':40}\t{'CH':>3}\t{'PWR':>5}\t{'ENC'}\n")
            fh.write("-"*100 + "\n")
            for n in networks:
                ssid = (n.get("ssid") or "<hidden>")[:40]
                fh.write(f"{n.get('bssid', '?'):20}\t{ssid:40}\t{str(n.get('channel','?')):>3}\t{str(n.get('power','?')):>5}\t{n.get('encryption','?')}\n")

    def main(self):
        parser = argparse.ArgumentParser(description="Run airodump-ng for duration and save networks to TXT")
        parser.add_argument("--iface", required=True, help="Interfaz en modo monitor (ej: wlan1mon)")
        parser.add_argument("--duration", type=int, default=8, help="Segundos que ejecuta airodump-ng")
        parser.add_argument("--out", default="airodump_scan.txt", help="Archivo TXT de salida")
        args = parser.parse_args()

        tmpdir = tempfile.mkdtemp(prefix="airodump_tmp_")
        try:
            print(f"[+] Ejecutando airodump-ng en {args.iface} por {args.duration}s ... (asegurate de usar sudo)")
            self.run_airodump(args.iface, args.duration, tmpdir)
            csv_path = self.find_csv(tmpdir)
            if not csv_path:
                print("[-] No se generó CSV. Revisa que airodump-ng esté instalado y que la interfaz esté en modo monitor.")
                return
            nets = self.parse_airodump_csv(csv_path)
            if not nets:
                print("[!] No se detectaron redes (o no se pudo parsear el CSV).")
            else:
                self.save_txt(nets, args.out)
                print(f"[+] Guardado {len(nets)} redes en {args.out}")
        finally:
            # limpiar archivos temporales
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass