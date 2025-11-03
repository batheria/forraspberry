import subprocess

class MonitorManager:
    def __init__(self, interface):
        self.interface = interface

    def run_command(self, cmd):
        """Ejecuta un comando y devuelve la salida."""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()

    def enable_monitor_mode(self):
        print(f"[*] Activando modo monitor en {self.interface}...")
        self.run_command(f"sudo ip link set {self.interface} down")
        self.run_command(f"sudo iwconfig {self.interface} mode monitor")
        self.run_command(f"sudo ip link set {self.interface} up")
        print(f"[+] {self.interface} ahora está en modo monitor.")

    def disable_monitor_mode(self):
        print(f"[*] Desactivando modo monitor en {self.interface}...")
        self.run_command(f"sudo ip link set {self.interface} down")
        self.run_command(f"sudo iwconfig {self.interface} mode managed")
        self.run_command(f"sudo ip link set {self.interface} up")
        print(f"[+] {self.interface} ahora está en modo managed.")
