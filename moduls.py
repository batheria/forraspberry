import subprocess

# ---------------- RUN CMD TODOS LOS COMANDOS VAN POR ACA ----------------

class Commands:
    def __init__(self):
        pass

    
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
