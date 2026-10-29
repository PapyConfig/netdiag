"""Utilitaires communs : exécution de commandes, PowerShell, DNS inverse, droits admin."""
from __future__ import annotations

import base64
import ctypes
import os
import socket
import subprocess
import threading

IS_WINDOWS = os.name == "nt"
# Empêche l'ouverture d'une fenêtre console à chaque sous-processus depuis l'exe GUI
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _oem_codepage() -> str:
    if IS_WINDOWS:
        try:
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            return "cp850"
    return "latin-1"


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(_oem_codepage(), errors="replace")


def run(cmd: list[str], timeout: float = 30, c_locale: bool = False) -> tuple[int, str, str]:
    """Exécute une commande et renvoie (code, stdout, stderr). Ne lève jamais.
    c_locale=True force une sortie non traduite (pour les sorties qu'on analyse)."""
    env = {**os.environ, "LC_ALL": "C"} if c_locale else None
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW, env=env)
    except subprocess.TimeoutExpired:
        return 1, "", f"Délai dépassé ({timeout}s) : {' '.join(cmd)}"
    except OSError as e:
        return 1, "", str(e)
    return p.returncode, decode(p.stdout), decode(p.stderr)


def run_powershell(script: str, timeout: float = 90) -> tuple[int, str, str]:
    prefix = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
              "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';\n")
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode()
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", encoded], timeout=timeout)


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def resolve_ipv4(host: str) -> str:
    """Résout un nom en IPv4 (lève socket.gaierror si impossible)."""
    host = host.strip()
    return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]


_rdns_cache: dict[str, str] = {}
_rdns_lock = threading.Lock()


def reverse_dns(ip: str) -> str:
    with _rdns_lock:
        if ip in _rdns_cache:
            return _rdns_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        name = ""
    with _rdns_lock:
        _rdns_cache[ip] = name
    return name
