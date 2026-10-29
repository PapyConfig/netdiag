"""Envoi d'echo ICMP avec contrôle du TTL, de la taille et du bit DF.

Sous Windows on utilise l'API IcmpSendEcho (iphlpapi.dll) : pas besoin des droits
administrateur, et c'est ce qu'utilisent tracert / PingPlotter. Ailleurs (dev Linux)
on se rabat sur la commande `ping`.
"""
from __future__ import annotations

import ctypes
import math
import re
import time
from dataclasses import dataclass

from .utils import IS_WINDOWS, run


@dataclass
class PingResult:
    status: str               # ok | ttl | timeout | unreach | toobig | error
    rtt: float | None = None  # ms
    addr: str | None = None   # adresse ayant répondu (destination ou routeur)
    ttl: int | None = None    # TTL de la réponse
    detail: str = ""

    @property
    def answered(self) -> bool:
        return self.status in ("ok", "ttl")


# --------------------------------------------------------------------------- Windows
if IS_WINDOWS:
    from ctypes import wintypes

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.POINTER(ctypes.c_ubyte))]

    class ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [("Address", wintypes.ULONG), ("Status", wintypes.ULONG),
                    ("RoundTripTime", wintypes.ULONG), ("DataSize", wintypes.USHORT),
                    ("Reserved", wintypes.USHORT), ("Data", ctypes.c_void_p),
                    ("Options", IP_OPTION_INFORMATION)]

    _STATUS = {
        0: ("ok", ""),
        11002: ("unreach", "Réseau de destination injoignable"),
        11003: ("unreach", "Hôte de destination injoignable"),
        11004: ("unreach", "Protocole injoignable"),
        11005: ("unreach", "Port injoignable"),
        11009: ("toobig", "Paquet trop grand (fragmentation nécessaire)"),
        11010: ("timeout", "Délai d'attente dépassé"),
        11013: ("ttl", "TTL expiré en transit"),
        11014: ("ttl", "TTL expiré pendant le réassemblage"),
        11050: ("error", "Échec général"),
    }
    IP_FLAG_DF = 0x02

    _iphlp = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    _iphlp.IcmpCreateFile.restype = wintypes.HANDLE
    _iphlp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _iphlp.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                    ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD]
    _iphlp.IcmpSendEcho.restype = wintypes.DWORD

    def _ip_to_ulong(ip: str) -> int:
        import socket
        return int.from_bytes(socket.inet_aton(ip), "little")

    def _ulong_to_ip(v: int) -> str:
        import socket
        return socket.inet_ntoa(int(v).to_bytes(4, "little"))

    class Pinger:
        """Un handle ICMP par instance ; utiliser une instance par thread."""
        backend = "Windows IcmpSendEcho"

        def __init__(self):
            self._h = _iphlp.IcmpCreateFile()

        def close(self):
            if self._h:
                _iphlp.IcmpCloseHandle(self._h)
                self._h = None

        def __del__(self):
            try:
                self.close()
            except Exception:
                pass

        def ping(self, ip: str, ttl: int = 128, timeout: int = 1000, size: int = 32,
                 df: bool = False) -> PingResult:
            payload = (b"NetDiag-abcdefghijklmnopqrstuvwxyz" * (size // 34 + 1))[:size]
            req = ctypes.create_string_buffer(payload, max(size, 1))
            opts = IP_OPTION_INFORMATION(Ttl=ttl, Tos=0, Flags=IP_FLAG_DF if df else 0,
                                         OptionsSize=0, OptionsData=None)
            reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + max(size, 8) + 8 + 64
            buf = ctypes.create_string_buffer(reply_size)
            t0 = time.perf_counter()
            n = _iphlp.IcmpSendEcho(self._h, _ip_to_ulong(ip), req, size, ctypes.byref(opts),
                                    buf, reply_size, timeout)
            elapsed = (time.perf_counter() - t0) * 1000
            reply = ICMP_ECHO_REPLY.from_buffer(buf)
            code = reply.Status if n else ctypes.get_last_error()
            status, detail = _STATUS.get(code, ("error", f"Code IP {code}"))
            if status in ("timeout", "error") and not n:
                return PingResult(status, detail=detail)
            addr = _ulong_to_ip(reply.Address) if reply.Address else None
            rtt = float(reply.RoundTripTime) if reply.RoundTripTime >= 1 else round(elapsed, 2)
            return PingResult(status, rtt if status in ("ok", "ttl") else None, addr,
                              reply.Options.Ttl or None, detail)

# --------------------------------------------------------------------------- Fallback
else:
    _RE_OK = re.compile(r"bytes from ([\d.]+).*?ttl=(\d+).*?time=([\d.]+)", re.I)
    _RE_FROM = re.compile(r"From ([\d.]+)", re.I)

    class Pinger:
        backend = "commande ping (mode développement)"

        def close(self):
            pass

        def ping(self, ip: str, ttl: int = 128, timeout: int = 1000, size: int = 32,
                 df: bool = False) -> PingResult:
            cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout / 1000))),
                   "-t", str(ttl), "-s", str(size), "-M", "do" if df else "dont", ip]
            t0 = time.perf_counter()
            _, out, err = run(cmd, timeout=timeout / 1000 + 3)
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            text = out + err
            m = _RE_OK.search(text)
            if m:
                return PingResult("ok", float(m.group(3)), m.group(1), int(m.group(2)))
            m = _RE_FROM.search(text)
            low = text.lower()
            if "time to live exceeded" in low and m:
                return PingResult("ttl", elapsed, m.group(1), detail="TTL expiré en transit")
            if "frag needed" in low or "message too long" in low:
                return PingResult("toobig", addr=m.group(1) if m else None,
                                  detail="Paquet trop grand (fragmentation nécessaire)")
            if "unreachable" in low:
                return PingResult("unreach", addr=m.group(1) if m else None, detail="Injoignable")
            return PingResult("timeout", detail="Délai d'attente dépassé")


BACKEND = Pinger.backend
