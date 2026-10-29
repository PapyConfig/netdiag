"""Envoi d'echo ICMP avec contrôle du TTL, de la taille et du bit DF.

Windows : API IcmpSendEcho (iphlpapi.dll), sans droits administrateur, comme tracert / PingPlotter.
Linux, par ordre de préférence (sélection automatique, forçable via NETDIAG_ICMP=socket|mtr|cmd) :
  1. socket ICMP « datagramme » non privilégié (si net.ipv4.ping_group_range l'autorise) ;
  2. mtr-packet (paquet mtr-tiny, installé par défaut sur Ubuntu, possède cap_net_raw) ;
  3. un processus `ping` par sonde.
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

# --------------------------------------------------------------------------- Linux
else:
    import errno
    import itertools
    import os
    import random
    import select
    import shutil
    import socket
    import struct
    import subprocess
    import threading

    _SOL_IP = getattr(socket, "SOL_IP", 0)
    _IP_TTL = getattr(socket, "IP_TTL", 2)
    _IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
    _IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
    _IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
    _PMTUDISC_DONT, _PMTUDISC_PROBE = 0, 3
    _MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)

    def _payload(size: int) -> bytes:
        return (b"NetDiag-abcdefghijklmnopqrstuvwxyz" * (size // 34 + 1))[:size]

    class _SocketPinger:
        """Sockets ICMP « datagramme » du noyau : sans root si net.ipv4.ping_group_range
        inclut le groupe de l'utilisateur. Les erreurs ICMP (TTL expiré, frag. nécessaire…)
        arrivent par la file d'erreurs du socket (IP_RECVERR)."""
        backend = "socket ICMP non privilégié (Linux)"

        @staticmethod
        def available() -> bool:
            try:
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
                return True
            except OSError:
                return False

        def __init__(self):
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            self._sock.setsockopt(_SOL_IP, _IP_RECVERR, 1)
            self._sock.setsockopt(_SOL_IP, _IP_RECVTTL, 1)
            self._sock.setblocking(False)
            self._seq = random.randint(0, 0xFFFF)

        def close(self):
            self._sock.close()

        def _drain(self):
            for flags in (_MSG_ERRQUEUE, 0):
                while True:
                    try:
                        self._sock.recvmsg(4096, 1024, flags)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        continue

        def ping(self, ip: str, ttl: int = 128, timeout: int = 1000, size: int = 32,
                 df: bool = False) -> PingResult:
            s = self._sock
            self._drain()
            s.setsockopt(_SOL_IP, _IP_TTL, ttl)
            s.setsockopt(_SOL_IP, _IP_MTU_DISCOVER, _PMTUDISC_PROBE if df else _PMTUDISC_DONT)
            self._seq = (self._seq + 1) & 0xFFFF
            seq = self._seq
            t0 = time.perf_counter()
            try:
                s.sendto(struct.pack("!BBHHH", 8, 0, 0, 0, seq) + _payload(size), (ip, 0))
            except OSError as e:
                return _errno_result(e.errno)
            deadline = t0 + timeout / 1000
            poller = select.poll()
            poller.register(s, select.POLLIN | select.POLLERR)
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return PingResult("timeout", detail="Délai d'attente dépassé")
                if not poller.poll(remaining * 1000):
                    continue
                rtt = round((time.perf_counter() - t0) * 1000, 3)
                # 1) erreurs ICMP / locales
                try:
                    data, anc, _, _ = s.recvmsg(4096, 1024, _MSG_ERRQUEUE)
                except (BlockingIOError, InterruptedError):
                    data = None
                if data is not None:
                    if len(data) < 8 or struct.unpack_from("!H", data, 6)[0] != seq:
                        continue  # erreur relative à une sonde précédente
                    for level, ctype, cdata in anc:
                        if level == _SOL_IP and ctype == _IP_RECVERR and len(cdata) >= 16:
                            return _ee_result(cdata, rtt)
                    continue
                # 2) echo reply
                try:
                    data, anc, _, addr = s.recvmsg(4096, 1024)
                except (BlockingIOError, InterruptedError):
                    continue
                if len(data) >= 8 and data[0] == 0 and struct.unpack_from("!H", data, 6)[0] == seq:
                    rttl = None
                    for level, ctype, cdata in anc:
                        if level == _SOL_IP and ctype == _IP_TTL and len(cdata) >= 4:
                            rttl = struct.unpack("=i", cdata[:4])[0]
                    return PingResult("ok", rtt, addr[0], rttl)

    def _ee_result(cdata: bytes, rtt: float) -> PingResult:
        """Décode struct sock_extended_err (+ sockaddr_in de l'émetteur de l'erreur)."""
        ee_errno, origin, etype, code, _pad, info, _data = struct.unpack_from("=IBBBBII", cdata)
        addr = socket.inet_ntoa(cdata[20:24]) if len(cdata) >= 24 and cdata[16:18] != b"\0\0" else None
        if origin == 2:  # SO_EE_ORIGIN_ICMP
            if etype == 11:
                return PingResult("ttl", rtt, addr, detail="TTL expiré en transit")
            if etype == 3 and code == 4:
                return PingResult("toobig", addr=addr, detail=f"Fragmentation nécessaire (MTU signalé : {info})")
            if etype == 3:
                return PingResult("unreach", addr=addr, detail={0: "Réseau injoignable", 1: "Hôte injoignable",
                                                                 3: "Port injoignable", 13: "Filtré (admin)"}
                                  .get(code, f"Injoignable (code {code})"))
        return _errno_result(ee_errno, info)

    def _errno_result(err: int | None, info: int = 0) -> PingResult:
        if err == errno.EMSGSIZE:
            return PingResult("toobig", detail="Paquet trop grand pour l'interface locale" + (f" (MTU {info})" if info else ""))
        if err in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return PingResult("unreach", detail=os.strerror(err))
        return PingResult("error", detail=os.strerror(err) if err else "Erreur inconnue")

    class _MtrPacket:
        """Processus mtr-packet partagé (paquet mtr-tiny, cap_net_raw). Les requêtes sont
        multiplexées par jeton : plusieurs sondes peuvent être en vol simultanément."""
        _inst = None
        _inst_lock = threading.Lock()

        def __init__(self):
            self.proc = subprocess.Popen([shutil.which("mtr-packet")], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            self._tokens = itertools.count(1)
            self._pending: dict[int, list] = {}
            self._lock = threading.Lock()
            threading.Thread(target=self._reader, daemon=True, name="mtr-packet").start()

        @classmethod
        def get(cls) -> "_MtrPacket":
            with cls._inst_lock:
                if cls._inst is None or cls._inst.proc.poll() is not None:
                    cls._inst = cls()
                return cls._inst

        def _reader(self):
            for line in self.proc.stdout:
                tok, _, rest = line.strip().partition(" ")
                with self._lock:
                    waiter = self._pending.pop(int(tok), None) if tok.isdigit() else None
                if waiter:
                    waiter[1] = rest
                    waiter[0].set()

        def request(self, command: str, wait: float) -> str:
            tok = next(self._tokens)
            waiter = [threading.Event(), "no-reply"]
            with self._lock:
                self._pending[tok] = waiter
                try:
                    self.proc.stdin.write(f"{tok} {command}\n")
                    self.proc.stdin.flush()
                except OSError:
                    self._pending.pop(tok, None)
                    return "unexpected-error mtr-packet-dead"
            if not waiter[0].wait(wait):
                with self._lock:
                    self._pending.pop(tok, None)
            return waiter[1]

        @staticmethod
        def available() -> bool:
            if not shutil.which("mtr-packet"):
                return False
            try:
                return _MtrPacket.get().request("send-probe ip-4 127.0.0.1 timeout 1", 3).startswith("reply")
            except OSError:
                return False

    class _CmdPinger:
        """Dernier recours : un processus `ping` par sonde (iputils, cap_net_raw)."""
        backend = "commande ping"
        _RE_OK = re.compile(r"bytes from ([\d.]+).*?ttl=(\d+).*?time=([\d.]+)", re.I)
        _RE_FROM = re.compile(r"From ([\d.]+)", re.I)
        _RE_MTU = re.compile(r"mtu\s*=\s*(\d+)", re.I)

        def close(self):
            pass

        def ping(self, ip: str, ttl: int = 128, timeout: int = 1000, size: int = 32,
                 df: bool = False) -> PingResult:
            cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout / 1000))),
                   "-t", str(ttl), "-s", str(size), "-M", "do" if df else "dont", ip]
            t0 = time.perf_counter()
            _, out, err = run(cmd, timeout=timeout / 1000 + 3, c_locale=True)
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            text = out + err
            m = self._RE_OK.search(text)
            if m:
                return PingResult("ok", float(m.group(3)), m.group(1), int(m.group(2)))
            m = self._RE_FROM.search(text)
            low = text.lower()
            if "time to live exceeded" in low and m:
                return PingResult("ttl", elapsed, m.group(1), detail="TTL expiré en transit")
            if "frag needed" in low or "message too long" in low:
                mtu = self._RE_MTU.search(text)
                return PingResult("toobig", addr=m.group(1) if m else None,
                                  detail="Fragmentation nécessaire" + (f" (MTU {mtu.group(1)})" if mtu else ""))
            if "unreachable" in low:
                return PingResult("unreach", addr=m.group(1) if m else None, detail="Injoignable")
            return PingResult("timeout", detail="Délai d'attente dépassé")

    class _MtrPinger:
        backend = "mtr-packet (Linux)"
        _MAX_SIZE = 1500

        def __init__(self):
            self._mtr = _MtrPacket.get()
            self._cmd = _CmdPinger()

        def close(self):
            pass

        def ping(self, ip: str, ttl: int = 128, timeout: int = 1000, size: int = 32,
                 df: bool = False) -> PingResult:
            # mtr-packet positionne toujours DF : pour un vrai test DF (messages « frag needed »)
            # ou un gros paquet fragmentable, on passe par ping.
            if df or size + 28 > self._MAX_SIZE:
                return self._cmd.ping(ip, ttl, timeout, size, df)
            secs = max(1, math.ceil(timeout / 1000))
            rep = self._mtr.request(f"send-probe ip-4 {ip} ttl {ttl} timeout {secs} size {max(size + 28, 28)}",
                                    secs + 2).split()
            kind, args = (rep[0] if rep else "no-reply"), dict(zip(rep[1::2], rep[2::2]))
            rtt = int(args["round-trip-time"]) / 1000 if "round-trip-time" in args else None
            if kind == "reply":
                if rtt is not None and rtt > timeout:
                    return PingResult("timeout", detail="Délai d'attente dépassé")
                return PingResult("ok", rtt, args.get("ip-4"))
            if kind == "ttl-expired":
                return PingResult("ttl", rtt, args.get("ip-4"), detail="TTL expiré en transit")
            if kind == "no-reply":
                return PingResult("timeout", detail="Délai d'attente dépassé")
            if kind in ("no-route", "network-down"):
                return PingResult("unreach", detail=kind)
            if kind == "unexpected-error" and args.get("errno") == str(errno.EMSGSIZE):
                return PingResult("toobig", detail="Paquet trop grand pour l'interface locale")
            return PingResult("error", detail=" ".join(rep))

    def _pick():
        forced = os.environ.get("NETDIAG_ICMP", "")
        for cls, ok in ((_SocketPinger, _SocketPinger.available), (_MtrPinger, _MtrPacket.available),
                        (_CmdPinger, lambda: True)):
            if forced and forced not in cls.__name__.lower():
                continue
            if ok():
                return cls
        return _CmdPinger

    Pinger = _pick()


BACKEND = Pinger.backend
