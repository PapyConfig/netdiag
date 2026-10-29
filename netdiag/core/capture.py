"""Capture de paquets.

Mode principal : Scapy + Npcap (live, filtre BPF, export .pcap).
Mode secours : pktmon, intégré à Windows 10 2004+ (admin requis, sans affichage live),
converti en .pcapng à l'arrêt.
"""
from __future__ import annotations

import os
import queue
import tempfile
import threading
import time
from dataclasses import dataclass

from .utils import IS_WINDOWS, run

_scapy = None
_scapy_error = ""


def load_scapy() -> tuple[bool, str]:
    """Import paresseux (scapy met 1 à 3 s à se charger)."""
    global _scapy, _scapy_error
    if _scapy is not None:
        return True, ""
    try:
        import scapy.all as sc
        sc.conf.verb = 0
        if IS_WINDOWS and not sc.conf.use_pcap:
            _scapy_error = ("Npcap n'est pas installé : capture live indisponible. "
                            "Installez Npcap (https://npcap.com) ou utilisez pktmon ci-dessous.")
            return False, _scapy_error
        _scapy = sc
        return True, ""
    except Exception as e:  # ImportError, OSError…
        _scapy_error = f"Scapy indisponible : {e}"
        return False, _scapy_error


@dataclass
class Iface:
    name: str          # identifiant passé à scapy
    label: str         # texte affiché


def list_interfaces() -> list[Iface]:
    if _scapy is None:
        return []
    out = []
    for i in _scapy.conf.ifaces.values():
        ip = getattr(i, "ip", "") or ""
        desc = getattr(i, "description", "") or i.name
        label = f"{desc}  [{ip}]" if ip else desc
        if IS_WINDOWS and getattr(i, "name", "") and i.name != desc:
            label = f"{i.name} — {label}"
        out.append(Iface(i.name, label))
    return sorted(out, key=lambda x: (not x.label.endswith("]"), x.label.lower()))


@dataclass
class PacketRow:
    no: int
    time: float
    src: str
    dst: str
    proto: str
    length: int
    info: str


def summarize(pkt, no: int, t0: float) -> PacketRow:
    sc = _scapy
    src = dst = ""
    proto = pkt.lastlayer().name
    info = ""
    if pkt.haslayer(sc.IP):
        src, dst = pkt[sc.IP].src, pkt[sc.IP].dst
    elif pkt.haslayer(sc.IPv6):
        src, dst = pkt[sc.IPv6].src, pkt[sc.IPv6].dst
    elif pkt.haslayer(sc.ARP):
        a = pkt[sc.ARP]
        src, dst, proto = a.psrc, a.pdst, "ARP"
        info = f"Qui a {a.pdst} ? Dites {a.psrc}" if a.op == 1 else f"{a.psrc} est à {a.hwsrc}"
    elif pkt.haslayer(sc.Ether):
        src, dst = pkt[sc.Ether].src, pkt[sc.Ether].dst
    if pkt.haslayer(sc.DNS):
        d = pkt[sc.DNS]
        proto = "DNS"
        try:
            q = d.qd.qname.decode(errors="replace") if d.qd else ""
        except Exception:
            q = ""
        info = f"{'Réponse' if d.qr else 'Requête'} {q} (id {d.id}, {d.ancount or 0} rép.)"
    elif pkt.haslayer(sc.TCP):
        t = pkt[sc.TCP]
        proto = "TCP" if proto in ("TCP", "Raw", "Padding") else proto
        info = f"{t.sport} → {t.dport} [{t.flags}] seq={t.seq} win={t.window}"
    elif pkt.haslayer(sc.UDP):
        u = pkt[sc.UDP]
        proto = "UDP" if proto in ("UDP", "Raw", "Padding") else proto
        info = f"{u.sport} → {u.dport} len={u.len}"
    elif pkt.haslayer(sc.ICMP):
        i = pkt[sc.ICMP]
        proto = "ICMP"
        info = {0: "Echo reply", 3: "Destination injoignable", 8: "Echo request",
                11: "TTL dépassé"}.get(i.type, f"type {i.type}") + f" code {i.code}"
    if not info:
        info = pkt.summary()
    return PacketRow(no, float(pkt.time) - t0, src, dst, proto, len(pkt), info)


class ScapyCapture:
    MAX_PACKETS = 500_000

    def __init__(self):
        self.packets: list = []
        self.rows: "queue.Queue[PacketRow]" = queue.Queue()
        self.error = ""
        self._sniffer = None
        self._t0 = 0.0
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        s = self._sniffer
        if not s or not s.running:
            return False
        if s.thread is not None and not s.thread.is_alive():
            # le thread de capture est mort (droits insuffisants, interface disparue…)
            exc = getattr(s, "exception", None)
            if exc and not self.error:
                self.error = f"Capture interrompue : {exc}"
            return False
        return True

    def start(self, iface: str | None, bpf: str = "", limit: int = 0):
        sc = _scapy
        self.packets.clear()
        self.error = ""
        self._t0 = time.time()
        # compile le filtre avant de lancer pour remonter l'erreur proprement
        if bpf:
            try:
                from scapy.arch.common import compile_filter
                compile_filter(bpf, iface=iface)
            except Exception as e:
                raise ValueError(f"Filtre BPF invalide : {e}") from e
        self._sniffer = sc.AsyncSniffer(iface=iface or None, filter=bpf or None, prn=self._on_packet,
                                        store=False, count=limit or 0)
        self._sniffer.start()

    def stop(self):
        if self.running:
            try:
                self._sniffer.stop()
            except Exception as e:
                self.error = str(e)

    def _on_packet(self, pkt):
        with self._lock:
            if len(self.packets) >= self.MAX_PACKETS:
                return
            self.packets.append(pkt)
            no = len(self.packets)
        try:
            self.rows.put(summarize(pkt, no, self._t0))
        except Exception as e:
            self.rows.put(PacketRow(no, time.time() - self._t0, "", "", "?", len(pkt), f"(erreur décodage: {e})"))

    def save(self, path: str):
        with self._lock:
            _scapy.wrpcap(path, self.packets)

    def detail(self, index: int) -> str:
        with self._lock:
            pkt = self.packets[index]
        return pkt.show(dump=True) + "\n" + _scapy.hexdump(pkt, dump=True)


class PktmonCapture:
    """Capture via pktmon (Windows natif). Nécessite les droits administrateur."""

    def __init__(self):
        self.etl = os.path.join(tempfile.gettempdir(), "netdiag_pktmon.etl")
        self.running = False

    def start(self) -> str:
        run(["pktmon", "stop"])
        run(["pktmon", "filter", "remove"])
        code, out, err = run(["pktmon", "start", "--capture", "--pkt-size", "0", "--file-name", self.etl])
        if code != 0:
            raise RuntimeError((out + err).strip() or "pktmon a échoué (droits administrateur ?)")
        self.running = True
        return out.strip()

    def stop(self, pcapng_path: str) -> str:
        code, out, err = run(["pktmon", "stop"], timeout=120)
        self.running = False
        log = (out + err).strip()
        code, out, err = run(["pktmon", "etl2pcap", self.etl, "--out", pcapng_path], timeout=300)
        if code != 0:
            raise RuntimeError(log + "\n" + (out + err).strip())
        return log + "\n" + out.strip()


def wireshark_path() -> str | None:
    if not IS_WINDOWS:
        from shutil import which
        return which("wireshark")
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        p = os.path.join(base, "Wireshark", "Wireshark.exe")
        if os.path.exists(p):
            return p
    return None
