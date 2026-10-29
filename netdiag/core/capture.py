"""Capture de paquets.

Windows : Scapy + Npcap (live) ; secours pktmon (natif, admin, sans affichage live, .pcapng à l'arrêt).
Linux   : trois méthodes, selon les droits disponibles :
  - « scapy »   : capture directe, si le processus a cap_net_raw (root) ;
  - « dumpcap » : moteur de capture de Wireshark (groupe wireshark), flux pcap lu en direct ;
  - « pkexec »  : tcpdump lancé via polkit par netdiag-capture-helper (mot de passe admin), flux pcap ;
  - « sudo »    : idem via sudo, pour la version terminal (le mot de passe est demandé dans le terminal).
Dans tous les cas Scapy sert au décodage et à l'export.
"""
from __future__ import annotations

import os
import queue
import shutil
import socket
import subprocess
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


@dataclass
class Method:
    key: str           # scapy | dumpcap | pkexec
    label: str
    hint: str


HELPER_INSTALLED = "/usr/lib/netdiag/netdiag-capture-helper"


def helper_path() -> str | None:
    """Aide de capture polkit : installée par le .deb, sinon celle du dépôt (lancement depuis les sources)."""
    repo = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "packaging", "linux", "netdiag-capture-helper")
    for p in (HELPER_INSTALLED, repo):
        if os.path.isfile(p):
            return p
    return None


def _can_capture_directly() -> bool:
    if IS_WINDOWS:
        return _scapy is not None
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()
        return True
    except (OSError, AttributeError):
        return False


def _dumpcap_usable() -> bool:
    path = shutil.which("dumpcap")
    if not path or not os.access(path, os.X_OK):
        return False
    if os.geteuid() == 0 or not shutil.which("getcap"):
        return True
    _, out, _ = run(["getcap", path])
    return "cap_net_raw" in out


def available_methods(terminal: bool = False) -> list[Method]:
    """terminal=True : version TUI, où sudo remplace pkexec (pas d'agent polkit graphique en SSH)."""
    if _scapy is None:
        return []
    if IS_WINDOWS:
        return [Method("scapy", "Directe (Npcap)", "Capture live via Npcap.")]
    methods = []
    if _can_capture_directly():
        methods.append(Method("scapy", "Directe", "Le processus a les droits de capture (root ou cap_net_raw)."))
    if _dumpcap_usable():
        methods.append(Method("dumpcap", "dumpcap (Wireshark)",
                              "Moteur de capture de Wireshark : aucun mot de passe si vous êtes dans le groupe wireshark."))
    if terminal:
        if shutil.which("tcpdump") and shutil.which("sudo") and helper_path():
            methods.append(Method("sudo", "tcpdump (sudo)",
                                  "tcpdump via sudo : votre mot de passe est demandé dans le terminal au démarrage."))
    elif shutil.which("tcpdump") and shutil.which("pkexec") and helper_path():
        methods.append(Method("pkexec", "tcpdump (mot de passe admin)",
                              "tcpdump est lancé via polkit : le mot de passe administrateur est demandé au démarrage."))
    return methods


def list_interfaces() -> list[Iface]:
    if _scapy is None:
        return []
    pinned = [] if IS_WINDOWS else [Iface("any", "any (toutes)")]
    out = []
    for i in _scapy.conf.ifaces.values():
        ip = getattr(i, "ip", "") or ""
        desc = getattr(i, "description", "") or i.name
        label = f"{desc} [{ip}]" if ip else desc
        if IS_WINDOWS and getattr(i, "name", "") and i.name != desc:
            label = f"{i.name} — {label}"
        out.append(Iface(i.name, label))
    return pinned + sorted(out, key=lambda x: (not x.label.endswith("]"), x.label.lower()))


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


_PKEXEC_ERRORS = {126: "Authentification annulée.", 127: "Authentification refusée ou non autorisée."}


class Capture:
    """Capture live : directe (AsyncSniffer) ou flux pcap d'un outil externe (dumpcap / tcpdump)."""
    MAX_PACKETS = 500_000

    def __init__(self):
        self.packets: list = []
        self.rows: "queue.Queue[PacketRow]" = queue.Queue()
        self.error = ""
        self.method = ""
        self._sniffer = None
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stopping = False
        self._limit = 0
        self._t0 = 0.0
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        if self._proc is not None:
            return bool(self._reader and self._reader.is_alive())
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

    def start(self, method: str, iface: str | None, bpf: str = "", limit: int = 0):
        self.packets.clear()
        self.error = ""
        self.method = method
        self._sniffer = self._proc = None
        self._stopping = False
        self._limit = limit
        self._t0 = time.time()
        if method == "scapy":
            self._start_direct(None if iface == "any" else iface, bpf, limit)
        else:
            self._start_stream(method, iface or "any", bpf, limit)

    def _start_direct(self, iface: str | None, bpf: str, limit: int):
        sc = _scapy
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

    def _start_stream(self, method: str, iface: str, bpf: str, limit: int):
        if method == "dumpcap":
            cmd = ["dumpcap", "-i", iface, "-q", "-F", "pcap", "-w", "-"]
            cmd += (["-f", bpf] if bpf else []) + (["-c", str(limit)] if limit else [])
        else:
            # pkexec (GUI) ou sudo -n (TUI, identifiants validés au préalable par « sudo -v »)
            launcher = ["pkexec"] if method == "pkexec" else ["sudo", "-n"]
            cmd = launcher + [helper_path(), iface, str(limit or 0)] + ([bpf] if bpf else [])
        self._proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._reader = threading.Thread(target=self._read_stream, args=(self._proc,), daemon=True,
                                        name=f"capture-{method}")
        self._reader.start()

    def _read_stream(self, proc: subprocess.Popen):
        exc = None
        try:
            for pkt in _scapy.PcapReader(proc.stdout):
                self._on_packet(pkt)
        except Exception as e:  # flux vide (authentification refusée, filtre invalide…) ou tronqué
            exc = e
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        err = proc.stderr.read().decode(errors="replace").strip()
        if self._stopping:
            return
        if proc.returncode in _PKEXEC_ERRORS and self.method == "pkexec":
            self.error = _PKEXEC_ERRORS[proc.returncode]
        elif proc.returncode not in (0, None) or (exc and not self.packets):
            lines = [l for l in err.splitlines() if not l.startswith(("listening on", "Capturing on"))]
            self.error = "\n".join(lines) or str(exc or f"code de sortie {proc.returncode}")

    def stop(self):
        self._stopping = True
        if self._proc is not None:
            if self.method in ("pkexec", "sudo"):
                # le processus root ne peut pas être tué par nous : l'aide arrête tcpdump à la fermeture de stdin
                try:
                    self._proc.stdin.close()
                except OSError:
                    pass
            else:
                self._proc.terminate()
            if self._reader:
                self._reader.join(timeout=5)
        elif self.running:
            try:
                self._sniffer.stop()
            except Exception as e:
                self.error = str(e)

    def _on_packet(self, pkt):
        with self._lock:
            if len(self.packets) >= self.MAX_PACKETS or (self._limit and len(self.packets) >= self._limit):
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
