"""Onglet Capture : capture live dans le terminal (directe, dumpcap ou tcpdump via sudo)."""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import urwid

from ..core import capture
from .base import Tab
from .widgets import Button, Cycle, DataTable, field

COLS = ["N°", "Temps (s)", "Source", "Destination", "Proto", "Long.", "Info"]
WIDTHS = [6, 10, 26, 26, 6, 6, 80]
PROTO_ATTR = {"TCP": "proto_tcp", "UDP": "proto_udp", "DNS": "proto_dns", "ICMP": "proto_icmp", "ARP": "proto_arp"}
MAX_ROWS = 20_000  # lignes affichées (les paquets restent tous en mémoire pour l'export)


class CaptureTab(Tab):
    title = "Capture"
    main_index = 2
    keys = [("Échap", "quitter le champ"), ("s", "start/stop"), ("Entrée", "détail paquet"), ("w", "enregistrer .pcap"), ("c", "effacer"),
            ("m", "méthode"), ("i", "interface")]

    def __init__(self, app):
        super().__init__(app)
        self.cap = capture.Capture()
        self.methods: list[capture.Method] = []
        self._pool = ThreadPoolExecutor(max_workers=1)
        self._loading = None
        self._t_start = 0.0
        self.method = Cycle("Méthode", [("chargement…", None)], on_change=lambda _v: self._hint())
        self.iface = Cycle("Interface", [("chargement…", None)])
        self.bpf, bpf_w = field("Filtre BPF")
        self.limit, limit_w = field("Limite", "0", integer=True)
        top = urwid.Columns([("given", 34, self.method), ("weight", 2, self.iface), ("weight", 3, bpf_w),
                             ("given", 16, limit_w), ("pack", Button("Démarrer/Arrêter", self.toggle)),
                             ("pack", Button("Enregistrer", self.save))], dividechars=1)
        self.table = DataTable(COLS)
        self.status = urwid.Text(("dim", "Chargement de Scapy…"))
        self.pile = urwid.Pile([("pack", top), ("pack", urwid.Divider()), ("weight", 1, self.table),
                                ("pack", self.status)])
        self.widget = urwid.Padding(self.pile, left=1, right=1)
        self._rows: list[list] = []
        self._row_attrs: list[str | None] = []

    def on_show(self):
        if self._loading is None and not self.methods:
            def load():
                ok, err = capture.load_scapy()
                return (capture.list_interfaces() if ok else []), capture.available_methods(terminal=True), err
            self._loading = self._pool.submit(load)

    def _hint(self):
        m = next((m for m in self.methods if m.key == self.method.value), None)
        if m:
            self.status.set_text(("dim", m.hint))

    # ------------------------------------------------------------------ capture
    def toggle(self):
        if self.cap.running:
            self.cap.stop()
            self.app.notify(f"Capture arrêtée — {len(self.cap.packets)} paquets.")
            return
        method = self.method.value
        if not method:
            self.app.notify("Aucune méthode de capture disponible.", "error")
            return
        if method == "sudo" and not self._sudo_auth():
            return
        try:
            limit = self.limit.value() or 0
        except (ValueError, TypeError):
            limit = 0
        self._clear()
        try:
            self.cap.start(method, self.iface.value, self.bpf.edit_text.strip(), limit)
        except Exception as e:  # noqa: BLE001  (filtre BPF invalide…)
            self.app.notify(str(e), "error")
            return
        self._t_start = time.time()
        self.pile.focus_position = 2

    def _sudo_auth(self) -> bool:
        """Valide les identifiants sudo dans le terminal (écran urwid suspendu le temps de la saisie)."""
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            return True
        screen = self.app.loop.screen
        screen.stop()
        try:
            print("\nNetDiag — la capture utilise tcpdump via sudo.")
            ok = subprocess.run(["sudo", "-v", "-p", "Mot de passe sudo pour %u : "]).returncode == 0
        finally:
            screen.start()
            self.app.loop.screen_size = None
            self.app.loop.draw_screen()
        if not ok:
            self.app.notify("Authentification sudo refusée.", "error")
        return ok

    def save(self):
        if not self.cap.packets:
            self.app.notify("Aucun paquet à enregistrer.", "error")
            return
        path = os.path.abspath(time.strftime("capture_%Y%m%d_%H%M%S.pcap"))
        self.cap.save(path)
        self.app.notify(f"{len(self.cap.packets)} paquets enregistrés : {path}")

    def _clear(self):
        if not self.cap.running:
            self.cap.packets.clear()
        self._rows, self._row_attrs = [], []
        self.table.set_rows([], widths=WIDTHS)

    def on_key(self, key):
        if key == "s":
            self.toggle()
        elif key == "w":
            self.save()
        elif key == "c":
            self._clear()
        elif key == "m":
            self.method.next()
        elif key == "i":
            self.iface.next()
        elif key == "enter" and self.pile.focus_position == 2:
            self._detail()
        elif key == "enter" and self.app.focused_edit() is not None:
            self.toggle()  # Entrée dans le filtre ou la limite = démarrer
        else:
            return False
        return True

    def _detail(self):
        i = self.table.focus_index
        if i is None:
            return
        no = int(self._rows[i][0])
        try:
            text = self.cap.detail(no - 1)
        except Exception as e:  # noqa: BLE001
            text = f"Erreur de décodage : {e}"
        self.app.popup(f"Paquet n° {no}", text)

    # ------------------------------------------------------------------ rafraîchissement
    def tick(self):
        if self._loading and self._loading.done():
            ifaces, self.methods, err = self._loading.result()
            self._loading = None
            self.iface.set_choices([(i.label, i.name) for i in ifaces])
            self.method.set_choices([(m.label, m.key) for m in self.methods])
            if err or not self.methods:
                hint = "" if shutil.which("tcpdump") else " (sudo apt install tcpdump)"
                self.status.set_text(("error", err or f"Aucune méthode de capture disponible{hint}."))
            else:
                self._hint()
        new = []
        try:
            while len(new) < 5000:
                new.append(self.cap.rows.get_nowait())
        except queue.Empty:
            pass
        if new:
            at_end = self.table.focus_index is None or self.table.focus_index >= len(self._rows) - 1
            for r in new:
                self._rows.append([str(r.no), f"{r.time:.6f}", r.src, r.dst, r.proto, str(r.length), r.info])
                self._row_attrs.append(PROTO_ATTR.get(r.proto))
            if len(self._rows) > MAX_ROWS:
                del self._rows[:-MAX_ROWS], self._row_attrs[:-MAX_ROWS]
            self.table.set_rows(self._rows, self._row_attrs, widths=WIDTHS)
            if at_end and self._rows:
                self.table.walker.set_focus(len(self._rows) - 1)
        if self.cap.running:
            n, el = len(self.cap.packets), time.time() - self._t_start
            if n == 0 and self.cap.method == "sudo":
                self.status.set_text(("info", "Capture démarrée, en attente de paquets…"))
            else:
                self.status.set_text(("ok", f"● capture — {n} paquets — {n / el if el else 0:.0f} pkt/s — {el:.0f} s"))
        elif self.cap.error:
            self.status.set_text(("error", f"Capture terminée : {self.cap.error}"))
        elif self.cap.method:
            self.status.set_text(("dim", f"■ capture arrêtée — {len(self.cap.packets)} paquets "
                                         "(w pour enregistrer, s pour relancer)"))

    def shutdown(self):
        self.cap.stop()
