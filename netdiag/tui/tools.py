"""Onglet Outils : DNS, ports TCP, MTU du chemin."""
from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor

import urwid

from ..core import tools
from .base import Tab
from .widgets import Button, Cycle, field

DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA"]


class ToolsTab(Tab):
    title = "Outils"
    keys = [("Tab", "champ suivant"), ("Entrée", "lancer"), ("x", "effacer le journal")]

    def __init__(self, app):
        super().__init__(app)
        self._log: "queue.Queue[str]" = queue.Queue()
        self.dns_name, dns_name_w = field("Nom / IP")
        self.dns_type = Cycle("Type", [(t, t) for t in DNS_TYPES])
        self.dns_server, dns_server_w = field("Serveur", "")
        dns = urwid.LineBox(urwid.Pile([dns_name_w, urwid.Columns([("given", self.dns_type.width, self.dns_type), dns_server_w],
                                                                  dividechars=1),
                                        urwid.Columns([Button("Résoudre", self._dns),
                                                       Button("Comparer serveurs", self._dns_compare)],
                                                      dividechars=1)]), title="Résolution DNS")
        self.tcp_host, tcp_host_w = field("Hôte")
        self.tcp_ports, tcp_ports_w = field("Ports", "22,53,80,443,3389")
        ports = urwid.LineBox(urwid.Pile([tcp_host_w, tcp_ports_w, Button("Tester", self._tcp)]),
                              title="Ports TCP")
        self.mtu_host, mtu_host_w = field("Hôte")
        self.mtu_max, mtu_max_w = field("MTU max", "1500", integer=True)
        mtu = urwid.LineBox(urwid.Pile([mtu_host_w, mtu_max_w, Button("Découvrir", self._pmtu)]),
                            title="MTU du chemin (DF)")
        self.forms = urwid.Columns([dns, ports, mtu], dividechars=1)
        self.walker = urwid.SimpleFocusListWalker([])
        self.out = urwid.ListBox(self.walker)
        self.pile = urwid.Pile([("pack", self.forms), ("weight", 1, urwid.LineBox(self.out, title="Journal"))])
        self.widget = urwid.Padding(self.pile, left=1, right=1)
        # Entrée dans un champ = lancer l'outil correspondant
        self._enter = {id(self.dns_name): self._dns, id(self.dns_server): self._dns,
                       id(self.tcp_host): self._tcp, id(self.tcp_ports): self._tcp,
                       id(self.mtu_host): self._pmtu, id(self.mtu_max): self._pmtu}

    def log(self, line: str):
        self._log.put(line)

    def _bg(self, fn, prefix: str):
        def run():
            try:
                res = fn()
                if res:
                    for line in str(res).splitlines():
                        self.log(f"{prefix}{line}")
            except Exception as e:  # noqa: BLE001
                self.log(f"{prefix}Erreur : {e}")
            self.log("")
        threading.Thread(target=run, daemon=True).start()

    def _dns(self):
        name = self.dns_name.edit_text.strip()
        if name:
            self._bg(lambda: tools.dns_lookup(name, self.dns_type.value, self.dns_server.edit_text), "[DNS] ")

    def _dns_compare(self):
        name, rtype = self.dns_name.edit_text.strip(), self.dns_type.value
        if not name:
            return

        def job():
            with ThreadPoolExecutor(4) as p:
                return "\n".join(p.map(lambda s: tools.dns_lookup(name, rtype, s), ["", "8.8.8.8", "1.1.1.1", "9.9.9.9"]))
        self._bg(job, "[DNS] ")

    def _tcp(self):
        host = self.tcp_host.edit_text.strip()
        if not host:
            return
        try:
            ports = tools.parse_ports(self.tcp_ports.edit_text)
        except ValueError as e:
            self.log(f"[TCP] Ports invalides : {e}")
            return

        def job():
            self.log(f"[TCP] Test de {host} sur {len(ports)} port(s)…")
            with ThreadPoolExecutor(min(64, len(ports))) as p:
                for port, (state, ms, msg) in zip(ports, p.map(lambda pt: tools.tcp_check(host, pt, 2.0), ports)):
                    self.log(f"[TCP] {port:>5}/tcp  {state:<7} {ms:7.1f} ms  {msg}")
            return "Terminé."
        self._bg(job, "[TCP] ")

    def _pmtu(self):
        host = self.mtu_host.edit_text.strip()
        try:
            max_mtu = self.mtu_max.value() or 1500
        except (ValueError, TypeError):
            max_mtu = 1500
        if host:
            self._bg(lambda: tools.path_mtu(host, lambda m: self.log(f"[MTU] {m}"), max_mtu=max_mtu) and None,
                     "[MTU] ")

    def on_key(self, key):
        if key == "enter":
            focus = self.app.focused_edit()
            fn = self._enter.get(id(focus)) if focus else None
            if fn:
                fn()
                return True
        if key == "x" and self.app.focused_edit() is None:
            self.walker[:] = []
            return True
        return False

    def tick(self):
        lines = []
        try:
            while True:
                lines.append(self._log.get_nowait())
        except queue.Empty:
            pass
        if lines:
            attr = lambda l: ("error" if "Erreur" in l or "ERREUR" in l else
                              "ok" if "OUVERT" in l or "MTU du chemin" in l else None)
            self.walker.extend(urwid.Text((attr(l), l) if attr(l) else l, wrap="any") for l in lines)
            self.walker.set_focus(len(self.walker) - 1)
