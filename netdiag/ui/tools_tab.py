"""Onglet Outils : DNS, test de ports TCP, découverte du MTU de chemin."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QPushButton, QSpinBox, QVBoxLayout, QWidget)

from ..core import tools
from .common import run_async


class ToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        # DNS
        dns = QGroupBox("Résolution DNS")
        g = QGridLayout(dns)
        self.dns_name = QLineEdit(placeholderText="nom ou IP (pour PTR)")
        self.dns_type = QComboBox()
        self.dns_type.addItems(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA"])
        self.dns_server = QLineEdit(placeholderText="serveur (vide = système)")
        b = QPushButton("Résoudre")
        b.clicked.connect(self._dns)
        self.dns_name.returnPressed.connect(self._dns)
        bcmp = QPushButton("Comparer serveurs")
        bcmp.setToolTip("Interroge système, 8.8.8.8, 1.1.1.1 et 9.9.9.9 en parallèle")
        bcmp.clicked.connect(self._dns_compare)
        g.addWidget(self.dns_name, 0, 0, 1, 3)
        g.addWidget(self.dns_type, 1, 0)
        g.addWidget(self.dns_server, 1, 1)
        g.addWidget(b, 1, 2)
        g.addWidget(bcmp, 2, 2)

        # Ports
        ports = QGroupBox("Test de ports TCP")
        g = QGridLayout(ports)
        self.tcp_host = QLineEdit(placeholderText="hôte")
        self.tcp_ports = QLineEdit("22,53,80,443,3389", placeholderText="80,443,8000-8010")
        self.tcp_timeout = QSpinBox(minimum=200, maximum=20000, value=2000, singleStep=500, suffix=" ms")
        b = QPushButton("Tester")
        b.clicked.connect(self._tcp)
        self.tcp_host.returnPressed.connect(self._tcp)
        g.addWidget(self.tcp_host, 0, 0, 1, 3)
        g.addWidget(self.tcp_ports, 1, 0)
        g.addWidget(self.tcp_timeout, 1, 1)
        g.addWidget(b, 1, 2)

        # PMTU
        pmtu = QGroupBox("MTU du chemin (ping avec DF)")
        g = QGridLayout(pmtu)
        self.mtu_host = QLineEdit(placeholderText="hôte (doit répondre au ping)")
        self.mtu_max = QSpinBox(minimum=100, maximum=9216, value=1500, suffix=" o")
        self.mtu_max.setToolTip("MTU maximum testé (1500 Ethernet, 9000 jumbo)")
        b = QPushButton("Découvrir")
        b.clicked.connect(self._pmtu)
        self.mtu_host.returnPressed.connect(self._pmtu)
        g.addWidget(self.mtu_host, 0, 0, 1, 3)
        g.addWidget(QLabel("MTU max"), 1, 0)
        g.addWidget(self.mtu_max, 1, 1)
        g.addWidget(b, 1, 2)

        row = QHBoxLayout()
        for w in (dns, ports, pmtu):
            row.addWidget(w, 1)

        self.out = QPlainTextEdit(readOnly=True)
        self.out.setFont(QFont("Consolas", 10))
        clear = QPushButton("Effacer le journal")
        clear.clicked.connect(self.out.clear)
        lay = QVBoxLayout(self)
        lay.addLayout(row)
        lay.addWidget(self.out, 1)
        lay.addWidget(clear)

    def log(self, text: str):
        self.out.appendPlainText(text)

    def _done(self, res, err):
        self.log(f"Erreur : {err}" if err else (str(res) if res is not None else ""))
        self.log("")

    def _dns(self):
        name = self.dns_name.text().strip()
        if name:
            run_async(tools.dns_lookup, self._done, None, name, self.dns_type.currentText(), self.dns_server.text())

    def _dns_compare(self):
        name, rtype = self.dns_name.text().strip(), self.dns_type.currentText()
        if not name:
            return

        def job():
            with ThreadPoolExecutor(4) as p:
                return "\n".join(p.map(lambda s: tools.dns_lookup(name, rtype, s), ["", "8.8.8.8", "1.1.1.1", "9.9.9.9"]))
        run_async(job, self._done)

    def _tcp(self):
        host = self.tcp_host.text().strip()
        if not host:
            return
        try:
            ports = tools.parse_ports(self.tcp_ports.text())
        except ValueError as e:
            self.log(f"Ports invalides : {e}")
            return
        timeout = self.tcp_timeout.value() / 1000

        def job(log):
            log(f"[TCP] Test de {host} sur {len(ports)} port(s)…")
            with ThreadPoolExecutor(min(64, len(ports))) as p:
                for port, (state, ms, msg) in zip(ports, p.map(lambda pt: tools.tcp_check(host, pt, timeout), ports)):
                    log(f"  [TCP] {port:>5}/tcp  {state:<7} {ms:7.1f} ms  {msg}")
            return "Terminé."
        run_async(job, self._done, self.log)

    def _pmtu(self):
        host = self.mtu_host.text().strip()
        if host:
            run_async(tools.path_mtu, lambda r, e: self._done(None, e) if e else self.log(""),
                      lambda m: self.log(f"[MTU] {m}"),
                      host, max_mtu=self.mtu_max.value())
