"""Onglet Capture : capture live (Scapy + Npcap) ou pktmon natif."""
from __future__ import annotations

import queue
import subprocess
import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter, QTableView,
                               QVBoxLayout, QWidget)

from ..core import capture
from ..core.utils import is_admin
from .common import run_async

PROTO_COLORS = {"TCP": "#2a3b4d", "UDP": "#2d3a2a", "DNS": "#3d3350", "ICMP": "#4d3a22", "ARP": "#4a4a26"}
HEADERS = ["N°", "Temps (s)", "Source", "Destination", "Proto", "Long.", "Info"]


class PacketModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.rows: list[capture.PacketRow] = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        r = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return (r.no, f"{r.time:.6f}", r.src, r.dst, r.proto, r.length, r.info)[index.column()]
        if role == Qt.BackgroundRole:
            c = PROTO_COLORS.get(r.proto)
            return QColor(c) if c else None
        return None

    def append(self, rows):
        if not rows:
            return
        n = len(self.rows)
        self.beginInsertRows(QModelIndex(), n, n + len(rows) - 1)
        self.rows.extend(rows)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.rows.clear()
        self.endResetModel()


class CaptureTab(QWidget):
    def __init__(self):
        super().__init__()
        self.cap = capture.ScapyCapture()
        self.pktmon = capture.PktmonCapture()
        self.ifaces: list[capture.Iface] = []
        self.loaded = False

        # --- Scapy / Npcap
        self.iface = QComboBox()
        self.iface.setMinimumWidth(380)
        self.bpf = QLineEdit(placeholderText="Filtre BPF : icmp, port 53, host 10.0.0.1 and tcp…")
        self.limit = QSpinBox(minimum=0, maximum=10_000_000, value=0, specialValueText="illimité")
        self.limit.setToolTip("Nombre max de paquets (0 = illimité)")
        self.btn = QPushButton("▶ Capturer")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(self.toggle)
        self.btn.setEnabled(False)
        self.btn_save = QPushButton("Enregistrer .pcap…")
        self.btn_save.clicked.connect(self._save)
        self.btn_ws = QPushButton("Ouvrir dans Wireshark")
        self.btn_ws.clicked.connect(self._open_wireshark)
        self.btn_ws.setEnabled(capture.wireshark_path() is not None)
        btn_clear = QPushButton("Effacer")
        btn_clear.clicked.connect(self._clear)
        self.autoscroll = True

        top = QHBoxLayout()
        top.addWidget(QLabel("Interface"))
        top.addWidget(self.iface)
        top.addWidget(self.bpf, 1)
        top.addWidget(QLabel("Limite"))
        top.addWidget(self.limit)
        for w in (self.btn, self.btn_save, self.btn_ws, btn_clear):
            top.addWidget(w)

        self.model = PacketModel()
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(20)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setSelectionMode(QTableView.SingleSelection)
        hh = self.view.horizontalHeader()
        for c, w in enumerate((60, 100, 230, 230, 60, 60)):
            self.view.setColumnWidth(c, w)
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(QHeaderView.Interactive)
        self.view.selectionModel().selectionChanged.connect(self._on_select)
        self.view.verticalScrollBar().valueChanged.connect(self._on_scroll)

        self.detail = QPlainTextEdit(readOnly=True)
        self.detail.setFont(QFont("Consolas", 9))
        self.detail.setLineWrapMode(QPlainTextEdit.NoWrap)
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.view)
        split.addWidget(self.detail)
        split.setSizes([500, 220])

        # --- pktmon
        box = QGroupBox("Alternative sans Npcap : pktmon (natif Windows 10 2004+, admin requis, pas d'affichage live)")
        bl = QHBoxLayout(box)
        self.btn_pm_start = QPushButton("▶ Démarrer pktmon")
        self.btn_pm_start.clicked.connect(self._pktmon_start)
        self.btn_pm_stop = QPushButton("■ Arrêter et convertir en .pcapng…")
        self.btn_pm_stop.clicked.connect(self._pktmon_stop)
        self.btn_pm_stop.setEnabled(False)
        bl.addWidget(self.btn_pm_start)
        bl.addWidget(self.btn_pm_stop)
        bl.addStretch(1)
        if not is_admin():
            bl.addWidget(QLabel("⚠ Relancez NetDiag en administrateur pour pktmon."))

        self.status = QLabel("Chargement de Scapy…")
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        lay.addWidget(box)
        lay.addWidget(self.status)

        self.timer = QTimer(self, interval=300, timeout=self._drain)

    # ------------------------------------------------------------------ init paresseuse
    def ensure_loaded(self):
        if self.loaded:
            return
        self.loaded = True

        def load():
            ok, err = capture.load_scapy()
            return (capture.list_interfaces() if ok else []), err

        run_async(load, self._on_loaded)

    def _on_loaded(self, res, err):
        ifaces, msg = res or ([], str(err))
        self.ifaces = ifaces
        self.iface.clear()
        for i in ifaces:
            self.iface.addItem(i.label, i.name)
        self.btn.setEnabled(bool(ifaces))
        self.status.setText(msg or f"{len(ifaces)} interfaces disponibles. "
                                   "La capture live nécessite Npcap (et souvent les droits admin).")
        if msg:
            self.status.setStyleSheet("color:#ffca28")

    # ------------------------------------------------------------------ capture scapy
    def toggle(self):
        if self.cap.running:
            self.cap.stop()
            self._drain()
            self.timer.stop()
            self._set_btn(False)
            self.status.setText(f"Capture arrêtée — {len(self.cap.packets)} paquets.")
            return
        self._clear()
        try:
            self.cap.start(self.iface.currentData(), self.bpf.text().strip(), self.limit.value())
        except Exception as e:
            QMessageBox.warning(self, "Capture", str(e))
            return
        self._t_start = time.time()
        self._set_btn(True)
        self.timer.start()

    def _set_btn(self, running: bool):
        self.btn.setText("■ Arrêter" if running else "▶ Capturer")
        self.btn.setObjectName("danger" if running else "primary")
        self.btn.setStyle(self.btn.style())

    def _drain(self):
        batch = []
        try:
            while len(batch) < 5000:
                batch.append(self.cap.rows.get_nowait())
        except queue.Empty:
            pass
        self.model.append(batch)
        if batch and self.autoscroll:
            self.view.scrollToBottom()
        if self.cap.running:
            el = time.time() - self._t_start
            n = len(self.cap.packets)
            self.status.setText(f"Capture en cours — {n} paquets — {n / el if el else 0:.0f} pkt/s — {el:.0f} s")
        elif self.timer.isActive():
            self.timer.stop()
            self._set_btn(False)
            self.status.setText(f"Capture terminée — {len(self.cap.packets)} paquets. {self.cap.error}")

    def _on_scroll(self, value):
        sb = self.view.verticalScrollBar()
        self.autoscroll = value >= sb.maximum() - 2

    def _on_select(self):
        rows = self.view.selectionModel().selectedRows()
        if rows:
            try:
                self.detail.setPlainText(self.cap.detail(rows[0].row()))
            except Exception as e:
                self.detail.setPlainText(f"Erreur de décodage : {e}")

    def _clear(self):
        if not self.cap.running:
            self.cap.packets.clear()
        self.model.clear()
        self.detail.clear()

    def _save(self) -> str | None:
        if not self.cap.packets:
            QMessageBox.information(self, "Capture", "Aucun paquet à enregistrer.")
            return None
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer la capture",
                                              time.strftime("capture_%Y%m%d_%H%M%S.pcap"), "PCAP (*.pcap)")
        if path:
            self.cap.save(path)
            self.status.setText(f"{len(self.cap.packets)} paquets enregistrés dans {path}")
        return path or None

    def _open_wireshark(self):
        path = self._save()
        if path:
            subprocess.Popen([capture.wireshark_path(), path])

    # ------------------------------------------------------------------ pktmon
    def _pktmon_start(self):
        def done(res, err):
            if err:
                QMessageBox.warning(self, "pktmon", str(err))
                return
            self.btn_pm_start.setEnabled(False)
            self.btn_pm_stop.setEnabled(True)
            self.status.setText("pktmon capture en cours (toutes interfaces)…")
        run_async(self.pktmon.start, done)

    def _pktmon_stop(self):
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer la capture pktmon",
                                              time.strftime("pktmon_%Y%m%d_%H%M%S.pcapng"), "PCAPNG (*.pcapng)")
        if not path:
            return
        self.status.setText("Arrêt de pktmon et conversion…")

        def done(res, err):
            self.btn_pm_start.setEnabled(True)
            self.btn_pm_stop.setEnabled(False)
            if err:
                QMessageBox.warning(self, "pktmon", str(err))
            else:
                self.status.setText(f"Capture pktmon convertie : {path}")
                if capture.wireshark_path() and QMessageBox.question(
                        self, "pktmon", "Ouvrir la capture dans Wireshark ?") == QMessageBox.Yes:
                    subprocess.Popen([capture.wireshark_path(), path])
        run_async(self.pktmon.stop, done, None, path)

    def shutdown(self):
        self.cap.stop()
        if self.pktmon.running:
            capture.run(["pktmon", "stop"])
