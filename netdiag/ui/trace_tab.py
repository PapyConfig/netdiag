"""Onglet « Trace » inspiré de PingPlotter : tableau des sauts + graphe temporel du saut choisi."""
from __future__ import annotations

import csv
import math
import time

import numpy as np
import pyqtgraph as pg
from .qt import Qt, QTimer
from .qt import QBrush, QColor
from .qt import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QPushButton, QSpinBox, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ..core.stats import compute_stats
from ..core.trace import TraceSession
from .common import LatencyBarDelegate, WindowCombo, fmt_ms, latency_color, loss_color, make_time_plot

COLS = ["Saut", "Perte %", "IP", "Nom d'hôte", "Moy", "Min", "Cur", "Max", "Jitter", "Envoyés", "Latence (ms)"]
C_HOP, C_LOSS, C_IP, C_NAME, C_AVG, C_MIN, C_CUR, C_MAX, C_JIT, C_SENT, C_BAR = range(len(COLS))


class TraceTab(QWidget):
    def __init__(self):
        super().__init__()
        self.session: TraceSession | None = None
        self.selected_ttl: int | None = None

        self.target = QLineEdit(placeholderText="Cible : 8.8.8.8, www.google.fr…")
        self.target.returnPressed.connect(self.toggle)
        self.interval = QComboBox()
        for label, v in (("0,5 s", 0.5), ("1 s", 1.0), ("2,5 s", 2.5), ("5 s", 5.0), ("10 s", 10.0),
                         ("30 s", 30.0), ("60 s", 60.0)):
            self.interval.addItem(label, v)
        self.interval.setCurrentIndex(2)
        self.size = QSpinBox(minimum=0, maximum=65000, value=32, suffix=" o")
        self.size.setToolTip("Taille de la charge ICMP (hors en-têtes IP/ICMP de 28 octets)")
        self.max_hops = QSpinBox(minimum=1, maximum=64, value=30)
        self.timeout = QSpinBox(minimum=200, maximum=10000, value=2000, singleStep=500, suffix=" ms")
        self.rdns = QCheckBox("Noms DNS", checked=True)
        self.window = WindowCombo("10 min")
        self.btn = QPushButton("▶ Démarrer")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(self.toggle)
        btn_export = QPushButton("Exporter CSV…")
        btn_export.clicked.connect(self._export)

        top = QHBoxLayout()
        top.addWidget(self.target, 1)
        for label, w in (("Intervalle", self.interval), ("Taille", self.size), ("Sauts max", self.max_hops),
                         ("Délai", self.timeout), ("Focus", self.window)):
            top.addWidget(QLabel(label))
            top.addWidget(w)
        top.addWidget(self.rdns)
        top.addWidget(self.btn)
        top.addWidget(btn_export)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setItemDelegateForColumn(C_BAR, LatencyBarDelegate(self.table))
        hh = self.table.horizontalHeader()
        for c in range(len(COLS)):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(C_NAME, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(C_BAR, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(C_NAME, 260)
        self.table.itemSelectionChanged.connect(self._on_select)

        self.plot = make_time_plot()
        self.curve = self.plot.plot([], [], pen=pg.mkPen("#4fc3f7", width=1.5), connect="finite",
                                    symbol="o", symbolSize=3, symbolBrush="#4fc3f7", symbolPen=None)
        self.loss_bars = pg.BarGraphItem(x=[0], height=[0], width=1, brush=QColor(239, 83, 80, 160), pen=None)
        self.loss_bars.setVisible(False)
        self.plot.addItem(self.loss_bars)
        self.avg_line = pg.InfiniteLine(angle=0, pen=pg.mkPen("#bbbbbb", width=1, style=Qt.PenStyle.DashLine),
                                        label="moy {value:.1f} ms", labelOpts={"position": 0.03, "color": "#bbb"})
        self.plot.addItem(self.avg_line)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.plot)
        split.setSizes([420, 300])

        self.status = QLabel("Saisissez une cible puis Démarrer. Barres : moyenne (couleur), "
                             "moustache min–max, point blanc = dernière valeur, liseré rouge = perte.")
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        lay.addWidget(self.status)

        self.timer = QTimer(self, interval=500, timeout=self.refresh)

    # ------------------------------------------------------------------ contrôle
    def toggle(self):
        if self.session and self.session.running:
            self.session.stop()
            self._set_running(False)
            return
        host = self.target.text().strip()
        if not host:
            return
        self.session = TraceSession(host, interval=self.interval.currentData(), max_hops=self.max_hops.value(),
                                    size=self.size.value(), timeout=self.timeout.value(),
                                    resolve_names=self.rdns.isChecked())
        self.selected_ttl = None
        self.table.setRowCount(0)
        self.session.start()
        self._set_running(True)
        self.timer.start()

    def _set_running(self, running: bool):
        self.btn.setText("■ Arrêter" if running else "▶ Démarrer")
        self.btn.setObjectName("danger" if running else "primary")
        self.btn.setStyle(self.btn.style())

    def stop(self):
        if self.session:
            self.session.stop()

    # ------------------------------------------------------------------ rafraîchissement
    def refresh(self):
        s = self.session
        if not s:
            return
        if s.error:
            self.status.setText(s.error)
            self._set_running(False)
            self.timer.stop()
            return
        if not s.running and self.btn.text().startswith("■"):
            self._set_running(False)
        window = self.window.seconds()
        hops = s.hops()
        stats = [compute_stats(h.series.snapshot(window)) for h in hops]
        scale = max([st.max for st in stats if st.max is not None] or [0])
        scale = max(10.0, _nice_ceil(scale))

        self.table.setRowCount(len(hops))
        for row, (h, st) in enumerate(zip(hops, stats)):
            is_dest = s.dest_ttl == h.ttl
            ip = h.ip or "*"
            if len(h.ips) > 1:
                ip += f"  (+{len(h.ips) - 1})"
            values = [str(h.ttl), f"{st.loss:.1f}" if st.sent else "-", ip, h.hostname,
                      fmt_ms(st.avg), fmt_ms(st.min), fmt_ms(st.cur), fmt_ms(st.max), fmt_ms(st.jitter),
                      str(st.sent), ""]
            for c, v in enumerate(values):
                it = self.table.item(row, c)
                if it is None:
                    it = QTableWidgetItem()
                    self.table.setItem(row, c, it)
                it.setText(v)
                if c in (C_HOP, C_LOSS, C_AVG, C_MIN, C_CUR, C_MAX, C_JIT, C_SENT):
                    it.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lc = loss_color(st.loss)
            self.table.item(row, C_LOSS).setBackground(QBrush(lc) if lc else QBrush())
            self.table.item(row, C_AVG).setForeground(QBrush(latency_color(st.avg)))
            if len(h.ips) > 1:
                self.table.item(row, C_IP).setToolTip("Plusieurs routeurs ont répondu à ce saut :\n" +
                                                      "\n".join(sorted(h.ips)))
            f = self.table.item(row, C_HOP).font()
            f.setBold(is_dest)
            for c in (C_HOP, C_IP, C_NAME):
                self.table.item(row, c).setFont(f)
            self.table.item(row, C_BAR).setData(Qt.ItemDataRole.UserRole, {
                "min": st.min, "avg": st.avg, "max": st.max, "cur": st.cur, "loss": st.loss, "scale": scale})

        # sélection par défaut : la destination (ou le dernier saut)
        if hops and (self.selected_ttl is None or self.selected_ttl > len(hops)):
            target_row = (s.dest_ttl or len(hops)) - 1
            self.table.blockSignals(True)
            self.table.selectRow(target_row)
            self.table.blockSignals(False)
        self._update_plot(hops, window, s.interval)

        elapsed = time.time() - (s.started_at or time.time())
        where = (f"destination {s.target_ip} atteinte en {s.dest_ttl} sauts" if s.dest_ttl
                 else f"destination {s.target_ip or s.target} non atteinte (≤ {s.max_hops} sauts)")
        self.status.setText(f"{'En cours' if s.running else 'Arrêté'} — {where} — {s.cycles} cycles, "
                            f"{int(elapsed // 60)} min {int(elapsed % 60)} s — échelle barres 0–{scale:.0f} ms")

    def _on_select(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.selected_ttl = rows[0].row() + 1
            if self.session:
                self._update_plot(self.session.hops(), self.window.seconds(), self.session.interval)

    def _update_plot(self, hops, window, interval):
        rows = self.table.selectionModel().selectedRows()
        idx = rows[0].row() if rows else (len(hops) - 1)
        if not hops or idx >= len(hops):
            return
        hop = hops[idx]
        data = hop.series.snapshot(window)
        title = f"Saut {hop.ttl} — {hop.ip or '*'} {hop.hostname}"
        self.plot.setTitle(title, color="#d4d4d4", size="10pt")
        if not data:
            self.curve.setData([], [])
            self.loss_bars.setVisible(False)
            return
        xs = np.array([t for t, _ in data], dtype=float)
        ys = np.array([r if r is not None else math.nan for _, r in data], dtype=float)
        self.curve.setData(xs, ys, connect="finite")
        finite = ys[np.isfinite(ys)]
        ymax = float(finite.max()) * 1.15 if finite.size else 100.0
        lost = xs[~np.isfinite(ys)]
        if lost.size:
            self.loss_bars.setOpts(x=lost, height=np.full(lost.size, ymax), width=interval * 0.7)
            self.loss_bars.setVisible(True)
        else:
            self.loss_bars.setVisible(False)
        if finite.size:
            self.avg_line.setValue(float(finite.mean()))
            self.avg_line.setVisible(True)
        else:
            self.avg_line.setVisible(False)
        now = time.time()
        start = max(now - window, xs[0]) if window else xs[0]
        self.plot.setXRange(start, now + interval, padding=0)
        self.plot.setYRange(0, max(ymax, 10), padding=0)

    def _export(self):
        if not self.session:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter la trace", "trace.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(COLS[:-1])
            for r in range(self.table.rowCount()):
                w.writerow([self.table.item(r, c).text() for c in range(len(COLS) - 1)])
            w.writerow([])
            w.writerow(["Saut", "IP", "Horodatage", "RTT ms (vide = perte)"])
            for h in self.session.hops():
                for t, rtt in h.series.snapshot():
                    w.writerow([h.ttl, h.ip or "", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)),
                                "" if rtt is None else f"{rtt:.2f}"])
        self.status.setText(f"Trace exportée : {path}")


def _nice_ceil(v: float) -> float:
    if v <= 0:
        return 0
    mag = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag
