"""Onglet Multi-Ping : plusieurs cibles pingées en parallèle sur un même graphe."""
from __future__ import annotations

import csv
import math
import time

import numpy as np
import pyqtgraph as pg
from .qt import Qt, QTimer
from .qt import QBrush
from .qt import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QPushButton, QSpinBox, QSplitter, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ..core.multiping import PingTarget
from ..core.stats import compute_stats
from .common import SERIES_COLORS, WindowCombo, fmt_ms, latency_color, loss_color, make_time_plot

COLS = ["", "Cible", "IP", "État", "Envoyés", "Perte %", "Cur", "Min", "Moy", "Max", "Jitter", "Dernier statut"]


class MultiPingTab(QWidget):
    def __init__(self):
        super().__init__()
        self.targets: list[PingTarget] = []
        self.curves: list[pg.PlotDataItem] = []
        self.loss_marks: list[pg.ScatterPlotItem] = []

        self.input = QLineEdit(placeholderText="Cibles séparées par des virgules : 8.8.8.8, 1.1.1.1, passerelle…")
        self.input.returnPressed.connect(self.add_targets)
        btn_add = QPushButton("+ Ajouter et démarrer")
        btn_add.setObjectName("primary")
        btn_add.clicked.connect(self.add_targets)
        btn_gw = QPushButton("+ Passerelle && DNS")
        btn_gw.setToolTip("Ajoute la passerelle par défaut et les serveurs DNS de la machine")
        btn_gw.clicked.connect(self._add_local)
        self.interval = QComboBox()
        for label, v in (("0,2 s", 0.2), ("0,5 s", 0.5), ("1 s", 1.0), ("2 s", 2.0), ("5 s", 5.0)):
            self.interval.addItem(label, v)
        self.interval.setCurrentIndex(2)
        self.size = QSpinBox(minimum=0, maximum=65000, value=32, suffix=" o")
        self.timeout = QSpinBox(minimum=100, maximum=10000, value=1000, singleStep=250, suffix=" ms")
        self.df = QCheckBox("DF (ne pas fragmenter)")
        self.window = WindowCombo("5 min")

        top = QHBoxLayout()
        top.addWidget(self.input, 1)
        top.addWidget(btn_add)
        top.addWidget(btn_gw)
        opts = QHBoxLayout()
        for label, w in (("Intervalle", self.interval), ("Taille", self.size), ("Délai", self.timeout)):
            opts.addWidget(QLabel(label))
            opts.addWidget(w)
        opts.addWidget(self.df)
        opts.addWidget(QLabel("Focus"))
        opts.addWidget(self.window)
        opts.addStretch(1)
        for text, slot in (("▶ Tout démarrer", self.start_all), ("■ Tout arrêter", self.stop_all),
                           ("Supprimer la sélection", self.remove_selected), ("Remettre à zéro", self.reset),
                           ("Exporter CSV…", self._export)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            opts.addWidget(b)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.table.horizontalHeader()
        for c in range(len(COLS)):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(len(COLS) - 1, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._highlight)

        self.plot = make_time_plot()
        self.legend = self.plot.addLegend(offset=(10, 10))

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.plot)
        split.setSizes([220, 450])

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(opts)
        lay.addWidget(split, 1)
        self.timer = QTimer(self, interval=500, timeout=self.refresh)
        self.timer.start()

    # ------------------------------------------------------------------ gestion des cibles
    def add_targets(self, hosts: list[str] | None = None):
        if not isinstance(hosts, list):
            hosts = [h.strip() for h in self.input.text().replace(";", ",").split(",") if h.strip()]
        for host in hosts:
            if any(t.host == host for t in self.targets):
                continue
            t = PingTarget(host, interval=self.interval.currentData(), size=self.size.value(),
                           timeout=self.timeout.value(), df=self.df.isChecked())
            color = SERIES_COLORS[len(self.targets) % len(SERIES_COLORS)]
            curve = self.plot.plot([], [], name=host, pen=pg.mkPen(color, width=1.5), connect="finite")
            marks = pg.ScatterPlotItem(symbol="t1", size=9, brush=color, pen=pg.mkPen("#ef5350"))
            self.plot.addItem(marks)
            self.targets.append(t)
            self.curves.append(curve)
            self.loss_marks.append(marks)
            t.start()
        self.input.clear()

    def _add_local(self):
        from ..core.utils import IS_WINDOWS, run, run_powershell
        from .common import run_async

        def find():
            hosts = []
            if IS_WINDOWS:
                _, out, _ = run_powershell(
                    "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric).NextHop;"
                    "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses")
                hosts = [l.strip() for l in out.splitlines()]
            else:
                _, out, _ = run(["ip", "route", "show", "default"])
                hosts = [l.split()[2] for l in out.splitlines() if len(l.split()) > 2]
                try:
                    with open("/etc/resolv.conf") as f:
                        hosts += [l.split()[1] for l in f if l.startswith("nameserver")]
                except OSError:
                    pass
            seen = []
            for h in hosts:
                if h and h not in seen and h not in ("0.0.0.0",) and ":" not in h:
                    seen.append(h)
            return seen

        run_async(find, lambda r, e: self.add_targets(r or []))

    def start_all(self):
        for t in self.targets:
            t.interval, t.size, t.timeout, t.df = (self.interval.currentData(), self.size.value(),
                                                   self.timeout.value(), self.df.isChecked())
            t.start()

    def stop_all(self):
        for t in self.targets:
            t.stop()

    def remove_selected(self):
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()}, reverse=True)
        for r in rows:
            self.targets[r].stop()
            self.plot.removeItem(self.curves[r])
            self.legend.removeItem(self.curves[r])
            self.plot.removeItem(self.loss_marks[r])
            del self.targets[r], self.curves[r], self.loss_marks[r]
        self.table.setRowCount(len(self.targets))

    def reset(self):
        for t in self.targets:
            t.series.clear()

    # ------------------------------------------------------------------ affichage
    def refresh(self):
        window = self.window.seconds()
        self.table.setRowCount(len(self.targets))
        now = time.time()
        ymax = 10.0
        for row, (t, curve, marks) in enumerate(zip(self.targets, self.curves, self.loss_marks)):
            data = t.series.snapshot(window)
            st = compute_stats(data)
            state = "erreur" if t.error else ("en cours" if t.running else "arrêté")
            vals = ["", t.host, t.ip or "", state, str(st.sent), f"{st.loss:.1f}" if st.sent else "-",
                    fmt_ms(st.cur), fmt_ms(st.min), fmt_ms(st.avg), fmt_ms(st.max), fmt_ms(st.jitter),
                    t.error or t.last_detail]
            for c, v in enumerate(vals):
                it = self.table.item(row, c)
                if it is None:
                    it = QTableWidgetItem()
                    self.table.setItem(row, c, it)
                it.setText(v)
            color = curve.opts["pen"].color()
            self.table.item(row, 0).setBackground(QBrush(color))
            lc = loss_color(st.loss)
            self.table.item(row, 5).setBackground(QBrush(lc) if lc else QBrush())
            self.table.item(row, 8).setForeground(QBrush(latency_color(st.avg)))
            if data:
                xs = np.array([d[0] for d in data], dtype=float)
                ys = np.array([d[1] if d[1] is not None else math.nan for d in data], dtype=float)
                curve.setData(xs, ys, connect="finite")
                lost = xs[~np.isfinite(ys)]
                marks.setData(lost, np.zeros(lost.size))   # triangle en bas = paquet perdu
                if st.max:
                    ymax = max(ymax, st.max * 1.15)
            else:
                curve.setData([], [])
                marks.setData([], [])
        if self.targets:
            first = min((t.series.snapshot(window)[:1] or [(now, None)])[0][0] for t in self.targets)
            self.plot.setXRange(max(now - window, first) if window else first, now + 1, padding=0)
            self.plot.setYRange(-ymax * 0.03, ymax, padding=0)

    def _highlight(self):
        sel = {i.row() for i in self.table.selectionModel().selectedRows()}
        for r, c in enumerate(self.curves):
            pen = pg.mkPen(c.opts["pen"].color(), width=3 if r in sel else (1 if sel else 1.5))
            c.setPen(pen)

    def _export(self):
        if not self.targets:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter les pings", "multiping.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Cible", "IP", "Horodatage", "RTT ms (vide = perte)"])
            for t in self.targets:
                for ts, rtt in t.series.snapshot():
                    w.writerow([t.host, t.ip or "", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                                "" if rtt is None else f"{rtt:.2f}"])

    def shutdown(self):
        self.stop_all()
