"""Onglet Multi-Ping : plusieurs cibles en parallèle."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import urwid

from ..core import export
from ..core.multiping import PingTarget, local_targets
from ..core.stats import compute_stats
from .base import WINDOWS, Tab
from .trace import fill_width
from .widgets import Button, Chart, Cycle, DataTable, fmt_ms, field, lat_attr, loss_attr, nice_ceil, sparkline

COLS = ["Cible", "IP", "État", "Env", "Perte%", "Cur", "Min", "Moy", "Max", "Jit", "Dernier statut", "Historique"]
INTERVALS = [("0,2 s", 0.2), ("0,5 s", 0.5), ("1 s", 1.0), ("2 s", 2.0), ("5 s", 5.0)]


class MultiPingTab(Tab):
    title = "Multi-Ping"
    main_index = 2
    keys = [("Entrée", "ajouter"), ("g", "passerelle+DNS"), ("s", "start/stop"), ("d", "supprimer"),
            ("r", "remise à zéro"), ("f", "focus"), ("e", "export CSV")]

    def __init__(self, app, hosts: list[str] | None = None, interval: float = 1.0):
        super().__init__(app)
        self.targets: list[PingTarget] = []
        self._pool = ThreadPoolExecutor(max_workers=1)
        self._pending_local = None
        self.input, input_w = field("Cibles (séparées par des virgules)")
        idx = next((i for i, (_, v) in enumerate(INTERVALS) if v == interval), 2)
        self.interval = Cycle("Intervalle", INTERVALS, idx)
        self.window = Cycle("Focus", WINDOWS, 1)
        top = urwid.Columns([("weight", 3, input_w), ("pack", Button("Ajouter", self.add_from_input)),
                             ("pack", Button("Passerelle & DNS", self.add_local)),
                             ("given", self.interval.width, self.interval), ("given", self.window.width, self.window)], dividechars=1)
        self.table = DataTable(COLS)
        urwid.connect_signal(self.table, "select", lambda _i: self._update_chart())
        self.chart = Chart()
        self.status = urwid.Text(("dim", "Ajoutez des cibles (Entrée) ou « g » pour la passerelle et les DNS."))
        self.pile = urwid.Pile([("pack", top), ("pack", urwid.Divider()), ("weight", 1, self.table),
                                ("given", 14, self.chart), ("pack", self.status)])
        self.widget = urwid.Padding(self.pile, left=1, right=1)
        if hosts:
            self.add(hosts)

    def add(self, hosts: list[str]):
        for h in hosts:
            h = h.strip()
            if h and not any(t.host == h for t in self.targets):
                t = PingTarget(h, interval=self.interval.value)
                self.targets.append(t)
                t.start()
        if self.targets:
            self.pile.focus_position = 2

    def add_from_input(self):
        self.add(self.input.edit_text.replace(";", ",").split(","))
        self.input.set_edit_text("")

    def add_local(self):
        self._pending_local = self._pool.submit(local_targets)
        self.app.notify("Recherche de la passerelle et des serveurs DNS…")

    def on_key(self, key):
        if key == "enter" and self.pile.focus_position == 0:
            self.add_from_input()
        elif key == "g":
            self.add_local()
        elif key == "s":
            running = any(t.running for t in self.targets)
            for t in self.targets:
                if running:
                    t.stop()
                else:
                    t.interval = self.interval.value
                    t.start()
        elif key in ("d", "delete"):
            i = self.table.focus_index
            if i is not None and i < len(self.targets):
                self.targets.pop(i).stop()
        elif key == "r":
            for t in self.targets:
                t.series.clear()
        elif key == "f":
            self.window.next()
        elif key == "e":
            if self.targets:
                path = os.path.abspath(time.strftime("multiping_%Y%m%d_%H%M%S.csv"))
                export.multiping_csv(self.targets, path)
                self.app.notify(f"Export : {path}")
        else:
            return False
        return True

    def tick(self):
        if self._pending_local and self._pending_local.done():
            hosts = self._pending_local.result()
            self._pending_local = None
            self.add(hosts)
            self.app.notify(f"Ajouté : {', '.join(hosts) or 'rien trouvé'}")
        window = self.window.value
        snaps = [t.series.snapshot(window) for t in self.targets]
        stats = [compute_stats(d) for d in snaps]
        scale = max(10.0, nice_ceil(max([st.max for st in stats if st.max is not None] or [0.0])))
        host_w = min(28, max([6] + [len(t.host) for t in self.targets]))
        status_w = min(26, max([14] + [len(t.error or t.last_detail) for t in self.targets]))
        widths = [host_w, 15, 7, 5, 6, 5, 5, 5, 5, 5, status_w]
        hist_w = fill_width(self.app, widths)
        rows = []
        for t, st, data in zip(self.targets, stats, snaps):
            state = [("error", "erreur")] if t.error else ([("ok", "actif")] if t.running else [("dim", "arrêté")])
            rows.append([t.host, t.ip or "", state, str(st.sent),
                         [(loss_attr(st.loss) or "body", f"{st.loss:5.1f}%" if st.sent else "    -")],
                         fmt_ms(st.cur), fmt_ms(st.min), [(lat_attr(st.avg), fmt_ms(st.avg))], fmt_ms(st.max),
                         fmt_ms(st.jitter), t.error or t.last_detail, sparkline(data, hist_w, scale)])
        self.table.set_rows(rows, widths=widths + [hist_w])
        self._update_chart()
        n = sum(t.running for t in self.targets)
        self.status.set_text(("dim", f"{len(self.targets)} cible(s), {n} active(s) — échelle 0–{scale:.0f} ms"))

    def _update_chart(self):
        i = self.table.focus_index
        if i is None or i >= len(self.targets):
            self.chart.set_data([], " Sélectionnez une cible")
            return
        t = self.targets[i]
        window = self.window.value
        self.chart.set_data(t.series.snapshot(window), f" {t.host} ({t.ip or '?'})  — latence ms, ┃ rouge = perte",
                            window)

    def shutdown(self):
        for t in self.targets:
            t.stop()
