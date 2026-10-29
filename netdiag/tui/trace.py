"""Onglet Trace : traceroute continu façon mtr / PingPlotter."""
from __future__ import annotations

import os
import time

import urwid

from ..core import export
from ..core.stats import compute_stats
from ..core.trace import TraceSession
from .base import WINDOWS, Tab
from .widgets import (Button, Chart, Cycle, DataTable, fmt_ms, field, lat_attr, latency_bar, loss_attr, nice_ceil,
                      sparkline)

COLS = ["#", "Perte%", "IP", "Nom d'hôte", "Moy", "Min", "Cur", "Max", "Jit", "Env", "Latence", "Historique"]
INTERVALS = [("0,5 s", 0.5), ("1 s", 1.0), ("2,5 s", 2.5), ("5 s", 5.0), ("10 s", 10.0), ("30 s", 30.0)]
BAR_W = 22


def fill_width(app, widths: list[int], minimum: int = 10) -> int:
    """Largeur restante pour la dernière colonne (bordure de 2 + 1 espace par colonne)."""
    return max(minimum, app.screen_cols() - 2 - sum(widths) - len(widths) - 1)


class TraceTab(Tab):
    title = "Trace"
    main_index = 2
    keys = [("Entrée", "lancer"), ("s", "start/stop"), ("i", "intervalle"), ("f", "focus"),
            ("n", "noms DNS"), ("e", "export CSV"), ("←→", "colonnes")]

    def __init__(self, app, target: str = "", interval: float = 2.5):
        super().__init__(app)
        self.session: TraceSession | None = None
        self.resolve_names = True
        self._focus_dest = False
        self.target, target_w = field("Cible", target)
        idx = next((i for i, (_, v) in enumerate(INTERVALS) if v == interval), 2)
        self.interval = Cycle("Intervalle", INTERVALS, idx)
        self.window = Cycle("Focus", WINDOWS, 2)
        btn = Button("Démarrer / Arrêter", self.toggle)
        top = urwid.Columns([("weight", 3, target_w), ("given", self.interval.width, self.interval),
                             ("given", self.window.width, self.window), ("pack", btn)], dividechars=1)
        self.table = DataTable(COLS, fixed=1)
        urwid.connect_signal(self.table, "select", lambda _i: self._update_chart())
        self.chart = Chart()
        self.status = urwid.Text(("dim", "Saisissez une cible puis Entrée."))
        self.pile = urwid.Pile([("pack", top), ("pack", urwid.Divider()), ("weight", 1, self.table),
                                ("given", 14, self.chart), ("pack", self.status)])
        self.widget = urwid.Padding(self.pile, left=1, right=1)
        if target:
            self.start()

    # ------------------------------------------------------------------ contrôle
    def toggle(self):
        if self.session and self.session.running:
            self.session.stop()
            self.app.notify("Trace arrêtée.")
        else:
            self.start()

    def start(self):
        host = self.target.edit_text.strip()
        if not host:
            self.app.notify("Saisissez une cible.", "error")
            return
        if self.session:
            self.session.stop()
        self.session = TraceSession(host, interval=self.interval.value, resolve_names=self.resolve_names)
        self.session.start()
        self._focus_dest = True
        self.pile.focus_position = 2  # focus sur le tableau des sauts

    def on_key(self, key):
        if key == "enter" and self.pile.focus_position == 0:
            self.start()
        elif key == "s":
            self.toggle()
        elif key == "i":
            self.interval.next()
            if self.session:
                self.session.interval = self.interval.value
        elif key == "f":
            self.window.next()
        elif key == "n":
            self.resolve_names = not self.resolve_names
            if self.session:
                self.session.resolve_names = self.resolve_names
            self.app.notify(f"Résolution des noms {'activée' if self.resolve_names else 'désactivée'}.")
        elif key == "e":
            self._export()
        else:
            return False
        return True

    # ------------------------------------------------------------------ affichage
    def tick(self):
        s = self.session
        if not s:
            return
        if s.error:
            self.status.set_text(("error", s.error))
            return
        window = self.window.value
        hops = s.hops()
        snaps = [h.series.snapshot(window) for h in hops]
        stats = [compute_stats(d) for d in snaps]
        scale = max(10.0, nice_ceil(max([st.max for st in stats if st.max is not None] or [0.0])))
        name_w = min(30, max([10] + [len(h.hostname) for h in hops])) if self.resolve_names else 10
        widths = [2, 6, 18, name_w, 5, 5, 5, 5, 5, 5, BAR_W]
        hist_w = fill_width(self.app, widths)
        rows, attrs = [], []
        for h, st, data in zip(hops, stats, snaps):
            ip = (h.ip or "*") + (f" (+{len(h.ips) - 1})" if len(h.ips) > 1 else "")
            la = loss_attr(st.loss)
            rows.append([
                str(h.ttl),
                [(la or "body", f"{st.loss:5.1f}%" if st.sent else "    -")],
                [("title" if s.dest_ttl == h.ttl else "body", ip)],
                h.hostname if self.resolve_names else "",
                [(lat_attr(st.avg), fmt_ms(st.avg))], fmt_ms(st.min), fmt_ms(st.cur), fmt_ms(st.max),
                fmt_ms(st.jitter), str(st.sent),
                latency_bar(st, scale, BAR_W),
                sparkline(data, hist_w, scale),
            ])
            attrs.append(None)
        self.table.set_rows(rows, attrs, widths=widths + [hist_w])
        if self._focus_dest and s.dest_ttl and len(rows) >= s.dest_ttl:
            # comme PingPlotter : la destination est sélectionnée par défaut
            self.table.walker.set_focus(s.dest_ttl - 1)
            self._focus_dest = False
        self._update_chart(hops, window)
        el = time.time() - (s.started_at or time.time())
        where = (f"destination {s.target_ip} atteinte en {s.dest_ttl} sauts" if s.dest_ttl
                 else f"destination {s.target_ip or s.target} non atteinte (≤ {s.max_hops} sauts)")
        state = ("ok", "● en cours") if s.running else ("dim", "■ arrêté")
        self.status.set_text([state, f"  {where} — {s.cycles} cycles en {int(el // 60)} min {int(el % 60):02d} s"
                                     f" — échelle 0–{scale:.0f} ms"])

    def _update_chart(self, hops=None, window=None):
        s = self.session
        if not s:
            return
        hops = hops if hops is not None else s.hops()
        if not hops:
            return
        idx = self.table.focus_index
        hop = hops[idx] if idx is not None and idx < len(hops) else hops[-1]
        window = window if window is not None else self.window.value
        self.chart.set_data(hop.series.snapshot(window),
                            f" Saut {hop.ttl} — {hop.ip or '*'} {hop.hostname}  (latence ms, ┃ rouge = perte)",
                            window)

    def _export(self):
        if not self.session:
            return
        path = os.path.abspath(time.strftime("trace_%Y%m%d_%H%M%S.csv"))
        export.trace_csv(self.session, path, self.window.value)
        self.app.notify(f"Trace exportée : {path}")

    def shutdown(self):
        if self.session:
            self.session.stop()
