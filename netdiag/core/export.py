"""Exports CSV (séparateur « ; », UTF-8 avec BOM pour Excel) communs aux versions graphique et terminal."""
from __future__ import annotations

import csv
import time

from .stats import compute_stats


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _fmt(v) -> str:
    return "" if v is None else f"{v:.2f}"


def trace_csv(session, path: str, window: float | None = None):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Saut", "IP", "Nom", "Perte %", "Moy", "Min", "Cur", "Max", "Jitter", "Envoyés"])
        hops = session.hops()
        for h in hops:
            st = compute_stats(h.series.snapshot(window))
            w.writerow([h.ttl, h.ip or "", h.hostname, f"{st.loss:.1f}", _fmt(st.avg), _fmt(st.min),
                        _fmt(st.cur), _fmt(st.max), _fmt(st.jitter), st.sent])
        w.writerow([])
        w.writerow(["Saut", "IP", "Horodatage", "RTT ms (vide = perte)"])
        for h in hops:
            for t, rtt in h.series.snapshot():
                w.writerow([h.ttl, h.ip or "", _ts(t), _fmt(rtt)])


def multiping_csv(targets, path: str):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Cible", "IP", "Horodatage", "RTT ms (vide = perte)"])
        for t in targets:
            for ts, rtt in t.series.snapshot():
                w.writerow([t.host, t.ip or "", _ts(ts), _fmt(rtt)])
