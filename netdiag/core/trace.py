"""Moteur de traceroute continu façon PingPlotter.

À chaque cycle, une sonde ICMP est envoyée en parallèle pour chaque TTL de 1 à N.
Chaque saut accumule ses propres échantillons : on voit donc où la latence ou la
perte apparaît le long du chemin, dans la durée.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .icmp import Pinger
from .stats import Series
from .utils import resolve_ipv4, reverse_dns


class Hop:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self.ip: str | None = None
        self.ips: set[str] = set()      # plusieurs IP = chemin variable (ECMP / changement de route)
        self.hostname = ""
        self.series = Series()


class TraceSession:
    def __init__(self, target: str, interval: float = 2.5, max_hops: int = 30, size: int = 32,
                 timeout: int = 2000, resolve_names: bool = True):
        self.target = target.strip()
        self.target_ip: str | None = None
        self.interval = interval
        self.max_hops = max_hops
        self.size = size
        self.timeout = timeout
        self.resolve_names = resolve_names
        self.dest_ttl: int | None = None
        self.error = ""
        self.cycles = 0
        self.started_at: float | None = None
        self._hops: dict[int, Hop] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._local = threading.local()

    # ------------------------------------------------------------------ API
    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"trace-{self.target}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def hops(self) -> list[Hop]:
        with self._lock:
            limit = self.dest_ttl or self.max_hops
            return [self._hops[t] for t in sorted(self._hops) if t <= limit]

    # ------------------------------------------------------------------ interne
    def _pinger(self) -> Pinger:
        p = getattr(self._local, "pinger", None)
        if p is None:
            p = self._local.pinger = Pinger()
        return p

    def _probe(self, ttl: int, t0: float):
        res = self._pinger().ping(self.target_ip, ttl=ttl, timeout=self.timeout, size=self.size)
        if self._stop.is_set():
            return
        with self._lock:
            hop = self._hops.setdefault(ttl, Hop(ttl))
            if res.addr and res.answered:
                if res.addr != hop.ip and self.resolve_names:
                    self._rdns.submit(self._resolve, hop, res.addr)
                hop.ip = res.addr
                hop.ips.add(res.addr)
            hop.series.add(res.rtt if res.answered else None, t0)
            if res.status == "ok" and (self.dest_ttl is None or ttl < self.dest_ttl):
                self.dest_ttl = ttl

    def _run(self):
        try:
            self.target_ip = resolve_ipv4(self.target)
        except OSError as e:
            self.error = f"Impossible de résoudre « {self.target} » : {e}"
            return
        self.started_at = time.time()
        self._rdns = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")
        # Envois asynchrones : un saut muet (timeout) ne ralentit pas la cadence des autres.
        overlap = int(self.timeout / 1000 / self.interval) + 2
        pool = ThreadPoolExecutor(max_workers=min(512, self.max_hops * overlap), thread_name_prefix="probe")
        try:
            while not self._stop.is_set():
                t0 = time.time()
                for ttl in range(1, (self.dest_ttl or self.max_hops) + 1):
                    with self._lock:
                        self._hops.setdefault(ttl, Hop(ttl))
                    pool.submit(self._probe, ttl, t0)
                self.cycles += 1
                self._stop.wait(max(0.0, self.interval - (time.time() - t0)))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
            self._rdns.shutdown(wait=False)

    @staticmethod
    def _resolve(hop: Hop, ip: str):
        name = reverse_dns(ip)
        if hop.ip == ip:
            hop.hostname = name
