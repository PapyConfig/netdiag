"""Ping continu de plusieurs cibles en parallèle."""
from __future__ import annotations

import threading
import time

from .icmp import Pinger
from .stats import Series
from .utils import resolve_ipv4


class PingTarget:
    def __init__(self, host: str, interval: float = 1.0, size: int = 32, timeout: int = 1000,
                 ttl: int = 128, df: bool = False):
        self.host = host.strip()
        self.ip: str | None = None
        self.interval = interval
        self.size = size
        self.timeout = timeout
        self.ttl = ttl
        self.df = df
        self.series = Series()
        self.error = ""
        self.last_detail = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"ping-{self.host}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        try:
            self.ip = resolve_ipv4(self.host)
            self.error = ""
        except OSError as e:
            self.error = f"Résolution impossible : {e}"
            return
        pinger = Pinger()
        try:
            while not self._stop.is_set():
                t0 = time.time()
                res = pinger.ping(self.ip, ttl=self.ttl, timeout=self.timeout, size=self.size, df=self.df)
                self.series.add(res.rtt if res.status == "ok" else None, t0)
                self.last_detail = res.detail
                self._stop.wait(max(0.0, self.interval - (time.time() - t0)))
        finally:
            pinger.close()
