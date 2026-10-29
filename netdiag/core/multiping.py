"""Ping continu de plusieurs cibles en parallèle."""
from __future__ import annotations

import threading
import time

from .icmp import Pinger
from .stats import Series
from .utils import IS_WINDOWS, resolve_ipv4, run, run_powershell


def local_targets() -> list[str]:
    """Passerelle(s) par défaut puis serveurs DNS IPv4 de la machine (cibles de ping « locales »)."""
    hosts: list[str] = []
    if IS_WINDOWS:
        _, out, _ = run_powershell(
            "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric).NextHop;"
            "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses")
        hosts = [l.strip() for l in out.splitlines()]
    else:
        from .sysinfo_linux import _resolv_conf, _resolvectl
        _, out, _ = run(["ip", "route", "show", "default"], c_locale=True)
        hosts = [l.split()[2] for l in out.splitlines() if len(l.split()) > 2 and l.split()[1] == "via"]
        for _, _, servers in _resolvectl("dns"):
            hosts += servers.split()
        hosts += _resolv_conf()[0]
    seen: list[str] = []
    for h in hosts:
        # 127.0.0.53 = résolveur local systemd-resolved : inutile à pinger
        if h and h not in seen and h != "0.0.0.0" and ":" not in h and not h.startswith("127."):
            seen.append(h)
    return seen


class PingTarget:
    def __init__(self, host: str, interval: float = 1.0, size: int = 32, timeout: int = 1000,
                 ttl: int = 128, df: bool = False, count: int | None = None):
        self.host = host.strip()
        self.ip: str | None = None
        self.interval = interval
        self.size = size
        self.timeout = timeout
        self.ttl = ttl
        self.df = df
        self.count = count                # None = continu ; sinon N pings puis arrêt (mode rapport)
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
            sent = 0
            while not self._stop.is_set() and (self.count is None or sent < self.count):
                t0 = time.time()
                res = pinger.ping(self.ip, ttl=self.ttl, timeout=self.timeout, size=self.size, df=self.df)
                sent += 1
                self.series.add(res.rtt if res.status == "ok" else None, t0)
                self.last_detail = res.detail
                if self.count is not None and sent >= self.count:
                    break
                self._stop.wait(max(0.0, self.interval - (time.time() - t0)))
        finally:
            pinger.close()
