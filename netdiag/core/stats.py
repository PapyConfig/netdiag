"""Série temporelle d'échantillons de latence et statistiques associées."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass
class Stats:
    sent: int = 0
    recv: int = 0
    loss: float = 0.0
    cur: float | None = None
    min: float | None = None
    avg: float | None = None
    max: float | None = None
    jitter: float | None = None


class Series:
    """Échantillons (timestamp, rtt_ms ou None si perte). Thread-safe."""

    def __init__(self, maxlen: int = 50_000):
        self._samples: deque[tuple[float, float | None]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, rtt: float | None, t: float | None = None):
        t = t if t is not None else time.time()
        with self._lock:
            s = self._samples
            if not s or s[-1][0] <= t:
                s.append((t, rtt))
            else:  # réponse arrivée après une plus récente : on garde l'ordre chronologique
                i = len(s) - 1
                while i > 0 and s[i - 1][0] > t:
                    i -= 1
                if len(s) == s.maxlen:
                    s.popleft()
                    i = max(0, i - 1)
                s.insert(i, (t, rtt))

    def clear(self):
        with self._lock:
            self._samples.clear()

    def snapshot(self, window: float | None = None) -> list[tuple[float, float | None]]:
        with self._lock:
            data = list(self._samples)
        if window and data:
            limit = time.time() - window
            # les échantillons sont chronologiques : recherche du premier dans la fenêtre
            lo, hi = 0, len(data)
            while lo < hi:
                mid = (lo + hi) // 2
                if data[mid][0] < limit:
                    lo = mid + 1
                else:
                    hi = mid
            data = data[lo:]
        return data

    def stats(self, window: float | None = None) -> Stats:
        return compute_stats(self.snapshot(window))


def compute_stats(samples: list[tuple[float, float | None]]) -> Stats:
    s = Stats(sent=len(samples))
    if not samples:
        return s
    vals = [r for _, r in samples if r is not None]
    s.recv = len(vals)
    s.loss = 100.0 * (s.sent - s.recv) / s.sent
    s.cur = samples[-1][1]
    if vals:
        s.min, s.max = min(vals), max(vals)
        s.avg = sum(vals) / len(vals)
        if len(vals) > 1:
            s.jitter = sum(abs(b - a) for a, b in zip(vals, vals[1:])) / (len(vals) - 1)
    return s
