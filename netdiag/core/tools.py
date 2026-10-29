"""Outils ponctuels : résolution DNS, test de ports TCP, découverte du MTU de chemin."""
from __future__ import annotations

import socket
import time
from typing import Callable

from .icmp import Pinger
from .utils import resolve_ipv4, run

Log = Callable[[str], None]


def dns_lookup(name: str, rtype: str = "A", server: str = "") -> str:
    name, rtype, server = name.strip(), rtype.upper(), server.strip()
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        return _nslookup(name, rtype, server)
    res = dns.resolver.Resolver()
    if server:
        res.nameservers = [resolve_ipv4(server)]
    res.lifetime = 5
    qname = dns.reversename.from_address(name) if rtype == "PTR" else name
    t0 = time.perf_counter()
    try:
        ans = res.resolve(qname, rtype, raise_on_no_answer=False)
    except Exception as e:
        return f"{rtype} {name} @ {server or ', '.join(res.nameservers)} → échec : {e}"
    ms = (time.perf_counter() - t0) * 1000
    lines = [f"{rtype} {name} @ {ans.nameserver}:{ans.port}  ({ms:.1f} ms)"]
    if ans.rrset is None:
        lines.append("  (aucune réponse)")
    else:
        lines += [f"  {r.to_text()}   TTL={ans.rrset.ttl}" for r in ans.rrset]
    return "\n".join(lines)


def _nslookup(name: str, rtype: str, server: str) -> str:
    cmd = ["nslookup", f"-type={rtype}", name] + ([server] if server else [])
    t0 = time.perf_counter()
    _, out, err = run(cmd, timeout=15)
    return f"$ {' '.join(cmd)}  ({(time.perf_counter() - t0) * 1000:.0f} ms)\n{(out + err).strip()}"


def tcp_check(host: str, port: int, timeout: float = 3.0) -> tuple[str, float, str]:
    """Renvoie (état, ms, détail) avec état ∈ OUVERT | FERMÉ | FILTRÉ | ERREUR. IPv4 uniquement."""
    t0 = time.perf_counter()
    ms = lambda: (time.perf_counter() - t0) * 1000
    try:
        ip = resolve_ipv4(host)
        with socket.create_connection((ip, port), timeout=timeout):
            return "OUVERT", ms(), ip
    except socket.timeout:
        return "FILTRÉ", ms(), "pas de réponse (pare-feu ?)"
    except ConnectionRefusedError:
        return "FERMÉ", ms(), "RST reçu"
    except OSError as e:
        return "ERREUR", ms(), str(e)


def parse_ports(spec: str) -> list[int]:
    """'80,443,8000-8010' → liste de ports."""
    ports: list[int] = []
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    if any(not 0 < p < 65536 for p in ports):
        raise ValueError("Ports hors limites (1-65535)")
    return ports


def path_mtu(host: str, log: Log, max_mtu: int = 1500, timeout: int = 1500) -> int | None:
    """Recherche dichotomique du plus gros paquet passant avec DF=1 (en-têtes IP+ICMP = 28 o)."""
    ip = resolve_ipv4(host)
    log(f"Découverte du MTU vers {host} ({ip}), bit DF positionné…")
    pinger = Pinger()
    try:
        base = pinger.ping(ip, timeout=timeout, size=32)
        if base.status != "ok":
            log(f"La cible ne répond pas au ping ({base.detail}) : test impossible.")
            return None
        lo, hi = 0, max_mtu - 28          # lo passe toujours, on cherche le max
        while lo < hi:
            mid = (lo + hi + 1) // 2
            res = None
            for _ in range(2):            # 2 essais pour distinguer perte et rejet
                res = pinger.ping(ip, timeout=timeout, size=mid, df=True)
                if res.status == "ok":
                    break
            ok = res.status == "ok"
            log(f"  charge {mid:5d} o → paquet {mid + 28:5d} o : "
                f"{'OK' if ok else res.detail or res.status}"
                f"{f' (signalé par {res.addr})' if res.addr and not ok else ''}")
            if ok:
                lo = mid
            else:
                hi = mid - 1
        mtu = lo + 28
        log(f"MTU du chemin : {mtu} octets (charge ICMP max {lo} o, MSS TCP ≈ {mtu - 40})")
        return mtu
    finally:
        pinger.close()
