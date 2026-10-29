"""netdiag-tui : version terminal de NetDiag (interactive, ou rapports pour les scripts).

  netdiag-tui                          interface interactive (onglet Système)
  netdiag-tui trace 8.8.8.8            interface ouverte sur la trace
  netdiag-tui ping 1.1.1.1 8.8.8.8     interface ouverte sur le multi-ping
  netdiag-tui capture | tools | sys    interface ouverte sur l'onglet choisi

  netdiag-tui report [-s routes -s dns_servers] [--json] [--list]
  netdiag-tui trace 8.8.8.8 --report [-c 10] [--json]     (comme mtr --report)
  netdiag-tui ping 1.1.1.1 8.8.8.8 --report [-c 10] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .. import __version__


def _stats_dict(st) -> dict:
    return {"sent": st.sent, "received": st.recv, "loss_pct": round(st.loss, 1),
            **{k: (round(v, 3) if v is not None else None)
               for k, v in (("last", st.cur), ("min", st.min), ("avg", st.avg), ("max", st.max),
                            ("jitter", st.jitter))}}


def _fmt(v) -> str:
    return "-" if v is None else (f"{v:.2f}" if v < 10 else f"{v:.1f}")


def report_sys(args) -> int:
    from ..core import sysinfo
    sections = sysinfo.collect()
    if args.list:
        for s in sections:
            print(f"{s.key:18} {s.group} / {s.title}")
        return 0
    if args.section:
        wanted = set(args.section)
        unknown = wanted - {s.key for s in sections}
        if unknown:
            print(f"Section(s) inconnue(s) : {', '.join(sorted(unknown))} (voir --list)", file=sys.stderr)
            return 2
        sections = [s for s in sections if s.key in wanted]
    if args.json:
        json.dump([{"key": s.key, "group": s.group, "title": s.title, "error": s.error or None,
                    **({"text": s.text} if s.text is not None else
                       {"rows": [dict(zip(s.columns, r)) for r in s.rows]})} for s in sections],
                  sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        sys.stdout.write(sysinfo.report_text(sections))
    return 0


def report_trace(args) -> int:
    from ..core.icmp import BACKEND
    from ..core.trace import TraceSession
    s = TraceSession(args.hosts[0], interval=args.interval or 1.0, max_hops=args.max_hops,
                     timeout=args.timeout, resolve_names=not args.no_dns, max_cycles=args.count)
    s.start()
    progress = sys.stderr.isatty() and not args.json
    time.sleep(0.05)
    while s.running:
        time.sleep(0.1)
        if progress:
            print(f"\r{s.cycles}/{args.count} cycles…", end="", file=sys.stderr)
    if progress:
        print("\r" + " " * 30 + "\r", end="", file=sys.stderr)
    if s.error:
        print(s.error, file=sys.stderr)
        return 1
    hops = [(h, h.series.stats()) for h in s.hops()]
    if args.json:
        json.dump({"target": s.target, "ip": s.target_ip, "reached_at": s.dest_ttl, "engine": BACKEND,
                   "hops": [{"hop": h.ttl, "ip": h.ip, "ips": sorted(h.ips), "hostname": h.hostname,
                             **_stats_dict(st)} for h, st in hops]}, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    print(f"Trace vers {s.target} ({s.target_ip}) — {args.count} cycles — {time.strftime('%Y-%m-%d %H:%M:%S')}")
    name_w = max([20] + [len(h.hostname or h.ip or "") for h, _ in hops])
    print(f"{'#':>3}  {'Hôte':<{name_w}}  {'Perte%':>6}  {'Env':>4}  {'Dern':>6}  {'Moy':>6}  {'Min':>6}  "
          f"{'Max':>6}  {'Jit':>6}")
    for h, st in hops:
        host = (h.hostname or h.ip or "???") + (f" (+{len(h.ips) - 1})" if len(h.ips) > 1 else "")
        print(f"{h.ttl:>3}  {host:<{name_w}}  {st.loss:6.1f}  {st.sent:>4}  {_fmt(st.cur):>6}  {_fmt(st.avg):>6}  "
              f"{_fmt(st.min):>6}  {_fmt(st.max):>6}  {_fmt(st.jitter):>6}")
    return 0


def report_ping(args) -> int:
    from ..core.multiping import PingTarget
    interval = args.interval or 1.0
    targets = [PingTarget(h, interval=interval, timeout=args.timeout, count=args.count) for h in args.hosts]
    for t in targets:
        t.start()
    time.sleep(0.05)
    while any(t.running for t in targets):
        time.sleep(0.1)
    rows = [(t, t.series.stats()) for t in targets]
    if args.json:
        json.dump([{"target": t.host, "ip": t.ip, "error": t.error or None, **_stats_dict(st)} for t, st in rows],
                  sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    w = max([6] + [len(t.host) for t in targets])
    print(f"{'Cible':<{w}}  {'IP':<15}  {'Perte%':>6}  {'Env':>4}  {'Dern':>6}  {'Moy':>6}  {'Min':>6}  {'Max':>6}  "
          f"{'Jit':>6}")
    for t, st in rows:
        print(f"{t.host:<{w}}  {(t.ip or t.error or '?'):<15}  {st.loss:6.1f}  {st.sent:>4}  {_fmt(st.cur):>6}  "
              f"{_fmt(st.avg):>6}  {_fmt(st.min):>6}  {_fmt(st.max):>6}  {_fmt(st.jitter):>6}")
    return 0 if all(st.recv for _, st in rows) else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netdiag-tui", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"NetDiag {__version__}")
    sub = p.add_subparsers(dest="cmd")
    for name in ("sys", "capture", "tools"):
        sub.add_parser(name, help=f"ouvrir l'onglet {name}")
    for name, nargs in (("trace", 1), ("ping", "+")):
        sp = sub.add_parser(name, help=f"{name} (interactif, ou --report)")
        sp.add_argument("hosts", nargs=nargs, metavar="HÔTE")
        sp.add_argument("-i", "--interval", type=float, help="intervalle entre cycles (s)")
        sp.add_argument("-r", "--report", action="store_true", help="mode rapport non interactif")
        sp.add_argument("-c", "--count", type=int, default=10, help="nombre de cycles en mode rapport (10)")
        sp.add_argument("-W", "--timeout", type=int, default=2000, help="délai de réponse en ms (2000)")
        sp.add_argument("--json", action="store_true", help="sortie JSON (implique --report)")
        if name == "trace":
            sp.add_argument("-m", "--max-hops", type=int, default=30)
            sp.add_argument("-n", "--no-dns", action="store_true", help="ne pas résoudre les noms")
    rp = sub.add_parser("report", help="rapport système en texte ou JSON")
    rp.add_argument("-s", "--section", action="append", help="clé de section (répétable, voir --list)")
    rp.add_argument("--list", action="store_true", help="lister les sections disponibles")
    rp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "report":
        return report_sys(args)
    if args.cmd in ("trace", "ping") and (args.report or args.json):
        return report_trace(args) if args.cmd == "trace" else report_ping(args)

    if not sys.stdout.isatty():
        print("netdiag-tui : un terminal est nécessaire pour l'interface (ou utilisez « report » / --report).",
              file=sys.stderr)
        return 2
    from .app import App
    tab = {"trace": "trace", "ping": "ping", "capture": "capture", "tools": "tools"}.get(args.cmd, "system")
    App(start_tab=tab,
        trace_target=args.hosts[0] if args.cmd == "trace" else "",
        ping_hosts=args.hosts if args.cmd == "ping" else None,
        interval=getattr(args, "interval", None)).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
