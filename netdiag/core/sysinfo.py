"""Collecte des informations réseau du système.

Windows : un seul appel PowerShell (cmdlets NetTCPIP / DnsClient / NetAdapter, sortie CSV
pour récupérer les énumérations sous forme de texte) + quelques commandes texte classiques
(ipconfig, route, netsh). Autres OS : psutil + commandes `ip` (pour le développement).
"""
from __future__ import annotations

import csv
import io
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .utils import IS_WINDOWS, is_admin, run, run_powershell


@dataclass
class Section:
    key: str
    title: str
    group: str
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    text: str | None = None     # section texte brut (sortie de commande)
    error: str = ""


# (clé, titre, groupe, script PowerShell renvoyant des objets)
_PS_SECTIONS = [
    ("adapters", "Cartes réseau", "Interfaces",
     "Get-NetAdapter | Select-Object Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed,"
     "MediaType,PhysicalMediaType,MtuSize,VlanID,FullDuplex,DriverVersion,DriverDate"),
    ("ipaddr", "Adresses IP", "Interfaces",
     "Get-NetIPAddress | Select-Object ifIndex,InterfaceAlias,AddressFamily,IPAddress,PrefixLength,"
     "Type,PrefixOrigin,SuffixOrigin,AddressState,ValidLifetime,PreferredLifetime,SkipAsSource"),
    ("ipif", "Paramètres IP / MTU par interface", "Interfaces",
     "Get-NetIPInterface | Select-Object ifIndex,InterfaceAlias,AddressFamily,NlMtu,InterfaceMetric,"
     "AutomaticMetric,Dhcp,ConnectionState,Forwarding,RouterDiscovery,WeakHostSend,WeakHostReceive,"
     "CurrentHopLimit,BaseReachableTime,ReachableTime,RetransmitTime,DadTransmits,EcnMarking,"
     "AdvertiseDefaultRoute,ManagedAddressConfiguration,OtherStatefulConfiguration"),
    ("adapter_stats", "Statistiques des cartes", "Interfaces",
     "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,"
     "SentUnicastPackets,ReceivedDiscardedPackets,ReceivedPacketErrors,OutboundDiscardedPackets,"
     "OutboundPacketErrors"),
    ("adapter_adv", "Propriétés avancées des pilotes", "Interfaces",
     "Get-NetAdapterAdvancedProperty | Select-Object Name,DisplayName,DisplayValue,RegistryKeyword"),
    ("profiles", "Profils de connexion", "Interfaces",
     "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory,"
     "IPv4Connectivity,IPv6Connectivity"),
    ("routes", "Table de routage", "Routage",
     "Get-NetRoute | Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceAlias,ifIndex,"
     "RouteMetric,Protocol,Store,TypeOfRoute,State"),
    ("neighbors", "Voisins (ARP / NDP)", "Routage",
     "Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } | Select-Object ifIndex,"
     "InterfaceAlias,AddressFamily,IPAddress,LinkLayerAddress,State"),
    ("dns_servers", "Serveurs DNS", "DNS",
     "Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,"
     "@{n='ServerAddresses';e={$_.ServerAddresses -join ', '}}"),
    ("dns_client", "Client DNS par interface", "DNS",
     "Get-DnsClient | Select-Object InterfaceAlias,InterfaceIndex,ConnectionSpecificSuffix,"
     "RegisterThisConnectionsAddress,UseSuffixWhenRegistering"),
    ("dns_global", "Paramètres DNS globaux", "DNS",
     "Get-DnsClientGlobalSetting | Select-Object UseSuffixSearchList,"
     "@{n='SuffixSearchList';e={$_.SuffixSearchList -join ', '}},UseDevolution,DevolutionLevel"),
    ("dns_cache", "Cache DNS", "DNS",
     "Get-DnsClientCache | Select-Object Entry,Name,Type,Status,Section,TimeToLive,Data"),
    ("tcp", "Connexions TCP", "Connexions",
     "$p=@{}; Get-Process | ForEach-Object { $p[$_.Id]=$_.ProcessName }; "
     "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,"
     "OwningProcess,@{n='Process';e={$p[[int]$_.OwningProcess]}}"),
    ("udp", "Écoutes UDP", "Connexions",
     "$p=@{}; Get-Process | ForEach-Object { $p[$_.Id]=$_.ProcessName }; "
     "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,"
     "@{n='Process';e={$p[[int]$_.OwningProcess]}}"),
    ("firewall", "Profils pare-feu", "Sécurité",
     "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,"
     "LogAllowed,LogBlocked,LogFileName"),
]

# (clé, titre, groupe, commande)
_WIN_TEXT_SECTIONS = [
    ("ipconfig", "ipconfig /all", "Commandes", ["ipconfig", "/all"]),
    ("route_print", "route print", "Commandes", ["route", "print"]),
    ("ipv4_global", "netsh ipv4 global", "Commandes", ["netsh", "interface", "ipv4", "show", "global"]),
    ("ipv4_subif", "netsh ipv4 subinterfaces (MTU)", "Commandes",
     ["netsh", "interface", "ipv4", "show", "subinterfaces"]),
    ("ipv6_subif", "netsh ipv6 subinterfaces (MTU)", "Commandes",
     ["netsh", "interface", "ipv6", "show", "subinterfaces"]),
    ("tcp_global", "netsh tcp global", "Commandes", ["netsh", "interface", "tcp", "show", "global"]),
    ("proxy", "Proxy WinHTTP", "Commandes", ["netsh", "winhttp", "show", "proxy"]),
    ("wlan", "Wi-Fi (netsh wlan)", "Commandes", ["netsh", "wlan", "show", "interfaces"]),
    ("arp", "arp -a", "Commandes", ["arp", "-a"]),
]

GROUP_ORDER = ["Vue d'ensemble", "Interfaces", "Routage", "DNS", "Connexions", "Sécurité", "Commandes"]


def _parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    rows = list(csv.reader(io.StringIO(text.strip())))
    if not rows:
        return [], []
    return rows[0], rows[1:]


def _collect_windows_ps() -> list[Section]:
    parts = []
    for key, *_ , script in _PS_SECTIONS:
        parts.append(
            f"Write-Output '#####BEGIN {key}'\n"
            f"try {{ {script} | ConvertTo-Csv -NoTypeInformation }} "
            f"catch {{ Write-Output ('#####ERROR ' + $_.Exception.Message) }}\n"
            f"Write-Output '#####END {key}'")
    code, out, err = run_powershell("\n".join(parts), timeout=120)
    blocks: dict[str, list[str]] = {}
    current = None
    for line in out.splitlines():
        if line.startswith("#####BEGIN "):
            current = line[11:].strip()
            blocks[current] = []
        elif line.startswith("#####END "):
            current = None
        elif current is not None:
            blocks[current].append(line)
    sections = []
    for key, title, group, _ in _PS_SECTIONS:
        sec = Section(key, title, group)
        lines = blocks.get(key)
        if lines is None:
            sec.error = err.strip() or "PowerShell n'a rien renvoyé"
        elif lines and lines[0].startswith("#####ERROR"):
            sec.error = lines[0][11:]
        else:
            sec.columns, sec.rows = _parse_csv("\n".join(lines))
        sections.append(sec)
    return sections


def _collect_windows_text() -> list[Section]:
    def one(item):
        key, title, group, cmd = item
        code, out, err = run(cmd, timeout=30)
        return Section(key, title, group, text=(out or err).rstrip())
    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(one, _WIN_TEXT_SECTIONS))


def _collect_generic() -> list[Section]:
    import psutil
    secs = []
    stats = psutil.net_if_stats()
    s = Section("adapters", "Cartes réseau", "Interfaces",
                ["Name", "Status", "Speed (Mb/s)", "MTU", "Duplex", "MacAddress"])
    addrs = psutil.net_if_addrs()
    for name, st in stats.items():
        mac = next((a.address for a in addrs.get(name, []) if a.family == psutil.AF_LINK), "")
        s.rows.append([name, "Up" if st.isup else "Down", str(st.speed), str(st.mtu),
                       str(st.duplex).split(".")[-1], mac])
    secs.append(s)
    s = Section("ipaddr", "Adresses IP", "Interfaces",
                ["InterfaceAlias", "AddressFamily", "IPAddress", "Netmask", "Broadcast"])
    for name, lst in addrs.items():
        for a in lst:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                s.rows.append([name, "IPv4" if a.family == socket.AF_INET else "IPv6", a.address,
                               a.netmask or "", a.broadcast or ""])
    secs.append(s)
    s = Section("ipif", "Paramètres IP / MTU par interface", "Interfaces", ["Paramètre", "Valeur"])
    for p in ["ip_forward", "ip_default_ttl", "tcp_mtu_probing", "tcp_congestion_control",
              "tcp_ecn", "tcp_window_scaling", "tcp_timestamps", "ip_local_port_range"]:
        try:
            with open(f"/proc/sys/net/ipv4/{p}") as f:
                s.rows.append([f"net.ipv4.{p}", f.read().strip()])
        except OSError:
            pass
    secs.append(s)
    s = Section("adapter_stats", "Statistiques des cartes", "Interfaces",
                ["Name", "BytesRecv", "BytesSent", "PacketsRecv", "PacketsSent", "ErrIn", "ErrOut",
                 "DropIn", "DropOut"])
    for name, c in psutil.net_io_counters(pernic=True).items():
        s.rows.append([name] + [str(v) for v in (c.bytes_recv, c.bytes_sent, c.packets_recv,
                                                 c.packets_sent, c.errin, c.errout, c.dropin, c.dropout)])
    secs.append(s)
    s = Section("routes", "Table de routage", "Routage",
                ["AddressFamily", "DestinationPrefix", "NextHop", "InterfaceAlias", "RouteMetric", "Protocol"])
    for fam, flag in (("IPv4", "-4"), ("IPv6", "-6")):
        _, out, _ = run(["ip", flag, "route", "show", "table", "main"])
        for line in out.splitlines():
            tok = line.split()
            if not tok:
                continue
            dest = "0.0.0.0/0" if tok[0] == "default" and fam == "IPv4" else ("::/0" if tok[0] == "default" else tok[0])
            get = lambda k: tok[tok.index(k) + 1] if k in tok and tok.index(k) + 1 < len(tok) else ""
            s.rows.append([fam, dest, get("via"), get("dev"), get("metric"), get("proto")])
    secs.append(s)
    s = Section("neighbors", "Voisins (ARP / NDP)", "Routage", ["IPAddress", "InterfaceAlias", "LinkLayerAddress", "State"])
    _, out, _ = run(["ip", "neigh"])
    for line in out.splitlines():
        tok = line.split()
        if tok:
            get = lambda k: tok[tok.index(k) + 1] if k in tok else ""
            s.rows.append([tok[0], get("dev"), get("lladdr"), tok[-1]])
    secs.append(s)
    s = Section("dns_servers", "Serveurs DNS", "DNS", ["InterfaceAlias", "AddressFamily", "ServerAddresses"])
    try:
        with open("/etc/resolv.conf") as f:
            ns = [l.split()[1] for l in f if l.startswith("nameserver")]
        s.rows.append(["(système)", "", ", ".join(ns)])
    except OSError as e:
        s.error = str(e)
    secs.append(s)
    for key, title, cmd in [("ipaddr_txt", "ip addr", ["ip", "addr"]),
                            ("route_txt", "ip route", ["ip", "route"]),
                            ("resolv", "resolv.conf", ["cat", "/etc/resolv.conf"])]:
        _, out, err = run(cmd)
        secs.append(Section(key, title, "Commandes", text=(out or err).rstrip()))
    return secs


def _overview(sections: dict[str, Section]) -> Section:
    def rows(key):
        s = sections.get(key)
        if not s or not s.columns:
            return []
        return [dict(zip(s.columns, r)) for r in s.rows]

    ov = Section("overview", "Synthèse", "Vue d'ensemble", ["Élément", "Valeur"])
    add = lambda k, v: ov.rows.append([k, v])
    add("Nom d'hôte", socket.gethostname())
    try:
        add("FQDN", socket.getfqdn())
    except OSError:
        pass
    add("Système", f"{platform.system()} {platform.release()} ({platform.version()})")
    add("Droits administrateur", "Oui" if is_admin() else "Non (capture / certaines actions limitées)")
    gws = [f"{r.get('NextHop')}  via {r.get('InterfaceAlias')}  (métrique {r.get('RouteMetric', '')})"
           for r in rows("routes") if r.get("DestinationPrefix") in ("0.0.0.0/0", "::/0")
           and r.get("NextHop") not in ("", "0.0.0.0", "::")]
    for gw in gws or ["(aucune passerelle par défaut)"]:
        add("Passerelle par défaut", gw)
    up = {r.get("Name") for r in rows("adapters") if str(r.get("Status", "")).lower() == "up"}
    for r in rows("ipaddr"):
        fam = r.get("AddressFamily", "")
        if fam in ("IPv4",) and not r.get("IPAddress", "").startswith(("127.", "169.254.")):
            alias = r.get("InterfaceAlias", "")
            mark = "" if not up or alias in up else "  [interface down]"
            prefix = r.get("PrefixLength") or r.get("Netmask", "")
            add("Adresse IPv4", f"{r.get('IPAddress')}/{prefix}  ({alias}){mark}")
    mtus = {(r.get("InterfaceAlias"), r.get("NlMtu")) for r in rows("ipif")
            if r.get("AddressFamily") == "IPv4" and r.get("ConnectionState") == "Connected"}
    for alias, mtu in sorted(mtus):
        add("MTU IPv4", f"{mtu}  ({alias})")
    dns = []
    for r in rows("dns_servers"):
        for ip in str(r.get("ServerAddresses", "")).split(","):
            ip = ip.strip()
            if ip and ip not in dns:
                dns.append(ip)
    add("Serveurs DNS", ", ".join(dns) or "(aucun)")
    for r in rows("dns_global"):
        if r.get("SuffixSearchList"):
            add("Suffixes DNS", r["SuffixSearchList"])
    return ov


def collect() -> list[Section]:
    """Collecte complète (bloquant, plusieurs secondes sous Windows)."""
    if IS_WINDOWS:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_ps = pool.submit(_collect_windows_ps)
            f_txt = pool.submit(_collect_windows_text)
            sections = f_ps.result() + f_txt.result()
        _add_effective_metric(sections)
    else:
        sections = _collect_generic()
    by_key = {s.key: s for s in sections}
    sections.insert(0, _overview(by_key))
    return sections


def _add_effective_metric(sections: list[Section]):
    """Ajoute la métrique effective (route + interface), celle que Windows utilise vraiment."""
    by_key = {s.key: s for s in sections}
    routes, ipif = by_key.get("routes"), by_key.get("ipif")
    if not routes or not ipif or not routes.columns or not ipif.columns:
        return
    try:
        iidx, ifam, imet = (ipif.columns.index(c) for c in ("ifIndex", "AddressFamily", "InterfaceMetric"))
        ridx, rfam, rmet = (routes.columns.index(c) for c in ("ifIndex", "AddressFamily", "RouteMetric"))
    except ValueError:
        return
    metrics = {(r[iidx], r[ifam]): r[imet] for r in ipif.rows}
    routes.columns.insert(rmet + 1, "MétriqueEffective")
    for r in routes.rows:
        try:
            eff = str(int(r[rmet]) + int(metrics.get((r[ridx], r[rfam]), 0)))
        except ValueError:
            eff = ""
        r.insert(rmet + 1, eff)


def public_ip(timeout: float = 5) -> str:
    """Interroge un service externe (action déclenchée par l'utilisateur uniquement)."""
    import urllib.request
    with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
        return r.read().decode().strip()


def flush_dns() -> str:
    if IS_WINDOWS:
        _, out, err = run(["ipconfig", "/flushdns"])
    else:
        _, out, err = run(["resolvectl", "flush-caches"])
    return (out or err).strip() or "OK"


def renew_dhcp() -> str:
    if not IS_WINDOWS:
        return "Disponible uniquement sous Windows"
    _, out, err = run(["ipconfig", "/renew"], timeout=90)
    return (out or err).strip()
