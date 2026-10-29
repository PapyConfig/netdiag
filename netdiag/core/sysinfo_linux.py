"""Collecte des informations réseau sous Linux (Ubuntu) : `ip -j`, /proc/sys, resolvectl, nmcli, ss, ethtool.

Les noms de colonnes reprennent ceux de la version Windows quand la notion est la même
(InterfaceAlias, NextHop, RouteMetric, NlMtu…) pour que la synthèse et l'interface restent communes.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from concurrent.futures import ThreadPoolExecutor

import psutil

from .sysinfo import Section
from .utils import run


def _ipj(*args: str) -> list[dict]:
    code, out, _ = run(["ip", "-j", *args], c_locale=True)
    try:
        return json.loads(out) if code == 0 and out.strip() else []
    except json.JSONDecodeError:
        return []


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def _fam(family: str) -> str:
    return {"inet": "IPv4", "inet6": "IPv6"}.get(family, family)


def _is_physical(ifname: str) -> bool:
    return os.path.exists(f"/sys/class/net/{ifname}/device")


# ------------------------------------------------------------------ interfaces
def _adapters(links: list[dict]) -> Section:
    s = Section("adapters", "Cartes réseau", "Interfaces",
                ["Name", "ifIndex", "Status", "Type", "MacAddress", "MTU", "LinkSpeed (Mb/s)", "Duplex",
                 "Driver", "Master", "Qdisc", "TxQueueLen", "Flags"])
    for l in links:
        name = l.get("ifname", "")
        kind = (l.get("linkinfo") or {}).get("info_kind", "")
        typ = l.get("link_type", "") + (f" / {kind}" if kind else "") + ("" if _is_physical(name) or name == "lo"
                                                                          else " (virtuelle)")
        speed = _read(f"/sys/class/net/{name}/speed")
        driver = os.path.basename(os.path.realpath(f"/sys/class/net/{name}/device/driver")) \
            if _is_physical(name) else ""
        s.rows.append([name, str(l.get("ifindex", "")), l.get("operstate", ""), typ, l.get("address", ""),
                       str(l.get("mtu", "")), speed if speed and not speed.startswith("-") else "",
                       _read(f"/sys/class/net/{name}/duplex"), driver, l.get("master", ""), l.get("qdisc", ""),
                       str(l.get("txqlen", "")), ",".join(l.get("flags", []))])
    return s


def _addresses(addrs: list[dict]) -> Section:
    s = Section("ipaddr", "Adresses IP", "Interfaces",
                ["ifIndex", "InterfaceAlias", "AddressFamily", "IPAddress", "PrefixLength", "Scope", "Origine",
                 "ValidLifetime", "PreferredLifetime", "Label", "Flags"])
    for l in addrs:
        for a in l.get("addr_info", []):
            flags = [f for f in ("dynamic", "temporary", "deprecated", "tentative", "noprefixroute", "mngtmpaddr")
                     if a.get(f)]
            life = lambda v: "" if v is None else ("infini" if v == 4294967295 else f"{v} s")
            s.rows.append([str(l.get("ifindex", "")), l.get("ifname", ""), _fam(a.get("family", "")),
                           a.get("local", ""), str(a.get("prefixlen", "")), a.get("scope", ""),
                           "DHCP/SLAAC" if a.get("dynamic") else "Statique / noyau",
                           life(a.get("valid_life_time")), life(a.get("preferred_life_time")),
                           a.get("label", ""), ",".join(flags)])
    return s


def _ip_params(links: list[dict], addrs: list[dict]) -> Section:
    """Paramètres IP par interface (équivalent de Get-NetIPInterface)."""
    v4 = {"Forwarding": "forwarding", "RpFilter": "rp_filter", "AcceptRedirects": "accept_redirects",
          "SendRedirects": "send_redirects", "ArpIgnore": "arp_ignore", "ArpAnnounce": "arp_announce",
          "ProxyArp": "proxy_arp", "AcceptSourceRoute": "accept_source_route"}
    v6 = {"Forwarding": "forwarding", "DisableIPv6": "disable_ipv6", "AcceptRA": "accept_ra",
          "Autoconf": "autoconf", "UseTempAddr": "use_tempaddr", "CurrentHopLimit": "hop_limit"}
    cols = ["ifIndex", "InterfaceAlias", "AddressFamily", "NlMtu", "ConnectionState", "Dhcp"]
    cols += list(dict.fromkeys(list(v4) + list(v6)))
    s = Section("ipif", "Paramètres IP / MTU par interface", "Interfaces", cols)
    dyn = {(l.get("ifname"), a.get("family")) for l in addrs for a in l.get("addr_info", []) if a.get("dynamic")}
    for l in links:
        name, flags = l.get("ifname", ""), l.get("flags", [])
        state = "Connected" if "UP" in flags and "LOWER_UP" in flags else "Disconnected"
        for fam, params, base in (("IPv4", v4, "ipv4"), ("IPv6", v6, "ipv6")):
            if not os.path.isdir(f"/proc/sys/net/{base}/conf/{name}"):
                continue
            mtu = str(l.get("mtu", "")) if fam == "IPv4" else _read(f"/proc/sys/net/ipv6/conf/{name}/mtu")
            row = dict(ifIndex=str(l.get("ifindex", "")), InterfaceAlias=name, AddressFamily=fam, NlMtu=mtu,
                       ConnectionState=state,
                       Dhcp="Enabled" if (name, "inet" if fam == "IPv4" else "inet6") in dyn else "Disabled")
            for col, key in params.items():
                row[col] = _read(f"/proc/sys/net/{base}/conf/{name}/{key}")
            s.rows.append([row.get(c, "") for c in cols])
    return s


_SYSCTLS = [
    "net.ipv4.ip_forward", "net.ipv4.ip_default_ttl", "net.ipv4.ip_local_port_range", "net.ipv4.ip_no_pmtu_disc",
    "net.ipv4.tcp_mtu_probing", "net.ipv4.tcp_base_mss", "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_available_congestion_control", "net.ipv4.tcp_ecn", "net.ipv4.tcp_sack",
    "net.ipv4.tcp_timestamps", "net.ipv4.tcp_window_scaling", "net.ipv4.tcp_fastopen", "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem", "net.ipv4.tcp_syn_retries", "net.ipv4.tcp_keepalive_time",
    "net.ipv4.icmp_echo_ignore_all", "net.ipv4.icmp_ratelimit", "net.ipv4.ping_group_range",
    "net.ipv4.conf.all.rp_filter", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.forwarding",
    "net.core.default_qdisc", "net.core.rmem_max", "net.core.wmem_max", "net.core.netdev_max_backlog",
    "net.core.somaxconn", "net.netfilter.nf_conntrack_count", "net.netfilter.nf_conntrack_max",
]


def _global_params() -> Section:
    s = Section("ipv4_global", "Paramètres IPv4 / TCP globaux (sysctl)", "Interfaces", ["Paramètre", "Valeur"])
    for key in _SYSCTLS:
        val = _read("/proc/sys/" + key.replace(".", "/"))
        if val:
            s.rows.append([key, re.sub(r"\s+", " ", val)])
    return s


def _adapter_stats(links: list[dict]) -> Section:
    s = Section("adapter_stats", "Statistiques des cartes", "Interfaces",
                ["Name", "ReceivedBytes", "SentBytes", "ReceivedPackets", "SentPackets", "ReceivedErrors",
                 "SentErrors", "ReceivedDropped", "SentDropped", "Collisions", "Multicast"])
    for l in links:
        st = l.get("stats64", {})
        rx, tx = st.get("rx", {}), st.get("tx", {})
        s.rows.append([l.get("ifname", "")] + [str(v) for v in (
            rx.get("bytes", ""), tx.get("bytes", ""), rx.get("packets", ""), tx.get("packets", ""),
            rx.get("errors", ""), tx.get("errors", ""), rx.get("dropped", ""), tx.get("dropped", ""),
            tx.get("collisions", ""), rx.get("multicast", ""))])
    return s


# ------------------------------------------------------------------ routage
def _routes() -> Section:
    s = Section("routes", "Table de routage", "Routage",
                ["AddressFamily", "DestinationPrefix", "NextHop", "InterfaceAlias", "RouteMetric", "Protocol",
                 "Scope", "Source", "Table", "Type"])
    for fam, flag in (("IPv4", "-4"), ("IPv6", "-6")):
        for r in _ipj(flag, "route", "show", "table", "all"):
            table = str(r.get("table", "main"))
            if table == "local":
                continue  # routes locales/broadcast générées par le noyau : bruit
            dst = r.get("dst", "")
            if dst == "default":
                dst = "0.0.0.0/0" if fam == "IPv4" else "::/0"
            hop = r.get("gateway") or (r.get("via") or {}).get("host", "")
            s.rows.append([fam, dst, hop, r.get("dev", ""), str(r.get("metric", "")), r.get("protocol", ""),
                           r.get("scope", ""), r.get("prefsrc", ""), table, r.get("type", "unicast")])
    return s


def _rules() -> Section:
    s = Section("rules", "Règles de routage (policy routing)", "Routage",
                ["Priorité", "From", "To", "Iif", "Oif", "Fwmark", "Table", "Action"])
    for fam in ("-4", "-6"):
        for r in _ipj(fam, "rule"):
            src = r.get("src", "all") + (f"/{r['srclen']}" if "srclen" in r else "")
            dst = r.get("dst", "") + (f"/{r['dstlen']}" if "dstlen" in r else "")
            s.rows.append([str(r.get("priority", "")), src, dst, r.get("iif", ""), r.get("oif", ""),
                           str(r.get("fwmark", "")), str(r.get("table", "")), r.get("action", "")])
    return s


def _neighbors() -> Section:
    s = Section("neighbors", "Voisins (ARP / NDP)", "Routage",
                ["InterfaceAlias", "AddressFamily", "IPAddress", "LinkLayerAddress", "State", "Router"])
    for n in _ipj("neigh"):
        dst = n.get("dst", "")
        s.rows.append([n.get("dev", ""), "IPv6" if ":" in dst else "IPv4", dst, n.get("lladdr", ""),
                       ",".join(n.get("state", [])), "oui" if "router" in n else ""])
    return s


# ------------------------------------------------------------------ DNS
_RE_LINK = re.compile(r"^(Global|Link (\d+) \(([^)]+)\)):\s*(.*)$")


def _resolvectl(what: str) -> list[tuple[str, str, str]]:
    """(index, interface, valeur) depuis `resolvectl dns|domain`."""
    if not shutil.which("resolvectl"):
        return []
    code, out, _ = run(["resolvectl", what], c_locale=True)
    res = []
    for line in out.splitlines() if code == 0 else []:
        m = _RE_LINK.match(line.strip())
        if m and m.group(4).strip():
            res.append((m.group(2) or "", m.group(3) or "(global)", m.group(4).strip()))
    return res


def _resolv_conf() -> tuple[list[str], list[str]]:
    ns, search = [], []
    for line in _read("/etc/resolv.conf").splitlines():
        parts = line.split()
        if parts[:1] == ["nameserver"] and len(parts) > 1:
            ns.append(parts[1])
        elif parts[:1] in (["search"], ["domain"]):
            search += parts[1:]
    return ns, search


def _dns() -> list[Section]:
    servers = Section("dns_servers", "Serveurs DNS", "DNS", ["InterfaceAlias", "InterfaceIndex", "ServerAddresses"])
    for idx, ifname, val in _resolvectl("dns"):
        servers.rows.append([ifname, idx, ", ".join(val.split())])
    ns, search = _resolv_conf()
    stub = any(n.startswith("127.0.0.53") for n in ns)
    if not servers.rows or not stub:
        servers.rows.append(["(/etc/resolv.conf)", "", ", ".join(ns)])
    client = Section("dns_client", "Domaines DNS par interface", "DNS",
                     ["InterfaceAlias", "InterfaceIndex", "ConnectionSpecificSuffix"])
    for idx, ifname, val in _resolvectl("domain"):
        client.rows.append([ifname, idx, ", ".join(val.split())])
    glob = Section("dns_global", "Paramètres DNS globaux", "DNS",
                   ["Résolveur", "SuffixSearchList", "resolv.conf nameservers"])
    glob.rows.append(["systemd-resolved (stub 127.0.0.53)" if stub else "direct (/etc/resolv.conf)",
                      ", ".join(search), ", ".join(ns)])
    return [servers, client, glob]


# ------------------------------------------------------------------ connexions
def _connections(kind: str) -> Section:
    tcp = kind == "tcp"
    s = Section(kind, "Connexions TCP" if tcp else "Sockets UDP", "Connexions",
                ["LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "OwningProcess", "Process"]
                if tcp else ["LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "OwningProcess", "Process"])
    names: dict[int, str] = {}
    try:
        conns = psutil.net_connections(kind)
    except (psutil.AccessDenied, OSError) as e:
        s.error = str(e)
        return s
    for c in conns:
        name = ""
        if c.pid:
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except psutil.Error:
                    names[c.pid] = ""
            name = names[c.pid]
        la, ra = c.laddr, c.raddr
        row = [la.ip if la else "", str(la.port) if la else "", ra.ip if ra else "", str(ra.port) if ra else ""]
        if tcp:
            row.append(c.status)
        s.rows.append(row + [str(c.pid or ""), name])
    if not os.geteuid() == 0:
        s.error = "Processus des autres utilisateurs non visibles sans droits root."
    return s


def _nm_devices() -> Section:
    s = Section("profiles", "Périphériques NetworkManager", "Interfaces",
                ["Device", "Type", "State", "Connection"])
    if not shutil.which("nmcli"):
        s.error = "NetworkManager (nmcli) absent : voir « networkctl » dans Commandes."
        return s
    code, out, err = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], c_locale=True)
    if code != 0:
        s.error = err.strip()
    for line in out.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) == 4:
            s.rows.append([p.replace("\\:", ":") for p in parts])
    return s


def _firewall_text() -> str:
    out = []
    if shutil.which("systemctl"):
        for svc in ("ufw", "firewalld", "nftables", "netfilter-persistent"):
            _, st, _ = run(["systemctl", "is-active", svc], c_locale=True)
            out.append(f"{svc:<22} {st.strip() or 'absent'}")
    for cmd in (["ufw", "status", "verbose"], ["nft", "list", "ruleset"]):
        if shutil.which(cmd[0]):
            code, o, e = run(cmd)
            body = (o or e).strip()
            if code != 0 and os.geteuid() != 0:
                body += "\n(droits root nécessaires pour le détail)"
            out.append(f"\n$ {' '.join(cmd)}\n{body}")
    return "\n".join(out)


def _proxy_text() -> str:
    lines = [f"{k}={v}" for k, v in sorted(os.environ.items()) if k.lower().endswith("_proxy")]
    if shutil.which("gsettings"):
        _, mode, _ = run(["gsettings", "get", "org.gnome.system.proxy", "mode"])
        if mode.strip():
            lines.append(f"GNOME proxy mode : {mode.strip()}")
    return "\n".join(lines) or "Aucun proxy configuré (variables *_proxy vides)."


def _ethtool_text(links: list[dict]) -> str:
    if not shutil.which("ethtool"):
        return "ethtool non installé (sudo apt install ethtool)"
    parts = []
    for l in links:
        name = l.get("ifname", "")
        if _is_physical(name):
            _, o, e = run(["ethtool", name])
            _, oi, _ = run(["ethtool", "-i", name])
            parts.append(f"===== {name}\n{(o or e).strip()}\n{oi.strip()}")
    return "\n\n".join(parts) or "Aucune interface physique."


_TEXT_CMDS = [
    ("ip_addr", "ip addr", ["ip", "addr"]),
    ("ip_link", "ip -s link", ["ip", "-s", "link"]),
    ("ip_route", "ip route (toutes tables)", ["ip", "route", "show", "table", "all"]),
    ("ip6_route", "ip -6 route", ["ip", "-6", "route"]),
    ("resolvectl", "resolvectl status", ["resolvectl", "status"]),
    ("resolvectl_stats", "resolvectl statistics", ["resolvectl", "statistics"]),
    ("nmcli_show", "nmcli device show", ["nmcli", "device", "show"]),
    ("wifi", "Wi-Fi (nmcli)", ["nmcli", "-f", "IN-USE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                               "device", "wifi", "list", "--rescan", "no"]),
    ("networkctl", "networkctl", ["networkctl", "list"]),
    ("ss_summary", "ss -s", ["ss", "-s"]),
    ("hosts", "/etc/hosts", ["cat", "/etc/hosts"]),
    ("resolv", "/etc/resolv.conf", ["cat", "/etc/resolv.conf"]),
]


def collect_linux() -> list[Section]:
    with ThreadPoolExecutor(max_workers=8) as pool:
        f_links = pool.submit(_ipj, "-d", "-s", "link")
        f_addrs = pool.submit(_ipj, "addr")
        f_routes = pool.submit(_routes)
        f_rules = pool.submit(_rules)
        f_neigh = pool.submit(_neighbors)
        f_dns = pool.submit(_dns)
        f_tcp = pool.submit(_connections, "tcp")
        f_udp = pool.submit(_connections, "udp")
        f_nm = pool.submit(_nm_devices)
        f_fw = pool.submit(_firewall_text)

        def text(item):
            key, title, cmd = item
            if not shutil.which(cmd[0]):
                return None
            _, out, err = run(cmd, timeout=20)
            return Section(key, title, "Commandes", text=(out or err).rstrip())
        f_txt = [pool.submit(text, item) for item in _TEXT_CMDS]

        links, addrs = f_links.result(), f_addrs.result()
        f_eth = pool.submit(_ethtool_text, links)
        sections = [_adapters(links), _addresses(addrs), _ip_params(links, addrs), _global_params(),
                    _adapter_stats(links), f_nm.result(), f_routes.result(), f_rules.result(), f_neigh.result(),
                    *f_dns.result(), f_tcp.result(), f_udp.result(),
                    Section("firewall", "Pare-feu", "Sécurité", text=f_fw.result()),
                    Section("proxy", "Proxy", "Commandes", text=_proxy_text()),
                    Section("ethtool", "ethtool (interfaces physiques)", "Commandes", text=f_eth.result())]
        sections += [s for s in (f.result() for f in f_txt) if s is not None]
    return sections


def flush_dns() -> str:
    code, out, err = run(["resolvectl", "flush-caches"])
    return (out or err).strip() or ("Cache DNS vidé." if code == 0 else "Échec")


def renew_dhcp() -> str:
    """Renouvelle le bail de l'interface portant la route par défaut (NetworkManager ou systemd-networkd)."""
    default = next((r for r in _ipj("-4", "route", "show", "default")), None)
    if not default:
        return "Aucune route par défaut : interface à renouveler introuvable."
    dev = default.get("dev", "")
    if shutil.which("nmcli"):
        code, conn, _ = run(["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", dev], c_locale=True)
        conn = conn.strip()
        if code == 0 and conn:
            code, out, err = run(["nmcli", "connection", "up", "id", conn], timeout=60)
            return f"nmcli connection up « {conn} » ({dev}) :\n{(out or err).strip()}"
    if shutil.which("networkctl"):
        code, out, err = run(["networkctl", "renew", dev], timeout=60)
        return f"networkctl renew {dev} : " + ((out or err).strip() or ("OK" if code == 0 else "échec"))
    return f"Ni NetworkManager ni systemd-networkd ne gèrent {dev}."
