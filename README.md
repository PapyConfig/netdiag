# NetDiag — prototype d'outil de diagnostic réseau (Windows, Ubuntu, terminal)

Outil qui regroupe ce qu'on fait d'habitude avec `ipconfig` / `ip`, `route print`, `netsh` / `resolvectl`,
`tracert` / `mtr`, PingPlotter et Wireshark. Il existe en deux versions qui partagent le même moteur :
- **NetDiag** : application de bureau (Qt), pour Windows et Ubuntu ;
- **netdiag-tui** : version terminal, utilisable dans tmux ou en SSH, avec des modes rapport pour les scripts.

## Fonctionnalités

| Onglet | Contenu |
|---|---|
| **Système** | Synthèse (passerelles, IPv4, MTU, DNS, moteur ICMP utilisé), cartes réseau, adresses IP, paramètres IPv4/IPv6 par interface (MTU, métrique, DHCP, forwarding, weak host…), statistiques et propriétés avancées des pilotes, table de routage avec **métrique effective**, ARP/NDP, serveurs DNS, suffixes, cache DNS, connexions TCP/UDP avec processus, profils pare-feu, sortie brute de `ipconfig /all`, `route print`, `netsh` (global, subinterfaces, tcp, wlan, proxy). Filtre, copie vers Excel, export du rapport complet en .txt. Actions : IP publique, vider le cache DNS, renouveler le bail DHCP. |
| **Trace (PingPlotter)** | Traceroute **continu** : chaque saut est sondé à chaque cycle, avec pour chacun perte %, moyenne, min, max, valeur courante et jitter, plus une barre de latence (moyenne colorée, moustache min–max, point = dernière valeur, liseré rouge = perte). En dessous, le graphe temporel du saut sélectionné, avec les pertes en barres rouges. Réglages : intervalle (0,5 à 60 s), taille, nombre de sauts, délai, fenêtre de focus. Détection des sauts à IP multiples (ECMP). Export CSV. |
| **Multi-Ping** | Plusieurs cibles pingées en parallèle sur un même graphe, avec les stats par cible et des triangles pour les pertes. Bouton « Passerelle & DNS » pour ajouter les cibles locales en un clic. Option DF. Export CSV. |
| **Capture** | Capture live : choix de l'interface, filtre BPF, liste colorée par protocole, détail et hexdump du paquet, export .pcap, ouverture dans Wireshark. Windows : Npcap, avec repli **pktmon** (natif, conversion .pcapng). Linux : voir plus bas. |
| **Outils** | Résolution DNS (tous types, serveur au choix, comparaison système / 8.8.8.8 / 1.1.1.1 / 9.9.9.9), test de ports TCP (plages acceptées), **découverte du MTU de chemin** par dichotomie avec le bit DF. |

### Points techniques

- **Ping et traceroute sans droits admin**, sur les deux systèmes (voir les moteurs ICMP ci-dessous).
- **Envois asynchrones** : un saut qui ne répond pas ne ralentit pas la cadence des autres.
- **Infos système Windows** : un seul appel PowerShell (cmdlets `NetTCPIP`, `DnsClient`, `NetAdapter`).
  La sortie CSV conserve le nom des énumérations, ce qui la rend lisible.
- **Infos système Linux** : `ip -j` (JSON), `/proc/sys` (paramètres IPv4/IPv6 par interface et sysctl
  globaux), `resolvectl`, `nmcli` / `networkctl`, `ss` / psutil, `ethtool`, état du pare-feu (ufw, nftables).
- **Qt** : PySide6 sous Windows, PyQt6 (paquet Ubuntu) sous Linux, via la couche `netdiag/ui/qt.py`.

### Moteurs ICMP (ping / trace)

| Système | Moteur | Remarque |
|---|---|---|
| Windows | `IcmpSendEcho` (iphlpapi.dll) | Le même que `tracert` et PingPlotter. TTL, taille et bit DF réglables. |
| Linux | socket ICMP « datagramme » | Utilisé si `net.ipv4.ping_group_range` l'autorise (désactivé par défaut sur Ubuntu). |
| Linux | `mtr-packet` (paquet mtr-tiny) | Cas normal sur Ubuntu : installé par défaut avec `cap_net_raw`. Précision à la microseconde. |
| Linux | commande `ping` | Dernier recours, et pour les tests avec le bit DF. |

La sélection est automatique (`NETDIAG_ICMP=socket|mtr|cmd` pour forcer un moteur) et s'affiche dans la barre d'état.

## Version terminal : netdiag-tui

```
 NetDiag 0.3.0   F1 Système   F2 Trace   F3 Multi-Ping   F4 Capture   F5 Outils                         ICMP : mtr-packet (Linux)
 Cible 1.1.1.1                                                     < Intervalle: 1 s   > < Focus: 10 min > < Démarrer / Arrêter >

 #  Perte% IP                 Nom d'hôte      Moy   Min   Cur   Max   Jit   Env   Latence                Historique
 1    0.0% 10.42.1.1                          0.24  0.16  0.19  0.32  0.04  15    ●                      ········▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁
 2    0.0% 194.149.162.228                    3.1   2.7   2.7   3.5   0.40  15    ●                      ········▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁
 3  100.0% *                                  -     -     -     -     -     13    perte totale           ··········×××××××××××××
 4    0.0% 141.101.67.54                      9.9   9.4   9.4   11    0.39  15    █●█                    ········▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁
 5    0.0% 141.101.67.155                     22    10    14    59    20    15    ██●██───────├          ········▂▁▄▁▁▁▁▄▂▁▁▁▅▂▁
 6    0.0% 1.1.1.1            one.one.one.one 11    10    10    12    0.48  15    ██●                    ········▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁



  Saut 6 — 1.1.1.1 one.one.one.one  (latence ms, ┃ rouge = perte)
     20│
       │
       │
       │
       │                                                                                                                 ▁
       │                                                                                                          ▄▃▂▁▄▂▁█▂▂▁▁▃▁▁
     10│                                                                                                          ███████████████
       │                                                                                                          ███████████████
       │                                                                                                          ███████████████
       │                                                                                                          ███████████████
       │                                                                                                          ███████████████
       │                                                                                                          ███████████████
     ms└-14 s                                                                                                          maintenant
 ● en cours  destination 1.1.1.1 atteinte en 6 sauts — 15 cycles en 0 min 14 s — échelle 0–100 ms
```

Mêmes onglets que la version graphique (F1 à F5, Alt+1 à 5 ou clic) : Système, Trace, Multi-Ping, Capture, Outils.
- **Trace** : un tableau façon mtr, avec une barre de latence (█ moyenne, ─ jusqu'au max, ● dernière valeur) et un
  historique sur chaque ligne (× = perte). En dessous, le graphe du saut sélectionné, comme dans PingPlotter.
- **Capture** : méthode « tcpdump (sudo) », où le mot de passe est demandé directement dans le terminal.
  « Directe » si l'outil tourne en root, « dumpcap » pour les membres du groupe wireshark.
- **Clavier** : `?` affiche l'aide, Tab passe au champ suivant, Échap quitte un champ (les raccourcis lettres
  redeviennent actifs), ← → font défiler les colonnes larges, `q` quitte.
  Dans tmux, `set -g mouse on` active aussi la souris.

```bash
netdiag-tui                                  # interface interactive
netdiag-tui trace 8.8.8.8                    # ouverte directement sur la trace
netdiag-tui ping 1.1.1.1 8.8.8.8 -i 0.5      # ouverte sur le multi-ping

# modes rapport (non interactifs, pour scripts / supervision)
netdiag-tui trace 8.8.8.8 --report -c 10     # comme « mtr --report »
netdiag-tui ping 1.1.1.1 192.168.1.1 -r -c 5 # code de sortie 1 si une cible ne répond pas
netdiag-tui report                           # rapport système complet en texte
netdiag-tui report --list                    # sections disponibles
netdiag-tui report -s routes -s dns_servers --json
netdiag-tui trace 1.1.1.1 --json -c 5        # JSON exploitable avec jq
```

Fonctionne sous Linux (et donc WSL) ainsi que macOS en lançant depuis les sources. Windows natif n'est pas encore pris en charge.

## Ubuntu (24.04 ou plus récent)

Deux paquets, à télécharger depuis l'artefact `netdiag-deb` de la CI GitHub Actions ou à construire :

| Paquet | Contenu | Pour |
|---|---|---|
| `netdiag-tui` | moteur + version terminal (`netdiag-tui`), sans Qt | serveurs, SSH, tmux |
| `netdiag` | interface graphique (`netdiag`, entrée de menu) ; dépend de `netdiag-tui` | postes de travail |

```bash
packaging/build-deb.sh                                   # → dist/netdiag-tui_<v>_all.deb + dist/netdiag_<v>_all.deb

# serveur : version terminal seule, installation légère (≈ 40 paquets, sans Qt ni ipython)
sudo apt install --no-install-recommends ./dist/netdiag-tui_*_all.deb

# poste de travail : les deux
sudo apt install ./dist/netdiag-tui_*_all.deb ./dist/netdiag_*_all.deb
```

Les paquets ne font que quelques dizaines de Ko : ils s'appuient sur les paquets Python d'Ubuntu (« Architecture: all »).
Sans `--no-install-recommends`, apt ajoute les paquets recommandés par scapy (ipython, matplotlib…), soit environ
300 Mo inutiles pour NetDiag. Ubuntu 22.04 n'est pas pris en charge pour l'interface graphique, car PyQt6 n'y est pas packagé.
La mise à jour depuis l'ancien paquet unique `netdiag` 0.2.0 se fait sans conflit.

**Capture sans lancer l'appli en root** (interface graphique), par ordre de préférence :
1. **dumpcap** (Wireshark) : aucun mot de passe si Wireshark est installé et que l'utilisateur est dans le groupe `wireshark`
   (`sudo dpkg-reconfigure wireshark-common` puis `sudo usermod -aG wireshark $USER`).
2. **tcpdump via polkit** : le mot de passe administrateur est demandé au démarrage de la capture, puis gardé quelques minutes.
   L'aide `netdiag-capture-helper` vérifie ses arguments et s'arrête dès que NetDiag ferme la capture.
3. **Directe** : si l'appli tourne en root.

Lancer depuis les sources : `sudo apt install python3-pyqt6 python3-pyqtgraph python3-scapy python3-dnspython python3-psutil python3-urwid`,
puis `python3 main.py` (graphique) ou `python3 tui.py` (terminal).

## Windows

Prérequis : Windows 10/11, Python 3.10+.

```bat
run.bat
```

Ou à la main : `py -m venv .venv && .venv\Scripts\pip install -r requirements.txt && .venv\Scripts\python main.py`

Pour la capture live, installer [Npcap](https://npcap.com) (option « WinPcap API-compatible mode »).
Certaines captures et pktmon demandent de lancer NetDiag **en administrateur**.

### Construire l'exécutable

```bat
build.bat
```

Résultat : `dist\NetDiag\NetDiag.exe`, dossier autonome qui ne nécessite pas Python sur le poste cible.
La CI produit aussi ce dossier (artefact `netdiag-windows`).

## Intégration continue

À chaque push, GitHub Actions :
- construit les deux `.deb` et installe `netdiag-tui` seul sur Ubuntu 24.04, en vérifiant qu'aucun paquet Qt n'est tiré.
  Il lance ensuite `tests/smoke_tui.py` (modes rapport, rendu de chaque onglet, navigation au clavier), installe
  l'interface graphique et lance `tests/smoke.py` (moteur ICMP, collecte système, interface hors écran) ;
- lance le même test sur Windows (IcmpSendEcho, PowerShell), puis construit `NetDiag.exe`.

## Lire une trace (rappel façon PingPlotter)

- Une perte sur un saut **intermédiaire** qui ne se propage pas aux sauts suivants n'est en général
  pas un problème : beaucoup de routeurs limitent leurs réponses ICMP « TTL expiré ».
  Seule la perte qui continue jusqu'à la destination compte.
- Une latence qui augmente à partir d'un saut et **reste** élevée jusqu'à la destination désigne ce lien.
- Avec un intervalle court (0,5 s), les box et passerelles limitent souvent leurs réponses ICMP.
  On voit alors une perte « fantôme » sur le saut 1.

## Limites du prototype

- Ping et trace en **IPv4 uniquement** (l'IPv6 demanderait `Icmp6SendEcho2` sous Windows ; `mtr-packet` le gère déjà sous Linux).
- Pas encore de sauvegarde ni de rechargement de sessions, ni d'alertes (seuils et notifications).
- Pas encore de traceroute en TCP ou UDP (utile quand l'ICMP est filtré).
- Codes couleur fixes : vert < 100 ms, jaune < 200 ms, rouge au-delà.

## Structure

```
main.py / tui.py           points d'entrée (graphique / terminal)
netdiag/core/              logique sans interface (testable seule)
  icmp.py                  IcmpSendEcho (Windows) / socket ICMP, mtr-packet, ping (Linux)
  trace.py                 moteur de traceroute continu
  multiping.py             ping multi-cibles
  stats.py                 séries temporelles + stats (perte, jitter…)
  sysinfo.py               collecte Windows (PowerShell / netsh) + synthèse commune
  sysinfo_linux.py         collecte Linux (ip -j, /proc/sys, resolvectl, nmcli…)
  capture.py               Npcap, pktmon, dumpcap, tcpdump via polkit
  tools.py                 DNS, ports TCP, MTU du chemin
  export.py                exports CSV communs
netdiag/ui/                onglets Qt (pyqtgraph ; qt.py = compatibilité PySide6 / PyQt6)
netdiag/tui/               version terminal (urwid) : app.py, un module par onglet, widgets.py, __main__.py (CLI)
packaging/                 build-deb.sh + fichiers Debian (lanceurs, .desktop, règle polkit, aide de capture)
tests/                     smoke.py (graphique, multiplateforme) et smoke_tui.py (terminal), utilisés par la CI
```
