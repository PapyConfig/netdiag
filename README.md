# NetDiag — prototype d'outil de diagnostic réseau (Windows et Ubuntu)

Application de bureau (Python + Qt) qui regroupe en une seule fenêtre ce qu'on fait d'habitude
avec `ipconfig` / `ip`, `route print`, `netsh` / `resolvectl`, `tracert` / `mtr`, PingPlotter et Wireshark.

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

## Ubuntu (24.04 ou plus récent)

Télécharger le `.deb` (artefact `netdiag-deb` de la CI GitHub Actions) ou le construire :

```bash
packaging/build-deb.sh                        # → dist/netdiag_<version>_all.deb
sudo apt install ./dist/netdiag_*_all.deb     # installe aussi PyQt6, pyqtgraph, scapy… depuis les dépôts
netdiag                                       # ou « NetDiag » dans le menu des applications
```

Le paquet ne fait que 40 Ko : il s'appuie sur les paquets Python d'Ubuntu (« Architecture: all »).
Ubuntu 22.04 n'est pas pris en charge, car PyQt6 n'y est pas packagé.

**Capture sans lancer l'appli en root**, par ordre de préférence :
1. **dumpcap** (Wireshark) : aucun mot de passe si Wireshark est installé et que l'utilisateur est dans le groupe `wireshark`
   (`sudo dpkg-reconfigure wireshark-common` puis `sudo usermod -aG wireshark $USER`).
2. **tcpdump via polkit** : le mot de passe administrateur est demandé au démarrage de la capture, puis gardé quelques minutes.
   L'aide `netdiag-capture-helper` vérifie ses arguments et s'arrête dès que NetDiag ferme la capture.
3. **Directe** : si l'appli tourne en root.

Lancer depuis les sources : `sudo apt install python3-pyqt6 python3-pyqtgraph python3-scapy python3-dnspython python3-psutil`,
puis `python3 main.py`.

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
- construit le `.deb`, l'installe sur Ubuntu 24.04 et lance `tests/smoke.py` (moteur ICMP, collecte système, interface hors écran) ;
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
main.py                    point d'entrée
netdiag/core/              logique sans interface (testable seule)
  icmp.py                  IcmpSendEcho (Windows) / socket ICMP, mtr-packet, ping (Linux)
  trace.py                 moteur de traceroute continu
  multiping.py             ping multi-cibles
  stats.py                 séries temporelles + stats (perte, jitter…)
  sysinfo.py               collecte Windows (PowerShell / netsh) + synthèse commune
  sysinfo_linux.py         collecte Linux (ip -j, /proc/sys, resolvectl, nmcli…)
  capture.py               Npcap, pktmon, dumpcap, tcpdump via polkit
  tools.py                 DNS, ports TCP, MTU du chemin
netdiag/ui/                onglets Qt (pyqtgraph ; qt.py = compatibilité PySide6 / PyQt6)
packaging/                 build-deb.sh + fichiers Debian (lanceur, .desktop, règle polkit, aide de capture)
tests/smoke.py             test de fumée multiplateforme (utilisé par la CI)
```
