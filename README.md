# NetDiag — prototype d'outil de diagnostic réseau pour Windows

Application de bureau (Python + Qt) qui regroupe en une seule fenêtre ce qu'on fait d'habitude
avec `ipconfig`, `route print`, `netsh`, `tracert`, PingPlotter et Wireshark.

## Fonctionnalités

| Onglet | Contenu |
|---|---|
| **Système** | Synthèse (passerelles, IPv4, MTU, DNS), cartes réseau, adresses IP, paramètres IPv4/IPv6 par interface (MTU, métrique, DHCP, forwarding, weak host…), statistiques et propriétés avancées des pilotes, table de routage avec **métrique effective**, ARP/NDP, serveurs DNS, suffixes, cache DNS, connexions TCP/UDP avec processus, profils pare-feu, sortie brute de `ipconfig /all`, `route print`, `netsh` (global, subinterfaces, tcp, wlan, proxy). Filtre, copie vers Excel, export du rapport complet en .txt. Actions : IP publique, vider le cache DNS, renouveler le bail DHCP. |
| **Trace (PingPlotter)** | Traceroute **continu** : chaque saut est sondé à chaque cycle, avec pour chacun perte %, moyenne, min, max, valeur courante et jitter, plus une barre de latence (moyenne colorée, moustache min–max, point = dernière valeur, liseré rouge = perte). En dessous, le graphe temporel du saut sélectionné, avec les pertes en barres rouges. Réglages : intervalle (0,5 à 60 s), taille, nombre de sauts, délai, fenêtre de focus. Détection des sauts à IP multiples (ECMP). Export CSV. |
| **Multi-Ping** | Plusieurs cibles pingées en parallèle sur un même graphe, avec les stats par cible et des triangles pour les pertes. Bouton « Passerelle & DNS » pour ajouter les cibles locales en un clic. Option DF. Export CSV. |
| **Capture** | Capture live avec Scapy + Npcap : choix de l'interface, filtre BPF, liste colorée par protocole, détail et hexdump du paquet, export .pcap, ouverture dans Wireshark. Repli **pktmon** (natif Windows, sans Npcap) avec conversion .pcapng. |
| **Outils** | Résolution DNS (tous types, serveur au choix, comparaison système / 8.8.8.8 / 1.1.1.1 / 9.9.9.9), test de ports TCP (plages acceptées), **découverte du MTU de chemin** par dichotomie avec le bit DF. |

### Points techniques

- **Ping et traceroute sans droits admin** : ils passent par l'API Windows `IcmpSendEcho`
  (`iphlpapi.dll`, via ctypes), comme `tracert` et PingPlotter. Elle permet de fixer le TTL, la taille et le bit DF.
- **Envois asynchrones** : un saut qui ne répond pas ne ralentit pas la cadence des autres.
- **Infos système** : un seul appel PowerShell (cmdlets `NetTCPIP`, `DnsClient`, `NetAdapter`).
  La sortie CSV conserve le nom des énumérations, ce qui la rend lisible.
- Sous Linux, l'appli tourne en mode développement : `ping` système, `psutil` et `ip`.

## Lancer

Prérequis : Windows 10/11, Python 3.10+.

```bat
run.bat
```

Ou à la main : `py -m venv .venv && .venv\Scripts\pip install -r requirements.txt && .venv\Scripts\python main.py`

Pour la capture live, installer [Npcap](https://npcap.com) (option « WinPcap API-compatible mode »).
Certaines captures et pktmon demandent de lancer NetDiag **en administrateur**.

## Construire l'exécutable

```bat
build.bat
```

Résultat : `dist\NetDiag\NetDiag.exe`, dossier autonome qui ne nécessite pas Python sur le poste cible.

## Lire une trace (rappel façon PingPlotter)

- Une perte sur un saut **intermédiaire** qui ne se propage pas aux sauts suivants n'est en général
  pas un problème : beaucoup de routeurs limitent leurs réponses ICMP « TTL expiré ».
  Seule la perte qui continue jusqu'à la destination compte.
- Une latence qui augmente à partir d'un saut et **reste** élevée jusqu'à la destination désigne ce lien.
- Avec un intervalle court (0,5 s), les box et passerelles limitent souvent leurs réponses ICMP.
  On voit alors une perte « fantôme » sur le saut 1.

## Limites du prototype

- Ping et trace en **IPv4 uniquement** (l'IPv6 demanderait `Icmp6SendEcho2`).
- Pas encore de sauvegarde ni de rechargement de sessions, ni d'alertes (seuils et notifications).
- Pas encore de traceroute en TCP ou UDP (utile quand l'ICMP est filtré).
- Codes couleur fixes : vert < 100 ms, jaune < 200 ms, rouge au-delà.

## Structure

```
main.py                    point d'entrée
netdiag/core/              logique sans interface (testable seule)
  icmp.py                  IcmpSendEcho (Windows) / ping (dev)
  trace.py                 moteur de traceroute continu
  multiping.py             ping multi-cibles
  stats.py                 séries temporelles + stats (perte, jitter…)
  sysinfo.py               collecte PowerShell / netsh
  capture.py               Scapy/Npcap + pktmon
  tools.py                 DNS, ports TCP, MTU du chemin
netdiag/ui/                onglets Qt (PySide6 + pyqtgraph)
```
