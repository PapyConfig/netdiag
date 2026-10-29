"""Test de fumée multiplateforme : moteur ICMP, collecte système, interface hors écran.

Usage : QT_QPA_PLATFORM=offscreen python tests/smoke.py [capture.png]
Sortie non nulle si une vérification échoue ou si une exception survient dans l'interface.
"""
import os
import sys
import time
import traceback

# console Windows en cp1252 : forcer l'UTF-8 pour les messages accentués / flèches
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.environ.get("NETDIAG_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

errors: list[str] = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        errors.append(msg)


def hook(etype, value, tb):
    errors.append("".join(traceback.format_exception(etype, value, tb)))
    traceback.print_exception(etype, value, tb)


sys.excepthook = hook

# ------------------------------------------------------------------ cœur
from netdiag.core import icmp, sysinfo, tools  # noqa: E402

print("Moteur ICMP :", icmp.BACKEND)
p = icmp.Pinger()
r = p.ping("127.0.0.1", timeout=2000)
check(r.status == "ok" and r.rtt is not None, f"ping 127.0.0.1 → {r}")
r = p.ping("8.8.8.8", ttl=1, timeout=2000)
print("info : ping 8.8.8.8 TTL=1 →", r)
check(tools.parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002], "parse_ports")

t0 = time.time()
sections = sysinfo.collect()
print(f"Collecte système : {len(sections)} sections en {time.time() - t0:.1f} s")
for s in sections:
    flag = "ERR " if s.error else "    "
    print(f"  {flag}{s.group:15} {s.title:45} lignes={len(s.rows):4} texte={len(s.text or ''):6} {s.error[:90]}")
by = {s.key: s for s in sections}
check("overview" in by and len(by["overview"].rows) >= 4, "synthèse présente")
for key in ("adapters", "ipaddr", "routes", "dns_servers"):
    check(key in by and bool(by[key].rows), f"section {key} non vide")

# ------------------------------------------------------------------ interface
from netdiag.ui.qt import QApplication, QTimer  # noqa: E402
from netdiag.ui.common import apply_theme  # noqa: E402
from netdiag.ui.main_window import MainWindow  # noqa: E402

app = QApplication(sys.argv[:1])
apply_theme(app)
w = MainWindow()
w.resize(1400, 860)
w.show()
w.trace_tab.target.setText("127.0.0.1")
w.trace_tab.interval.setCurrentIndex(0)
w.trace_tab.toggle()
w.ping_tab.add_targets(["127.0.0.1", "192.0.2.1"])  # 192.0.2.1 (TEST-NET) : pertes attendues


def browse_sysinfo(waited=0):
    tree = w.sys_tab.tree
    if tree.topLevelItemCount() == 0 and waited < 60:  # collecte encore en cours (≈ 10 s sous Windows)
        QTimer.singleShot(1000, lambda: browse_sysinfo(waited + 1))
        return
    for i in range(tree.topLevelItemCount()):
        g = tree.topLevelItem(i)
        for j in range(g.childCount()):
            tree.setCurrentItem(g.child(j))
            app.processEvents()
    check(tree.topLevelItemCount() > 0, "arbre système rempli")
    visit_tabs()
    QTimer.singleShot(5000, finish)


def visit_tabs():
    for i in range(w.tabs.count()):
        w.tabs.setCurrentIndex(i)
        app.processEvents()
    w.trace_tab.table.selectRow(0)


def finish():
    hops = w.trace_tab.session.hops() if w.trace_tab.session else []
    check(bool(hops) and hops[-1].ip == "127.0.0.1", f"trace 127.0.0.1 : {len(hops)} saut(s)")
    t = w.ping_tab.targets[0]
    st = t.series.stats()
    check(st.recv > 0, f"multi-ping 127.0.0.1 : {st.recv}/{st.sent} réponses")
    w.tabs.setCurrentWidget(w.cap_tab)
    print("Capture :", w.cap_tab.status.text(), "| méthodes :", [m.key for m in w.cap_tab.methods])
    w.tabs.setCurrentWidget(w.trace_tab)
    app.processEvents()
    if len(sys.argv) > 1:
        w.grab().save(sys.argv[1])
        print("capture d'écran :", sys.argv[1])
    w.close()
    app.quit()


QTimer.singleShot(3000, browse_sysinfo)
app.exec()

if errors:
    print(f"\n{len(errors)} échec(s)")
    sys.exit(1)
print("\nTous les tests de fumée sont passés.")
