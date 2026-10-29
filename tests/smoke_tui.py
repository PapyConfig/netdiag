"""Test de fumée de la version terminal : rendu de chaque onglet sans terminal + modes rapport.

Usage : python3 tests/smoke_tui.py
"""
import io
import json
import os
import sys
import time
from contextlib import redirect_stdout

sys.path.insert(0, os.environ.get("NETDIAG_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

errors = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        errors.append(msg)


from netdiag.tui.__main__ import main  # noqa: E402
from netdiag.tui.app import App  # noqa: E402

# ------------------------------------------------------------------ modes rapport
buf = io.StringIO()
with redirect_stdout(buf):
    rc = main(["report", "--json", "-s", "overview", "-s", "routes"])
data = json.loads(buf.getvalue())
check(rc == 0 and [s["key"] for s in data] == ["overview", "routes"], "report --json -s overview -s routes")

buf = io.StringIO()
with redirect_stdout(buf):
    rc = main(["trace", "127.0.0.1", "--json", "-c", "3", "-i", "0.2"])
tr = json.loads(buf.getvalue())
check(rc == 0 and tr["reached_at"] == 1 and tr["hops"][0]["sent"] == 3, f"trace --json -c 3 → {tr['hops'][:1]}")

buf = io.StringIO()
with redirect_stdout(buf):
    rc = main(["ping", "127.0.0.1", "--report", "-c", "3", "-i", "0.2"])
check(rc == 0 and "127.0.0.1" in buf.getvalue(), "ping --report -c 3")

# ------------------------------------------------------------------ interface (rendu hors terminal)
app = App(start_tab="trace", trace_target="127.0.0.1", ping_hosts=["127.0.0.1"], interval=0.5)
SIZE = (160, 45)


def screen() -> str:
    canvas = app.frame.render(SIZE, focus=True)
    return "\n".join(line.decode("utf-8", "replace") for line in canvas.text)


def wait_for(pred, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        for t in app.tabs:
            t.tick()
        if pred():
            return True
        time.sleep(0.25)
    return False


wait_for(lambda: app.tabs[1].session and app.tabs[1].session.cycles >= 3 and app.tabs[2].targets[0].series.stats().recv)
expected = {0: "Synthèse", 1: "destination 127.0.0.1 atteinte", 2: "127.0.0.1", 3: "Méthode", 4: "Résolution DNS"}
for i, tab in enumerate(app.tabs):
    app.show_tab(i)
    if i == 0:
        wait_for(lambda: bool(app.tabs[0].sections), 60)
    if i == 3:
        wait_for(lambda: bool(app.tabs[3].methods) or app.tabs[3]._loading is None, 30)
    tab.tick()
    text = screen()
    check(expected[i] in text, f"onglet {tab.title} : « {expected[i]} » affiché")
    if i == 1:
        print("\n".join(text.splitlines()[:8]))

# navigation clavier simulée
app.show_tab(0)
for key in ("tab", "down", "down", "right", "?"):
    app.loop = type("L", (), {"widget": app.frame, "set_alarm_in": lambda *a: None})()
    if key == "?":
        app.on_input(key)
    else:
        app.frame.keypress(SIZE, key) and app.on_input(key)
check(app.overlay_open, "aide ouverte avec « ? »")
app.on_input("esc")
check(not app.overlay_open, "aide fermée avec Échap")
for t in app.tabs:
    t.shutdown()

if errors:
    print(f"\n{len(errors)} échec(s)")
    sys.exit(1)
print("\nTous les tests de fumée TUI sont passés.")
