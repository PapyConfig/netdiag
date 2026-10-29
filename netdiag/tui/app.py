"""Application urwid : barre d'onglets, pied de page, aide, fenêtres popup, boucle de rafraîchissement."""
from __future__ import annotations

import time
import traceback

import urwid

from .. import __version__
from ..core.icmp import BACKEND
from ..core.utils import is_admin
from .capture import CaptureTab
from .multiping import MultiPingTab
from .system import SystemTab
from .tools import ToolsTab
from .trace import TraceTab
from .widgets import PALETTE

GLOBAL_KEYS = [("F1-F5", "onglets"), ("Tab", "champ suivant"), ("?", "aide"), ("q", "quitter")]

HELP = """NetDiag — version terminal

NAVIGATION
  F1 … F5 / Alt+1 … Alt+5   changer d'onglet (ou clic sur l'onglet)
  Tab / Maj+Tab             champ ou zone suivante / précédente
  ↑ ↓ PgUp PgDn             parcourir les tableaux
  ← →                       faire défiler les colonnes d'un tableau
  Entrée                    valider un champ / lancer / détail
  Échap                     quitter un champ de saisie (les raccourcis lettres redeviennent actifs)
  ?                         cette aide          q ou F10   quitter
  Échap / q                 fermer une fenêtre

TRACE (F2)        s start/stop · i intervalle · f fenêtre de focus · n noms DNS · e export CSV
                  Colonnes : perte, latences (moy/min/cur/max), jitter, barre de latence
                  (█ moyenne, ─ jusqu'au max, ● dernière valeur), historique (× = perte).
                  Le graphe du bas montre le saut sélectionné.
MULTI-PING (F3)   Entrée ajouter · g passerelle+DNS · s start/stop · d supprimer · r remise à zéro
CAPTURE (F4)      s start/stop · Entrée détail du paquet · w enregistrer .pcap · m méthode · i interface
                  La méthode « tcpdump (sudo) » demande votre mot de passe dans le terminal.
SYSTÈME (F1)      r rafraîchir · / filtrer · Tab liste ⇄ contenu · p IP publique · e exporter

LECTURE D'UNE TRACE
  Une perte sur un saut intermédiaire qui ne se propage pas aux suivants est en général
  sans conséquence (limitation ICMP du routeur). Seule la perte qui va jusqu'à la
  destination compte. Une latence qui augmente à partir d'un saut et reste élevée
  désigne ce lien.

Dans tmux : activez la souris avec « set -g mouse on » pour cliquer onglets et boutons.
"""


class _TabLabel(urwid.Text):
    def __init__(self, text, on_click):
        super().__init__(text)
        self._on_click = on_click

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self._on_click()
            return True
        return False


class App:
    def __init__(self, start_tab: str = "system", trace_target: str = "", ping_hosts=None,
                 interval: float | None = None):
        self.loop: urwid.MainLoop | None = None
        self.message = ("", "footer", 0.0)
        self.tabs = [SystemTab(self), TraceTab(self, trace_target, interval or 2.5),
                     MultiPingTab(self, ping_hosts, interval or 1.0), CaptureTab(self), ToolsTab(self)]
        self.index = 0
        self.tabbar = urwid.Columns([], dividechars=1)
        self.header_right = urwid.Text(("header", f"ICMP : {BACKEND}{'  [root]' if is_admin() else ''} "),
                                       align="right")
        self.footer_keys = urwid.Text("", wrap="clip")
        self.footer_msg = urwid.Text("", wrap="clip")
        self.body = urwid.WidgetPlaceholder(self.tabs[0].widget)
        header = urwid.AttrMap(urwid.Columns([("pack", urwid.Text(("header", f" NetDiag {__version__} "))),
                                              ("weight", 1, self.tabbar), ("pack", self.header_right)],
                                             dividechars=1), "header")
        footer = urwid.Pile([urwid.AttrMap(self.footer_keys, "footer"), self.footer_msg])
        self.frame = urwid.Frame(urwid.AttrMap(self.body, "body"), header=header, footer=footer)
        self.overlay_open = False
        names = {"system": 0, "trace": 1, "ping": 2, "capture": 3, "tools": 4}
        self.show_tab(names.get(start_tab, 0))

    # ------------------------------------------------------------------ onglets
    def show_tab(self, i: int):
        self.index = i
        tab = self.tabs[i]
        self.body.original_widget = tab.widget
        self.tabbar.contents = [
            (urwid.AttrMap(_TabLabel(f" F{j + 1} {t.title} ", lambda j=j: self.show_tab(j)),
                           "tab_active" if j == i else "tab"), self.tabbar.options("pack"))
            for j, t in enumerate(self.tabs)]
        markup = []
        for k, d in tab.keys + GLOBAL_KEYS:
            markup += [("key", f" {k} "), ("footer", f"{d} ")]
        self.footer_keys.set_text(markup)
        try:
            tab.on_show()
            tab.tick()
        except Exception:  # noqa: BLE001
            self._report_error()

    # ------------------------------------------------------------------ services pour les onglets
    def notify(self, text: str, attr: str = "info"):
        self.message = (text, attr, time.time())
        self.footer_msg.set_text((attr, " " + text))

    def popup(self, title: str, text: str):
        lines = [urwid.Text(l or " ", wrap="clip") for l in text.splitlines()]
        box = urwid.LineBox(urwid.ListBox(urwid.SimpleFocusListWalker(lines)),
                            title=f"{title}  (Échap pour fermer)")
        self.loop.widget = urwid.Overlay(urwid.AttrMap(box, "body"), self.frame, "center", ("relative", 85),
                                         "middle", ("relative", 85))
        self.overlay_open = True

    def close_popup(self):
        self.loop.widget = self.frame
        self.overlay_open = False

    def screen_cols(self) -> int:
        try:
            return self.loop.screen.get_cols_rows()[0]
        except Exception:  # noqa: BLE001  (pas encore de terminal : tests, rendu hors écran)
            return 160

    def focused_edit(self) -> urwid.Edit | None:
        for w in reversed(self.frame.get_focus_widgets()):
            base = w.base_widget
            if isinstance(base, urwid.Edit):
                return base
        return None

    # ------------------------------------------------------------------ clavier
    def on_input(self, key):
        if not isinstance(key, str):
            return
        if self.overlay_open:
            if key in ("esc", "q", "enter"):
                self.close_popup()
            return
        tab = self.tabs[self.index]
        try:
            if tab.on_key(key):
                return
        except Exception:  # noqa: BLE001
            self._report_error()
            return
        if key == "esc" and tab.main_index is not None:
            tab.pile.focus_position = tab.main_index  # quitter le champ de saisie → zone principale
            return
        fkeys = {f"f{i + 1}": i for i in range(len(self.tabs))}
        fkeys.update({f"meta {i + 1}": i for i in range(len(self.tabs))})
        if key in fkeys:
            self.show_tab(fkeys[key])
        elif key in ("q", "Q", "f10"):
            raise urwid.ExitMainLoop()
        elif key == "?":
            self.popup("Aide", HELP)
        elif key in ("tab", "shift tab"):
            self._cycle_focus(tab, reverse=key == "shift tab")

    def _cycle_focus(self, tab, reverse: bool):
        """Passe au champ / à la zone sélectionnable suivante de l'onglet (dans le Pile principal)."""
        pile = getattr(tab, "pile", None)
        if pile is None:
            return
        targets = []
        for pi, (w, _) in enumerate(pile.contents):
            base = w.base_widget
            if isinstance(base, urwid.Columns):
                targets += [(pi, ci) for ci, (cw, _) in enumerate(base.contents) if cw.selectable()]
            elif w.selectable():
                targets.append((pi, None))
        if not targets:
            return
        cur_p = pile.focus_position
        cur_base = pile.contents[cur_p][0].base_widget
        cur = (cur_p, cur_base.focus_position if isinstance(cur_base, urwid.Columns) else None)
        i = targets.index(cur) if cur in targets else -1
        pi, ci = targets[(i + (-1 if reverse else 1)) % len(targets)]
        pile.focus_position = pi
        if ci is not None:
            pile.contents[pi][0].base_widget.focus_position = ci

    # ------------------------------------------------------------------ boucle
    def _tick(self, loop, _data):
        try:
            self.tabs[self.index].tick()
        except Exception:  # noqa: BLE001
            self._report_error()
        text, attr, t = self.message
        if text and time.time() - t > 8:
            self.message = ("", "footer", 0.0)
            self.footer_msg.set_text("")
        loop.set_alarm_in(0.5, self._tick)

    def _report_error(self):
        last = traceback.format_exc().strip().splitlines()[-1]
        self.notify(f"Erreur interne : {last}", "error")

    def run(self):
        self.loop = urwid.MainLoop(self.frame, PALETTE, unhandled_input=self.on_input, handle_mouse=True)
        self.loop.set_alarm_in(0.1, self._tick)
        try:
            self.loop.run()
        finally:
            for t in self.tabs:
                try:
                    t.shutdown()
                except Exception:  # noqa: BLE001
                    pass
