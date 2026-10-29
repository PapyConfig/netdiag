"""Onglet Système : sections d'informations réseau (liste à gauche, contenu à droite)."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import urwid

from ..core import sysinfo
from .base import Tab
from .widgets import DataTable, SelectableRow, field


class _SectionItem(SelectableRow):
    def __init__(self, section):
        self.section = section
        label = section.title + (f" ({len(section.rows)})" if section.columns and section.key != "overview" else "")
        super().__init__([("error" if section.error else "body", "  " + label)], wrap="clip")


class SystemTab(Tab):
    title = "Système"
    main_index = 1
    keys = [("r", "rafraîchir"), ("/", "filtrer"), ("Tab", "liste ⇄ contenu"), ("p", "IP publique"),
            ("e", "exporter le rapport"), ("←→", "colonnes")]

    def __init__(self, app):
        super().__init__(app)
        self.sections: list[sysinfo.Section] = []
        self.current: sysinfo.Section | None = None
        self._pool = ThreadPoolExecutor(max_workers=2)
        self._future = None
        self._pub = None
        self.filter, filter_w = field("Filtre")
        urwid.connect_signal(self.filter, "change", lambda _w, _t: self.app.loop.set_alarm_in(0, self._show_later))
        self.nav_walker = urwid.SimpleFocusListWalker([])
        self.nav = urwid.ListBox(self.nav_walker)
        urwid.connect_signal(self.nav_walker, "modified", self._on_nav)
        self.table = DataTable([])
        self.text_walker = urwid.SimpleListWalker([])
        self.text = urwid.ListBox(self.text_walker)
        self.err = urwid.Text("")
        self.content = urwid.WidgetPlaceholder(self.table)
        right = urwid.Pile([("pack", self.err), ("weight", 1, self.content)])
        self.cols = urwid.Columns([("given", 44, urwid.LineBox(self.nav, title="Sections")),
                                   ("weight", 1, urwid.LineBox(right, title="Contenu"))], dividechars=0)
        self.status = urwid.Text(("dim", ""))
        self.pile = urwid.Pile([("pack", filter_w), ("weight", 1, self.cols), ("pack", self.status)])
        self.pile.focus_position = 1
        self.widget = urwid.Padding(self.pile, left=1, right=1)
        self.refresh()

    def refresh(self):
        if self._future and not self._future.done():
            return
        self.status.set_text(("info", "Collecte des informations système…"))
        self._future = self._pool.submit(sysinfo.collect)

    def tick(self):
        if self._future and self._future.done():
            fut, self._future = self._future, None
            try:
                self._load(fut.result())
            except Exception as e:  # noqa: BLE001
                self.status.set_text(("error", f"Erreur de collecte : {e}"))
        if self._pub and self._pub.done():
            fut, self._pub = self._pub, None
            try:
                self.app.notify(f"IP publique : {fut.result()}")
            except Exception as e:  # noqa: BLE001
                self.app.notify(f"IP publique introuvable : {e}", "error")

    def _load(self, sections):
        prev = self.current.key if self.current else "overview"
        self.sections = sections
        items, focus = [], 0
        groups = sysinfo.GROUP_ORDER + sorted({s.group for s in sections} - set(sysinfo.GROUP_ORDER))
        for g in groups:
            members = [s for s in sections if s.group == g]
            if not members:
                continue
            items.append(urwid.Text(("title", g)))
            for s in members:
                if s.key == prev:
                    focus = len(items)
                items.append(urwid.AttrMap(_SectionItem(s), None, "sel"))
        self.nav_walker[:] = items
        self.nav_walker.set_focus(focus or 1)
        self._show(self.nav_walker[self.nav_walker.focus].original_widget.section)
        self.status.set_text(("dim", f"{len(sections)} sections — {time.strftime('%H:%M:%S')}"))

    def _on_nav(self):
        w = self.nav_walker[self.nav_walker.focus] if self.nav_walker else None
        if w is not None and hasattr(w, "original_widget"):
            self._show(w.original_widget.section)

    def _show_later(self, *_):
        if self.current:
            self._show(self.current)

    def _show(self, sec):
        self.current = sec
        self.err.set_text(("error", sec.error) if sec.error else "")
        q = self.filter.edit_text.lower().strip()
        if sec.text is not None:
            lines = [l for l in sec.text.splitlines() if not q or q in l.lower()]
            self.text_walker[:] = [urwid.Text(l or " ", wrap="any") for l in lines]
            self.content.original_widget = self.text
        else:
            rows = [r for r in sec.rows if not q or any(q in c.lower() for c in r)]
            self.table.columns = sec.columns
            self.table.offset = 0
            self.table.set_rows(rows)
            self.content.original_widget = self.table

    def on_key(self, key):
        if key == "r":
            self.refresh()
        elif key == "/":
            self.pile.focus_position = 0
        elif key == "enter" and self.pile.focus_position == 0:
            self.pile.focus_position = 1
        elif key == "p":
            self._pub = self._pool.submit(sysinfo.public_ip)
            self.app.notify("Interrogation de api.ipify.org…")
        elif key == "e":
            self._export()
        elif key == "tab":
            self.cols.focus_position = 1 - self.cols.focus_position
        else:
            return False
        return True

    def _export(self):
        if not self.sections:
            return
        path = os.path.abspath(time.strftime("rapport_reseau_%Y%m%d_%H%M%S.txt"))
        with open(path, "w", encoding="utf-8") as f:
            f.write(sysinfo.report_text(self.sections))
        self.app.notify(f"Rapport exporté : {path}")
