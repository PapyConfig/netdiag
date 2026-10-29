"""Briques urwid partagées : palette, tableau défilant, mini-graphes, graphe de latence."""
from __future__ import annotations

import math

import urwid

WARN_MS, BAD_MS = 100, 200
BLOCKS = "▁▂▃▄▅▆▇█"

PALETTE = [
    ("body", "light gray", "default"),
    ("header", "white,bold", "dark blue"),
    ("tab", "light gray", "dark gray"),
    ("tab_active", "white,bold", "dark blue"),
    ("footer", "light gray", "dark gray"),
    ("key", "yellow,bold", "dark gray"),
    ("title", "white,bold", "default"),
    ("colhead", "white,bold", "dark gray"),
    ("dim", "dark gray", "default"),
    ("ok", "light green", "default"),
    ("warn", "yellow", "default"),
    ("bad", "light red", "default"),
    ("loss", "light red,bold", "default"),
    ("loss_low", "white", "brown"),
    ("loss_mid", "white", "dark magenta"),
    ("loss_high", "white,bold", "dark red"),
    ("sel", "white,bold", "dark blue"),
    ("edit", "white", "dark gray"),
    ("edit_focus", "white,bold", "dark cyan"),
    ("button", "white", "dark gray"),
    ("button_focus", "white,bold", "dark cyan"),
    ("error", "light red,bold", "default"),
    ("info", "light cyan", "default"),
    ("proto_tcp", "light blue", "default"),
    ("proto_udp", "light green", "default"),
    ("proto_dns", "light magenta", "default"),
    ("proto_icmp", "yellow", "default"),
    ("proto_arp", "brown", "default"),
]

# attributs focalisés : même couleur de texte, fond de sélection
FOCUS_MAP = {name: "sel" for name, *_ in PALETTE}
FOCUS_MAP[None] = "sel"


def lat_attr(ms: float | None) -> str:
    if ms is None:
        return "dim"
    return "ok" if ms < WARN_MS else ("warn" if ms < BAD_MS else "bad")


def loss_attr(loss: float) -> str | None:
    if loss <= 0:
        return None
    return "loss_low" if loss < 10 else ("loss_mid" if loss < 50 else "loss_high")


def fmt_ms(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    if v < 1:
        return f"{v:.2f}"
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


def sparkline(samples: list[tuple[float, float | None]], width: int, scale: float) -> list:
    """Un caractère par échantillon (les plus récents à droite) : hauteur = latence, × rouge = perte."""
    data = samples[-width:]
    out = []
    for _, rtt in data:
        if rtt is None:
            out.append(("loss", "×"))
        else:
            lvl = min(len(BLOCKS) - 1, int(rtt / scale * (len(BLOCKS) - 1))) if scale else 0
            out.append((lat_attr(rtt), BLOCKS[lvl]))
    pad = width - len(data)
    return ([("dim", "·" * pad)] if pad > 0 else []) + out


def latency_bar(st, scale: float, width: int) -> list:
    """Barre façon PingPlotter : remplissage jusqu'à la moyenne, ┤ min / ├ max, ● dernière valeur."""
    if st.avg is None or not scale or width < 4:
        return [("loss" if st.sent else "dim", ("perte totale" if st.sent else "")[:width].ljust(width))]
    pos = lambda v: max(0, min(width - 1, int(v / scale * (width - 1))))
    cells = [" "] * width
    a, lo, hi = pos(st.avg), pos(st.min), pos(st.max)
    for i in range(lo, hi + 1):
        cells[i] = "─"
    for i in range(0, a + 1):
        cells[i] = "█"
    cells[hi] = "├" if hi > a else cells[hi]
    if st.cur is not None:
        cells[pos(st.cur)] = "●"
    return [(lat_attr(st.avg), "".join(cells))]


class SelectableRow(urwid.Text):
    _selectable = True

    def keypress(self, size, key):
        return key


class DataTable(urwid.WidgetWrap):
    """Tableau texte : en-tête fixe, lignes sélectionnables, défilement horizontal par colonne (← →).

    Les cellules sont du texte ou un markup urwid [(attr, texte), …]."""

    signals = ["select"]

    def __init__(self, columns: list[str], max_col: int = 34, fixed: int = 0):
        self.columns = columns
        self.max_col = max_col
        self.fixed = fixed          # nombre de colonnes figées à gauche lors du défilement
        self.offset = 0
        self.data: list[list] = []
        self.attrs: list[str | None] = []
        self.widths: list[int] = []
        self.header = urwid.Text("", wrap="clip")
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        urwid.connect_signal(self.walker, "modified", self._on_focus)
        super().__init__(urwid.Frame(self.listbox, header=urwid.AttrMap(self.header, "colhead")))

    @staticmethod
    def _plain(cell) -> str:
        if isinstance(cell, list):
            return "".join(t for _, t in cell)
        return str(cell)

    def set_rows(self, rows: list[list], attrs: list[str | None] | None = None, widths: list[int] | None = None):
        """Remplace le contenu en conservant la ligne focalisée."""
        self.data = rows
        self.attrs = attrs or [None] * len(rows)
        if widths:
            self.widths = widths
        else:
            self.widths = [min(self.max_col, max([len(c)] + [len(self._plain(r[i])) for r in rows if i < len(r)]))
                           for i, c in enumerate(self.columns)]
        self.offset = min(self.offset, max(0, len(self.columns) - 1))
        focus = self.walker.focus if self.walker else 0
        n = len(rows)
        while len(self.walker) > n:
            self.walker.pop()
        while len(self.walker) < n:
            self.walker.append(urwid.AttrMap(SelectableRow("", wrap="clip"), None, FOCUS_MAP))
        for i in range(n):
            self.walker[i].original_widget.set_text(self._render_row(rows[i]))
            self.walker[i].set_attr_map({None: self.attrs[i]})
        if n:
            self.walker.set_focus(min(focus or 0, n - 1))
        self.header.set_text(self._render_row(self.columns))

    def _visible(self) -> list[int]:
        return list(range(self.fixed)) + list(range(self.fixed + self.offset, len(self.columns)))

    def _render_row(self, row) -> list:
        out = []
        for i in self._visible():
            if i >= len(row):
                break
            w = self.widths[i] if i < len(self.widths) else 10
            cell = row[i]
            if isinstance(cell, list):
                text = self._plain(cell)
                if len(text) > w:
                    out.append((cell[0][0] if cell else None, text[:w - 1] + "…"))
                else:
                    out.extend(cell)
                    out.append(" " * (w - len(text)))
            else:
                text = str(cell)
                text = text[:w - 1] + "…" if len(text) > w else text.ljust(w)
                out.append(text)
            out.append(" ")
        return out or [""]

    @property
    def focus_index(self) -> int | None:
        return self.walker.focus if len(self.walker) else None

    def _on_focus(self):
        urwid.emit_signal(self, "select", self.focus_index)

    def keypress(self, size, key):
        if key in ("right", "l") and self.offset < len(self.columns) - self.fixed - 1:
            self.offset += 1
        elif key in ("left", "h") and self.offset > 0:
            self.offset -= 1
        else:
            return super().keypress(size, key)
        self.set_rows(self.data, self.attrs, self.widths)
        return None


class Chart(urwid.Widget):
    """Graphe de latence en colonnes (8 niveaux par ligne grâce aux blocs Unicode).
    Une colonne = un échantillon, ou l'agrégat de plusieurs si la fenêtre est plus large que l'écran.
    Colonne rouge ┃ = perte."""

    _sizing = frozenset(["box"])

    def __init__(self):
        super().__init__()
        self.samples: list[tuple[float, float | None]] = []
        self.title = ""
        self.window: float | None = None

    def set_data(self, samples, title: str = "", window: float | None = None):
        self.samples, self.title, self.window = samples, title, window
        self._invalidate()

    def render(self, size, focus=False):
        maxcol, maxrow = size
        lines: list[list] = [[("title", self.title[:maxcol])]]
        height = max(1, maxrow - 2)
        axis_w = 7
        plot_w = max(1, maxcol - axis_w)
        cols = self._bucket(plot_w)
        vals = [v for v in cols if v is not None and v >= 0]
        top = nice_ceil(max(vals) if vals else 10) or 10
        for r in range(height):
            level_hi = (height - r) / height * top
            level_lo = (height - r - 1) / height * top
            label = f"{_axis(level_hi):>6}│" if r in (0, height // 2) else "      │"
            line = [("dim", label)]
            for v in cols:
                if v is None:
                    line.append(("dim", " "))
                elif v < 0:
                    line.append(("loss", "┃"))
                elif v >= level_hi:
                    line.append((lat_attr(v), "█"))
                elif v > level_lo:
                    frac = (v - level_lo) / (level_hi - level_lo)
                    line.append((lat_attr(v), BLOCKS[max(0, min(7, int(frac * 8) - 1))]))
                else:
                    line.append(" ")
            lines.append(line)
        span = (self.samples[-1][0] - self.samples[0][0]) if len(self.samples) > 1 else 0
        left = f"-{_fmt_span(span)}" if span else ""
        lines.append([("dim", "    ms└" + left + "maintenant".rjust(max(0, plot_w - len(left))))])
        canvases = []
        for markup in lines[:maxrow]:
            t = urwid.Text(markup, wrap="clip")
            canvases.append((t.render((maxcol,)), None, False))
        while len(canvases) < maxrow:
            canvases.append((urwid.Text("").render((maxcol,)), None, False))
        return urwid.CanvasCombine(canvases)

    def _bucket(self, width: int) -> list[float | None]:
        """Valeur par colonne (les plus récentes à droite) : un échantillon par colonne tant que ça tient,
        sinon moyenne de groupes d'échantillons ; -1 si le groupe contient une perte, None si vide."""
        data = self.samples
        per = max(1, math.ceil(len(data) / width))
        groups = [[r for _, r in data[i:i + per]] for i in range(0, len(data), per)][-width:]
        out: list[float | None] = [None] * (width - len(groups))
        for g in groups:
            out.append(-1 if any(r is None for r in g) else sum(g) / len(g))
        return out


def _axis(v: float) -> str:
    return f"{v:.0f}" if v >= 10 else (f"{v:.1f}" if v >= 1 else f"{v:.2f}")


def nice_ceil(v: float) -> float:
    if v <= 0:
        return 0
    mag = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag


def _fmt_span(sec: float) -> str:
    if sec >= 3600:
        return f"{sec / 3600:.0f} h"
    if sec >= 60:
        return f"{sec / 60:.0f} min"
    return f"{sec:.0f} s"


class Button(urwid.WidgetWrap):
    """Bouton compact « [ texte ] »."""

    def __init__(self, label: str, on_press):
        b = urwid.Button(label, on_press=lambda _b: on_press())
        b._label.align = "center"
        self.width = len(label) + 4
        super().__init__(urwid.AttrMap(b, "button", "button_focus"))


def field(caption: str, text: str = "", width: int | None = None,
          integer: bool = False) -> tuple[urwid.Edit, urwid.Widget]:
    """Champ de saisie avec légende ; renvoie (edit, widget à placer)."""
    edit = urwid.IntEdit("", int(text or 0)) if integer else urwid.Edit("", text)
    w = urwid.Columns([("pack", urwid.Text(caption + " ")), urwid.AttrMap(edit, "edit", "edit_focus")])
    return edit, (("given", width, w) if width else w)


class Cycle(urwid.WidgetWrap):
    """Sélecteur à valeurs cycliques (Entrée / espace / clic pour changer)."""

    def __init__(self, caption: str, choices: list[tuple[str, object]], index: int = 0, on_change=None):
        self.caption, self.choices, self.index, self.on_change = caption, choices, index, on_change
        self._btn = urwid.Button("", on_press=lambda _b: self.next())
        self._btn._label.set_wrap_mode("clip")
        # largeur fixe = libellé le plus long (+4 pour « < » et « > »)
        self.width = max(len(f"{caption}: {c}") for c, _ in choices) + 4
        super().__init__(urwid.AttrMap(self._btn, "button", "button_focus"))
        self._update()

    def _update(self):
        self._btn.set_label(f"{self.caption}: {self.choices[self.index][0]}")

    def next(self):
        self.index = (self.index + 1) % len(self.choices)
        self._update()
        if self.on_change:
            self.on_change(self.value)

    def set_choices(self, choices, index: int = 0):
        self.choices, self.index = choices or [("—", None)], index
        self._update()

    @property
    def value(self):
        return self.choices[self.index][1]

    @property
    def label(self) -> str:
        return self.choices[self.index][0]
