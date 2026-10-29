"""Briques UI partagées : thème, exécution en arrière-plan, couleurs de latence, délégué barre."""
from __future__ import annotations

import math
import threading
import traceback

import pyqtgraph as pg
from .qt import QLineF, QObject, QRectF, Qt, Signal
from .qt import QBrush, QColor, QFont, QFontDatabase, QPainter, QPalette, QPen
from .qt import QApplication, QComboBox, QStyledItemDelegate

BG = "#1e1f22"
FG = "#d4d4d4"
SERIES_COLORS = ["#4fc3f7", "#ffb74d", "#81c784", "#f06292", "#ba68c8", "#fff176",
                 "#4db6ac", "#e57373", "#9575cd", "#aed581"]

# Seuils PingPlotter-like (ms)
WARN_MS, BAD_MS = 100, 200


def apply_theme(app: QApplication):
    app.setStyle("Fusion")
    p = QPalette()
    roles = {
        QPalette.ColorRole.Window: "#2b2d30", QPalette.ColorRole.WindowText: FG, QPalette.ColorRole.Base: BG,
        QPalette.ColorRole.AlternateBase: "#26282b", QPalette.ColorRole.ToolTipBase: "#2b2d30", QPalette.ColorRole.ToolTipText: FG,
        QPalette.ColorRole.Text: FG, QPalette.ColorRole.Button: "#3c3f41", QPalette.ColorRole.ButtonText: FG,
        QPalette.ColorRole.BrightText: "#ff5555", QPalette.ColorRole.Highlight: "#2f65ca", QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.PlaceholderText: "#7a7a7a", QPalette.ColorRole.Link: "#4fc3f7",
    }
    for role, color in roles.items():
        p.setColor(role, QColor(color))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor("#6a6a6a"))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor("#6a6a6a"))
    app.setPalette(p)
    app.setStyleSheet("""
        QTabBar::tab { padding: 7px 16px; }
        QTabBar::tab:selected { font-weight: bold; }
        QHeaderView::section { background: #33363a; padding: 4px; border: 0; border-right: 1px solid #222; }
        QTableView { gridline-color: #2f3134; }
        QTreeWidget::item { padding: 3px 0; }
        QGroupBox { border: 1px solid #3c3f41; border-radius: 4px; margin-top: 10px; padding-top: 6px; }
        QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
        QPushButton { padding: 5px 12px; }
        QPushButton#primary { background: #2f65ca; color: white; font-weight: bold; }
        QPushButton#danger { background: #a33; color: white; font-weight: bold; }
        QPlainTextEdit { font-family: Consolas, 'DejaVu Sans Mono', monospace; }
    """)
    pg.setConfigOptions(antialias=True, background=BG, foreground=FG)


def mono_font(size: int = 10) -> QFont:
    """Police à chasse fixe du système (Consolas sous Windows, DejaVu Sans Mono/Ubuntu Mono sous Linux)."""
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(size)
    return f


def latency_color(ms: float | None) -> QColor:
    if ms is None:
        return QColor("#888")
    if ms < WARN_MS:
        return QColor("#66bb6a")
    if ms < BAD_MS:
        return QColor("#ffca28")
    return QColor("#ef5350")


def loss_color(loss: float) -> QColor | None:
    if loss <= 0:
        return None
    if loss < 10:
        return QColor(255, 202, 40, 110)
    if loss < 50:
        return QColor(255, 140, 0, 150)
    return QColor(239, 83, 80, 190)


def fmt_ms(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    if v < 1:
        return f"{v:.2f}"
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


class _Bridge(QObject):
    done = Signal(object, object)
    progress = Signal(str)


_alive: set[_Bridge] = set()


def run_async(fn, on_done=None, on_progress=None, *args, **kwargs):
    """Exécute fn dans un thread ; on_done(result, error) est rappelé dans le thread GUI.
    Si on_progress est fourni, fn reçoit un callback `log` en mot-clé."""
    bridge = _Bridge()
    _alive.add(bridge)

    def finish(res, err):
        _alive.discard(bridge)
        if on_done:
            on_done(res, err)

    bridge.done.connect(finish)
    if on_progress:
        bridge.progress.connect(on_progress)
        kwargs["log"] = bridge.progress.emit

    def target():
        try:
            res, err = fn(*args, **kwargs), None
        except Exception as e:
            traceback.print_exc()
            res, err = None, e
        bridge.done.emit(res, err)

    threading.Thread(target=target, daemon=True).start()


class WindowCombo(QComboBox):
    """Fenêtre de focus pour les stats et les graphes."""
    CHOICES = [("1 min", 60), ("5 min", 300), ("10 min", 600), ("30 min", 1800),
               ("1 h", 3600), ("6 h", 21600), ("Tout", None)]

    def __init__(self, default: str = "5 min"):
        super().__init__()
        for label, sec in self.CHOICES:
            self.addItem(label, sec)
        self.setCurrentText(default)

    def seconds(self) -> float | None:
        return self.currentData()


class LatencyBarDelegate(QStyledItemDelegate):
    """Dessine dans la cellule : min–max (moustache), barre jusqu'à la moyenne, point = courant,
    bandeau rouge proportionnel à la perte. Données dans Qt.ItemDataRole.UserRole : dict."""

    def paint(self, painter: QPainter, option, index):
        super().paint(painter, option, index)
        d = index.data(Qt.ItemDataRole.UserRole)
        if not d or not d.get("scale"):
            return
        r = QRectF(option.rect).adjusted(4, 4, -4, -4)
        scale = d["scale"]
        x = lambda v: r.left() + min(v, scale) / scale * r.width()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # graduations des seuils
        painter.setPen(QPen(QColor(255, 255, 255, 35), 1, Qt.PenStyle.DashLine))
        for t in (WARN_MS, BAD_MS):
            if t < scale:
                painter.drawLine(QLineF(x(t), r.top(), x(t), r.bottom()))
        if d.get("avg") is not None:
            col = latency_color(d["avg"])
            col.setAlpha(170)
            painter.fillRect(QRectF(r.left(), r.top() + 3, x(d["avg"]) - r.left(), r.height() - 6), col)
            painter.setPen(QPen(QColor("#e0e0e0"), 1.2))
            cy = r.center().y()
            painter.drawLine(QLineF(x(d["min"]), cy, x(d["max"]), cy))
            painter.drawLine(QLineF(x(d["min"]), cy - 4, x(d["min"]), cy + 4))
            painter.drawLine(QLineF(x(d["max"]), cy - 4, x(d["max"]), cy + 4))
        if d.get("cur") is not None:
            painter.setBrush(QBrush(QColor("#ffffff")))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QRectF(x(d["cur"]) - 3, r.center().y() - 3, 6, 6))
        if d.get("loss", 0) > 0:
            painter.fillRect(QRectF(r.left(), r.bottom() - 3, r.width() * d["loss"] / 100, 3), QColor("#ef5350"))
        painter.restore()


def make_time_plot(ylabel: str = "Latence (ms)") -> pg.PlotWidget:
    pw = pg.PlotWidget(axisItems={"bottom": pg.DateAxisItem()})
    pw.showGrid(x=True, y=True, alpha=0.2)
    pw.setLabel("left", ylabel)
    pw.setMouseEnabled(x=True, y=False)
    pw.getPlotItem().getViewBox().setLimits(yMin=-50)
    for t, c in ((WARN_MS, "#ffca28"), (BAD_MS, "#ef5350")):
        pw.addItem(pg.InfiniteLine(pos=t, angle=0, pen=pg.mkPen(c, width=1, style=Qt.PenStyle.DotLine)))
    return pw
