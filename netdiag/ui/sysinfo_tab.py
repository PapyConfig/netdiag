from __future__ import annotations

from .qt import Qt
from .qt import QBrush, QColor, QGuiApplication
from .qt import (QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core import sysinfo
from ..core.utils import IS_WINDOWS
from .common import mono_font, run_async


class SysInfoTab(QWidget):
    def __init__(self):
        super().__init__()
        self.sections: list[sysinfo.Section] = []
        self.current: sysinfo.Section | None = None

        bar = QHBoxLayout()
        self.btn_refresh = QPushButton("⟳ Rafraîchir")
        self.btn_refresh.setObjectName("primary")
        self.btn_refresh.clicked.connect(self.refresh)
        self.filter = QLineEdit(placeholderText="Filtrer la vue (texte libre)…")
        self.filter.textChanged.connect(self._apply_filter)
        btn_copy = QPushButton("Copier la vue")
        btn_copy.clicked.connect(self._copy)
        btn_export = QPushButton("Exporter tout…")
        btn_export.clicked.connect(self._export)
        btn_pub = QPushButton("IP publique")
        btn_pub.setToolTip("Interroge api.ipify.org")
        btn_pub.clicked.connect(self._public_ip)
        btn_flush = QPushButton("Vider le cache DNS")
        btn_flush.clicked.connect(lambda: self._action(sysinfo.flush_dns, "Vider le cache DNS"))
        btn_renew = QPushButton("Renouveler DHCP")
        btn_renew.clicked.connect(self._renew)
        self.status = QLabel("")
        for w in (self.btn_refresh, self.filter, btn_copy, btn_export, btn_pub, btn_flush, btn_renew):
            bar.addWidget(w)
        bar.setStretchFactor(self.filter, 1)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setMinimumWidth(240)
        self.tree.currentItemChanged.connect(self._on_select)

        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.text = QPlainTextEdit(readOnly=True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(mono_font(10))
        self.err = QLabel(wordWrap=True)
        self.err.setStyleSheet("color:#ef5350; padding:4px")
        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(self.text)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.err)
        rl.addWidget(self.stack)

        split = QSplitter()
        split.addWidget(self.tree)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        split.setSizes([260, 1000])

        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(split, 1)
        lay.addWidget(self.status)

    # ------------------------------------------------------------------ collecte
    def refresh(self):
        self.btn_refresh.setEnabled(False)
        self.status.setText("Collecte des informations système en cours…")
        run_async(sysinfo.collect, self._on_collected)

    def _on_collected(self, sections, err):
        self.btn_refresh.setEnabled(True)
        if err:
            self.status.setText(f"Erreur de collecte : {err}")
            return
        prev = self.current.key if self.current else "overview"
        self.sections = sections
        self.tree.clear()
        groups: dict[str, QTreeWidgetItem] = {}
        select = None
        for g in sysinfo.GROUP_ORDER + sorted({s.group for s in sections} - set(sysinfo.GROUP_ORDER)):
            members = [s for s in sections if s.group == g]
            if not members:
                continue
            gi = QTreeWidgetItem([g])
            gi.setFlags(gi.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            f = gi.font(0)
            f.setBold(True)
            gi.setFont(0, f)
            self.tree.addTopLevelItem(gi)
            groups[g] = gi
            for s in members:
                label = s.title + (f"  ({len(s.rows)})" if s.columns and s.key != "overview" else "")
                it = QTreeWidgetItem([label])
                it.setData(0, Qt.ItemDataRole.UserRole, s)
                if s.error:
                    it.setForeground(0, QBrush(QColor("#ef5350")))
                gi.addChild(it)
                if s.key == prev:
                    select = it
        self.tree.expandAll()
        if select:
            self.tree.setCurrentItem(select)
        self.status.setText(f"{len(sections)} sections collectées.")

    # ------------------------------------------------------------------ affichage
    def _on_select(self, item, _prev):
        sec = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if not sec:
            return
        self.current = sec
        self.err.setVisible(bool(sec.error))
        self.err.setText(sec.error)
        if sec.text is not None:
            self.text.setPlainText(sec.text)
            self.stack.setCurrentWidget(self.text)
        else:
            self.table.setSortingEnabled(False)
            self.table.clear()
            self.table.setColumnCount(len(sec.columns))
            self.table.setHorizontalHeaderLabels(sec.columns)
            self.table.setRowCount(len(sec.rows))
            for r, row in enumerate(sec.rows):
                for c, val in enumerate(row):
                    it = QTableWidgetItem(val)
                    if val.lstrip("-").isdigit():  # tri numérique correct
                        it.setData(Qt.ItemDataRole.DisplayRole, int(val))
                    self.table.setItem(r, c, it)
            self.table.resizeColumnsToContents()
            for c in range(self.table.columnCount()):
                self.table.setColumnWidth(c, min(self.table.columnWidth(c), 380))
            self.table.setSortingEnabled(sec.key != "overview")
            self.stack.setCurrentWidget(self.table)
        self._apply_filter()

    def _apply_filter(self):
        q = self.filter.text().lower().strip()
        if self.current and self.current.text is not None:
            text = self.current.text
            if q:
                text = "\n".join(l for l in text.splitlines() if q in l.lower())
            self.text.setPlainText(text)
            return
        for r in range(self.table.rowCount()):
            match = not q or any(q in (self.table.item(r, c).text().lower() if self.table.item(r, c) else "")
                                 for c in range(self.table.columnCount()))
            self.table.setRowHidden(r, not match)

    @staticmethod
    def _section_text(s: sysinfo.Section, visible_rows=None) -> str:
        if s.text is not None:
            return s.text
        rows = visible_rows if visible_rows is not None else s.rows
        return "\n".join(["\t".join(s.columns)] + ["\t".join(r) for r in rows])

    def _copy(self):
        if not self.current:
            return
        if self.current.text is not None:
            txt = self.text.toPlainText()
        else:
            rows = [[self.table.item(r, c).text() if self.table.item(r, c) else ""
                     for c in range(self.table.columnCount())]
                    for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
            txt = self._section_text(self.current, rows)
        QGuiApplication.clipboard().setText(txt)
        self.status.setText("Vue copiée dans le presse-papiers (format tabulé, collable dans Excel).")

    def _export(self):
        if not self.sections:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter le rapport", "rapport_reseau.txt",
                                              "Texte (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for s in self.sections:
                f.write(f"\n{'=' * 100}\n{s.group} / {s.title}\n{'=' * 100}\n")
                if s.error:
                    f.write(f"ERREUR : {s.error}\n")
                f.write(self._section_text(s) + "\n")
        self.status.setText(f"Rapport exporté : {path}")

    def _public_ip(self):
        self.status.setText("Interrogation de api.ipify.org…")
        run_async(sysinfo.public_ip, lambda r, e: self.status.setText(
            f"IP publique : {r}" if not e else f"IP publique introuvable : {e}"))

    def _action(self, fn, title):
        run_async(fn, lambda r, e: QMessageBox.information(self, title, str(e or r)))

    def _renew(self):
        if QMessageBox.question(self, "Renouveler DHCP",
                                f"Lancer « {'ipconfig /renew' if IS_WINDOWS else 'renouvellement via NetworkManager'} » ? "
                                "La connectivité peut être brièvement coupée.") \
                == QMessageBox.StandardButton.Yes:
            self._action(sysinfo.renew_dhcp, "Renouveler DHCP")
