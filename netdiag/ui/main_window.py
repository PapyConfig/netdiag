from __future__ import annotations

from PySide6.QtWidgets import QLabel, QMainWindow, QTabWidget

from ..core.icmp import BACKEND
from ..core.utils import is_admin
from .capture_tab import CaptureTab
from .multiping_tab import MultiPingTab
from .sysinfo_tab import SysInfoTab
from .tools_tab import ToolsTab
from .trace_tab import TraceTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetDiag — diagnostic réseau")
        self.resize(1400, 860)
        self.tabs = QTabWidget()
        self.sys_tab = SysInfoTab()
        self.trace_tab = TraceTab()
        self.ping_tab = MultiPingTab()
        self.cap_tab = CaptureTab()
        self.tools_tab = ToolsTab()
        self.tabs.addTab(self.sys_tab, "Système")
        self.tabs.addTab(self.trace_tab, "Trace (PingPlotter)")
        self.tabs.addTab(self.ping_tab, "Multi-Ping")
        self.tabs.addTab(self.cap_tab, "Capture")
        self.tabs.addTab(self.tools_tab, "Outils")
        self.tabs.currentChanged.connect(self._on_tab)
        self.setCentralWidget(self.tabs)

        admin = is_admin()
        lbl = QLabel(f"  ICMP : {BACKEND}   |   "
                     f"{'Administrateur' if admin else 'Utilisateur standard (capture limitée)'}  ")
        lbl.setStyleSheet("color:#9a9a9a")
        self.statusBar().addPermanentWidget(lbl)
        self.sys_tab.refresh()

    def _on_tab(self, idx):
        if self.tabs.widget(idx) is self.cap_tab:
            self.cap_tab.ensure_loaded()

    def closeEvent(self, e):
        self.trace_tab.stop()
        self.ping_tab.shutdown()
        self.cap_tab.shutdown()
        super().closeEvent(e)
