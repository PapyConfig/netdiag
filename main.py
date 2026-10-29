"""Point d'entrée de NetDiag."""
import os
import sys
import traceback

from netdiag.ui.qt import QApplication, QIcon

from netdiag.ui.common import apply_theme
from netdiag.ui.main_window import MainWindow


def _log_exception(etype, value, tb):
    # Sans ce hook, PyQt6 interrompt l'application à la première exception levée dans un slot.
    traceback.print_exception(etype, value, tb)


def main():
    sys.excepthook = _log_exception
    app = QApplication(sys.argv)
    app.setApplicationName("NetDiag")
    app.setDesktopFileName("netdiag")  # associe la fenêtre à netdiag.desktop (icône sous Wayland)
    app.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "netdiag", "ui", "netdiag.svg")))
    apply_theme(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
