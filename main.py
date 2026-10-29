"""Point d'entrée de NetDiag."""
import sys

from PySide6.QtWidgets import QApplication

from netdiag.ui.common import apply_theme
from netdiag.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetDiag")
    apply_theme(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
