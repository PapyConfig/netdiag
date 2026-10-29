"""Couche de compatibilité Qt : PySide6 (pip / Windows) ou PyQt6 (paquet Ubuntu python3-pyqt6).

Les modules UI importent tout depuis ici et utilisent les énumérations entièrement qualifiées
(Qt.AlignmentFlag.AlignRight…), seule forme acceptée par PyQt6. NETDIAG_QT force le choix.
"""
import os

_preferred = os.environ.get("NETDIAG_QT", "")
for API in [_preferred] + ["PySide6", "PyQt6"]:
    try:
        if API == "PySide6":
            from PySide6.QtCore import *   # noqa: F401,F403
            from PySide6.QtGui import *    # noqa: F401,F403
            from PySide6.QtWidgets import *  # noqa: F401,F403
            from PySide6.QtCore import Signal  # noqa: F401
            break
        if API == "PyQt6":
            from PyQt6.QtCore import *   # noqa: F401,F403
            from PyQt6.QtGui import *    # noqa: F401,F403
            from PyQt6.QtWidgets import *  # noqa: F401,F403
            from PyQt6.QtCore import pyqtSignal as Signal  # noqa: F401
            break
    except ImportError:
        continue
else:
    raise ImportError("NetDiag nécessite PySide6 ou PyQt6 (paquet python3-pyqt6 sous Ubuntu)")

# pyqtgraph doit utiliser la même liaison Qt
os.environ["PYQTGRAPH_QT_LIB"] = API
