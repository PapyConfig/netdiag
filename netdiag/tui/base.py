"""Classe de base d'un onglet de la TUI."""
from __future__ import annotations

import urwid


class Tab:
    title = ""
    main_index: int | None = None   # position dans self.pile de la zone principale (cible de Échap)
    # raccourcis affichés en pied de page quand l'onglet est actif : [(touche, description)]
    keys: list[tuple[str, str]] = []

    def __init__(self, app):
        self.app = app
        self.widget: urwid.Widget = urwid.SolidFill(" ")

    def tick(self):
        """Rafraîchissement périodique (≈ 2 fois par seconde) quand l'onglet est visible."""

    def on_show(self):
        """Appelé quand l'onglet devient visible."""

    def on_key(self, key: str) -> bool:
        """Touche non consommée par le widget focalisé. Renvoie True si gérée."""
        return False

    def shutdown(self):
        """Arrêt des tâches de fond à la fermeture."""


WINDOWS = [("1 min", 60), ("5 min", 300), ("10 min", 600), ("30 min", 1800), ("1 h", 3600), ("tout", None)]
