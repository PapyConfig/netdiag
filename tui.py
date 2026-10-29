"""Point d'entrée de la version terminal (netdiag-tui)."""
import sys

from netdiag.tui.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
