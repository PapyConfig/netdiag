#!/usr/bin/env bash
# Construit les paquets Ubuntu 24.04+ dans dist/ (aucune dépendance de build hors dpkg-deb) :
#   netdiag-tui_<v>_all.deb  moteur + version terminal (léger, sans Qt : serveurs, SSH, tmux)
#   netdiag_<v>_all.deb      interface graphique (dépend de netdiag-tui)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' netdiag/__init__.py)
L=packaging/linux
mkdir -p dist

# $1 = racine du paquet ; $2 = répertoires Python dont le paquet gère les __pycache__
write_scripts() {
    cat > "$1/DEBIAN/postinst" <<EOS
#!/bin/sh
set -e
if [ "\$1" = "configure" ]; then
    for d in $2; do python3 -m compileall -q -l "/usr/lib/netdiag/\$d" >/dev/null 2>&1 || true; done
fi
EOS
    cat > "$1/DEBIAN/prerm" <<EOS
#!/bin/sh
set -e
for d in $2; do rm -rf "/usr/lib/netdiag/\$d/__pycache__"; done
EOS
    chmod 755 "$1/DEBIAN/postinst" "$1/DEBIAN/prerm"
}

finish() {  # $1 = racine, $2 = modèle control, $3 = nom du paquet
    local size
    size=$(du -sk --exclude=DEBIAN "$1" | cut -f1)
    sed -e "s/@VERSION@/$VERSION/g" -e "s/@SIZE@/$size/" "$2" > "$1/DEBIAN/control"
    find "$1" -type d -exec chmod 755 {} +
    find "$1" -name __pycache__ -type d -prune -exec rm -rf {} +
    dpkg-deb --root-owner-group --build "$1" "dist/${3}_${VERSION}_all.deb" >/dev/null
    echo "OK : dist/${3}_${VERSION}_all.deb"
}

# ------------------------------------------------------------------ netdiag-tui (moteur + terminal)
R="build/deb/netdiag-tui"
rm -rf "$R"
install -d "$R/DEBIAN" "$R/usr/lib/netdiag/netdiag" "$R/usr/bin" "$R/usr/share/doc/netdiag-tui"
cp netdiag/__init__.py "$R/usr/lib/netdiag/netdiag/"
cp -r netdiag/core netdiag/tui "$R/usr/lib/netdiag/netdiag/"
install -m 644 tui.py "$R/usr/lib/netdiag/"
install -m 755 "$L/netdiag-capture-helper" "$R/usr/lib/netdiag/"
install -m 755 "$L/netdiag-tui.sh" "$R/usr/bin/netdiag-tui"
install -m 644 README.md "$R/usr/share/doc/netdiag-tui/"
printf 'NetDiag\nCopyright %s PapyConfig\n' "$(date +%Y)" > "$R/usr/share/doc/netdiag-tui/copyright"
write_scripts "$R" "netdiag netdiag/core netdiag/tui"
finish "$R" "$L/control-tui.in" netdiag-tui

# ------------------------------------------------------------------ netdiag (interface graphique)
R="build/deb/netdiag"
rm -rf "$R"
install -d "$R/DEBIAN" "$R/usr/lib/netdiag/netdiag" "$R/usr/bin" "$R/usr/share/applications" \
           "$R/usr/share/icons/hicolor/scalable/apps" "$R/usr/share/polkit-1/actions" "$R/usr/share/doc/netdiag"
cp -r netdiag/ui "$R/usr/lib/netdiag/netdiag/"
install -m 644 main.py "$R/usr/lib/netdiag/"
install -m 755 "$L/netdiag.sh" "$R/usr/bin/netdiag"
install -m 644 "$L/netdiag.desktop" "$R/usr/share/applications/"
install -m 644 netdiag/ui/netdiag.svg "$R/usr/share/icons/hicolor/scalable/apps/"
install -m 644 "$L/io.github.papyconfig.netdiag.policy" "$R/usr/share/polkit-1/actions/"
printf 'NetDiag\nCopyright %s PapyConfig\n' "$(date +%Y)" > "$R/usr/share/doc/netdiag/copyright"
write_scripts "$R" "netdiag/ui"
finish "$R" "$L/control-gui.in" netdiag
