#!/usr/bin/env bash
# Construit dist/netdiag_<version>_all.deb (Ubuntu 24.04+). Aucune dépendance de build hors dpkg-deb.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' netdiag/__init__.py)
ROOT="build/deb/netdiag_${VERSION}_all"
L=packaging/linux
rm -rf "$ROOT"
install -d "$ROOT/DEBIAN" "$ROOT/usr/lib/netdiag" "$ROOT/usr/bin" "$ROOT/usr/share/applications" \
           "$ROOT/usr/share/icons/hicolor/scalable/apps" "$ROOT/usr/share/polkit-1/actions" \
           "$ROOT/usr/share/doc/netdiag"

cp -r netdiag main.py "$ROOT/usr/lib/netdiag/"
find "$ROOT/usr/lib/netdiag" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m 755 "$L/netdiag-capture-helper" "$ROOT/usr/lib/netdiag/"
install -m 755 "$L/netdiag.sh" "$ROOT/usr/bin/netdiag"
install -m 644 "$L/netdiag.desktop" "$ROOT/usr/share/applications/"
install -m 644 netdiag/ui/netdiag.svg "$ROOT/usr/share/icons/hicolor/scalable/apps/"
install -m 644 "$L/io.github.papyconfig.netdiag.policy" "$ROOT/usr/share/polkit-1/actions/"
install -m 644 README.md "$ROOT/usr/share/doc/netdiag/"
printf 'NetDiag\nCopyright %s PapyConfig\n' "$(date +%Y)" > "$ROOT/usr/share/doc/netdiag/copyright"
install -m 755 "$L/postinst" "$L/prerm" "$ROOT/DEBIAN/"

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" "$L/control.in" > "$ROOT/DEBIAN/control"
find "$ROOT" -type d -exec chmod 755 {} +

mkdir -p dist
dpkg-deb --root-owner-group --build "$ROOT" "dist/netdiag_${VERSION}_all.deb"
echo "OK : dist/netdiag_${VERSION}_all.deb"
