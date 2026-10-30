#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python_cmd="${PYTHON:-python3}"
if [ -z "${VIRTUAL_ENV:-}" ]; then
  build_venv="$root/build/venv-linux"
  if [ ! -x "$build_venv/bin/python" ]; then
    "$python_cmd" -m venv "$build_venv"
  fi
  python_cmd="$build_venv/bin/python"
fi

version="${VERSION:-$("$python_cmd" -c 'from desktop.config import APP_VERSION; print(APP_VERSION)')}"
arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
if [ "$arch" != "amd64" ]; then
  echo "This package targets Debian amd64 (x64); current architecture is $arch." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required to build the desktop package." >&2
  exit 1
fi
if [ "$(node -p 'process.arch')" != "x64" ]; then
  echo "The bundled Node.js runtime must be x64." >&2
  exit 1
fi
if [ "$("$python_cmd" -c 'import struct; print(struct.calcsize("P") * 8)')" != "64" ]; then
  echo "The build Python runtime must be 64-bit." >&2
  exit 1
fi
"$python_cmd" -m pip install --upgrade pip
"$python_cmd" -m pip install -r "$root/desktop/packaging/requirements-desktop.txt"

mkdir -p "$root/vendor/node"
install -m 0755 "$(command -v node)" "$root/vendor/node/node"

node_depends=""
node_lib="$(ldd "$root/vendor/node/node" 2>/dev/null | awk '/libnode\.so/{print $3}' | head -n 1)"
if [ -n "$node_lib" ]; then
  node_depends="$(dpkg -S "$(readlink -f "$node_lib")" 2>/dev/null | cut -d: -f1 | head -n 1)"
  if [ -z "$node_depends" ]; then
    echo "Could not determine the package that provides $node_lib." >&2
    exit 1
  fi
fi

if [ ! -f "$root/node_modules/wasmoon/package.json" ]; then
  npm ci --omit=dev
fi

"$python_cmd" -m PyInstaller --clean --noconfirm "$root/desktop/packaging/rm7-desktop.spec"

pkgroot="$root/build/deb/rm7-nexus"
rm -rf "$pkgroot"
install -d \
  "$pkgroot/DEBIAN" \
  "$pkgroot/opt/rm7-nexus" \
  "$pkgroot/usr/bin" \
  "$pkgroot/usr/share/applications" \
  "$pkgroot/usr/share/icons/hicolor/256x256/apps"

cp -a "$root/dist/RM7NexusDesktop/." "$pkgroot/opt/rm7-nexus/"
ln -s /opt/rm7-nexus/RM7NexusDesktop "$pkgroot/usr/bin/rm7-nexus"
install -m 0644 "$root/desktop/packaging/assets/rm7nexus.png" \
  "$pkgroot/usr/share/icons/hicolor/256x256/apps/rm7-nexus.png"

cat > "$pkgroot/usr/share/applications/rm7-nexus.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=RM7 Nexus
Comment=Browser-based RM7 Nexus desktop control plane
Exec=rm7-nexus %u
Icon=rm7-nexus
Terminal=false
Categories=Utility;Development;
StartupNotify=true
StartupWMClass=RM7NexusDesktop
DESKTOP

installed_kb="$(du -sk "$pkgroot/opt/rm7-nexus" | awk '{print $1}')"
cat > "$pkgroot/DEBIAN/control" <<CONTROL
Package: rm7-nexus
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Installed-Size: $installed_kb
Maintainer: RM7 Nexus <maintainer@example.invalid>
Depends: xdg-utils${node_depends:+, $node_depends}
Recommends: gnome-keyring | keepassxc | kwalletmanager
Description: RM7 Nexus desktop control plane
 Local browser-based RM7 Nexus control plane with local AMX processing,
 secure Discord account pairing, Premium verification, and signed updates.
CONTROL

cat > "$pkgroot/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
POSTINST

cat > "$pkgroot/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
POSTRM

chmod 0755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/postrm"
chmod 0644 "$pkgroot/DEBIAN/control"

output="$root/dist/rm7-nexus_${version}_${arch}.deb"
rm -f "$output"
dpkg-deb --root-owner-group --build "$pkgroot" "$output"
sha256sum "$output" > "$output.sha256"

echo "Built $output"
dpkg-deb --info "$output"
