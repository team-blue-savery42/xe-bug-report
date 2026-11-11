#!/bin/sh
# SPDX-License-Identifier: MIT
# Builds the Arch Linux package from packaging/arch/PKGBUILD and the committed tree (HEAD):
#   dist/xe-bug-report-<version>-source.tar.gz        git archive of HEAD, the PKGBUILD's source
#   dist/xe-bug-report-<version>-<pkgrel>-<arch>.pkg.tar.zst
#   dist/aur/PKGBUILD, dist/aur/.SRCINFO              pkgver and checksum filled in, for the AUR
# Usage: scripts/package-arch.sh   (on Arch, as a user that may run makepkg, i.e. not root)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

name=xe-bug-report
version=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
if [ -z "$version" ]; then
    echo "package-arch.sh: cannot read the version from Cargo.toml" >&2
    exit 1
fi
# makepkg forbids "-" in pkgver; a pre-release such as 1.0.0-rc.1 becomes 1.0.0_rc.1.
pkgver=$(printf '%s' "$version" | tr '-' '_')
if ! command -v makepkg >/dev/null 2>&1; then
    echo "package-arch.sh: makepkg not found (run it on Arch Linux)" >&2
    exit 1
fi

dist=$root/dist
mkdir -p "$dist/aur"
work=$(mktemp -d "${TMPDIR:-/tmp}/$name-arch.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The PKGBUILD unpacks to $pkgname-$_version (the release version), so that is the prefix.
source=$name-$version-source.tar.gz
git archive --format=tar.gz --prefix="$name-$version/" -o "$work/$source" HEAD
sum=$(sha256sum "$work/$source" | cut -d ' ' -f 1)
sed -e "s/^pkgver=.*/pkgver=$pkgver/" -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums=.*/sha256sums=('$sum')/" packaging/arch/PKGBUILD >"$work/PKGBUILD"

# The tarball is already beside the PKGBUILD, so makepkg verifies it instead of downloading.
(cd "$work" && PKGDEST="$dist" makepkg --noconfirm --cleanbuild && makepkg --printsrcinfo >.SRCINFO)
cp "$work/PKGBUILD" "$work/.SRCINFO" "$dist/aur/"
cp "$work/$source" "$dist/"
echo "wrote $dist/$source"
for pkg in "$dist"/"$name"-"$pkgver"-*.pkg.tar.zst; do
    [ -f "$pkg" ] && echo "wrote $pkg"
done
echo "wrote $dist/aur/PKGBUILD and $dist/aur/.SRCINFO"
