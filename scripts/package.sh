#!/bin/sh
# SPDX-License-Identifier: MIT
# Builds the release binary and packages it under dist/:
#   dist/xe-bug-report-<version>-<target>.tar.gz   binary, LICENSE, README.md (always)
#   dist/xe-bug-report_<version>_<arch>.deb        when dpkg-deb exists (packaging/deb/control)
#   dist/xe-bug-report-<version>-1<dist>.<arch>.rpm when rpmbuild exists (packaging/rpm/xe-bug-report.spec)
# Usage: scripts/package.sh        (from anywhere; builds for the host target)
# DEB_DIST=<tag> (e.g. deb12, ubuntu24.04) builds a .deb for one distribution release: its version
# becomes <version>-1~<tag> and the file dist/xe-bug-report_<version>_<tag>_<arch>.deb.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

name=xe-bug-report
version=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
if [ -z "$version" ]; then
    echo "package.sh: cannot read the version from Cargo.toml" >&2
    exit 1
fi
target=$(rustc -vV | sed -n 's/^host: //p')
if [ -z "$target" ]; then
    echo "package.sh: cannot read the host target from rustc -vV" >&2
    exit 1
fi
# The Debian architecture name comes from dpkg itself (only needed when building the .deb).
deb_arch=
if command -v dpkg >/dev/null 2>&1; then
    deb_arch=$(dpkg --print-architecture)
fi

cargo build --release --locked
binary=${CARGO_TARGET_DIR:-target}/release/$name
case "$binary" in /*) ;; *) binary=$root/$binary ;; esac
if [ ! -x "$binary" ]; then
    echo "package.sh: $binary was not built" >&2
    exit 1
fi

dist=$root/dist
mkdir -p "$dist"
work=$(mktemp -d "${TMPDIR:-/tmp}/$name-package.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# --- tar.gz ---
stage=$work/$name-$version-$target
mkdir -p "$stage"
cp "$binary" "$stage/$name"
cp LICENSE README.md "$stage/"
chmod 0755 "$stage" "$stage/$name"
chmod 0644 "$stage/LICENSE" "$stage/README.md"
tarball=$dist/$name-$version-$target.tar.gz
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --owner=0 --group=0 --numeric-owner -C "$work" -czf "$tarball" "$name-$version-$target"
else
    tar -C "$work" -czf "$tarball" "$name-$version-$target"
fi
echo "wrote $tarball"

# --- deb ---
if command -v dpkg-deb >/dev/null 2>&1; then
    tree=$work/deb
    mkdir -p "$tree/DEBIAN" "$tree/usr/bin" "$tree/usr/share/doc/$name"
    install -m 0755 "$binary" "$tree/usr/bin/$name"
    install -m 0644 README.md "$tree/usr/share/doc/$name/README.md"
    install -m 0644 LICENSE "$tree/usr/share/doc/$name/copyright"
    find "$tree" -type d -exec chmod 0755 {} +
    size=$(du -sk "$tree/usr" | cut -f 1)
    # The binary needs the newest glibc symbol version it references; the package must say so.
    glibc=
    if command -v objdump >/dev/null 2>&1; then
        glibc=$(objdump -T "$binary" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -n 1 || true)
    fi
    if [ -n "$glibc" ]; then
        libc6="libc6 (>= $glibc)"
    else
        echo "objdump not found or no GLIBC symbols; the .deb gets an unversioned libc6 dependency" >&2
        libc6=libc6
    fi
    deb_version=$version
    deb=$dist/${name}_${version}_$deb_arch.deb
    if [ -n "${DEB_DIST:-}" ]; then
        case "$DEB_DIST" in
            *[!A-Za-z0-9.]*)
                echo "package.sh: DEB_DIST may hold only letters, digits and dots" >&2
                exit 1
                ;;
        esac
        # "~" sorts the build below a distribution's own <version>-1.
        deb_version=$version-1~$DEB_DIST
        deb=$dist/${name}_${version}_${DEB_DIST}_$deb_arch.deb
    fi
    sed -e "s/@VERSION@/$deb_version/" -e "s/@ARCH@/$deb_arch/" -e "s/@LIBC6@/$libc6/" \
        packaging/deb/control >"$tree/DEBIAN/control"
    echo "Installed-Size: $size" >>"$tree/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$tree" "$deb" >/dev/null
    echo "wrote $deb"
else
    echo "dpkg-deb not found; skipping the .deb"
fi

# --- rpm ---
if command -v rpmbuild >/dev/null 2>&1; then
    top=$work/rpm
    mkdir -p "$top/BUILD" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"
    cp "$binary" "$top/SOURCES/$name"
    cp LICENSE README.md "$top/SOURCES/"
    rpmbuild --quiet --define "_topdir $top" --define "pkg_version $version" \
        -bb packaging/rpm/$name.spec
    found=0
    for rpm in "$top"/RPMS/*/*.rpm; do
        [ -f "$rpm" ] || continue
        cp "$rpm" "$dist/"
        echo "wrote $dist/$(basename "$rpm")"
        found=1
    done
    if [ "$found" -eq 0 ]; then
        echo "package.sh: rpmbuild produced no package" >&2
        exit 1
    fi
else
    echo "rpmbuild not found; skipping the .rpm"
fi
