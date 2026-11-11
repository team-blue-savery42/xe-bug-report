// SPDX-License-Identifier: MIT
//! The package-manager sources.
//!
//! Only the package managers installed on the host get sources: a system has one, and the other is
//! not a missing source. A missing tool is "not installed", never "needs root".

use std::path::Path;

use crate::bundle::source::{Profile, Source};
use crate::sources::Tools;
use crate::units::Bytes;

use super::usermode::repositories;

/// Substrings that keep a package line (case-insensitive): the GPU drivers and runtimes, and the
/// rest of the user-mode graphics stack, the kernel image and firmware packages and the display
/// servers and virtualisation packages that decide how the GPU is used. `libigc` rather than `igc`
/// so that `libsigc++` does not match.
pub const PKG_KEEP: &[&str] = &[
    "intel",
    "level-zero",
    "libze",
    "libigc",
    "igdgmm",
    "gmmlib",
    "igsc",
    "metee",
    "xpu",
    "opencl",
    "ocl-icd",
    "libva",
    "vpl",
    "mesa",
    "vulkan",
    "libdrm",
    "libgbm",
    "libegl",
    "libgl1",
    "libglx",
    "libglvnd",
    "libgles",
    "gallium",
    "linux-firmware",
    "linux-image",
    "linux-modules",
    "linux-headers",
    "kernel-core",
    "kernel-modules",
    "kernel-devel",
    "xserver-xorg-core",
    "xwayland",
    "mutter",
    "kwin",
    "gnome-shell",
    "wayland",
    "ffmpeg",
    "gstreamer1.0-vaapi",
    "qemu",
    "libvirt",
    "vfio",
];

/// Size cap of `/var/log/dpkg.log`.
const DPKG_LOG_MAX: Bytes = Bytes::mib(4);
/// Size cap of `/var/log/apt/history.log`.
const APT_HISTORY_MAX: Bytes = Bytes::mib(1);

/// The package sources for the package managers `tools` says are installed, in table order.
pub fn package_sources(tools: &Tools) -> Vec<Source> {
    let mut out = Vec::new();
    if tools.dpkg {
        out.push(
            Source::command(
                "packages/dpkg.txt",
                &["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n"],
                Profile::Minimal,
                "Installed GPU-related Debian packages.",
            )
            .keep_lines(PKG_KEEP),
        );
    }
    if tools.rpm {
        out.push(
            Source::command(
                "packages/rpm.txt",
                &["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"],
                Profile::Minimal,
                "Installed GPU-related RPM packages.",
            )
            .keep_lines(PKG_KEEP),
        );
    }
    out.push(Source::builtin(
        "packages/repositories.txt",
        Box::new(|reader| repositories(reader, Path::new("/"), "packages/repositories.txt")),
        Profile::Default,
        "Package repositories the driver and libraries were installed from.",
    ));
    out.push(
        Source::file(
            "packages/dpkg-log.txt",
            "/var/log/dpkg.log",
            Profile::Default,
            "Recent Debian package installs and upgrades.",
        )
        .keep_lines(PKG_KEEP)
        .tail()
        .cap(DPKG_LOG_MAX),
    );
    out.push(
        Source::file(
            "packages/apt-history.log",
            "/var/log/apt/history.log",
            Profile::Default,
            "Recent apt transactions.",
        )
        .tail()
        .cap(APT_HISTORY_MAX),
    );
    if tools.rpm {
        out.push(
            Source::command(
                "packages/rpm-last.txt",
                &["rpm", "-qa", "--last"],
                Profile::Default,
                "RPM packages by install time.",
            )
            .keep_lines(PKG_KEEP),
        );
    }
    out
}

#[cfg(test)]
#[path = "packages_tests.rs"]
mod tests;
