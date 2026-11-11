// SPDX-License-Identifier: MIT
//! The package-manager sources.
//!
//! Only the package managers installed on the host get sources: a system has one, and the other is
//! not a missing source (a missing tool is "not installed", never "needs root").
#![forbid(unsafe_code)]

use crate::bundle::source::{Profile, Source};
use crate::units::Bytes;

use crate::sources::Tools;

/// Substrings that keep a package line (case-insensitive).
pub const PKG_KEEP: &[&str] = &[
    "intel",
    "level-zero",
    "libze",
    "igc",
    "igdgmm",
    "gmmlib",
    "igsc",
    "metee",
    "xpu",
    "opencl",
    "ocl-icd",
    "libva",
    "vpl",
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
