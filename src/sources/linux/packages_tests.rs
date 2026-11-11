// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/packages.rs`.

use super::*;
use crate::bundle::source::Spec;

fn paths(tools: &Tools) -> Vec<String> {
    package_sources(tools).into_iter().map(|s| s.rel_path).collect()
}

#[test]
fn only_installed_package_managers_get_sources() {
    let debian = Tools { dpkg: true, ..Tools::default() };
    assert_eq!(
        paths(&debian),
        [
            "packages/dpkg.txt",
            "packages/repositories.txt",
            "packages/dpkg-log.txt",
            "packages/apt-history.log"
        ]
    );
    let redhat = Tools { rpm: true, ..Tools::default() };
    assert_eq!(
        paths(&redhat),
        [
            "packages/rpm.txt",
            "packages/repositories.txt",
            "packages/dpkg-log.txt",
            "packages/apt-history.log",
            "packages/rpm-last.txt"
        ]
    );
    let neither = Tools::default();
    assert_eq!(
        paths(&neither),
        ["packages/repositories.txt", "packages/dpkg-log.txt", "packages/apt-history.log"]
    );
}

#[test]
fn package_lists_are_filtered_and_no_source_runs_a_shell() {
    let tools = Tools { dpkg: true, rpm: true, ..Tools::default() };
    for source in package_sources(&tools) {
        if let Spec::Command { argv } = &source.spec {
            assert!(!argv.iter().any(|a| a == "-c" || a == "sh" || a == "bash"), "{argv:?}");
            assert!(!source.keep_lines.is_empty(), "{}", source.rel_path);
        }
    }
}

/// Whether a package line is kept, as the collector's case-insensitive substring filter decides.
fn kept(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    PKG_KEEP.iter().any(|needle| lower.contains(needle))
}

#[test]
fn the_stack_that_decides_a_graphics_report_is_kept() {
    for line in [
        "libgl1-mesa-dri\t25.3.0\tii",
        "libgallium-25.3.0\t25.3.0\tii",
        "libvulkan1\t1.3.275\tii",
        "libdrm2\t2.4.121\tii",
        "libegl-mesa0\t25.3.0\tii",
        "libgbm1\t25.3.0\tii",
        "linux-firmware\t20240318\tii",
        "linux-image-6.14.0-37-generic\t6.14.0\tii",
        "linux-modules-6.14.0-37-generic\t6.14.0\tii",
        "libigc1\t1.0.1\tii",
        "intel-igc-core\t1.0.1\tii",
        "libze-intel-gpu1\t1\tii",
        "libva2\t2.20\tii",
        "mesa-vulkan-drivers\t25\tii",
        "xserver-xorg-core\t21\tii",
        "libwayland-client0\t1.22\tii",
        "kernel-core\t6.8\tx86_64",
        "mesa-libGL\t25\tx86_64",
    ] {
        assert!(kept(line), "{line}");
    }
}

#[test]
fn unrelated_packages_are_not_kept() {
    for line in [
        "libsigc++-3.0-0\t3.6.0\tii",
        "libglib2.0-0\t2.80\tii",
        "bash\t5.2\tii",
        "libc6\t2.39\tii",
        "coreutils\t9\tii",
    ] {
        assert!(!kept(line), "{line}");
    }
}
