// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/packages.rs`.

use super::*;
use crate::bundle::source::Spec;

fn paths(tools: &Tools) -> Vec<String> {
    package_sources(tools).into_iter().map(|s| s.rel_path).collect()
}

#[test]
fn only_installed_package_managers_get_sources() {
    let debian = Tools { dpkg: true, rpm: false, iclg: false };
    assert_eq!(paths(&debian), ["packages/dpkg.txt", "packages/dpkg-log.txt", "packages/apt-history.log"]);
    let redhat = Tools { dpkg: false, rpm: true, iclg: false };
    assert_eq!(
        paths(&redhat),
        ["packages/rpm.txt", "packages/dpkg-log.txt", "packages/apt-history.log", "packages/rpm-last.txt"]
    );
    let neither = Tools { dpkg: false, rpm: false, iclg: false };
    assert_eq!(paths(&neither), ["packages/dpkg-log.txt", "packages/apt-history.log"]);
}

#[test]
fn package_lists_are_filtered_and_no_source_runs_a_shell() {
    let tools = Tools { dpkg: true, rpm: true, iclg: false };
    for source in package_sources(&tools) {
        if let Spec::Command { argv } = &source.spec {
            assert!(!argv.iter().any(|a| a == "-c" || a == "sh" || a == "bash"), "{argv:?}");
            assert!(!source.keep_lines.is_empty(), "{}", source.rel_path);
        }
    }
}
