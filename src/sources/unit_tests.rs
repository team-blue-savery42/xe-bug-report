// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/mod.rs`.

use super::*;

#[test]
fn the_version_line_is_the_one_that_says_version() {
    // A build that prints its version first.
    assert_eq!(
        version_line("\n  \nxpu-smi version 2.3.0 (x)\nBuild:\n").unwrap(),
        "xpu-smi version 2.3.0 (x)"
    );
    // An older build prints a heading first.
    assert_eq!(
        version_line("CLI:\n  Version: 2.0.1.20250225\n  Build ID: 8389eee7\n").unwrap(),
        "Version: 2.0.1.20250225"
    );
    assert_eq!(version_line("one\ntwo\n").unwrap(), "one");
    assert_eq!(version_line("\n\nfirst\nVERSION 3\n").unwrap(), "VERSION 3");
    assert!(version_line("").is_none());
    assert!(version_line(" \n\t\n").is_none());
}
