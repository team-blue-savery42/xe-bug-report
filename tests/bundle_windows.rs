// SPDX-License-Identifier: MIT
//! End-to-end tests on Windows.
#![cfg(windows)]

mod common;

#[test]
fn binary_exists() {
    assert!(common::binary().exists());
}
