// SPDX-License-Identifier: MIT
//! End-to-end tests on Linux.
#![cfg(unix)]

mod common;

#[test]
fn binary_exists() {
    assert!(common::binary().exists());
}
