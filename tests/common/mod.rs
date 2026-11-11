// SPDX-License-Identifier: MIT
//! Shared helpers for the integration tests: a zip central-directory reader, temp dirs and running
//! the binary.
#![allow(dead_code)]

use std::path::PathBuf;

/// The built binary.
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xe-bug-report"))
}
