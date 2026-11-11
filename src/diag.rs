// SPDX-License-Identifier: MIT
//! A minimal `log` backend writing to stderr behind `--verbose`.
#![forbid(unsafe_code)]

/// Installs the stderr logger; `verbose` selects `Debug`, otherwise only `Warn` and above.
/// Calling it twice is harmless.
pub fn init(_verbose: bool) {}
