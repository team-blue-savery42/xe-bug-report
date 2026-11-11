// SPDX-License-Identifier: MIT
//! Build provenance recorded by `build.rs`.
#![forbid(unsafe_code)]

/// The crate version, e.g. "0.1.0".
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// `git describe --tags --always --dirty` at build time; empty outside a git checkout.
pub const DESCRIBE: &str = env!("XE_BUG_REPORT_DESCRIBE");
/// The abbreviated commit at build time; empty outside a git checkout.
pub const COMMIT: &str = env!("XE_BUG_REPORT_COMMIT");
/// Build time as seconds since the Unix epoch (`SOURCE_DATE_EPOCH` when set).
pub const BUILT_EPOCH: &str = env!("XE_BUG_REPORT_BUILT_EPOCH");
