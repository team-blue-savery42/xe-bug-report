// SPDX-License-Identifier: MIT
//! Build provenance recorded by `build.rs`.

use std::time::{Duration, UNIX_EPOCH};

use crate::timefmt::utc_human;

/// The crate version, e.g. "0.1.0".
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// `git describe --tags --always --dirty` at build time; empty outside a git checkout.
pub const DESCRIBE: &str = env!("XE_BUG_REPORT_DESCRIBE");
/// The abbreviated commit at build time; empty outside a git checkout.
pub const COMMIT: &str = env!("XE_BUG_REPORT_COMMIT");
/// Build time as seconds since the Unix epoch (`SOURCE_DATE_EPOCH` when set).
pub const BUILT_EPOCH: &str = env!("XE_BUG_REPORT_BUILT_EPOCH");

/// [`BUILT_EPOCH`] as human UTC text ("2026-01-02 03:04:05 UTC"); empty when it is missing or not
/// a number.
pub fn built_human() -> String {
    human_from_epoch(BUILT_EPOCH)
}

/// Formats `epoch` (decimal seconds since the Unix epoch) as human UTC; empty when it is not a
/// number.
fn human_from_epoch(epoch: &str) -> String {
    match epoch.trim().parse::<u64>() {
        Ok(seconds) => utc_human(UNIX_EPOCH + Duration::from_secs(seconds)),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
#[path = "build_info_tests.rs"]
mod tests;
