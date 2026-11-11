// SPDX-License-Identifier: MIT
//! UTC timestamps for the manifest and file names, and the DOS date/time of zip entries.
#![forbid(unsafe_code)]

use std::time::SystemTime;

/// ISO-8601 UTC with seconds, e.g. "2026-11-10T14:28:03Z".
pub fn utc_iso8601(_t: SystemTime) -> String {
    String::new()
}

/// Compact UTC for file names, e.g. "20261110T142803Z".
pub fn utc_compact(_t: SystemTime) -> String {
    String::new()
}

/// Human UTC for build provenance, e.g. "2026-01-02 03:04:05 UTC".
pub fn utc_human(_t: SystemTime) -> String {
    String::new()
}

/// The zip (DOS) `(date, time)` fields of `t` in UTC; clamped to 1980-01-01 00:00:00 .. 2107-12-31 23:59:58.
pub fn dos_date_time(_t: SystemTime) -> (u16, u16) {
    (0x21, 0)
}
