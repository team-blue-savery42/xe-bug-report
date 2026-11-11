// SPDX-License-Identifier: MIT
//! UTC timestamps for the manifest and file names, and the DOS date/time of zip entries.

use std::time::{SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::macros::format_description;

/// First second `time` formats with a four-digit year: 0000-01-01 00:00:00 UTC.
const MIN_FORMAT_SECS: i64 = -62_167_219_200;
/// Last second formatted: 9999-12-31 23:59:59 UTC.
const MAX_FORMAT_SECS: i64 = 253_402_300_799;
/// 1980-01-01 00:00:00 UTC, the first DOS time.
const DOS_MIN_SECS: i64 = 315_532_800;
/// 2107-12-31 23:59:58 UTC, the last DOS time (two-second resolution).
const DOS_MAX_SECS: i64 = 4_354_819_198;

/// Whole seconds since the Unix epoch, rounded toward negative infinity; saturates at the i64 range.
fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(err) => {
            let before = err.duration();
            let whole = i64::try_from(before.as_secs()).unwrap_or(i64::MAX);
            let floor_extra = i64::from(before.subsec_nanos() > 0);
            0i64.saturating_sub(whole).saturating_sub(floor_extra)
        }
    }
}

/// `t` as a UTC date-time, clamped to years 0000..=9999 so that formatting always works.
fn clamped(t: SystemTime) -> OffsetDateTime {
    let secs = unix_secs(t).clamp(MIN_FORMAT_SECS, MAX_FORMAT_SECS);
    OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// ISO-8601 UTC with seconds, e.g. "2026-11-10T14:28:03Z".
pub fn utc_iso8601(t: SystemTime) -> String {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    clamped(t).format(&format).unwrap_or_default()
}

/// Compact UTC for file names, e.g. "20261110T142803Z".
pub fn utc_compact(t: SystemTime) -> String {
    let format = format_description!("[year][month][day]T[hour][minute][second]Z");
    clamped(t).format(&format).unwrap_or_default()
}

/// Human UTC for build provenance, e.g. "2026-01-02 03:04:05 UTC".
pub fn utc_human(t: SystemTime) -> String {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    clamped(t).format(&format).unwrap_or_default()
}

/// The zip (DOS) `(date, time)` fields of `t` in UTC; clamped to 1980-01-01 00:00:00 .. 2107-12-31 23:59:58.
///
/// DOS time has two-second resolution, so an odd second rounds down.
pub fn dos_date_time(t: SystemTime) -> (u16, u16) {
    let secs = unix_secs(t).clamp(DOS_MIN_SECS, DOS_MAX_SECS);
    let dt = OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let year = u16::try_from(dt.year().saturating_sub(1980)).unwrap_or(0).min(127);
    let date = (year << 9) | (u16::from(u8::from(dt.month())) << 5) | u16::from(dt.day());
    let time = (u16::from(dt.hour()) << 11) | (u16::from(dt.minute()) << 5) | u16::from(dt.second() / 2);
    (date, time)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "timefmt_tests.rs"]
mod tests;
