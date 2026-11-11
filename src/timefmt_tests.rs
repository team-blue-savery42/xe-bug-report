// SPDX-License-Identifier: MIT
//! Unit tests for `src/timefmt.rs`.

use super::*;
use std::time::Duration;

fn at(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

// 2026-11-10 14:28:03 UTC
const SAMPLE: i64 = 1_794_320_883;

#[test]
fn formats_a_known_instant() {
    assert_eq!(utc_iso8601(at(SAMPLE)), "2026-11-10T14:28:03Z");
    assert_eq!(utc_compact(at(SAMPLE)), "20261110T142803Z");
    assert_eq!(utc_human(at(SAMPLE)), "2026-11-10 14:28:03 UTC");
}

#[test]
fn formats_the_epoch_and_other_instants() {
    assert_eq!(utc_iso8601(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    // 2024-02-29 23:59:59 UTC, a leap day
    assert_eq!(utc_iso8601(at(1_709_251_199)), "2024-02-29T23:59:59Z");
    assert_eq!(utc_human(at(1_604_954_311)), "2020-11-09 20:38:31 UTC");
}

#[test]
fn sub_second_parts_are_dropped() {
    let t = at(SAMPLE) + Duration::from_millis(999);
    assert_eq!(utc_iso8601(t), "2026-11-10T14:28:03Z");
}

#[test]
fn times_before_the_epoch_do_not_panic() {
    assert_eq!(utc_iso8601(at(-1)), "1969-12-31T23:59:59Z");
    let fraction = UNIX_EPOCH - Duration::from_millis(1);
    assert_eq!(utc_iso8601(fraction), "1969-12-31T23:59:59Z");
    assert_eq!(utc_compact(at(-3_153_600_000)), "18700125T000000Z");
    assert_eq!(dos_date_time(at(-1)), (0x21, 0));
}

#[test]
fn extreme_times_are_clamped_not_panicking() {
    // Windows' SystemTime overflows on offsets this large and does not reach year 0, so each
    // instant falls back to one it can hold: about year 11476, and 1601-01-01 (the FILETIME epoch).
    let huge = Duration::from_secs(u64::MAX / 2);
    let far_future = UNIX_EPOCH.checked_add(huge).unwrap_or_else(|| at(300_000_000_000));
    let far_past = UNIX_EPOCH.checked_sub(huge).unwrap_or_else(|| at(-11_644_473_600));
    assert_eq!(utc_iso8601(far_future), "9999-12-31T23:59:59Z");
    assert_eq!(utc_human(far_future), "9999-12-31 23:59:59 UTC");
    let year_zero = UNIX_EPOCH.checked_sub(Duration::from_secs(62_167_219_200));
    if year_zero.is_some_and(|y0| far_past < y0) {
        assert_eq!(utc_iso8601(far_past), "0000-01-01T00:00:00Z");
        assert_eq!(utc_compact(far_past), "00000101T000000Z");
    } else {
        assert_eq!(utc_iso8601(far_past), "1601-01-01T00:00:00Z");
    }
    assert_eq!(dos_date_time(far_past), (0x21, 0));
    let last = ((127 << 9) | (12 << 5) | 31, (23 << 11) | (59 << 5) | 29);
    assert_eq!(dos_date_time(far_future), last);
    if let Some(max) = UNIX_EPOCH.checked_add(Duration::new(u64::MAX, 999_999_999)) {
        assert_eq!(dos_date_time(max), last);
        assert_eq!(utc_iso8601(max), "9999-12-31T23:59:59Z");
    }
}

#[test]
fn dos_fields_for_a_known_instant() {
    // 2021-03-04 05:06:08 UTC
    let (date, time) = dos_date_time(at(1_614_834_368));
    assert_eq!(date, (41 << 9) | (3 << 5) | 4);
    assert_eq!(time, (5 << 11) | (6 << 5) | 4);
    // The odd second rounds down.
    let (_, odd) = dos_date_time(at(1_614_834_369));
    assert_eq!(odd, time);
}

#[test]
fn dos_range_edges() {
    assert_eq!(dos_date_time(at(DOS_MIN_SECS)), (0x21, 0));
    assert_eq!(dos_date_time(at(DOS_MIN_SECS - 1)), (0x21, 0));
    assert_eq!(dos_date_time(at(DOS_MIN_SECS + 2)), (0x21, 1));
    let last = ((127 << 9) | (12 << 5) | 31, (23 << 11) | (59 << 5) | 29);
    assert_eq!(dos_date_time(at(DOS_MAX_SECS)), last);
    assert_eq!(dos_date_time(at(DOS_MAX_SECS + 1)), last);
    assert_eq!(dos_date_time(at(DOS_MAX_SECS + 100_000_000)), last);
}
