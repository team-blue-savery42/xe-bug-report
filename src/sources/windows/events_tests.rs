// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/events.rs`.

use super::*;

#[test]
fn default_window_is_72_hours() {
    assert_eq!(window_ms(None), 259_200_000);
    assert_eq!(window_ms(Some(Duration::from_secs(24 * 3600))), 86_400_000);
    assert_eq!(window_ms(Some(Duration::ZERO)), 0);
    assert_eq!(window_ms(Some(Duration::MAX)), u64::MAX);
}

#[test]
fn system_query_text() {
    assert_eq!(
        system_events_query(1000),
        "/q:*[System[(Provider[@Name='Display'] or Provider[@Name='Microsoft-Windows-DxgKrnl'] or \
Provider[@Name='Microsoft-Windows-Kernel-PnP'] or Provider[@Name='Microsoft-Windows-WHEA-Logger'] or \
Provider[@Name='Microsoft-Windows-Kernel-Power'] or Provider[@Name='BugCheck'] or \
Provider[@Name='igfx'] or Provider[@Name='igfxn']) and TimeCreated[timediff(@SystemTime) <= 1000]]]"
    );
}

#[test]
fn application_query_text() {
    assert_eq!(
        application_events_query(5),
        "/q:*[System[Provider[@Name='Application Error' or @Name='Windows Error Reporting'] \
and TimeCreated[timediff(@SystemTime) <= 5]]]"
    );
}

#[test]
fn window_query_text() {
    assert_eq!(time_window_query(42), "/q:*[System[TimeCreated[timediff(@SystemTime) <= 42]]]");
}

#[test]
fn brackets_balance() {
    for q in [system_events_query(1), application_events_query(1), time_window_query(1)] {
        assert_eq!(q.matches('[').count(), q.matches(']').count(), "{q}");
        assert_eq!(q.matches('(').count(), q.matches(')').count(), "{q}");
        assert!(q.starts_with("/q:"));
    }
}
