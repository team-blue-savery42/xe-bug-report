// SPDX-License-Identifier: MIT
//! Unit tests for `src/build_info.rs`.

use super::*;

#[test]
fn constants_are_present() {
    assert!(!VERSION.is_empty());
    assert!(BUILT_EPOCH.parse::<u64>().is_ok(), "{BUILT_EPOCH:?}");
}

#[test]
fn non_numeric_epoch_gives_empty_text() {
    assert_eq!(human_from_epoch(""), "");
    assert_eq!(human_from_epoch("yesterday"), "");
    assert_eq!(human_from_epoch("-5"), "");
}

#[test]
fn epoch_is_formatted_as_human_utc() {
    assert_eq!(human_from_epoch("0"), "1970-01-01 00:00:00 UTC");
    assert_eq!(human_from_epoch("1783629511"), "2026-07-09 20:38:31 UTC");
}
