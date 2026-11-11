// SPDX-License-Identifier: MIT
//! Unit tests for `src/units.rs`.

use super::*;

#[test]
fn constructors_scale_and_saturate() {
    assert_eq!(Bytes::kib(2).get(), 2048);
    assert_eq!(Bytes::mib(16).get(), 16 * 1024 * 1024);
    assert_eq!(Bytes::kib(u64::MAX).get(), u64::MAX);
    assert_eq!(Bytes::mib(u64::MAX).get(), u64::MAX);
    assert!(Bytes::kib(1) < Bytes::mib(1));
}

#[test]
fn cap_label_picks_the_largest_exact_unit() {
    assert_eq!(Bytes(0).cap_label(), "0 B");
    assert_eq!(Bytes(1023).cap_label(), "1023 B");
    assert_eq!(Bytes(1024).cap_label(), "1 KiB");
    assert_eq!(Bytes(1_048_575).cap_label(), "1048575 B");
    assert_eq!(Bytes(1_048_576).cap_label(), "1 MiB");
    assert_eq!(Bytes(MIB * 16 + KIB).cap_label(), "16385 KiB");
    assert_eq!(Bytes::mib(16).cap_label(), "16 MiB");
}

#[test]
fn human_below_one_kib_is_whole_bytes() {
    assert_eq!(Bytes(0).human(), "0 B");
    assert_eq!(Bytes(512).human(), "512 B");
    assert_eq!(Bytes(1023).human(), "1023 B");
}

#[test]
fn human_kib_has_one_decimal() {
    assert_eq!(Bytes(1024).human(), "1.0 KiB");
    assert_eq!(Bytes(174_899).human(), "170.8 KiB");
    assert_eq!(Bytes(1536).human(), "1.5 KiB");
    assert_eq!(Bytes(MIB - 1).human(), "1024.0 KiB");
}

#[test]
fn human_mib_has_one_decimal_and_no_gib_step() {
    assert_eq!(Bytes(MIB).human(), "1.0 MiB");
    assert_eq!(Bytes::mib(3).human(), "3.0 MiB");
    assert_eq!(Bytes(MIB + MIB / 2).human(), "1.5 MiB");
    assert_eq!(Bytes::mib(1024).human(), "1024.0 MiB");
    assert_eq!(Bytes::mib(5 * 1024).human(), "5120.0 MiB");
}
