// SPDX-License-Identifier: MIT
//! Unit tests for `src/pci.rs`.

use super::*;
use std::collections::BTreeSet;

fn addr(domain: u32, bus: u8, device: u8, function: u8) -> PciAddress {
    PciAddress { domain, bus, device, function }
}

#[test]
fn parse_reads_each_field_as_a_number() {
    let a = PciAddress::parse("0001:3a:1f.7").unwrap();
    assert_eq!(a, addr(1, 0x3a, 0x1f, 7));
}

#[test]
fn display_is_canonical() {
    assert_eq!(addr(0, 3, 0, 0).to_string(), "0000:03:00.0");
    assert_eq!(addr(0x10000, 1, 0, 0).to_string(), "10000:01:00.0");
    assert_eq!(addr(0xabcd_ef12, 0xff, 0x1f, 6).to_string(), "abcdef12:ff:1f.6");
    assert_eq!(format!("[{}]", addr(0x10000, 1, 2, 3)), "[10000:01:02.3]");
    assert_eq!(format!("[{:<14}]", addr(0, 3, 0, 0)), "[0000:03:00.0  ]");
    assert_eq!(format!("[{:>14}]", addr(0, 3, 0, 0)), "[  0000:03:00.0]");
}

#[test]
fn dir_name_has_no_colon() {
    assert_eq!(addr(0, 3, 0, 0).dir_name(), "0000-03-00.0");
    assert_eq!(addr(0x10000, 0xab, 0x1f, 7).dir_name(), "10000-ab-1f.7");
    assert!(!addr(1, 2, 3, 4).dir_name().contains(':'));
}

#[test]
fn every_spelling_parses_to_the_same_value() {
    let canonical = PciAddress::parse("0000:3a:0f.7").unwrap();
    assert_eq!(PciAddress::parse("0000:3A:0F.7"), Some(canonical));
    assert_eq!(PciAddress::parse("00000:3a:0f.7"), Some(canonical));
    assert_eq!(PciAddress::parse("00000000:3a:0f.7"), Some(canonical));
    assert_eq!(PciAddress::parse("00000000:3A:0F.7").unwrap().to_string(), "0000:3a:0f.7");
}

#[test]
fn domains_of_four_to_eight_digits() {
    assert_eq!(PciAddress::parse("10000:01:00.0").unwrap().domain, 0x10000);
    assert_eq!(PciAddress::parse("ffffffff:01:00.0").unwrap().domain, 0xffff_ffff);
    assert!(PciAddress::parse("000:03:00.0").is_none());
    assert!(PciAddress::parse("123456789:03:00.0").is_none());
}

#[test]
fn device_and_function_range() {
    assert!(PciAddress::parse("0000:00:1f.7").is_some());
    assert!(PciAddress::parse("0000:00:20.0").is_none());
    assert!(PciAddress::parse("0000:00:00.8").is_none());
    assert!(PciAddress::parse("0000:00:ff.f").is_none());
}

#[test]
fn rejects_anything_else() {
    for bad in [
        "",
        "0000:03:00:0",
        "0000.03:00.0",
        "0000:0g:00.0",
        "-000:03:00.0",
        "+000:03:00.0",
        "0x00:03:00.0",
        " 0000:03:00.0",
        "0000:03:00.0 ",
        "0000:03:00.0/",
        "../../etc/x",
        "0000:03:00.",
        "0000:3:00.0",
        "0000:03:0.0",
        "0000:03:00.00",
        "0000:+3:00.0",
    ] {
        assert!(PciAddress::parse(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn non_ascii_input_does_not_panic() {
    for bad in ["0000:03:00.\u{e9}", "\u{e9}000:03:00.0", "0000:03:00.0\u{0}", "\u{1F600}\u{1F600}:03:00.0"] {
        assert!(PciAddress::parse(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn round_trips_through_display() {
    for a in [addr(0, 3, 0, 0), addr(0x10000, 0xff, 31, 7), addr(0xffff_ffff, 0, 0, 0)] {
        assert_eq!(PciAddress::parse(&a.to_string()), Some(a));
    }
}

#[test]
fn orders_by_domain_bus_device_function() {
    let a = addr(0, 3, 0, 0);
    let b = addr(0, 3, 0, 1);
    let c = addr(1, 0, 0, 0);
    assert!(a < b && b < c);
    let set: BTreeSet<_> = [c, a, b, a].into_iter().collect();
    assert_eq!(set.len(), 3);
    assert_eq!(set.iter().next(), Some(&a));
}
