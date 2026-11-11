// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/pci_config.rs`.

use super::*;
use std::fmt::Write as _;

/// A configuration space with the given extended capabilities: `(offset, id, next, payload)`.
fn space(extended: &[(usize, u32, usize, &[u8])]) -> Vec<u8> {
    let mut bytes = vec![0u8; CONFIG_SIZE];
    bytes[0] = 0x86;
    bytes[1] = 0x80;
    for &(at, id, next, payload) in extended {
        let header = id | (1 << 16) | ((next as u32) << 20);
        bytes[at..at + 4].copy_from_slice(&header.to_le_bytes());
        bytes[at + 4..at + 4 + payload.len()].copy_from_slice(payload);
    }
    bytes
}

/// The `lspci -xxxx` text of `bytes`: a header line, then 16 bytes per row.
fn dump_of(bytes: &[u8]) -> String {
    let mut text =
        String::from("03:00.0 VGA compatible controller [0300]: Intel Corporation Device [8086:e20b]\n");
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let tokens: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(text, "{:02x}: {}", row * 16, tokens.join(" "));
    }
    text
}

const SERIAL: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

#[test]
fn the_serial_number_capability_is_blanked_wherever_it_sits() {
    // AER at 0x100, then the serial number at 0x140, then a vendor capability.
    let bytes = space(&[
        (0x100, 0x0001, 0x140, &[0xaa; 8]),
        (0x140, DSN_CAPABILITY, 0x200, &SERIAL),
        (0x200, 0x000b, 0, &[0xbb; 8]),
    ]);
    let dump = dump_of(&bytes);
    assert!(dump.contains("12 34 56 78 9a bc de f0"));
    let clean = blank_serial_capability(&dump);
    assert!(!clean.contains("12 34 56 78"), "{clean}");
    assert!(!clean.contains("9a bc de f0"));
    // The capability header stays, the eight serial bytes become xx.
    assert!(clean.contains("140: 03 00 01 20 xx xx xx xx"), "{clean}");
    // Everything else is untouched, including the other capabilities and the header line.
    assert!(clean.contains("100: 01 00 01 14 aa aa aa aa aa aa aa aa"));
    assert!(clean.contains("200: 0b 00 01 00 bb bb bb bb"));
    assert!(
        clean.starts_with("03:00.0 VGA compatible controller [0300]: Intel Corporation Device [8086:e20b]\n")
    );
    assert_eq!(clean.lines().count(), dump.lines().count());
}

#[test]
fn a_serial_number_split_across_rows_is_blanked_in_both() {
    // The eight serial bytes start at 0x10c and end at 0x113: four on one row, four on the next.
    let bytes = space(&[(0x100, 0x0001, 0x108, &[0; 4]), (0x108, DSN_CAPABILITY, 0, &SERIAL)]);
    let clean = blank_serial_capability(&dump_of(&bytes));
    assert!(clean.contains(" 03 00 01 00 xx xx xx xx\n"), "{clean}");
    assert!(clean.contains("110: xx xx xx xx 00"), "{clean}");
    assert!(!clean.contains("12 34 56"));
}

#[test]
fn a_dump_without_the_capability_is_returned_unchanged() {
    let bytes = space(&[(0x100, 0x0001, 0x140, &[0xaa; 8]), (0x140, 0x000b, 0, &[0x12; 8])]);
    let dump = dump_of(&bytes);
    assert_eq!(blank_serial_capability(&dump), dump);
    // The 64 bytes an unprivileged read returns have no extended list at all.
    let short = dump_of(&bytes[..64]);
    assert_eq!(blank_serial_capability(&short), short);
    assert_eq!(blank_serial_capability(""), "");
    assert_eq!(
        blank_serial_capability("lspci: Cannot open /sys/bus/pci\n"),
        "lspci: Cannot open /sys/bus/pci\n"
    );
}

#[test]
fn a_corrupt_capability_list_ends_the_walk() {
    // A pointer back to the start would loop forever.
    let looping = space(&[(0x100, 0x0001, 0x100, &[0; 8])]);
    assert!(serial_capability_offsets(&dump_bytes(&dump_of(&looping))).is_empty());
    // A pointer that is not a multiple of four, or below the extended area, is not followed.
    let odd = space(&[(0x100, 0x0001, 0x142, &[0; 8]), (0x142, DSN_CAPABILITY, 0, &SERIAL)]);
    assert!(serial_capability_offsets(&dump_bytes(&dump_of(&odd))).is_empty());
    let low = space(&[(0x100, 0x0001, 0x040, &[0; 8])]);
    assert!(serial_capability_offsets(&dump_bytes(&dump_of(&low))).is_empty());
    // All ones (a device that does not answer) is an empty list.
    let mut ones = space(&[]);
    ones[0x100..0x104].copy_from_slice(&[0xff; 4]);
    assert!(serial_capability_offsets(&dump_bytes(&dump_of(&ones))).is_empty());
}

#[test]
fn the_serial_capability_is_found_at_the_head_of_the_list() {
    let bytes = space(&[(0x100, DSN_CAPABILITY, 0, &SERIAL)]);
    assert_eq!(serial_capability_offsets(&dump_bytes(&dump_of(&bytes))), [0x100]);
}

#[test]
fn rows_are_recognised_by_shape() {
    assert_eq!(parse_row("00: 86 80").unwrap().0, 0);
    assert_eq!(parse_row("1f0: 00 11 22").unwrap(), (0x1f0, vec!["00", "11", "22"]));
    assert!(parse_row("03:00.0 VGA compatible controller").is_none());
    assert!(parse_row("00: 8 80").is_none());
    assert!(parse_row("no colon").is_none());
    assert!(parse_row(": 00").is_none());
    assert!(parse_row("00000: 00").is_none());
}

#[test]
fn a_finished_lspci_run_maps_to_an_artifact() {
    let dump = dump_of(&space(&[(0x100, DSN_CAPABILITY, 0, &SERIAL)]));
    let run = |outcome: ChildOutcome, output: &[u8], truncated: bool| {
        dump_from("pci/x/lspci-xxxx.txt", "lspci -xxxx -s 0000:03:00.0", &outcome, output, truncated)
            .remove(0)
    };
    let ok = run(ChildOutcome::Exited(0), dump.as_bytes(), false);
    assert_eq!(ok.status, Status::Collected);
    assert_eq!(ok.via, "lspci -xxxx -s 0000:03:00.0");
    assert!(!String::from_utf8_lossy(&ok.data).contains("12 34 56 78"));
    let cut = run(ChildOutcome::Exited(0), dump.as_bytes(), true);
    assert_eq!(cut.status, Status::Truncated);
    assert_eq!(run(ChildOutcome::NotFound, b"", false).reason, "lspci not installed");
    assert_eq!(run(ChildOutcome::TimedOut, b"", false).status, Status::TimedOut);
    let failed = run(ChildOutcome::Exited(1), b"", false);
    assert_eq!((failed.status, failed.reason.as_str()), (Status::Failed, "exit code 1"));
    assert_eq!(run(ChildOutcome::Exited(0), b"", false).status, Status::Skipped);
    assert_eq!(run(ChildOutcome::SpawnFailed("denied".to_owned()), b"", false).status, Status::Failed);
}
