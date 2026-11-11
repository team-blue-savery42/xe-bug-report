// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/display.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put, text_of};

/// A text descriptor: tag, then the text, a line feed and blanks.
fn text_descriptor(tag: u8, text: &str) -> [u8; 18] {
    let mut d = [0x20u8; 18];
    d[..3].copy_from_slice(&[0, 0, 0]);
    d[3] = tag;
    d[4] = 0;
    for (i, b) in text.bytes().enumerate() {
        d[5 + i] = b;
    }
    // The text ends at a line feed unless it fills all thirteen bytes.
    if text.len() < 13 {
        d[5 + text.len()] = 0x0a;
    }
    d
}

/// A 1920x1080 detailed timing at 60 Hz (148.5 MHz pixel clock, 2200x1125 total).
fn timing_1080p60() -> [u8; 18] {
    let mut d = [0u8; 18];
    let clock = 14850u16;
    d[0] = (clock & 0xff) as u8;
    d[1] = (clock >> 8) as u8;
    d[2] = (1920 & 0xff) as u8;
    d[3] = ((2200 - 1920) & 0xff) as u8;
    d[4] = (((1920 >> 8) << 4) | ((2200 - 1920) >> 8)) as u8;
    d[5] = (1080 & 0xff) as u8;
    d[6] = ((1125 - 1080) & 0xff) as u8;
    // High nibble: the high bits of 1080; low nibble: the high bits of the 45 blank lines, none.
    d[7] = ((1080 >> 8) << 4) as u8;
    d
}

/// A base block with a serial number in the header and in a descriptor, plus an HDR extension.
fn edid_with_serial(extensions: bool) -> Vec<u8> {
    let mut e = vec![0u8; BLOCK];
    e[..8].copy_from_slice(&EDID_HEADER);
    // Manufacturer "ABC": A=1, B=2, C=3.
    let packed: u16 = (1 << 10) | (2 << 5) | 3;
    e[8] = (packed >> 8) as u8;
    e[9] = (packed & 0xff) as u8;
    e[10] = 0x34;
    e[11] = 0x12;
    e[12..16].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    e[16] = 17; // week
    e[17] = 33; // 2023
    e[18] = 1;
    e[19] = 4;
    e[20] = 0x80;
    e[21] = 53;
    e[22] = 30;
    e[54..72].copy_from_slice(&timing_1080p60());
    let mut range = text_descriptor(0xfd, "");
    range[4] = 0;
    range[5..10].copy_from_slice(&[48, 144, 30, 160, 25]);
    e[72..90].copy_from_slice(&range);
    e[90..108].copy_from_slice(&text_descriptor(0xfc, "Example Panel"));
    e[108..126].copy_from_slice(&text_descriptor(0xff, "SN-SECRET-77"));
    e[126] = u8::from(extensions);
    let sum = e[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    e[127] = 0u8.wrapping_sub(sum);
    if extensions {
        let mut cta = vec![0u8; BLOCK];
        cta[0] = 0x02;
        cta[1] = 3;
        // Data blocks: HDR static metadata (extended tag 6, EOTF SDR + PQ + HLG), HDMI Forum vendor block.
        let hdr = [0xe0 | 3, 0x06, 0b0000_1101, 0x01];
        let hf = [0x60 | 3, 0xd8, 0x5d, 0xc4];
        let mut at = 4;
        for part in [&hdr[..], &hf[..]] {
            cta[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        cta[2] = at as u8;
        e.extend(cta);
    }
    e
}

#[test]
fn manufacturer_ids_unpack_to_letters() {
    assert_eq!(manufacturer_id(0x04, 0x43), "ABC");
    assert_eq!(manufacturer_id(0x00, 0x00), "???");
}

#[test]
fn an_edid_is_decoded_without_its_serial_number() {
    let lines = decode_edid(&edid_with_serial(false));
    let text = lines.join("\n");
    assert_eq!(lines[0], "EDID 1.4, 128 bytes, base block checksum ok");
    assert_eq!(lines[1], "manufacturer ABC product 0x1234 year 2023");
    assert_eq!(lines[2], "digital input, size 53x30 cm");
    assert!(text.contains("display name \"Example Panel\""), "{text}");
    assert!(text.contains("range limits: vertical 48-144 Hz, horizontal 30-160 kHz"), "{text}");
    assert!(text.contains("detailed timings: 1920x1080@60.0Hz"), "{text}");
    // Neither the serial in the header, the serial descriptor nor the week appear in any form.
    assert!(!text.contains("SN-SECRET") && !text.to_lowercase().contains("deadbeef"), "{text}");
    assert!(!text.contains("week") && !text.contains("17"), "{text}");
}

#[test]
fn the_cta_extension_names_hdr_and_the_vendor_blocks() {
    let text = decode_edid(&edid_with_serial(true)).join("\n");
    assert!(
        text.contains(
            "extension 1: CTA-861 rev 3, HDR static metadata (SDR, ST 2084 PQ, HLG), HDMI Forum vendor block"
        ),
        "{text}"
    );
}

#[test]
fn bad_or_short_data_is_said_so() {
    assert_eq!(decode_edid(&[1, 2, 3]), ["not a valid EDID (3 bytes)"]);
    let mut wrong_header = edid_with_serial(false);
    wrong_header[0] = 1;
    assert_eq!(decode_edid(&wrong_header), ["not a valid EDID (128 bytes)"]);
    let mut bad = edid_with_serial(false);
    bad[100] ^= 0xff;
    assert!(decode_edid(&bad)[0].ends_with("checksum bad"));
    // An announced extension that is not in the data does not panic.
    let mut cut = edid_with_serial(false);
    cut[126] = 3;
    assert!(decode_edid(&cut).last().unwrap().contains("missing from the data"));
    // A corrupt data block length does not run past the block.
    let mut corrupt = edid_with_serial(true);
    corrupt[BLOCK + 4] = 0xff;
    let _ = decode_edid(&corrupt);
}

#[test]
fn refresh_rates_account_for_interlacing() {
    let mut d = timing_1080p60();
    d[17] = 0x80;
    assert_eq!(detailed_timing(&d).unwrap(), "1920x1080i@30.0Hz");
    assert_eq!(detailed_timing(&[0u8; 18]), None);
}

#[test]
fn range_limit_offsets_extend_above_255_hz() {
    let mut d = text_descriptor(0xfd, "");
    d[4] = 0x02;
    d[5..9].copy_from_slice(&[30, 40, 10, 20]);
    assert_eq!(range_limits(&d), "vertical 30-295 Hz, horizontal 10-20 kHz");
    d[4] = 0x0f;
    assert_eq!(range_limits(&d), "vertical 285-295 Hz, horizontal 265-275 kHz");
}

#[test]
fn modes_are_summarised_as_distinct_entries() {
    assert_eq!(
        mode_summary("1920x1080\n1920x1080\n1280x1024\n"),
        "3 listed, 2 distinct: 1920x1080 1280x1024"
    );
    let many: String = (0..30).map(|i| format!("{}x{}\n", 100 + i, 50)).collect();
    assert!(mode_summary(&many).ends_with("and 6 more"));
    assert_eq!(mode_summary(""), "0 listed, 0 distinct: ");
}

#[test]
fn connectors_are_listed_and_only_connected_ones_are_decoded() {
    let dir = PrivateTempDir::create("display").unwrap();
    let card = "drm/card0";
    for (name, status, id) in [("card0-DP-1", "disconnected", "512"), ("card0-HDMI-A-3", "connected", "543")]
    {
        put(dir.path(), &format!("{card}/{name}/status"), format!("{status}\n"));
        put(dir.path(), &format!("{card}/{name}/enabled"), "enabled\n");
        put(dir.path(), &format!("{card}/{name}/dpms"), "On\n");
        put(dir.path(), &format!("{card}/{name}/connector_id"), format!("{id}\n"));
    }
    put(dir.path(), "drm/card0/card0-HDMI-A-3/modes", "1920x1080\n1920x1080\n");
    put(dir.path(), "drm/card0/card0-HDMI-A-3/edid", edid_with_serial(false));
    put(dir.path(), "drm/card0/card0-DP-1/edid", edid_with_serial(false));
    put(dir.path(), "drm/renderD128/dev", "226:128\n");
    let out = connectors(&FsReader::default(), dir.path(), "devices/x/display.txt");
    let text = text_of(&out[0].data);
    assert!(text.starts_with("card0-DP-1: status=disconnected enabled=enabled dpms=On connector_id=512\ncard0-HDMI-A-3: status=connected"), "{text}");
    assert!(text.contains("  modes: 2 listed, 1 distinct: 1920x1080\n"));
    assert!(text.contains("  manufacturer ABC product 0x1234 year 2023\n"));
    assert_eq!(text.matches("manufacturer ABC").count(), 1, "the disconnected connector is not decoded");
    assert!(!text.contains("SN-SECRET"));

    let none = connectors(&FsReader::default(), &dir.path().join("nothing"), "x");
    assert_eq!(text_of(&none[0].data), "(no display connectors)\n");
}

#[test]
fn a_connected_sink_without_an_edid_says_so() {
    let dir = PrivateTempDir::create("display").unwrap();
    put(dir.path(), "drm/card1/card1-DP-1/status", "connected\n");
    let out = connectors(&FsReader::default(), dir.path(), "x");
    assert!(text_of(&out[0].data).contains("  edid: (none)\n"));
}
