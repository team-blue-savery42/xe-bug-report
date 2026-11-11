// SPDX-License-Identifier: MIT
//! The display connectors of a GPU: status, enabled state, power state, the mode list and a decoded
//! EDID.
//!
//! The raw EDID holds the monitor's serial number twice (header bytes 12 to 15 and a descriptor),
//! and the week of manufacture; neither can be recognised in binary, so the EDID is decoded here
//! and only the model-level fields are written: manufacturer, product code, year, size, display
//! name, supported timings, range limits and which extensions are present. Nothing from the
//! "unspecified text" or serial number descriptors is copied.

use std::fmt::Write as _;
use std::path::Path;

use crate::bundle::source::{Produced, Reader};
use crate::units::Bytes;

use super::debugfs::{collected, read_head};
use super::probes::{list_names, read_text, read_value};

/// Size cap of one EDID (up to 127 extension blocks).
const EDID_MAX: Bytes = Bytes::kib(16);
/// Size cap of a connector's mode list.
const MODES_MAX: Bytes = Bytes::kib(16);
/// Most connectors listed.
const CONNECTORS_MAX: usize = 32;
/// Most distinct modes listed per connector.
const MODES_SHOWN: usize = 24;
/// The size of one EDID block.
const BLOCK: usize = 128;
/// The fixed start of every EDID.
const EDID_HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];

/// The three-letter manufacturer id packed in two bytes (5 bits per letter, `A` is 1).
pub fn manufacturer_id(high: u8, low: u8) -> String {
    let packed = u16::from(high) << 8 | u16::from(low);
    [10, 5, 0]
        .iter()
        .map(|shift| match (packed >> shift & 0x1f) as u8 {
            n @ 1..=26 => (b'A' + n - 1) as char,
            _ => '?',
        })
        .collect()
}

/// Printable ASCII of a descriptor text field: ends at a line feed, trailing blanks removed.
fn descriptor_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0x0a).unwrap_or(bytes.len());
    let text: String =
        bytes[..end].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '?' }).collect();
    text.trim_end().to_owned()
}

/// A detailed timing descriptor as `1920x1080@60.0Hz` (`i` after the height when interlaced).
fn detailed_timing(d: &[u8]) -> Option<String> {
    let clock_khz = (u32::from(d[0]) | u32::from(d[1]) << 8) * 10;
    if clock_khz == 0 {
        return None;
    }
    let h_active = u32::from(d[2]) | (u32::from(d[4]) & 0xf0) << 4;
    let h_blank = u32::from(d[3]) | (u32::from(d[4]) & 0x0f) << 8;
    let v_active = u32::from(d[5]) | (u32::from(d[7]) & 0xf0) << 4;
    let v_blank = u32::from(d[6]) | (u32::from(d[7]) & 0x0f) << 8;
    let total = (h_active + h_blank) * (v_active + v_blank);
    if h_active == 0 || v_active == 0 || total == 0 {
        return None;
    }
    let interlaced = d[17] & 0x80 != 0;
    let refresh = f64::from(clock_khz) * 1000.0 / f64::from(total) / if interlaced { 2.0 } else { 1.0 };
    Some(format!("{h_active}x{v_active}{}@{refresh:.1}Hz", if interlaced { "i" } else { "" }))
}

/// The range limits descriptor as `vertical 48-144 Hz, horizontal 30-160 kHz`.
fn range_limits(d: &[u8]) -> String {
    let flags = d[4];
    let vertical_offset = |minimum: bool| match flags & 0x03 {
        0x03 => 255,
        0x02 if !minimum => 255,
        _ => 0,
    };
    let horizontal_offset = |minimum: bool| match flags >> 2 & 0x03 {
        0x03 => 255,
        0x02 if !minimum => 255,
        _ => 0,
    };
    format!(
        "vertical {}-{} Hz, horizontal {}-{} kHz",
        u32::from(d[5]) + vertical_offset(true),
        u32::from(d[6]) + vertical_offset(false),
        u32::from(d[7]) + horizontal_offset(true),
        u32::from(d[8]) + horizontal_offset(false),
    )
}

/// What a CTA-861 extension block holds: its revision and the data blocks that matter to a report.
fn cta_summary(block: &[u8]) -> String {
    let mut parts = vec![format!("CTA-861 rev {}", block[1])];
    let end = (block[2] as usize).clamp(4, BLOCK);
    let mut at = 4;
    while at < end {
        let header = block[at];
        let (tag, len) = (header >> 5, (header & 0x1f) as usize);
        let Some(data) = block.get(at + 1..at + 1 + len) else { break };
        match (tag, data.first()) {
            (7, Some(6)) => {
                let eotf = data.get(1).copied().unwrap_or(0);
                let mut kinds = Vec::new();
                for (bit, name) in [(0, "SDR"), (1, "traditional HDR"), (2, "ST 2084 PQ"), (3, "HLG")] {
                    if eotf >> bit & 1 == 1 {
                        kinds.push(name);
                    }
                }
                parts.push(format!("HDR static metadata ({})", kinds.join(", ")));
            }
            (7, Some(5)) => parts.push("colorimetry".to_owned()),
            (3, _) if data.len() >= 3 && data[..3] == [0x03, 0x0c, 0x00] => {
                parts.push("HDMI vendor block".to_owned())
            }
            (3, _) if data.len() >= 3 && data[..3] == [0xd8, 0x5d, 0xc4] => {
                parts.push("HDMI Forum vendor block".to_owned())
            }
            (1, _) => parts.push("audio".to_owned()),
            _ => {}
        }
        at += 1 + len;
    }
    parts.join(", ")
}

/// The extension blocks of an EDID in words.
fn extension_summary(edid: &[u8]) -> Vec<String> {
    let count = edid[126] as usize;
    let mut out = Vec::new();
    for index in 1..=count {
        let Some(block) = edid.get(index * BLOCK..(index + 1) * BLOCK) else {
            out.push(format!("extension {index}: missing from the data"));
            break;
        };
        out.push(match block[0] {
            0x02 => format!("extension {index}: {}", cta_summary(block)),
            0x70 => format!("extension {index}: DisplayID"),
            0xf0 => format!("extension {index}: extension block map"),
            tag => format!("extension {index}: tag {tag:#04x}"),
        });
    }
    out
}

/// The model-level facts of an EDID as report lines. The serial number, the week of manufacture and
/// free text descriptors are left out. A line says so when the data is not a valid EDID.
pub fn decode_edid(edid: &[u8]) -> Vec<String> {
    if edid.len() < BLOCK || edid[..8] != EDID_HEADER {
        return vec![format!("not a valid EDID ({} bytes)", edid.len())];
    }
    let base = &edid[..BLOCK];
    let checksum_ok = base.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0;
    let mut lines = vec![format!(
        "EDID {}.{}, {} bytes, base block checksum {}",
        edid[18],
        edid[19],
        edid.len(),
        if checksum_ok { "ok" } else { "bad" }
    )];
    let year = if edid[17] > 0 { format!("{}", 1990 + u32::from(edid[17])) } else { "unknown".to_owned() };
    lines.push(format!(
        "manufacturer {} product {:#06x} year {year}",
        manufacturer_id(edid[8], edid[9]),
        u16::from(edid[10]) | u16::from(edid[11]) << 8
    ));
    let digital = edid[20] & 0x80 != 0;
    let size = if edid[21] == 0 || edid[22] == 0 {
        "unspecified".to_owned()
    } else {
        format!("{}x{} cm", edid[21], edid[22])
    };
    lines.push(format!("{} input, size {size}", if digital { "digital" } else { "analog" }));
    let mut timings = Vec::new();
    for descriptor in (54..126).step_by(18) {
        let d = &edid[descriptor..descriptor + 18];
        if d[0] != 0 || d[1] != 0 {
            timings.extend(detailed_timing(d));
            continue;
        }
        match d[3] {
            0xfc => lines.push(format!("display name \"{}\"", descriptor_text(&d[5..18]))),
            0xfd => lines.push(format!("range limits: {}", range_limits(d))),
            // 0xff (serial number) and 0xfe (unspecified text) are never copied.
            _ => {}
        }
    }
    if !timings.is_empty() {
        lines.push(format!("detailed timings: {}", timings.join(" ")));
    }
    lines.extend(extension_summary(edid));
    lines
}

/// The mode list as distinct modes in order, with how many there are in all.
fn mode_summary(modes: &str) -> String {
    let all: Vec<&str> = modes.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let mut distinct: Vec<&str> = Vec::new();
    for mode in &all {
        if !distinct.contains(mode) {
            distinct.push(mode);
        }
    }
    let shown: Vec<&str> = distinct.iter().take(MODES_SHOWN).copied().collect();
    let more = distinct.len() - shown.len();
    format!(
        "{} listed, {} distinct: {}{}",
        all.len(),
        distinct.len(),
        shown.join(" "),
        if more > 0 { format!(" and {more} more") } else { String::new() }
    )
}

/// The connectors of the GPU at `device_dir` (`drm/card*/card*-*`): status lines for all, and the
/// decoded EDID and mode list of every connected one.
pub fn connectors(reader: &dyn Reader, device_dir: &Path, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    let mut count = 0;
    for card in
        list_names(&device_dir.join("drm")).into_iter().filter(|n| n.starts_with("card") && !n.contains('-'))
    {
        let card_dir = device_dir.join("drm").join(&card);
        for name in list_names(&card_dir).into_iter().filter(|n| n.starts_with(&format!("{card}-"))) {
            if count >= CONNECTORS_MAX {
                text.push_str("... more connectors not listed\n");
                return vec![collected(rel_path, text, "")];
            }
            count += 1;
            let dir = card_dir.join(&name);
            let value =
                |attribute: &str| read_value(reader, &dir.join(attribute)).unwrap_or_else(|| "?".to_owned());
            let status = value("status");
            let _ = writeln!(
                text,
                "{name}: status={status} enabled={} dpms={} connector_id={}",
                value("enabled"),
                value("dpms"),
                value("connector_id")
            );
            if status != "connected" {
                continue;
            }
            if let Some(modes) = read_text(reader, &dir.join("modes"), MODES_MAX) {
                let _ = writeln!(text, "  modes: {}", mode_summary(&modes));
            }
            let edid = read_head(reader, &dir.join("edid"), EDID_MAX);
            if edid.data.is_empty() {
                text.push_str("  edid: (none)\n");
            }
            for line in if edid.data.is_empty() { Vec::new() } else { decode_edid(&edid.data) } {
                let _ = writeln!(text, "  {line}");
            }
        }
    }
    if count == 0 {
        text.push_str("(no display connectors)\n");
    }
    vec![collected(rel_path, text, "")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "display_tests.rs"]
mod tests;
