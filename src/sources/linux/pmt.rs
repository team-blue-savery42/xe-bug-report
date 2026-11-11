// SPDX-License-Identifier: MIT
//! Firmware crash logs of the platform telemetry interface (`/sys/class/intel_pmt/crashlog*`).
//!
//! Attributes are only read, never written. The raw crash log and the text describing each region
//! are separate sources because redaction applies to a whole source.

use std::fs;
use std::path::{Path, PathBuf};

use crate::bundle::source::{Produced, Reader};
use crate::units::Bytes;

use super::debugfs::{PROBE_MAX, collected, from_read, read_head};
use super::text::format_probe_line;

/// The class directory of the platform telemetry regions.
pub const PMT_CLASS_DIR: &str = "/sys/class/intel_pmt";
/// Name prefix of a crash log region.
const PMT_REGION_PREFIX: &str = "crashlog";
/// Attributes described in the text part, in output order.
const PMT_INFO_KEYS: &[&str] = &["guid", "size", "offset", "enable", "error", "trigger", "consumed"];
/// Size cap of one raw crash log region.
const PMT_CRASHLOG_MAX: Bytes = Bytes::mib(1);

/// Which file of a crash log region a source collects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtPart {
    /// `pmt-<region>.bin`: the raw crash log.
    Binary,
    /// `pmt-<region>.txt`: guid, size, offset and the enable, error, trigger and consumed state.
    Info,
}

/// Whether a directory entry names a crash log region: `crashlog` followed by at least one digit
/// and nothing else. A telemetry region does not qualify.
pub fn is_pmt_crashlog_name(name: &str) -> bool {
    name.strip_prefix(PMT_REGION_PREFIX)
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// The platform-telemetry crash logs of one device.
///
/// Looks at every `crashlog*` entry of `class_dir` whose `device` link resolves below `os_path`
/// (the intel_vsec child of the GPU). For [`PmtPart::Binary`] one artifact per region: Collected,
/// Truncated (1 MiB cap), Skipped (`needs root`) or Failed. For [`PmtPart::Info`] one Collected
/// artifact per region. Empty when the device has no crash log region.
pub fn pmt_crashlogs(
    reader: &dyn Reader,
    class_dir: &Path,
    dir_rel: &str,
    os_path: &str,
    part: PmtPart,
) -> Vec<Produced> {
    let mut regions: Vec<PathBuf> = match fs::read_dir(class_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|e| is_pmt_crashlog_name(&e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect(),
        Err(_) => return Vec::new(),
    };
    regions.sort();
    let mut trimmed = os_path;
    while trimmed.len() > 1 && trimmed.ends_with('/') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    let below = format!("{trimmed}/");

    let mut out = Vec::new();
    for region in regions {
        let Ok(owner) = fs::canonicalize(region.join("device")) else {
            continue;
        };
        if !format!("{}/", owner.to_string_lossy()).starts_with(&below) {
            continue;
        }
        let name = region.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let base = format!("{dir_rel}pmt-{name}");
        let via = region.to_string_lossy().into_owned();
        match part {
            PmtPart::Binary => {
                if let Some(mut produced) = from_read(
                    format!("{base}.bin"),
                    read_head(reader, &region.join("crashlog"), PMT_CRASHLOG_MAX),
                ) {
                    produced.via = via;
                    out.push(produced);
                }
            }
            PmtPart::Info => {
                let mut text = String::new();
                for key in PMT_INFO_KEYS {
                    text.push_str(&format_probe_line(key, &read_head(reader, &region.join(key), PROBE_MAX)));
                    text.push('\n');
                }
                out.push(collected(format!("{base}.txt"), text, via));
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "pmt_tests.rs"]
mod tests;
