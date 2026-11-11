// SPDX-License-Identifier: MIT
//! The raw PCI configuration space dump (`lspci -xxxx`) with the Device Serial Number removed.
//!
//! A GPU can carry the PCIe Device Serial Number extended capability (id 0x0003): eight bytes that
//! identify the board. In a hex dump they are only digits, which no text rule can recognise, so
//! the dump is parsed here and those bytes are replaced by `xx` before the text is delivered.

use std::time::Duration;

use crate::bundle::source::{Produced, Status};
use crate::pci::PciAddress;
use crate::procio::{ChildOutcome, run_child};
use crate::units::Bytes;

use super::debugfs::{collected, skipped};

/// Wall-clock limit of the `lspci` run.
pub const LSPCI_TIMEOUT: Duration = Duration::from_secs(8);
/// Time the source gets: the `lspci` run plus the time to start and stop it.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest output kept: a 4 KiB configuration space is about 20 KiB of text.
const OUTPUT_MAX: Bytes = Bytes::kib(256);
/// The offset where the extended capability list starts.
const EXTENDED_START: usize = 0x100;
/// The id of the Device Serial Number extended capability.
const DSN_CAPABILITY: u32 = 0x0003;
/// The size of the extended configuration space.
const CONFIG_SIZE: usize = 4096;
/// Most extended capabilities followed, so a corrupt list ends.
const CAPABILITIES_MAX: usize = 96;

/// One row of the dump: `ff0: 00 01 ...` as the offset of its first byte and its byte tokens.
fn parse_row(line: &str) -> Option<(usize, Vec<&str>)> {
    let (offset, bytes) = line.split_once(':')?;
    if offset.is_empty() || offset.len() > 4 || !offset.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let tokens: Vec<&str> = bytes.split_whitespace().collect();
    let hex = |t: &&str| t.len() == 2 && t.bytes().all(|b| b.is_ascii_hexdigit());
    (!tokens.is_empty() && tokens.iter().all(hex))
        .then(|| (usize::from_str_radix(offset, 16).unwrap_or(0), tokens))
}

/// The configuration space bytes a dump holds, indexed by offset; None where the dump has no byte.
fn dump_bytes(dump: &str) -> Vec<Option<u8>> {
    let mut bytes = vec![None; CONFIG_SIZE];
    for (base, tokens) in dump.lines().filter_map(parse_row) {
        for (i, token) in tokens.iter().enumerate() {
            if let Some(slot) = bytes.get_mut(base + i) {
                *slot = u8::from_str_radix(token, 16).ok();
            }
        }
    }
    bytes
}

/// The offsets of the Device Serial Number capabilities in the extended list of `bytes`. The list
/// is followed through `next` pointers, at most [`CAPABILITIES_MAX`] links and never backwards.
pub fn serial_capability_offsets(bytes: &[Option<u8>]) -> Vec<usize> {
    let dword = |at: usize| -> Option<u32> {
        let b = bytes.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0]?, b[1]?, b[2]?, b[3]?]))
    };
    let mut found = Vec::new();
    let mut at = EXTENDED_START;
    for _ in 0..CAPABILITIES_MAX {
        let Some(header) = dword(at) else { break };
        // An empty list reads as all zeros or all ones.
        if header == 0 || header == u32::MAX {
            break;
        }
        if header & 0xffff == DSN_CAPABILITY {
            found.push(at);
        }
        let next = (header >> 20) as usize;
        if next < EXTENDED_START || !next.is_multiple_of(4) || next <= at {
            break;
        }
        at = next;
    }
    found
}

/// A dump with the eight serial bytes of every Device Serial Number capability replaced by `xx`.
/// Text that is not a dump row is left as it is.
pub fn blank_serial_capability(dump: &str) -> String {
    let bytes = dump_bytes(dump);
    let blanked: Vec<usize> =
        serial_capability_offsets(&bytes).into_iter().flat_map(|at| at + 4..at + 12).collect();
    if blanked.is_empty() {
        return dump.to_owned();
    }
    let mut out = String::with_capacity(dump.len());
    for line in dump.split_inclusive('\n') {
        let Some((base, tokens)) = parse_row(line.trim_end_matches('\n')) else {
            out.push_str(line);
            continue;
        };
        let (prefix, _) = line.split_once(':').unwrap_or((line, ""));
        out.push_str(prefix);
        out.push(':');
        for (i, token) in tokens.iter().enumerate() {
            out.push(' ');
            out.push_str(if blanked.contains(&(base + i)) { "xx" } else { token });
        }
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Runs `lspci -xxxx` for `bdf` and delivers the dump without the serial number. Skipped when
/// `lspci` is not installed, Failed when it exits non-zero without output, TimedOut at its limit.
pub fn config_dump(rel_path: &str, bdf: &PciAddress) -> Vec<Produced> {
    let argv: Vec<String> =
        ["lspci", "-xxxx", "-s"].iter().map(|s| (*s).to_owned()).chain([bdf.to_string()]).collect();
    let result = run_child(&argv, LSPCI_TIMEOUT, OUTPUT_MAX);
    dump_from(rel_path, &argv.join(" "), &result.outcome, &result.output, result.truncated)
}

/// [`config_dump`] for a finished `lspci` run.
pub fn dump_from(
    rel_path: &str,
    via: &str,
    outcome: &ChildOutcome,
    output: &[u8],
    truncated: bool,
) -> Vec<Produced> {
    let code = match outcome {
        ChildOutcome::NotFound => return vec![skipped(rel_path, "lspci not installed")],
        ChildOutcome::SpawnFailed(error) => {
            let mut out = skipped(rel_path, format!("could not start lspci: {error}"));
            out.status = Status::Failed;
            return vec![out];
        }
        ChildOutcome::TimedOut => {
            let mut out = skipped(rel_path, format!("did not finish within {} s", LSPCI_TIMEOUT.as_secs()));
            out.status = Status::TimedOut;
            return vec![out];
        }
        ChildOutcome::Exited(code) => *code,
    };
    if output.is_empty() {
        if code == 0 {
            return vec![skipped(rel_path, "produced no output")];
        }
        let mut out = skipped(rel_path, format!("exit code {code}"));
        out.status = Status::Failed;
        return vec![out];
    }
    let mut out = collected(rel_path, blank_serial_capability(&String::from_utf8_lossy(output)), via);
    if truncated {
        out.status = Status::Truncated;
        out.reason = "larger than the size cap".to_owned();
    }
    vec![out]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "pci_config_tests.rs"]
mod tests;
