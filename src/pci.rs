// SPDX-License-Identifier: MIT
//! PCI addresses (`dddd:bb:dd.f`).

use std::fmt;

/// A PCI function address. Ordered by domain, bus, device, function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PciAddress {
    /// PCI domain (segment).
    pub domain: u32,
    pub bus: u8,
    /// Device number, 0..=31.
    pub device: u8,
    /// Function number, 0..=7.
    pub function: u8,
}

/// The value of one hex digit, either case.
const fn hex_digit(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a') as u32 + 10),
        b'A'..=b'F' => Some((b - b'A') as u32 + 10),
        _ => None,
    }
}

/// Parses a non-empty run of hex digits (no sign, no prefix); None on a bad digit or u32 overflow.
fn parse_hex(field: &[u8]) -> Option<u32> {
    if field.is_empty() {
        return None;
    }
    field.iter().try_fold(0u32, |acc, &b| acc.checked_mul(16)?.checked_add(hex_digit(b)?))
}

impl PciAddress {
    /// Largest device number.
    pub const MAX_DEVICE: u8 = 31;
    /// Largest function number.
    pub const MAX_FUNCTION: u8 = 7;

    /// Parses `dddd:bb:dd.f`: a domain of 4 to 8 hex digits (Linux prints wider domains, for
    /// example behind VMD), 2-digit bus and device, a 1-digit function, any letter case. None for
    /// any other form or an out-of-range field.
    pub fn parse(text: &str) -> Option<Self> {
        const TAIL: usize = 8; // ":BB:DD.F"
        let bytes = text.as_bytes();
        if bytes.len() < 4 + TAIL || bytes.len() > 8 + TAIL {
            return None;
        }
        let (domain, tail) = bytes.split_at(bytes.len() - TAIL);
        if tail[0] != b':' || tail[3] != b':' || tail[6] != b'.' {
            return None;
        }
        let domain = parse_hex(domain)?;
        let bus = u8::try_from(parse_hex(&tail[1..3])?).ok()?;
        let device = u8::try_from(parse_hex(&tail[4..6])?).ok()?;
        let function = u8::try_from(parse_hex(&tail[7..8])?).ok()?;
        if device > Self::MAX_DEVICE || function > Self::MAX_FUNCTION {
            return None;
        }
        Some(Self { domain, bus, device, function })
    }

    /// The bundle directory name, valid on every OS: e.g. "0000-03-00.0".
    pub fn dir_name(&self) -> String {
        format!("{:04x}-{:02x}-{:02x}.{:x}", self.domain, self.bus, self.device, self.function)
    }
}

impl fmt::Display for PciAddress {
    /// Canonical text, lowercase, 4-digit domain unless wider: "0000:03:00.0".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("{:04x}:{:02x}:{:02x}.{:x}", self.domain, self.bus, self.device, self.function))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "pci_tests.rs"]
mod tests;
