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

impl PciAddress {
    /// Parses `dddd:bb:dd.f` with a 5 to 8 digit domain allowed and any letter case, as the
    /// reference `PciAddress::parse`. None for any other form or an out-of-range field.
    pub fn parse(_text: &str) -> Option<Self> {
        None
    }

    /// The bundle directory name, valid on every OS: e.g. "0000-03-00.0".
    pub fn dir_name(&self) -> String {
        String::new()
    }
}

impl fmt::Display for PciAddress {
    /// Canonical text, lowercase, 4-digit domain unless wider: "0000:03:00.0".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:02x}:{:02x}.{:x}", self.domain, self.bus, self.device, self.function)
    }
}
