// SPDX-License-Identifier: MIT
//! Byte counts.

const KIB: u64 = 1024;
const MIB: u64 = KIB * KIB;

/// A number of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes(pub u64);

impl Bytes {
    /// `n` KiB (saturating).
    pub const fn kib(n: u64) -> Self {
        Self(n.saturating_mul(KIB))
    }
    /// `n` MiB (saturating).
    pub const fn mib(n: u64) -> Self {
        Self(n.saturating_mul(MIB))
    }
    /// The count as u64.
    pub const fn get(self) -> u64 {
        self.0
    }
    /// Human-readable text with one decimal: "512 B", "170.8 KiB", "3.0 MiB". There is no GiB
    /// step; nothing the tool writes gets that large.
    pub fn human(self) -> String {
        let bytes = self.0;
        if bytes < KIB {
            format!("{bytes} B")
        } else if bytes < MIB {
            format!("{:.1} KiB", bytes as f64 / KIB as f64)
        } else {
            format!("{:.1} MiB", bytes as f64 / MIB as f64)
        }
    }
    /// A size cap in the largest unit that divides it exactly: "16 MiB", "64 KiB", "1023 B".
    pub fn cap_label(self) -> String {
        let bytes = self.0;
        if bytes >= MIB && bytes.is_multiple_of(MIB) {
            format!("{} MiB", bytes / MIB)
        } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
            format!("{} KiB", bytes / KIB)
        } else {
            format!("{bytes} B")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "units_tests.rs"]
mod tests;
