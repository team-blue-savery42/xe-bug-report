// SPDX-License-Identifier: MIT
//! Byte counts.
#![forbid(unsafe_code)]

/// A number of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes(pub u64);

impl Bytes {
    /// `n` KiB.
    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }
    /// `n` MiB.
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }
    /// The count as u64.
    pub const fn get(self) -> u64 {
        self.0
    }
    /// Human-readable text with one decimal, e.g. "170.8 KiB", "512 B", "3.0 MiB".
    pub fn human(self) -> String {
        String::new()
    }
}
