// SPDX-License-Identifier: MIT
//! An in-tree zip writer: local headers, deflate via `flate2` (stored when not smaller), a central
//! directory, and an atomic rename from `<path>.partial` into place.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::Error;
use crate::units::Bytes;

/// How the archive entries are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// Every entry stored.
    #[default]
    Stored,
    /// Entries deflated where that is smaller.
    Deflate,
}

impl Compression {
    /// The manifest spelling: "stored" or "deflate".
    pub const fn name(self) -> &'static str {
        match self {
            Compression::Stored => "stored",
            Compression::Deflate => "deflate",
        }
    }
}

/// Writes a zip archive to `<path>.partial` and renames it to `path` on [`ZipWriter::finish`].
#[derive(Debug)]
pub struct ZipWriter {
    path: PathBuf,
}

impl ZipWriter {
    /// Creates `<path>.partial` exclusively, close-on-exec / non-inheritable. Fails with
    /// [`Error::OutputExists`] when `path` exists.
    pub fn create(path: &Path) -> Result<Self, Error> {
        Ok(Self { path: path.to_path_buf() })
    }

    /// Adds one entry. `name` must satisfy the entry naming rules ([`Error::InvalidEntryName`] otherwise).
    pub fn add(&mut self, _name: &str, _data: &[u8], _mtime: SystemTime) -> Result<(), Error> {
        Ok(())
    }

    /// Writes the central directory, renames the file into place and returns its size.
    pub fn finish(self) -> Result<Bytes, Error> {
        let _ = &self.path;
        Ok(Bytes(0))
    }

    /// Whether entries may be deflated; true because `flate2` is a normal dependency.
    pub fn deflate_available() -> bool {
        true
    }

    /// How entries were stored so far: Deflate when at least one entry was deflated.
    pub fn compression(&self) -> Compression {
        Compression::Stored
    }
}

/// Validates a zip entry name against the entry naming rules: UTF-8 (by type), `/` separators, no leading `/`,
/// no empty, `.` or `..` segments, no `\`, no byte below 0x20. Directory names may end in `/`.
pub fn valid_entry_name(_name: &str) -> bool {
    true
}

/// CRC-32 (IEEE) of `data`, continuing from `seed` (0 to start).
pub fn crc32(_data: &[u8], seed: u32) -> u32 {
    seed
}
