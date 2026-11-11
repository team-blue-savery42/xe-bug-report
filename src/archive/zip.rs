// SPDX-License-Identifier: MIT
//! An in-tree zip writer: local headers, deflate via `flate2` (stored when not smaller), a central
//! directory, and an atomic rename from `<path>.partial` into place.
//!
//! The container is plain zip (APPNOTE 6.3) without zip64, which every unzip reads. The limits are
//! therefore 65534 entries and 4 GiB - 2 bytes in total; going past them is an error and never a
//! corrupt archive (0xFFFF and 0xFFFFFFFF are the zip64 marker values and are not used).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use flate2::Compression as Level;
use flate2::write::DeflateEncoder;

use crate::error::Error;
use crate::timefmt;
use crate::units::Bytes;

const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4B50;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4B50;
const END_RECORD_SIGNATURE: u32 = 0x0605_4B50;
const VERSION_NEEDED: u16 = 20;
const FLAG_UTF8: u16 = 0x0800;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
const LOCAL_HEADER_SIZE: u64 = 30;
const END_RECORD_SIZE: u64 = 22;
/// 0xFFFFFFFF is the zip64 marker, so the largest usable size and offset is one less.
const ZIP32_MAX: u64 = 0xFFFF_FFFE;
const NAME_MAX_LENGTH: usize = 0xFFFF;
/// 0xFFFF is the zip64 marker for the entry count.
const ENTRIES_MAX: usize = 0xFFFE;

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

/// One entry as recorded for the central directory.
#[derive(Debug)]
struct Entry {
    name: String,
    crc: u32,
    compressed_size: u32,
    size: u32,
    offset: u32,
    method: u16,
    dos_date: u16,
    dos_time: u16,
}

/// Lifecycle of the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    /// An earlier `add` failed; the writer is unusable and the `.partial` file is discarded on drop.
    Failed,
    Finished,
}

/// Writes a zip archive to `<path>.partial` and renames it to `path` on [`ZipWriter::finish`].
///
/// Dropping a writer that was not finished removes the `.partial` file, so an error or an early
/// return never leaves a truncated archive under the final name.
///
/// The `.partial` file is opened by `std`, which sets `O_CLOEXEC` on Unix and leaves the handle
/// non-inheritable on Windows (`bInheritHandle` is false); child processes spawned during
/// collection therefore never hold it, and the final rename cannot fail on Windows because of one.
#[derive(Debug)]
pub struct ZipWriter {
    path: PathBuf,
    partial: PathBuf,
    file: Option<BufWriter<File>>,
    entries: Vec<Entry>,
    written: u64,
    state: State,
    deflated: bool,
}

impl ZipWriter {
    /// Creates `<path>.partial` exclusively, close-on-exec / non-inheritable. Fails with
    /// [`Error::OutputExists`] when `path` exists (a dangling symlink counts) and with
    /// [`Error::OutputUnwritable`] for any other problem, including a stale `.partial` file.
    pub fn create(path: &Path) -> Result<Self, Error> {
        if path.file_name().is_none() {
            return Err(Error::OutputUnwritable {
                path: path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "empty output path"),
            });
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::OutputExists(path.to_path_buf())),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(Error::OutputUnwritable { path: path.to_path_buf(), source }),
        }
        let mut partial_name = path.as_os_str().to_os_string();
        partial_name.push(".partial");
        let partial = PathBuf::from(partial_name);
        let file = OpenOptions::new().write(true).create_new(true).open(&partial).map_err(|source| {
            let source = if source.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "left over from an interrupted run; remove it and retry",
                )
            } else {
                source
            };
            Error::OutputUnwritable { path: partial.clone(), source }
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            partial,
            file: Some(BufWriter::with_capacity(64 * 1024, file)),
            entries: Vec::new(),
            written: 0,
            state: State::Open,
            deflated: false,
        })
    }

    fn write_failed(&self, source: io::Error) -> Error {
        Error::WriteFailed { path: self.path.clone(), source }
    }

    fn limit_error(&self, what: &str) -> Error {
        self.write_failed(io::Error::new(io::ErrorKind::InvalidInput, what.to_string()))
    }

    /// Adds one entry. `name` must satisfy the entry naming rules ([`Error::InvalidEntryName`] otherwise).
    ///
    /// Data is deflated when that is smaller and stored otherwise. Any failure makes the writer
    /// unusable: later calls fail and `finish` discards the archive. The zip32 limits (65534
    /// entries, 4 GiB - 2 bytes) are errors, not a corrupt archive.
    pub fn add(&mut self, name: &str, data: &[u8], mtime: SystemTime) -> Result<(), Error> {
        if self.state != State::Open {
            return Err(self.limit_error("the archive writer is no longer usable"));
        }
        // Any refusal poisons the writer: a half-written entry must never be followed by another.
        self.state = State::Failed;
        if !valid_entry_name(name) {
            return Err(Error::InvalidEntryName(name.to_string()));
        }
        if self.entries.len() >= ENTRIES_MAX {
            return Err(self.limit_error("too many archive entries (limit 65534)"));
        }
        let Ok(name_len) = u16::try_from(name.len()) else {
            return Err(Error::InvalidEntryName(name.to_string()));
        };
        let size = u32::try_from(data.len()).ok().filter(|&n| u64::from(n) <= ZIP32_MAX);
        let Some(size) = size else {
            return Err(self.limit_error("archive entry larger than 4 GiB - 2 bytes"));
        };

        let (dos_date, dos_time) = timefmt::dos_date_time(mtime);
        let crc = crc32(data, 0);
        let deflated = deflate_smaller(data);
        let (method, payload): (u16, &[u8]) = match &deflated {
            Some(bytes) => (METHOD_DEFLATED, bytes),
            None => (METHOD_STORED, data),
        };
        let compressed_size = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let total = self
            .written
            .saturating_add(LOCAL_HEADER_SIZE)
            .saturating_add(name.len() as u64)
            .saturating_add(payload.len() as u64);
        if self.written > ZIP32_MAX || total > ZIP32_MAX {
            return Err(self.limit_error("archive larger than 4 GiB - 2 bytes"));
        }
        let offset = u32::try_from(self.written).unwrap_or(u32::MAX);

        let mut header = Vec::with_capacity(LOCAL_HEADER_SIZE as usize + name.len());
        put32(&mut header, LOCAL_HEADER_SIGNATURE);
        put16(&mut header, VERSION_NEEDED);
        put16(&mut header, FLAG_UTF8);
        put16(&mut header, method);
        put16(&mut header, dos_time);
        put16(&mut header, dos_date);
        put32(&mut header, crc);
        put32(&mut header, compressed_size);
        put32(&mut header, size);
        put16(&mut header, name_len);
        put16(&mut header, 0); // extra field length
        header.extend_from_slice(name.as_bytes());

        let Some(file) = self.file.as_mut() else {
            return Err(self.limit_error("the archive file is closed"));
        };
        let wrote = file.write_all(&header).and_then(|()| file.write_all(payload));
        if let Err(source) = wrote {
            return Err(self.write_failed(source));
        }
        self.written += header.len() as u64 + payload.len() as u64;
        self.deflated |= method == METHOD_DEFLATED;
        self.entries.push(Entry {
            name: name.to_string(),
            crc,
            compressed_size,
            size,
            offset,
            method,
            dos_date,
            dos_time,
        });
        self.state = State::Open;
        Ok(())
    }

    /// Writes the central directory, fsyncs, renames the file into place and returns its size.
    ///
    /// Never replaces a file that appeared at `path` meanwhile: that is [`Error::OutputExists`].
    /// On any error the `.partial` file is removed.
    pub fn finish(mut self) -> Result<Bytes, Error> {
        if self.state != State::Open {
            return Err(self.limit_error("the archive writer is no longer usable"));
        }
        self.state = State::Failed;

        let directory_offset = self.written;
        let mut directory = Vec::new();
        for entry in &self.entries {
            put32(&mut directory, CENTRAL_HEADER_SIGNATURE);
            put16(&mut directory, VERSION_NEEDED); // version made by
            put16(&mut directory, VERSION_NEEDED); // version needed
            put16(&mut directory, FLAG_UTF8);
            put16(&mut directory, entry.method);
            put16(&mut directory, entry.dos_time);
            put16(&mut directory, entry.dos_date);
            put32(&mut directory, entry.crc);
            put32(&mut directory, entry.compressed_size);
            put32(&mut directory, entry.size);
            let Ok(name_len) = u16::try_from(entry.name.len()) else {
                return Err(Error::InvalidEntryName(entry.name.clone()));
            };
            put16(&mut directory, name_len);
            put16(&mut directory, 0); // extra field length
            put16(&mut directory, 0); // comment length
            put16(&mut directory, 0); // disk number start
            put16(&mut directory, 0); // internal attributes
            put32(&mut directory, 0); // external attributes
            put32(&mut directory, entry.offset);
            directory.extend_from_slice(entry.name.as_bytes());
        }
        let directory_size = directory.len() as u64;
        if directory_offset > ZIP32_MAX
            || directory_size > ZIP32_MAX
            || directory_offset + directory_size + END_RECORD_SIZE > ZIP32_MAX
        {
            return Err(self.limit_error("archive larger than 4 GiB - 2 bytes"));
        }
        let count = u16::try_from(self.entries.len()).unwrap_or(u16::MAX);
        put32(&mut directory, END_RECORD_SIGNATURE);
        put16(&mut directory, 0); // this disk
        put16(&mut directory, 0); // disk with the central directory
        put16(&mut directory, count);
        put16(&mut directory, count);
        put32(&mut directory, u32::try_from(directory_size).unwrap_or(u32::MAX));
        put32(&mut directory, u32::try_from(directory_offset).unwrap_or(u32::MAX));
        put16(&mut directory, 0); // comment length

        let Some(mut writer) = self.file.take() else {
            return Err(self.limit_error("the archive file is closed"));
        };
        let flushed = writer.write_all(&directory).and_then(|()| writer.flush());
        if let Err(source) = flushed {
            return Err(self.write_failed(source));
        }
        let file = match writer.into_inner() {
            Ok(file) => file,
            Err(err) => return Err(self.write_failed(err.into_error())),
        };
        if let Err(source) = file.sync_all() {
            return Err(self.write_failed(source));
        }
        // The handle must be closed before the rename (required on Windows).
        drop(file);
        self.written += directory.len() as u64;

        publish(&self.partial, &self.path)?;
        self.state = State::Finished;
        Ok(Bytes(self.written))
    }

    /// Whether entries may be deflated; true because `flate2` is a normal dependency.
    pub fn deflate_available() -> bool {
        true
    }

    /// How entries were stored so far: Deflate when at least one entry was deflated.
    pub fn compression(&self) -> Compression {
        if self.deflated { Compression::Deflate } else { Compression::Stored }
    }

    /// Bytes written to the archive so far: local headers and data, plus the central directory
    /// once `finish` has run (which consumes the writer, so the result of `finish` is the final
    /// size).
    pub fn bytes_written(&self) -> Bytes {
        Bytes(self.written)
    }
}

impl Drop for ZipWriter {
    /// Removes the `.partial` file unless [`ZipWriter::finish`] succeeded.
    fn drop(&mut self) {
        if self.state != State::Finished {
            // Discard unflushed bytes instead of writing them just to delete the file.
            if let Some(writer) = self.file.take() {
                let (file, _unflushed) = writer.into_parts();
                drop(file);
            }
            let _ = fs::remove_file(&self.partial);
        }
    }
}

/// Moves the finished `partial` file to `path` without replacing anything that is there.
fn publish(partial: &Path, path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        // link(2) fails with EEXIST instead of replacing, so there is no check-then-rename race.
        match fs::hard_link(partial, path) {
            Ok(()) => {
                let _ = fs::remove_file(partial);
                sync_parent(path);
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                return Err(Error::OutputExists(path.to_path_buf()));
            }
            // A file system without hard links: fall back to check and rename below.
            Err(_) => {}
        }
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::OutputExists(path.to_path_buf()));
    }
    fs::rename(partial, path).map_err(|source| Error::WriteFailed { path: path.to_path_buf(), source })?;
    #[cfg(unix)]
    sync_parent(path);
    Ok(())
}

/// Best-effort fsync of the directory holding `path`, so the new name survives a power loss.
#[cfg(unix)]
fn sync_parent(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Raw-deflates `data`; None when that fails, `data` is empty or the result is not smaller.
fn deflate_smaller(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut encoder = DeflateEncoder::new(Vec::with_capacity(data.len() / 2 + 64), Level::default());
    encoder.write_all(data).ok()?;
    let out = encoder.finish().ok()?;
    (out.len() < data.len()).then_some(out)
}

/// Validates a zip entry name against the entry naming rules: UTF-8 (by type), `/` separators, no leading `/`,
/// no empty, `.` or `..` segments (so no trailing `/` either), no `\`, no
/// byte below 0x20, and at most 65535 bytes.
pub fn valid_entry_name(name: &str) -> bool {
    if name.is_empty() || name.len() > NAME_MAX_LENGTH {
        return false;
    }
    if name.bytes().any(|b| b == b'\\' || b < 0x20) {
        return false;
    }
    name.split('/').all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// CRC-32 (IEEE) of `data`, continuing from `seed` (0 to start).
pub fn crc32(data: &[u8], seed: u32) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(seed);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "zip_tests.rs"]
mod tests;
