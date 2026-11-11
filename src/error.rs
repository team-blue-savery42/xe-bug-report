// SPDX-License-Identifier: MIT
//! The crate-level error type.

use std::path::PathBuf;

/// Everything that can stop xe-bug-report from producing an archive.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An argument was malformed or out of range; the text is the user-facing message.
    #[error("{0}")]
    InvalidArgument(String),
    /// `--device` named an address that is not on this system.
    #[error("device {0} not found")]
    UnknownDevice(String),
    /// Something is already at the output path.
    #[error("{} already exists", .0.display())]
    OutputExists(PathBuf),
    /// The output path cannot be inspected or created.
    #[error("cannot create {}: {source}", path.display())]
    OutputUnwritable { path: PathBuf, source: std::io::Error },
    /// Writing or finishing the archive failed.
    #[error("cannot write {}: {source}", path.display())]
    WriteFailed { path: PathBuf, source: std::io::Error },
    /// An entry name violates the zip entry naming rules.
    #[error("invalid archive entry name {0:?}")]
    InvalidEntryName(String),
    /// Any other I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
