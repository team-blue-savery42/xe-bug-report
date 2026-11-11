// SPDX-License-Identifier: MIT
//! Bounded child processes, bounded file reads, private temp directories and PATH lookup.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bundle::source::{Keep, ReadResult};
use crate::units::Bytes;

/// How a child process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOutcome {
    /// Ran to completion with this exit code; death by signal is 128 + signal; -1 when the status
    /// is unavailable (SIGCHLD ignored, ECHILD) or cannot be decoded.
    Exited(i32),
    /// Killed with its process group (job object on Windows) at the deadline.
    TimedOut,
    /// argv[0] is not an executable on PATH.
    NotFound,
    /// Any other failure to start it; the OS error text.
    SpawnFailed(String),
}

/// The result of [`run_child`].
#[derive(Debug, Clone)]
pub struct ChildResult {
    pub outcome: ChildOutcome,
    /// stdout and stderr interleaved, at most the `max_output` passed in.
    pub output: Vec<u8>,
    /// Output reached `max_output`; the rest was drained and discarded.
    pub truncated: bool,
    /// Wall time from spawn to exit or kill.
    pub elapsed: Duration,
}

/// Runs `argv` with stdin null, stdout and stderr on one pipe, `LC_ALL=C`, in its own process
/// group (job object on Windows), killing it at `timeout`. `argv[0]` without a separator is looked
/// up with [`find_in_path`]. Never blocks much longer than `timeout` + 2 s.
pub fn run_child(argv: &[String], timeout: Duration, max_output: Bytes) -> ChildResult {
    let _ = (argv, timeout, max_output);
    ChildResult {
        outcome: ChildOutcome::NotFound,
        output: Vec::new(),
        truncated: false,
        elapsed: Duration::ZERO,
    }
}

/// Reads at most `max` bytes of `path`, keeping the head or the tail. Never seeks for the tail
/// unless the file reports allocated blocks (sysfs files report size 4096 and zero blocks).
pub fn read_file_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    let _ = (path, max, keep);
    ReadResult::default()
}

/// The full path of `program` on PATH (PATHEXT on Windows); never the current directory.
/// A `program` containing a path separator is returned as-is when it is an executable file.
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    let _ = program;
    None
}

/// The path of the running executable.
pub fn self_executable_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// A private (mode 0700) temporary directory, removed with everything in it on drop.
#[derive(Debug)]
pub struct PrivateTempDir {
    dir: tempfile::TempDir,
}

impl PrivateTempDir {
    /// Creates a new directory under the system temporary directory; `prefix` starts its name.
    pub fn create(prefix: &str) -> io::Result<Self> {
        Ok(Self { dir: tempfile::Builder::new().prefix(prefix).tempdir()? })
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}
