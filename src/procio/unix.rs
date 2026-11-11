// SPDX-License-Identifier: MIT
//! Unix parts of process and file I/O.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use super::{capacity, read_stream};
use crate::bundle::source::{Keep, ReadOutcome, ReadResult};
use crate::sys;
use crate::units::Bytes;

/// On Unix `run_child` waits for the output pipe to close, up to the deadline.
pub(super) const EOF_GRACE: Option<Duration> = None;

/// Puts the child in its own process group, restores `argv[0]` as typed (the path lookup is done
/// by the caller), resets SIGCHLD, which an ignoring parent would otherwise leak through exec, and
/// turns core dumps off. std already resets SIGPIPE and the signal mask in the child.
pub(super) fn configure(cmd: &mut Command, program: &str) {
    cmd.process_group(0).arg0(program);
    sys::unix::prepare_child(cmd);
}

/// The child's process group, which has the child's pid because of `process_group(0)`.
pub(super) struct Group {
    pgid: u32,
}

impl Group {
    /// Records the group of a freshly spawned child.
    pub(super) fn attach(child: &Child) -> Self {
        Self { pgid: child.id() }
    }

    /// Nothing to do: surviving group members are killed only at the deadline.
    pub(super) fn after_exit(&self) {}

    /// SIGKILLs every process of the group.
    pub(super) fn kill(&self, _child: &mut Child) {
        sys::unix::kill_process_group(self.pgid);
    }
}

/// Output is passed through unchanged.
pub(super) fn finish_output(output: Vec<u8>, truncated: bool, _cap: usize) -> (Vec<u8>, bool) {
    (output, truncated)
}

/// Maps an open error to the outcome the collector reports.
fn classify(err: &io::Error) -> ReadOutcome {
    match err.kind() {
        io::ErrorKind::PermissionDenied => ReadOutcome::Denied,
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => ReadOutcome::Missing,
        _ => ReadOutcome::Failed,
    }
}

/// Opens `path` read-only (std adds `O_CLOEXEC`) with `O_NOCTTY` plus `extra_flags`; on failure
/// returns the finished error result.
fn open_for_read(path: &Path, extra_flags: i32) -> Result<File, ReadResult> {
    OpenOptions::new()
        .read(true)
        .custom_flags(sys::unix::O_NOCTTY | extra_flags)
        .open(path)
        .map_err(|e| ReadResult { outcome: classify(&e), error: e.to_string(), ..ReadResult::default() })
}

/// See [`super::read_file_bounded`].
pub(super) fn read_file_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    let mut file = match open_for_read(path, 0) {
        Ok(file) => file,
        Err(failed) => return failed,
    };
    let cap = capacity(max);
    let mut result = ReadResult::default();
    if keep == Keep::Tail && enter_at_tail(&mut file, cap) {
        result.truncated = true;
    }
    read_stream(file, cap, keep, false, result)
}

/// See [`super::read_nonblocking_bounded`]. No tail seek: the nodes this is for are not files.
pub(super) fn read_nonblocking_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    match open_for_read(path, sys::unix::O_NONBLOCK) {
        Ok(file) => read_stream(file, capacity(max), keep, true, ReadResult::default()),
        Err(failed) => failed,
    }
}

/// Seeks `file` so that about `cap` bytes remain, but only for a regular file that reports
/// allocated blocks. sysfs and procfs files report a page of size (4096) and no blocks, so seeking
/// by that size would land past their real content. True when it seeked.
fn enter_at_tail(file: &mut File, cap: usize) -> bool {
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file() || meta.blocks() == 0 {
        return false;
    }
    let size = meta.size();
    let Some(skip) = size.checked_sub(cap as u64).filter(|skip| *skip > 0) else {
        return false;
    };
    file.seek(SeekFrom::Start(skip)).is_ok()
}

/// See [`super::find_in_path`].
pub(super) fn find_in_path(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    if program.contains('/') {
        let path = PathBuf::from(program);
        return is_executable_file(&path).then_some(path);
    }
    let path_var = std::env::var_os("PATH")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&path_var).collect();
    find_in_dirs(program, &dirs, is_executable_file)
}

/// The first `dir/program` accepted by `is_executable`. Only absolute directories are searched:
/// empty and relative entries (`.`, `bin`) are the current directory by another spelling.
fn find_in_dirs(program: &str, dirs: &[PathBuf], is_executable: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    dirs.iter()
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

/// A regular file (symlinks followed) with at least one execute bit.
fn is_executable_file(path: &Path) -> bool {
    // A NUL byte can never be part of a path; metadata would reject it anyway.
    if path.as_os_str().as_bytes().contains(&0) {
        return false;
    }
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "unix_tests.rs"]
mod tests;
