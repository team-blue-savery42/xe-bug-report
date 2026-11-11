// SPDX-License-Identifier: MIT
//! Windows parts of process and file I/O.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use super::{capacity, is_utf8_allowing_cut_tail, parse_pathext, pathext_candidates, read_stream};
use crate::bundle::source::{Keep, ReadOutcome, ReadResult};
use crate::sys::windows::{CREATE_NO_WINDOW, Job, oem_to_utf8};
use crate::units::Bytes;

/// `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`, `ERROR_ACCESS_DENIED`.
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;

/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`: an open log must stay readable
///.
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
/// `FILE_FLAG_SEQUENTIAL_SCAN`.
const FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

/// Longest wait for the last bytes after the child ended; a surviving descendant may keep writing.
pub(super) const EOF_GRACE: Option<Duration> = Some(Duration::from_secs(1));

/// No console window, and the default PATHEXT-resolved path is passed in by the caller.
pub(super) fn configure(cmd: &mut Command, _program: &str) {
    cmd.creation_flags(CREATE_NO_WINDOW);
}

/// The kill-on-close job the child was assigned to, if one could be set up.
///
/// The child is assigned right after `CreateProcess` returns, so it runs unconfined for a moment
/// (std does not expose `CREATE_SUSPENDED` without also giving up its handle management); a process
/// it starts in that window escapes the job. Without a job (creation failed, or the parent job
/// forbids nesting) a timeout kills only the child.
pub(super) struct Group {
    job: Option<Job>,
}

impl Group {
    /// Puts `child` in a new job object.
    pub(super) fn attach(child: &Child) -> Self {
        let job = Job::create().ok().filter(|job| job.assign(child).is_ok());
        Self { job }
    }

    /// Kills the descendants the child left behind: the call does not wait for the pipe to close.
    pub(super) fn after_exit(&self) {
        if let Some(job) = &self.job {
            let _ = job.terminate();
        }
    }

    /// Terminates the job; falls back to killing the child alone.
    pub(super) fn kill(&self, child: &mut Child) {
        let terminated = self.job.as_ref().is_some_and(|job| job.terminate().is_ok());
        if !terminated {
            let _ = child.kill();
        }
    }
}

/// Native tools print in the console's OEM code page when piped, the bundle holds UTF-8: output
/// that is not UTF-8 (allowing a sequence cut at the cap) is transcoded, then cut to `cap` again.
pub(super) fn finish_output(output: Vec<u8>, truncated: bool, cap: usize) -> (Vec<u8>, bool) {
    if is_utf8_allowing_cut_tail(&output) {
        return (output, truncated);
    }
    let mut text = oem_to_utf8(&output);
    let mut truncated = truncated;
    if text.len() > cap {
        let mut end = cap;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        truncated = true;
    }
    (text.into_bytes(), truncated)
}

/// Maps an open error to the outcome the collector reports.
fn classify(err: &std::io::Error) -> ReadOutcome {
    match err.raw_os_error() {
        Some(ERROR_ACCESS_DENIED) => ReadOutcome::Denied,
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => ReadOutcome::Missing,
        _ => ReadOutcome::Failed,
    }
}

/// See [`super::read_file_bounded`]. Opened with full sharing so a log another process holds open
/// can still be read.
pub(super) fn read_file_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    let mut result = ReadResult::default();
    let opened =
        OpenOptions::new().read(true).share_mode(SHARE_ALL).custom_flags(FLAG_SEQUENTIAL_SCAN).open(path);
    let mut file = match opened {
        Ok(file) => file,
        Err(e) => {
            result.outcome = classify(&e);
            result.error = e.to_string();
            // CreateFileW on a directory without FILE_FLAG_BACKUP_SEMANTICS says "access denied";
            // that is not a permission problem (Unix reports Failed, EISDIR).
            if result.outcome == ReadOutcome::Denied && path.is_dir() {
                result.outcome = ReadOutcome::Failed;
                result.error = "is a directory".to_owned();
            }
            return result;
        }
    };
    let cap = capacity(max);
    if keep == Keep::Tail && enter_at_tail(&mut file, cap) {
        result.truncated = true;
    }
    read_stream(file, cap, keep, false, result)
}

/// See [`super::read_nonblocking_bounded`]: Windows has no non-blocking open of this kind.
pub(super) fn read_nonblocking_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    read_file_bounded(path, max, keep)
}

/// A regular file can be entered at its tail; anything else is read through with a rolling window.
fn enter_at_tail(file: &mut File, cap: usize) -> bool {
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    let Some(skip) = meta.len().checked_sub(cap as u64).filter(|skip| *skip > 0) else {
        return false;
    };
    file.seek(SeekFrom::Start(skip)).is_ok()
}

/// See [`super::find_in_path`]: PATH and PATHEXT only, never the current directory.
pub(super) fn find_in_path(program: &str) -> Option<PathBuf> {
    // `C:tool` is relative to the per-drive current directory.
    if program.is_empty() || (program.contains(':') && !program.contains(['/', '\\'])) {
        return None;
    }
    let pathext =
        parse_pathext(&std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned()));
    if program.contains(['/', '\\']) {
        let path = PathBuf::from(program);
        if path.is_file() {
            return Some(path);
        }
        return pathext_candidates(Path::new(""), program, &pathext).into_iter().find(|c| c.is_file());
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| pathext_candidates(&dir, program, &pathext))
        .find(|candidate| candidate.is_file())
}
