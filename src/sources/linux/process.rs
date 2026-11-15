// SPDX-License-Identifier: MIT
//! `--pid`: what a process that uses the GPU has loaded, how its GPU runtime is configured and
//! where its threads wait.
//!
//! Three files per process under `processes/<pid>/`: `status.txt` (command name, state, thread
//! count and the state and kernel wait channel of each thread), `environment.txt` (the variables of
//! the allowlist `system/env.txt` uses, nothing else) and `libraries.txt` (the GPU runtime
//! libraries mapped into it). The command line is never read: it can hold file names, project
//! names or credentials; the command name (`comm`) is enough to tell the processes apart.
//!
//! `/proc/<pid>/environ` and `/proc/<pid>/maps` are readable by the process's own user and root
//! only. `maps` and `environ` take the process's memory map lock, which a process stuck in the
//! driver can hold, so they are read last, through the guarded reader of the process's own group.

use std::fmt::Write as _;
use std::path::Path;

use crate::bundle::source::{Gate, Produced, ReadOutcome, ReadResult, Reader, Status};
use crate::units::Bytes;

use super::debugfs::{collected, needs_text, read_head, skipped};
use super::runtime::is_runtime_library;
use super::text::{filter_environment, status_field, trim};

/// The most threads listed; the rest are counted.
pub const MAX_THREADS: usize = 256;
/// Size cap of `/proc/<pid>/maps`.
const MAPS_MAX: Bytes = Bytes::mib(8);
/// Size cap of `/proc/<pid>/environ`.
const ENVIRON_MAX: Bytes = Bytes::kib(512);
/// Size cap of `status`, `stat`, `comm` and `wchan`.
const SMALL_MAX: Bytes = Bytes::kib(64);

/// Library file name prefixes looked for in a process besides
/// [`super::runtime::RUNTIME_LIBRARIES`]: the OpenCL driver and the Mesa drivers a graphics
/// process may hold next to the compute runtime.
const EXTRA_LIBRARIES: &[&str] = &["libigdrcl", "libmesa", "libvulkan_intel"];

/// Why a file of another user's process could not be read.
pub fn denied_reason() -> String {
    format!("{} (or the user that owns the process)", needs_text(Gate::Root))
}

/// Whether a mapped file is one of the GPU libraries a process report lists, by its file name.
pub fn is_gpu_library(path: &str) -> bool {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    let name = path.rsplit('/').next().unwrap_or(path);
    is_runtime_library(name) || EXTRA_LIBRARIES.iter().any(|prefix| name.starts_with(prefix))
}

/// The GPU libraries of a `/proc/<pid>/maps` text, in first-mapped order without repeats. A path
/// keeps its ` (deleted)` suffix: a library replaced on disk after the process loaded it is a
/// finding of its own.
pub fn mapped_libraries(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        // address perms offset dev inode path; the path may contain blanks.
        let mut rest = line;
        for _ in 0..5 {
            rest = rest.trim_start();
            rest = rest.find(char::is_whitespace).map_or("", |at| &rest[at..]);
        }
        let path = rest.trim();
        if path.starts_with('/') && is_gpu_library(path) && !out.iter().any(|seen| seen == path) {
            out.push(path.to_owned());
        }
    }
    out
}

/// The state letter of a `/proc/<pid>/task/<tid>/stat` line: the field after the command name,
/// which is in parentheses and may itself contain blanks and parentheses.
pub fn stat_state(stat: &str) -> Option<char> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.trim_start().chars().next()
}

/// A wait channel as shown: `-` for none (`0` or empty).
pub fn wchan_label(wchan: &str) -> String {
    match trim(wchan) {
        "" | "0" => "-".to_owned(),
        name => name.to_owned(),
    }
}

/// The text of a successful read, or None.
fn text_of(read: &ReadResult) -> Option<String> {
    (read.outcome == ReadOutcome::Read).then(|| String::from_utf8_lossy(&read.data).into_owned())
}

/// The artifact of a file that could not be read: denied, gone or failed.
fn unreadable(rel_path: &str, read: &ReadResult) -> Produced {
    match read.outcome {
        ReadOutcome::Denied => skipped(rel_path, denied_reason()),
        ReadOutcome::Missing => skipped(rel_path, "the process has exited"),
        ReadOutcome::Read | ReadOutcome::Failed => {
            let mut out = skipped(rel_path, format!("error: {}", read.error));
            out.status = Status::Failed;
            out
        }
    }
}

/// The thread ids of the process, sorted numerically; empty when the task directory cannot be
/// listed.
fn thread_ids(task_dir: &Path) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(task_dir) else {
        return Vec::new();
    };
    let mut tids: Vec<u32> =
        entries.filter_map(Result::ok).filter_map(|entry| entry.file_name().to_str()?.parse().ok()).collect();
    tids.sort_unstable();
    tids
}

/// `status.txt`: command name, state and thread count, then one line per thread (at most
/// [`MAX_THREADS`]) with its state and wait channel.
fn status_report(reader: &dyn Reader, proc_dir: &Path, rel_path: &str) -> Produced {
    let status = read_head(reader, &proc_dir.join("status"), SMALL_MAX);
    let Some(status_text) = text_of(&status) else {
        return unreadable(rel_path, &status);
    };
    let comm = text_of(&read_head(reader, &proc_dir.join("comm"), SMALL_MAX)).unwrap_or_default();
    let mut text = String::new();
    let _ = writeln!(text, "comm: {}", trim(&comm));
    for field in ["State", "Threads"] {
        let value = status_field(&status_text, field).unwrap_or_else(|| "(absent)".to_owned());
        let _ = writeln!(text, "{field}: {value}");
    }
    let tids = thread_ids(&proc_dir.join("task"));
    let _ = writeln!(text, "\nthreads (tid, state, wchan):");
    let mut wchan_denied = false;
    for tid in tids.iter().take(MAX_THREADS) {
        let task = proc_dir.join("task").join(tid.to_string());
        let stat = text_of(&read_head(reader, &task.join("stat"), SMALL_MAX));
        let state = stat.as_deref().and_then(stat_state).map_or_else(|| "?".to_owned(), String::from);
        let wchan = read_head(reader, &task.join("wchan"), SMALL_MAX);
        wchan_denied |= wchan.outcome == ReadOutcome::Denied;
        let wchan = text_of(&wchan).map_or_else(|| "?".to_owned(), |w| wchan_label(&w));
        let _ = writeln!(text, "{tid} {state} {wchan}");
    }
    if tids.is_empty() {
        text.push_str("(the thread list could not be read)\n");
    }
    if tids.len() > MAX_THREADS {
        let _ = writeln!(text, "({} more threads not listed)", tids.len() - MAX_THREADS);
    }
    if wchan_denied {
        let _ = writeln!(text, "(wait channels denied; {})", denied_reason());
    }
    collected(rel_path, text, proc_dir.join("status").to_string_lossy())
}

/// `environment.txt`: the allowlisted variables of `/proc/<pid>/environ`.
fn environment_report(reader: &dyn Reader, proc_dir: &Path, rel_path: &str) -> Produced {
    let path = proc_dir.join("environ");
    let read = read_head(reader, &path, ENVIRON_MAX);
    if read.outcome != ReadOutcome::Read {
        return unreadable(rel_path, &read);
    }
    let entries: Vec<String> = read
        .data
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect();
    let mut text = filter_environment(&entries);
    if text.is_empty() {
        text.push_str("(no GPU runtime variables set)\n");
    }
    let mut out = collected(rel_path, text, path.to_string_lossy());
    if read.truncated {
        out.status = Status::Truncated;
        out.reason = "larger than the size cap".to_owned();
    }
    out
}

/// `libraries.txt`: the GPU libraries mapped into the process.
fn libraries_report(reader: &dyn Reader, proc_dir: &Path, rel_path: &str) -> Produced {
    let path = proc_dir.join("maps");
    let read = read_head(reader, &path, MAPS_MAX);
    let Some(maps) = text_of(&read) else {
        return unreadable(rel_path, &read);
    };
    let libraries = mapped_libraries(&maps);
    let mut text = libraries.join("\n");
    if libraries.is_empty() {
        text.push_str("(no GPU runtime library is mapped)");
    }
    text.push('\n');
    let mut out = collected(rel_path, text, path.to_string_lossy());
    if read.truncated {
        out.status = Status::Truncated;
        out.reason = "larger than the size cap".to_owned();
    }
    out
}

/// The files of `processes/<pid>/` (`dir`, ending in `/`) for the process whose `/proc` directory
/// is `proc_dir`. The status comes first: it never takes the memory map lock.
pub fn process_report(reader: &dyn Reader, proc_dir: &Path, dir: &str) -> Vec<Produced> {
    vec![
        status_report(reader, proc_dir, &format!("{dir}status.txt")),
        environment_report(reader, proc_dir, &format!("{dir}environment.txt")),
        libraries_report(reader, proc_dir, &format!("{dir}libraries.txt")),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "process_tests.rs"]
mod tests;
