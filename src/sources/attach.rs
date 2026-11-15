// SPDX-License-Identifier: MIT
//! `--attach`: files and directories the user adds to the bundle (a SPIR-V module, an IGC dump
//! directory, a reproduction's output).
//!
//! Each path becomes `attachments/<n>-<name>/`, with `<n>` its position on the command line. Only
//! regular files are copied; symbolic links inside a directory are recorded and never followed, so
//! nothing outside the given path is read, and FIFOs and device nodes are never opened. Files are
//! bounded one by one ([`FILE_MAX`]) and in total ([`TOTAL_MAX`], [`MAX_FILES`]), across all
//! attachments. Text files are redacted like any other text; anything else (a SPIR-V module, a
//! compiled kernel) is stored as it is, which redaction cannot inspect.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::bundle::collect::sanitize_segment;
use crate::bundle::source::{Keep, Produced, Profile, ReadOutcome, Reader, Source, Status};
use crate::units::Bytes;

/// Largest file attached.
pub const FILE_MAX: Bytes = Bytes::mib(16);
/// Largest total of all attachments.
pub const TOTAL_MAX: Bytes = Bytes::mib(64);
/// Most files attached, over all attachments.
pub const MAX_FILES: usize = 256;
/// Deepest directory level searched below an attached directory.
pub const MAX_DEPTH: usize = 16;
/// Most directory entries looked at in one attachment; a larger tree is cut there.
pub const MAX_ENTRIES: usize = 10_000;
/// Time one attachment may take.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(120);
/// Why a file over the total was left out.
const TOTAL_REASON: &str = "the attachment total of 64 MiB is reached";

/// What all attachments of a run have used so far.
#[derive(Debug, Default)]
pub struct Budget {
    bytes: AtomicU64,
    files: AtomicUsize,
}

impl Budget {
    /// Reserves one file of `size` bytes; the reason when it does not fit.
    fn reserve(&self, size: u64) -> Result<(), String> {
        if self.files.load(Ordering::Relaxed) >= MAX_FILES {
            return Err(format!("the limit of {MAX_FILES} attached files is reached"));
        }
        if self.bytes.load(Ordering::Relaxed).saturating_add(size) > TOTAL_MAX.get() {
            return Err(TOTAL_REASON.to_owned());
        }
        self.files.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(size, Ordering::Relaxed);
        Ok(())
    }

    /// Corrects a reservation of `reserved` bytes to the `actual` bytes read.
    fn settle(&self, reserved: u64, actual: u64) {
        if actual > reserved {
            self.bytes.fetch_add(actual - reserved, Ordering::Relaxed);
        } else {
            self.bytes.fetch_sub(reserved - actual, Ordering::Relaxed);
        }
    }
}

/// The bundle directory of attachment `index` (0-based): `attachments/<index + 1>-<name>/`, the
/// name being the path's last component with every character outside `[A-Za-z0-9._-]` replaced.
pub fn attachment_dir(index: usize, path: &Path) -> String {
    let name = path.file_name().map(|name| sanitize_segment(&name.to_string_lossy())).unwrap_or_default();
    let name = if name.is_empty() { "attachment".to_owned() } else { name };
    format!("attachments/{}-{name}/", index + 1)
}

/// One source per attached path, in the given order, sharing one [`Budget`].
pub fn attachment_sources(paths: &[PathBuf]) -> Vec<Source> {
    let budget = Arc::new(Budget::default());
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let dir = attachment_dir(index, path);
            let (root, prefix, budget) = (path.clone(), dir.clone(), Arc::clone(&budget));
            Source::builtin(
                &dir,
                Box::new(move |reader| attachment(reader, &root, &prefix, &budget)),
                Profile::Minimal,
                "A file or directory given with --attach; text is redacted, binary files are not.",
            )
            .detect_content()
            .cap(FILE_MAX)
            .timeout(SOURCE_TIMEOUT)
            .group(&format!("attachment:{}", index + 1))
        })
        .collect()
}

/// One file of an attachment that was found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Found {
    /// A regular file of this size.
    File(u64),
    /// A symbolic link (not followed).
    Link,
    /// Neither a regular file, a directory nor a link.
    Other,
    /// A directory that could not be listed, with the error.
    Unlisted(String),
}

/// Lists `root` (a directory) to [`MAX_DEPTH`] levels, without following links: (path relative to
/// `root` as components, full path, what it is): in each directory its entries in name order, then
/// its subdirectories the same way. True when the listing stopped at [`MAX_ENTRIES`].
fn walk(root: &Path) -> (Vec<(Vec<String>, PathBuf, Found)>, bool) {
    let mut out = Vec::new();
    let mut pending = vec![(Vec::<String>::new(), root.to_path_buf())];
    while let Some((components, dir)) = pending.pop() {
        if out.len() >= MAX_ENTRIES {
            return (out, true);
        }
        let mut entries: Vec<(String, PathBuf)> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| (entry.file_name().to_string_lossy().into_owned(), entry.path()))
                .collect(),
            Err(error) => {
                out.push((components, dir, Found::Unlisted(error.to_string())));
                continue;
            }
        };
        entries.sort();
        let mut subdirectories = Vec::new();
        for (name, path) in entries {
            let mut rel = components.clone();
            rel.push(name);
            let found = match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => Found::Link,
                Ok(meta) if meta.is_file() => Found::File(meta.len()),
                Ok(meta) if meta.is_dir() && rel.len() < MAX_DEPTH => {
                    subdirectories.push((rel, path));
                    continue;
                }
                Ok(meta) if meta.is_dir() => Found::Unlisted(format!("deeper than {MAX_DEPTH} levels")),
                Ok(_) => Found::Other,
                Err(error) => Found::Unlisted(error.to_string()),
            };
            out.push((rel, path, found));
        }
        // The subdirectories next, the first by name on top of the stack.
        pending.extend(subdirectories.into_iter().rev());
    }
    let cut = out.len() > MAX_ENTRIES;
    out.truncate(MAX_ENTRIES);
    (out, cut)
}

/// A skipped or failed artifact.
fn not_collected(rel_path: String, status: Status, reason: impl Into<String>, via: &Path) -> Produced {
    Produced {
        rel_path,
        status,
        data: Vec::new(),
        reason: reason.into(),
        via: via.to_string_lossy().into_owned(),
    }
}

/// Copies one regular file of `size` bytes as `rel_path`, within the budget.
fn copy_file(reader: &dyn Reader, path: &Path, size: u64, rel_path: String, budget: &Budget) -> Produced {
    if size > FILE_MAX.get() {
        return not_collected(
            rel_path,
            Status::Skipped,
            format!("larger than {}", FILE_MAX.cap_label()),
            path,
        );
    }
    if let Err(reason) = budget.reserve(size) {
        return not_collected(rel_path, Status::Skipped, reason, path);
    }
    let read = reader.read(path, FILE_MAX, Keep::Head);
    budget.settle(size, read.data.len() as u64);
    let via = path.to_string_lossy().into_owned();
    match read.outcome {
        ReadOutcome::Read => {
            let (status, reason) = if read.truncated {
                (Status::Truncated, format!("grew past {} while it was read", FILE_MAX.cap_label()))
            } else {
                (Status::Collected, String::new())
            };
            Produced { rel_path, status, data: read.data, reason, via }
        }
        ReadOutcome::Denied => not_collected(rel_path, Status::Skipped, "permission denied", path),
        ReadOutcome::Missing => not_collected(rel_path, Status::Skipped, "not present", path),
        ReadOutcome::Failed => {
            not_collected(rel_path, Status::Failed, format!("error: {}", read.error), path)
        }
    }
}

/// The files of one attachment: `root` itself when it is a file, else every regular file below it.
/// `dir` is the bundle directory, ending in `/`.
pub fn attachment(reader: &dyn Reader, root: &Path, dir: &str, budget: &Budget) -> Vec<Produced> {
    let meta = match std::fs::metadata(root) {
        Ok(meta) => meta,
        Err(error) => return vec![not_collected(dir.to_owned(), Status::Skipped, error.to_string(), root)],
    };
    if meta.is_file() {
        let name = root.file_name().map(|name| sanitize_segment(&name.to_string_lossy())).unwrap_or_default();
        let name = if name.is_empty() { "attachment".to_owned() } else { name };
        return vec![copy_file(reader, root, meta.len(), format!("{dir}{name}"), budget)];
    }
    if !meta.is_dir() {
        return vec![not_collected(dir.to_owned(), Status::Skipped, "not a regular file or directory", root)];
    }
    let (found, cut) = walk(root);
    if found.is_empty() {
        return vec![not_collected(dir.to_owned(), Status::Skipped, "empty directory", root)];
    }
    let mut out = Vec::new();
    let mut left_out = 0usize;
    for (components, path, kind) in found {
        let rel: Vec<String> = components.iter().map(|part| sanitize_segment(part)).collect();
        let rel_path = format!("{dir}{}", rel.join("/"));
        if matches!(kind, Found::File(_)) && budget.files.load(Ordering::Relaxed) >= MAX_FILES {
            // One entry for all of them, not one per file.
            left_out += 1;
            continue;
        }
        out.push(match kind {
            Found::File(size) => copy_file(reader, &path, size, rel_path, budget),
            Found::Link => not_collected(rel_path, Status::Skipped, "symbolic link, not followed", &path),
            Found::Other => not_collected(rel_path, Status::Skipped, "not a regular file", &path),
            Found::Unlisted(error) if rel.is_empty() => {
                not_collected(dir.to_owned(), Status::Skipped, format!("not listed: {error}"), &path)
            }
            Found::Unlisted(error) => {
                not_collected(format!("{rel_path}/"), Status::Skipped, format!("not listed: {error}"), &path)
            }
        });
    }
    if left_out > 0 {
        out.push(not_collected(
            dir.to_owned(),
            Status::Skipped,
            format!("{left_out} more files not attached: the limit of {MAX_FILES} attached files is reached"),
            root,
        ));
    }
    if cut {
        out.push(not_collected(
            dir.to_owned(),
            Status::Skipped,
            format!("the directory listing stopped after {MAX_ENTRIES} entries; the rest is not attached"),
            root,
        ));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "attach_tests.rs"]
mod tests;
