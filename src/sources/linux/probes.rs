// SPDX-License-Identifier: MIT
//! Small helpers shared by the builtin sources that report sysfs and proc attributes: bounded
//! text reads through the [`Reader`], sorted directory listings and the `label: value` line.
//!
//! Directory listings use `std::fs` directly like the older builtins (the collector runs every
//! builtin on a guarded helper thread); every file read goes through the reader.

use std::fs;
use std::path::Path;

use crate::bundle::source::{ReadOutcome, Reader};
use crate::units::Bytes;

use super::debugfs::{PROBE_MAX, read_head};
use super::text::{format_probe_line, link_target_name, trim};

/// The trimmed text of a small file; None unless it was read and holds something.
pub fn read_value(reader: &dyn Reader, path: &Path) -> Option<String> {
    read_value_capped(reader, path, PROBE_MAX)
}

/// [`read_value`] with a chosen cap.
pub fn read_value_capped(reader: &dyn Reader, path: &Path, cap: Bytes) -> Option<String> {
    let read = read_head(reader, path, cap);
    if read.outcome != ReadOutcome::Read {
        return None;
    }
    let text = String::from_utf8_lossy(&read.data);
    let value = trim(&text);
    (!value.is_empty()).then(|| value.to_owned())
}

/// The whole text of a file as read, lossy; None unless it was read.
pub fn read_text(reader: &dyn Reader, path: &Path, cap: Bytes) -> Option<String> {
    let read = read_head(reader, path, cap);
    (read.outcome == ReadOutcome::Read).then(|| String::from_utf8_lossy(&read.data).into_owned())
}

/// `label: value` for a small file, with `(absent)`, `(denied)` or `(empty)` where there is no
/// value; a line break inside the value becomes `; ` so the report keeps one line per attribute.
pub fn attribute_line(reader: &dyn Reader, label: &str, path: &Path) -> String {
    let line = format_probe_line(label, &read_head(reader, path, PROBE_MAX));
    line.lines().map(trim).collect::<Vec<_>>().join("; ")
}

/// The names in a directory, sorted; empty when it cannot be listed.
pub fn list_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> =
        entries.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

/// The names in a directory that start with `prefix`, shorter names first so a numeric tail sorts
/// naturally (`mei2` before `mei10`).
pub fn list_prefixed(dir: &Path, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = list_names(dir).into_iter().filter(|n| n.starts_with(prefix)).collect();
    names.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
    names
}

/// The last component of the target of a symlink; None when `path` is not a link.
pub fn link_name(path: &Path) -> Option<String> {
    let target = fs::read_link(path).ok()?;
    Some(link_target_name(&target.to_string_lossy()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "probes_tests.rs"]
mod tests;
