// SPDX-License-Identifier: MIT
//! The allowlisted debugfs files of a device, the device coredumps and the helpers they share.
//!
//! debugfs is read-only here: only the patterns of [`debugfs_patterns`] are expanded, names on the
//! denylist (anything that can change device state when opened) are skipped at every level, and
//! symlinks are never entered. File contents come through the [`Reader`], so a wedged driver costs
//! one source, not the run.

use std::fs;
use std::path::{Path, PathBuf};

use crate::bundle::source::{Gate, Keep, Produced, ReadOutcome, ReadResult, Reader, Status};
use crate::pci::PciAddress;
use crate::units::Bytes;

/// Names that can change device state when read, or are otherwise unsafe to open.
const DEBUGFS_DENY_EXACT: &[&str] = &["forcewake_all", "wedged_mode"];
/// Name patterns on the debugfs denylist.
const DEBUGFS_DENY_GLOBS: &[&str] = &["force_*", "fail_*", "*reset*", "*inject*"];

/// The root of the DRM debugfs directories.
pub const DEBUGFS_DRI: &str = "/sys/kernel/debug/dri";
/// The device coredump class directory.
pub const DEVCOREDUMP_CLASS_DIR: &str = "/sys/class/devcoredump";

/// Size cap of one debugfs file.
const DEBUGFS_FILE_MAX: Bytes = Bytes::mib(1);
/// Size cap of the GuC log.
const GUC_LOG_MAX: Bytes = Bytes::mib(4);
/// Size cap of one device coredump, and of the dumps source.
pub const DEVCOREDUMP_MAX: Bytes = Bytes::mib(32);
/// Size cap of a small attribute file.
pub const PROBE_MAX: Bytes = Bytes::kib(4);

/// The reason text of a denied source: `needs <gate>`.
pub fn needs_text(gate: Gate) -> String {
    format!("needs {}", gate.describe())
}

/// A successfully produced artifact.
pub fn collected(rel_path: impl Into<String>, data: impl Into<Vec<u8>>, via: impl Into<String>) -> Produced {
    Produced {
        rel_path: rel_path.into(),
        status: Status::Collected,
        data: data.into(),
        reason: String::new(),
        via: via.into(),
    }
}

/// An artifact that was not collected; `reason` starts with `needs ` when a privilege is missing.
pub fn skipped(rel_path: impl Into<String>, reason: impl Into<String>) -> Produced {
    Produced {
        rel_path: rel_path.into(),
        status: Status::Skipped,
        data: Vec::new(),
        reason: reason.into(),
        via: String::new(),
    }
}

/// Reads the start of a file through the collector's bounded reader.
pub fn read_head(reader: &dyn Reader, path: &Path, cap: Bytes) -> ReadResult {
    reader.read(path, cap, Keep::Head)
}

/// Maps a bounded read to the artifact it yields: Collected or Truncated (size cap) for data,
/// Skipped (`needs root`) for a denial, Failed for any other error; None when the file is absent.
pub fn from_read(rel_path: String, read: ReadResult) -> Option<Produced> {
    match read.outcome {
        ReadOutcome::Read => {
            let mut out = collected(rel_path, read.data, "");
            if read.truncated {
                out.status = Status::Truncated;
                out.reason = "larger than the size cap".to_owned();
            }
            Some(out)
        }
        ReadOutcome::Denied => Some(skipped(rel_path, needs_text(Gate::Root))),
        ReadOutcome::Missing => None,
        ReadOutcome::Failed => {
            let mut out = skipped(rel_path, read.error);
            out.status = Status::Failed;
            Some(out)
        }
    }
}

/// `*` matches any run of characters (including none) within one name; nothing else is special.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<usize> = None;
    let mut resume = 0;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            resume = t;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(s) = star {
            p = s + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Whether a debugfs name can change device state when read or is otherwise unsafe to open:
/// `forcewake_all`, `wedged_mode`, `force_*`, `fail_*`, `*reset*`, `*inject*`.
pub fn is_denied_debugfs_name(name: &str) -> bool {
    DEBUGFS_DENY_EXACT.contains(&name) || DEBUGFS_DENY_GLOBS.iter().any(|g| glob_match(g, name))
}

/// The debugfs files to read, relative to the device's `dri` directory; `*` matches within one
/// component. The GuC log is large and only collected with `include_guc_log`.
pub fn debugfs_patterns(include_guc_log: bool) -> Vec<String> {
    let mut patterns: Vec<String> = [
        "name",
        "info",
        "clients",
        "sriov_info",
        "gt*/hw_engines",
        "gt*/topology",
        "gt*/steering",
        "gt*/pat",
        "gt*/register-save-restore",
        "gt*/uc/guc_info",
        "gt*/uc/huc_info",
    ]
    .map(str::to_owned)
    .to_vec();
    if include_guc_log {
        patterns.push("gt*/uc/guc_log".to_owned());
    }
    patterns
}

/// The entries of `dir` that one pattern component selects, sorted. Denied names are never
/// returned, whether the component is a literal or a glob.
pub fn expand_component(dir: &Path, component: &str) -> Vec<String> {
    if is_denied_debugfs_name(component) {
        return Vec::new();
    }
    if !component.contains('*') {
        return if dir.join(component).exists() { vec![component.to_owned()] } else { Vec::new() };
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| glob_match(component, name) && !is_denied_debugfs_name(name))
        .collect();
    names.sort();
    names
}

/// Collects the regular files below `base` that match a `/`-separated path pattern, as paths
/// relative to `base`, appended to `files` in pattern order. Symlinks are never returned or
/// entered and denied names are skipped at every level.
pub fn expand_pattern(base: &Path, rel_dir: &Path, pattern: &str, files: &mut Vec<PathBuf>) {
    let (component, rest) = match pattern.split_once('/') {
        Some((component, rest)) => (component, Some(rest)),
        None => (pattern, None),
    };
    for name in expand_component(&base.join(rel_dir), component) {
        let rel = rel_dir.join(&name);
        match rest {
            None => {
                if fs::symlink_metadata(base.join(&rel)).is_ok_and(|m| m.file_type().is_file()) {
                    files.push(rel);
                }
            }
            Some(rest) => {
                // A symlinked directory is not entered.
                if fs::symlink_metadata(base.join(&rel)).is_ok_and(|m| m.file_type().is_dir()) {
                    expand_pattern(base, &rel, rest, files);
                }
            }
        }
    }
}

/// The debugfs directory of a device, or why it could not be found.
#[derive(Debug)]
pub enum DebugfsLookup {
    /// `/sys/kernel/debug/dri` cannot be listed.
    Error(std::io::Error),
    /// The listing worked but no directory belongs to the device.
    NotFound,
    /// The device's directory.
    Found(PathBuf),
}

/// Finds a device's directory below `dri_root`: an entry named after the device address, else the
/// entry whose `name` file mentions `dev=<address>`.
pub fn find_debugfs_dir(reader: &dyn Reader, dri_root: &Path, bdf: &PciAddress) -> DebugfsLookup {
    let entries = match fs::read_dir(dri_root) {
        Ok(entries) => entries,
        Err(e) => return DebugfsLookup::Error(e),
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    let text = bdf.to_string();
    if let Some(exact) = paths.iter().find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == text)) {
        return DebugfsLookup::Found(exact.clone());
    }
    let needle = format!("dev={text}");
    for entry in &paths {
        let name = read_head(reader, &entry.join("name"), PROBE_MAX);
        if name.outcome == ReadOutcome::Read && String::from_utf8_lossy(&name.data).contains(&needle) {
            return DebugfsLookup::Found(entry.clone());
        }
    }
    DebugfsLookup::NotFound
}

/// The allowlisted debugfs files of one device: one artifact per file named by its path below
/// `rel_dir` (Collected, Truncated, Skipped `needs root`, or Failed), or a single Skipped artifact
/// named `rel_dir` when debugfs is not mounted, not readable or has no directory for the device.
pub fn debugfs_builtin(
    reader: &dyn Reader,
    dri_root: &Path,
    rel_dir: &str,
    bdf: &PciAddress,
    include_guc_log: bool,
) -> Vec<Produced> {
    let dir = match find_debugfs_dir(reader, dri_root, bdf) {
        DebugfsLookup::Error(e) => {
            let denied = e.kind() == std::io::ErrorKind::PermissionDenied;
            let reason = if denied { needs_text(Gate::Root) } else { "debugfs is not mounted".to_owned() };
            return vec![skipped(rel_dir, reason)];
        }
        DebugfsLookup::NotFound => return vec![skipped(rel_dir, "no debugfs directory for this device")],
        DebugfsLookup::Found(dir) => dir,
    };
    let mut out = Vec::new();
    for pattern in debugfs_patterns(include_guc_log) {
        let mut files = Vec::new();
        expand_pattern(&dir, Path::new(""), &pattern, &mut files);
        for rel in files {
            let cap =
                if rel.file_name().is_some_and(|n| n == "guc_log") { GUC_LOG_MAX } else { DEBUGFS_FILE_MAX };
            let name = format!("{rel_dir}{}", rel.to_string_lossy());
            if let Some(produced) = from_read(name, read_head(reader, &dir.join(&rel), cap)) {
                out.push(produced);
            }
        }
    }
    out
}

/// The device coredumps the kernel holds for one device: one artifact per dump of `class_dir`
/// whose `failing_device` is `bdf`, named `devcoredump-N.txt` under `dir_rel` (ends in `/`).
/// Empty when there is none.
pub fn devcoredump_builtin(
    reader: &dyn Reader,
    class_dir: &Path,
    dir_rel: &str,
    bdf: &PciAddress,
) -> Vec<Produced> {
    let mut dumps: Vec<PathBuf> = match fs::read_dir(class_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("devcd"))
            .map(|e| e.path())
            .collect(),
        Err(_) => return Vec::new(),
    };
    dumps.sort();
    let mut out = Vec::new();
    let mut index = 0;
    for dump in dumps {
        let Ok(failing) = fs::canonicalize(dump.join("failing_device")) else {
            continue;
        };
        let owner = failing.file_name().and_then(|n| PciAddress::parse(&n.to_string_lossy()));
        if owner != Some(*bdf) {
            continue;
        }
        let rel_path = format!("{dir_rel}devcoredump-{index}.txt");
        index += 1;
        if let Some(produced) = from_read(rel_path, read_head(reader, &dump.join("data"), DEVCOREDUMP_MAX)) {
            out.push(produced);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "debugfs_tests.rs"]
mod tests;
