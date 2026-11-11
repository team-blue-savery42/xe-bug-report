// SPDX-License-Identifier: MIT
//! Listings of Minidump, LiveKernelReports and WER directories.
//!
//! Directory listing uses `std::fs` directly: the `Reader` handed to builtins only reads files.
//! The listing is bounded in depth and in the number of entries.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::bundle::source::{Gate, Produced, Status};
use crate::timefmt::utc_iso8601;

/// Recursion stops here; also bounds a junction loop.
pub const MAX_LISTING_DEPTH: usize = 8;
/// The most entries listed over all roots.
pub const MAX_LISTING_ENTRIES: usize = 20_000;
/// The path of the listing in the bundle.
pub const REL_PATH: &str = "dumps/listings.txt";

/// Crash reports of interest are folders named after the faulting module or the event type.
pub const WER_NAME_PARTS: &[&str] = &["igd", "ze_", "xpu", "livekernelevent"];

/// ERROR_ACCESS_DENIED.
const ERROR_ACCESS_DENIED: i32 = 5;

/// One directory to list and the name fragments a top-level entry must contain (empty: all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub path: PathBuf,
    /// Lower-case fragments; empty lists every top-level entry.
    pub filter: &'static [&'static str],
}

/// The four crash folders: Minidump and LiveKernelReports under the Windows
/// directory, and the WER ReportArchive and ReportQueue (filtered by name) under ProgramData.
pub fn roots(windows_dir: &Path, program_data: &Path) -> Vec<Root> {
    let wer = program_data.join("Microsoft").join("Windows").join("WER");
    vec![
        Root { path: windows_dir.join("Minidump"), filter: &[] },
        Root { path: windows_dir.join("LiveKernelReports"), filter: &[] },
        Root { path: wer.join("ReportArchive"), filter: WER_NAME_PARTS },
        Root { path: wer.join("ReportQueue"), filter: WER_NAME_PARTS },
    ]
}

/// The text and counters of a listing in progress.
#[derive(Debug)]
struct ListingState {
    max_entries: usize,
    text: String,
    denied_directories: usize,
    entries: usize,
    limit_hit: bool,
}

impl ListingState {
    fn new(max_entries: usize) -> Self {
        Self { max_entries, text: String::new(), denied_directories: 0, entries: 0, limit_hit: false }
    }
}

/// "access denied (needs an elevated (Administrator) prompt)".
fn denial_note() -> String {
    format!("access denied (needs {})", Gate::Elevated.describe())
}

/// Whether `error` means access was denied.
fn is_denied(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(ERROR_ACCESS_DENIED)
}

/// Whether `name` contains one of the lower-case `parts`; an empty list matches every name.
fn name_matches(name: &str, parts: &[&str]) -> bool {
    if parts.is_empty() {
        return true;
    }
    let lowered = name.to_ascii_lowercase();
    parts.iter().any(|part| lowered.contains(part))
}

/// "YYYY-MM-DDTHH:MM:SSZ" or "-" when the time is unknown.
fn format_modified(modified: io::Result<SystemTime>) -> String {
    match modified {
        Ok(time) => utc_iso8601(time),
        Err(_) => "-".to_owned(),
    }
}

/// Appends a recursive listing of `dir`, one line per entry, without following symlinks.
/// `relative` is the path of `dir` below the root ("" for the root), with backslashes.
fn list_directory(dir: &Path, relative: &str, depth: usize, filter: &[&str], state: &mut ListingState) {
    let mut error: Option<io::Error> = None;
    let mut entries: Vec<fs::DirEntry> = Vec::new();
    match fs::read_dir(dir) {
        Ok(iterator) => {
            for entry in iterator {
                match entry {
                    Ok(entry) => {
                        // Filtered-out names never count against the limit.
                        if depth == 0
                            && !filter.is_empty()
                            && !name_matches(&entry.file_name().to_string_lossy(), filter)
                        {
                            continue;
                        }
                        if entries.len() >= state.max_entries {
                            state.limit_hit = true;
                            break;
                        }
                        entries.push(entry);
                    }
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
        }
        Err(e) => error = Some(e),
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in &entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if depth == 0 && !name_matches(&name, filter) {
            continue;
        }
        if state.entries >= state.max_entries {
            state.limit_hit = true;
            return;
        }
        state.entries += 1;

        let file_type = entry.file_type();
        let is_link = file_type.as_ref().is_ok_and(fs::FileType::is_symlink);
        let is_dir = !is_link && file_type.as_ref().is_ok_and(fs::FileType::is_dir);
        let metadata = entry.metadata();
        let size = if is_dir {
            "<DIR>".to_owned()
        } else if is_link {
            "<LINK>".to_owned()
        } else {
            match &metadata {
                Ok(m) => m.len().to_string(),
                Err(_) => "?".to_owned(),
            }
        };
        let modified = format_modified(metadata.and_then(|m| m.modified()));
        let mut shown = if relative.is_empty() { name.clone() } else { format!("{relative}\\{name}") };
        let child_relative = shown.clone();
        if is_dir {
            shown.push('\\');
        }
        let _ = writeln!(state.text, "{modified}  {size:>12}  {shown}");

        // Symlinks are listed, not entered; the depth limit bounds a junction loop.
        if is_dir && depth < MAX_LISTING_DEPTH {
            list_directory(&entry.path(), &child_relative, depth + 1, filter, state);
            if state.limit_hit {
                return;
            }
        }
    }

    let Some(error) = error else { return };
    let location = if relative.is_empty() { "." } else { relative };
    if is_denied(&error) {
        state.denied_directories += 1;
        let _ = writeln!(state.text, "  {location}: {}", denial_note());
    } else if error.kind() == io::ErrorKind::NotFound {
        state.text.push_str("  (not present)\n");
    } else {
        let _ = writeln!(state.text, "  {location}: cannot be listed: {error}");
    }
}

/// Lists every root into one artifact, `dumps/listings.txt`: Collected, or Truncated when some
/// directory was denied or the entry limit was reached.
pub fn list_roots(roots: &[Root]) -> Produced {
    list_roots_limited(roots, MAX_LISTING_ENTRIES)
}

/// [`list_roots`] with an explicit entry limit.
fn list_roots_limited(roots: &[Root], max_entries: usize) -> Produced {
    let mut state = ListingState::new(max_entries);
    for root in roots {
        state.text.push_str(&format!("== {} ==\n", root.path.to_string_lossy()));
        if !state.limit_hit {
            list_directory(&root.path, "", 0, root.filter, &mut state);
        }
        state.text.push('\n');
    }
    if state.limit_hit {
        let _ = writeln!(state.text, "listing stopped after {} entries", state.entries);
    }

    let mut reasons: Vec<String> = Vec::new();
    if state.denied_directories > 0 {
        let count = state.denied_directories;
        reasons.push(format!(
            "{count} {} could not be listed; needs {}",
            if count == 1 { "directory" } else { "directories" },
            Gate::Elevated.describe()
        ));
    }
    if state.limit_hit {
        reasons.push(format!("listing stopped after {max_entries} entries"));
    }
    Produced {
        rel_path: REL_PATH.to_owned(),
        status: if reasons.is_empty() { Status::Collected } else { Status::Truncated },
        data: state.text.into_bytes(),
        reason: reasons.join("; "),
        via: String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "listings_tests.rs"]
mod tests;
