// SPDX-License-Identifier: MIT
//! Windows Error Reporting kernel reports: the bucket parameters of GPU watchdog and other
//! LiveKernelEvent reports, without any dump file.
//!
//! Each `Kernel_<code>_<hash>` folder under `ReportArchive` and `ReportQueue` holds a
//! `Report.wer` (UTF-16LE text of `key=value` lines) next to the attached files. The report names
//! the event, the bugcheck-style code (141 is a GPU hang, 117 a timeout recovery) and its
//! parameters; the module, driver version and OS version are in the signature lines. Only
//! whitelisted keys are kept: the free-form `UI[n]` and `LoadedModule[n]` lines hold paths and
//! user names and are dropped. Folder listing uses `std::fs` like the other listings; the report
//! itself is read through the [`Reader`].

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bundle::source::{Gate, Keep, Produced, ReadOutcome, Reader, Status};
use crate::timefmt::utc_iso8601;
use crate::units::Bytes;

/// The path of the report summaries in the bundle.
pub const REL_PATH: &str = "dumps/wer-kernel-reports.txt";
/// The most report folders summarised, newest first.
pub const MAX_REPORTS: usize = 30;
/// The most bytes read from one `Report.wer`.
const MAX_REPORT_BYTES: Bytes = Bytes::kib(64);
/// The most directory entries examined in one WER directory.
const MAX_SCANNED_ENTRIES: usize = 50_000;
/// The most attached files named for one report.
const MAX_FILES_PER_REPORT: usize = 40;
/// Values longer than this many characters are cut.
const MAX_VALUE_CHARS: usize = 256;
/// Seconds between 1601-01-01 (the Windows FILETIME epoch) and 1970-01-01.
const FILETIME_TO_UNIX_SECS: u64 = 11_644_473_600;
/// FILETIME ticks (100 ns) per second.
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;
/// Folder name prefix of kernel reports (any letter case).
const KERNEL_FOLDER_PREFIX: &str = "kernel_";

/// Keys of `Report.wer` that are kept as they are.
const KEPT_KEYS: &[&str] = &[
    "Version",
    "EventType",
    "EventName",
    "FriendlyEventName",
    "ConsentKey",
    "ReportType",
    "ReportStatus",
    "ReportIdentifier",
    "AppName",
    "NsAppName",
    "Response.type",
    "Response.BucketId",
    "Response.BucketTable",
    "Response.LegacyBucketId",
];
/// Keys whose value is a FILETIME; the date is added after the number.
const TIME_KEYS: &[&str] = &["EventTime", "UploadTime"];

/// Decodes the bytes of a `Report.wer`: UTF-16 with a byte order mark (little or big endian),
/// UTF-16LE without one when the second byte is zero, otherwise UTF-8. Never fails.
pub fn decode_report(bytes: &[u8]) -> String {
    let utf16 = |little: bool, body: &[u8]| -> String {
        let units = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| if little { u16::from_le_bytes(*pair) } else { u16::from_be_bytes(*pair) });
        char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    };
    match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(true, rest),
        [0xfe, 0xff, rest @ ..] => utf16(false, rest),
        [first, 0, ..] if *first != 0 => utf16(true, bytes),
        _ => {
            let text = String::from_utf8_lossy(bytes);
            text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned()
        }
    }
}

/// A FILETIME (100 ns ticks since 1601, as decimal text) as "YYYY-MM-DDTHH:MM:SSZ"; None when it
/// is not a number, precedes 1970 or is beyond the largest time the platform represents.
pub fn filetime_to_utc(text: &str) -> Option<String> {
    let ticks: u64 = text.trim().parse().ok()?;
    let secs = (ticks / FILETIME_TICKS_PER_SEC).checked_sub(FILETIME_TO_UNIX_SECS)?;
    // A time past what the platform's SystemTime holds is not a date.
    let when = UNIX_EPOCH.checked_add(Duration::from_secs(secs))?;
    Some(utc_iso8601(when))
}

/// Whether `key` is `<prefix>[<digits>].Name` or `<prefix>[<digits>].Value`.
fn is_signature_key(key: &str, prefix: &str) -> bool {
    let Some(rest) = key.strip_prefix(prefix).and_then(|r| r.strip_prefix('[')) else { return false };
    let Some((index, field)) = rest.split_once(']') else { return false };
    !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) && matches!(field, ".Name" | ".Value")
}

/// Whether a `Report.wer` key is one worth keeping.
fn is_kept_key(key: &str) -> bool {
    KEPT_KEYS.contains(&key)
        || TIME_KEYS.contains(&key)
        || is_signature_key(key, "Sig")
        || is_signature_key(key, "DynamicSig")
}

/// The whitelisted lines of a decoded `Report.wer`, as `key=value` (a FILETIME gets its date in
/// parentheses). Lines that are not `key=value`, other keys, and the parts of values past
/// [`MAX_VALUE_CHARS`] are dropped.
pub fn summarize_report(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim_end().split_once('=') else { continue };
        let key = key.trim_start_matches('\u{feff}').trim();
        if !is_kept_key(key) {
            continue;
        }
        let value: String = value.chars().take(MAX_VALUE_CHARS).collect();
        if TIME_KEYS.contains(&key)
            && let Some(date) = filetime_to_utc(&value)
        {
            lines.push(format!("{key}={value} ({date})"));
        } else {
            lines.push(format!("{key}={value}"));
        }
    }
    lines
}

/// Whether a folder name is a kernel report folder (`Kernel_<code>_<hash>`, any letter case).
pub fn is_kernel_report_folder(name: &str) -> bool {
    name.len() > KERNEL_FOLDER_PREFIX.len()
        && name
            .get(..KERNEL_FOLDER_PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(KERNEL_FOLDER_PREFIX))
}

/// One report folder found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFolder {
    /// The WER directory it is in: "ReportArchive" or "ReportQueue".
    pub area: &'static str,
    pub name: String,
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
}

/// What reading one `Report.wer` gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportText {
    Text(String),
    /// The file is not there.
    Missing,
    Denied,
    Failed(String),
}

/// The text block for one report folder: a header with the folder and date, the attached files
/// (name and size), then the whitelisted `Report.wer` lines.
pub fn format_report(folder: &ReportFolder, files: &[(String, u64)], report: &ReportText) -> String {
    let modified = folder.modified.map_or_else(|| "-".to_owned(), utc_iso8601);
    let mut text = format!("== {}\\{} (modified {modified}) ==\n", folder.area, folder.name);
    if files.is_empty() {
        text.push_str("  files: none listed\n");
    } else {
        let shown: Vec<String> = files.iter().map(|(name, size)| format!("{name} {size}")).collect();
        let _ = writeln!(text, "  files: {}", shown.join(", "));
    }
    match report {
        ReportText::Text(decoded) => {
            let lines = summarize_report(decoded);
            if lines.is_empty() {
                text.push_str("  Report.wer: no recognised keys\n");
            }
            for line in lines {
                text.push_str("  ");
                text.push_str(&line);
                text.push('\n');
            }
        }
        ReportText::Missing => text.push_str("  Report.wer: not present\n"),
        ReportText::Denied => {
            let _ = writeln!(text, "  Report.wer: access denied (needs {})", Gate::Elevated.describe());
        }
        ReportText::Failed(error) => _ = writeln!(text, "  Report.wer: cannot be read: {error}"),
    }
    text.push('\n');
    text
}

/// The kernel report folders directly under `dir`, labelled `area`. `denied` is set when the
/// directory cannot be listed for lack of access; a missing directory yields nothing.
fn find_folders(
    area: &'static str,
    dir: &Path,
    denied: &mut bool,
    failures: &mut Vec<String>,
) -> Vec<ReportFolder> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return found,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            *denied = true;
            return found;
        }
        Err(error) => {
            failures.push(format!("{area}: cannot be listed: {error}"));
            return found;
        }
    };
    for entry in entries.take(MAX_SCANNED_ENTRIES) {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_kernel_report_folder(&name) {
            continue;
        }
        // A symlink is not followed: file_type() does not resolve it.
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let modified = entry.metadata().and_then(|m| m.modified()).ok();
        found.push(ReportFolder { area, name, path: entry.path(), modified });
    }
    found
}

/// The files directly in a report folder with their sizes, sorted by name, at most
/// [`MAX_FILES_PER_REPORT`].
fn attached_files(folder: &Path) -> Vec<(String, u64)> {
    let Ok(entries) = fs::read_dir(folder) else { return Vec::new() };
    let mut files: Vec<(String, u64)> = entries
        .take(MAX_SCANNED_ENTRIES)
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = entry.metadata().ok()?;
            metadata.is_file().then_some((name, metadata.len()))
        })
        .collect();
    files.sort();
    files.truncate(MAX_FILES_PER_REPORT);
    files
}

/// Reads and decodes `folder\Report.wer` through `reader`.
fn read_report(reader: &dyn Reader, folder: &Path) -> ReportText {
    let result = reader.read(&folder.join("Report.wer"), MAX_REPORT_BYTES, Keep::Head);
    match result.outcome {
        ReadOutcome::Read => ReportText::Text(decode_report(&result.data)),
        ReadOutcome::Missing => ReportText::Missing,
        ReadOutcome::Denied => ReportText::Denied,
        ReadOutcome::Failed => ReportText::Failed(result.error),
    }
}

/// Summarises the newest [`MAX_REPORTS`] kernel report folders of `ReportArchive` and
/// `ReportQueue` under `wer_dir` (`...\ProgramData\Microsoft\Windows\WER`) as one artifact.
///
/// Collected normally. When a directory or report is denied the artifact is Truncated, or Skipped
/// when nothing at all could be read, with a reason that starts with "needs ".
pub fn produce(wer_dir: &Path, reader: &dyn Reader) -> Produced {
    let mut denied = false;
    let mut failures = Vec::new();
    let mut folders =
        find_folders("ReportArchive", &wer_dir.join("ReportArchive"), &mut denied, &mut failures);
    folders.extend(find_folders("ReportQueue", &wer_dir.join("ReportQueue"), &mut denied, &mut failures));
    // Newest first; folders with an unknown time last; ties by name for a stable order.
    folders.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| a.name.cmp(&b.name)));
    let total = folders.len();
    folders.truncate(MAX_REPORTS);

    let mut text = String::new();
    for folder in &folders {
        let report = read_report(reader, &folder.path);
        denied |= report == ReportText::Denied;
        text.push_str(&format_report(folder, &attached_files(&folder.path), &report));
    }
    if total > folders.len() {
        let _ = writeln!(text, "{} older report folders not shown", total - folders.len());
    }
    if total == 0 && !denied && failures.is_empty() {
        text.push_str("no kernel report folders\n");
    }
    for failure in &failures {
        text.push_str(failure);
        text.push('\n');
    }

    let needs = format!("needs {}", Gate::Elevated.describe());
    let (status, reason) = match (denied, folders.is_empty()) {
        (true, true) => (Status::Skipped, needs),
        (true, false) => (Status::Truncated, needs),
        (false, _) => (Status::Collected, String::new()),
    };
    let data = if status == Status::Skipped { Vec::new() } else { text.into_bytes() };
    Produced { rel_path: REL_PATH.to_owned(), status, data, reason, via: String::new() }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "wer_tests.rs"]
mod tests;
