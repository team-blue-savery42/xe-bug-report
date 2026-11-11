// SPDX-License-Identifier: MIT
//! The report printed after a bundle, the `--list` table and the `--json` objects.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Map, Value};

use crate::bundle::source::{Gate, Source, Status};
use crate::bundle::writer::{Artifact, BundleResult};

/// Spaces per level of the `--json` documents.
pub const JSON_INDENT: usize = 4;

/// The manifest entry name quoted by the report.
const MANIFEST_NAME: &str = "manifest.json";

/// What the process may do, which decides whether re-running as root would help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Neither root nor CAP_SYS_ADMIN (Linux), not elevated (Windows).
    Unprivileged,
    /// Root or CAP_SYS_ADMIN (Linux), elevated (Windows).
    Privileged,
}

/// The `--list` table: `PROFILE  NEEDS  PATH  WHY`, two-space separated and padded.
///
/// The first three columns are padded to their widest entry (header included); the last is not
/// padded. Every line ends with a newline.
pub fn format_source_list(sources: &[Source]) -> String {
    let mut rows: Vec<[&str; 4]> = vec![["PROFILE", "NEEDS", "PATH", "WHY"]];
    for source in sources {
        let needs = match source.gate.name() {
            "" => "-",
            name => name,
        };
        rows.push([source.profile.name(), needs, source.rel_path.as_str(), source.why]);
    }
    let width = |column: usize| rows.iter().map(|row| row[column].chars().count()).max().unwrap_or(0);
    let (profile_width, needs_width, path_width) = (width(0), width(1), width(2));
    let mut text = String::new();
    for [profile, needs, path, why] in rows {
        let _ =
            writeln!(text, "{profile:<profile_width$}  {needs:<needs_width$}  {path:<path_width$}  {why}");
    }
    text
}

/// Counts of one group of artifacts: not collected (skipped, timed out, failed) and partial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Tally {
    missing: usize,
    partial: usize,
}

impl Tally {
    fn add(&mut self, status: Status) {
        match status {
            Status::Collected => {}
            Status::Truncated => self.partial += 1,
            Status::Skipped | Status::TimedOut | Status::Failed => self.missing += 1,
        }
    }

    fn is_empty(self) -> bool {
        self.missing == 0 && self.partial == 0
    }

    /// "4 not collected, 2 partial", leaving out a zero count.
    fn describe(self) -> String {
        let mut parts = Vec::new();
        if self.missing > 0 {
            parts.push(format!("{} not collected", self.missing));
        }
        if self.partial > 0 {
            parts.push(format!("{} partial", self.partial));
        }
        parts.join(", ")
    }
}

/// The human-readable report printed after a bundle was written, one block on stdout:
///
/// ```text
/// Wrote xe-bug-report-20261110T163311Z.zip (713.5 KiB)
///   53 sources: 39 complete, 6 partial, 8 not collected
///   needs root: 4 not collected, 2 partial
///   needs root or CAP_SYS_ADMIN: 1 not collected, 4 partial
///   other reasons: 3 not collected
/// Re-run with sudo for the full bundle.
/// Details: unzip -p xe-bug-report-20261110T163311Z.zip manifest.json (or run with --verbose)
/// ```
///
/// "Partial" sources are in the archive but incomplete (a size cap, or some files denied); "not
/// collected" ones are absent (skipped, timed out or failed). Each gate that cost something gets
/// one line, in gate order. When `privilege` is [`Privilege::Privileged`], sudo cannot help: the
/// root and CAP_SYS_ADMIN lines merge into one "denied even with root privileges" line and the
/// sudo hint is left out. With `verbose`, every source that is not complete is listed with its
/// reason. Every line ends with a newline.
pub fn format_report(result: &BundleResult, output: &Path, privilege: Privilege, verbose: bool) -> String {
    let artifacts = &result.artifacts;
    let privileged = privilege == Privilege::Privileged;
    let shown = display_path(output);
    let mut text = format!("Wrote {shown} ({})\n", result.archive_bytes.human());

    let mut overall = Tally::default();
    let (mut timed_out, mut failed) = (0, 0);
    for artifact in artifacts {
        overall.add(artifact.status);
        timed_out += usize::from(artifact.status == Status::TimedOut);
        failed += usize::from(artifact.status == Status::Failed);
    }
    let complete = artifacts.len() - overall.missing - overall.partial;
    let mut line = format!("  {} source{}: {complete} complete", artifacts.len(), plural(artifacts.len()));
    if overall.partial > 0 {
        let _ = write!(line, ", {} partial", overall.partial);
    }
    if overall.missing > 0 {
        let _ = write!(line, ", {} not collected", overall.missing);
        let mut why = Vec::new();
        if timed_out > 0 {
            why.push(format!("{timed_out} timed out"));
        }
        if failed > 0 {
            why.push(format!("{failed} failed"));
        }
        if !why.is_empty() {
            let _ = write!(line, " ({})", why.join(", "));
        }
    }
    text.push_str(&line);
    text.push('\n');
    if overall.is_empty() {
        return text;
    }

    let tally_of = |gates: &[Gate]| {
        let mut tally = Tally::default();
        for artifact in artifacts.iter().filter(|artifact| gates.contains(&artifact.gate)) {
            tally.add(artifact.status);
        }
        tally
    };
    let (mut sudo_helps, mut elevation_helps) = (false, false);
    for gate in Gate::ALL {
        if gate == Gate::None || (privileged && gate == Gate::SysAdmin) {
            continue;
        }
        let denied_despite_privilege = privileged && gate == Gate::Root;
        let tally = if denied_despite_privilege {
            tally_of(&[Gate::Root, Gate::SysAdmin])
        } else {
            tally_of(&[gate])
        };
        if tally.is_empty() {
            continue;
        }
        let label = if denied_despite_privilege {
            "denied even with root privileges (kernel lockdown, container or security policy)".to_owned()
        } else {
            format!("needs {}", gate.describe())
        };
        let _ = writeln!(text, "  {label}: {}", tally.describe());
        match gate {
            Gate::Elevated => elevation_helps = true,
            _ if !denied_despite_privilege => sudo_helps = true,
            _ => {}
        }
    }
    let other = tally_of(&[Gate::None]);
    if !other.is_empty() {
        let _ = writeln!(text, "  other reasons: {}", other.describe());
    }
    if sudo_helps && !privileged {
        text.push_str("Re-run with sudo for the full bundle.\n");
    }
    if elevation_helps {
        text.push_str("Re-run from an elevated prompt for the full bundle.\n");
    }

    if verbose {
        text.push_str("Not complete:\n");
        let incomplete: Vec<&Artifact> =
            artifacts.iter().filter(|artifact| artifact.status != Status::Collected).collect();
        let width = incomplete.iter().map(|artifact| artifact.rel_path.chars().count()).max().unwrap_or(0);
        for artifact in incomplete {
            let state = if artifact.status == Status::Truncated { "partial" } else { "not collected" };
            let _ =
                writeln!(text, "  {state:<13}  {:<width$}  {}", artifact.rel_path, artifact_reason(artifact));
        }
    }
    let hint = if verbose { "" } else { " (or run with --verbose)" };
    let _ = writeln!(text, "Details: unzip -p {} {MANIFEST_NAME}{hint}", shell_quote(&shown));
    text
}

/// The reason shown for an artifact that is not complete; its status name when it has none.
fn artifact_reason(artifact: &Artifact) -> &str {
    if artifact.reason.is_empty() { artifact.status.name() } else { &artifact.reason }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// `text` as one POSIX shell word: as-is when it holds only safe characters, else single-quoted.
fn shell_quote(text: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "._/+-:@%,=".contains(c);
    if !text.is_empty() && text.chars().all(safe) {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The `--json` success object: `{"status":"OK","file":...,"collected":N,"truncated":N,"skipped":N,
/// "timed_out":N,"failed":N,"bytes":N}`.
pub fn json_result(result: &BundleResult, output: &Path) -> Value {
    let count_of =
        |status: Status| result.artifacts.iter().filter(|artifact| artifact.status == status).count();
    let mut doc = Map::new();
    doc.insert("status".into(), "OK".into());
    doc.insert("file".into(), display_path(output).into());
    doc.insert("collected".into(), count_of(Status::Collected).into());
    doc.insert("truncated".into(), count_of(Status::Truncated).into());
    doc.insert("skipped".into(), count_of(Status::Skipped).into());
    doc.insert("timed_out".into(), count_of(Status::TimedOut).into());
    doc.insert("failed".into(), count_of(Status::Failed).into());
    doc.insert("bytes".into(), result.archive_bytes.get().into());
    Value::Object(doc)
}

/// The `--json` error object: `{"errno":1,"error":"<message>"}`.
pub fn json_error(message: &str) -> Value {
    let mut doc = Map::new();
    doc.insert("errno".into(), 1.into());
    doc.insert("error".into(), message.into());
    Value::Object(doc)
}

/// A path as UTF-8 text for messages and JSON (lossy).
pub fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "summary_tests.rs"]
mod tests;
