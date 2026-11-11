// SPDX-License-Identifier: MIT
//! The list of recent user-space crashes (`coredumpctl list`), with the executable's directory
//! removed.
//!
//! The executable column holds full paths such as `/opt/<company>/<project>/bin/app`; the program
//! name is what a triage needs and the directories can name an employer or a project. No core file
//! is read.

use std::time::Duration;

use crate::bundle::source::{Produced, Status};
use crate::procio::{ChildOutcome, run_child};
use crate::units::Bytes;

use super::debugfs::{collected, skipped};
use super::text::window_minutes;

/// Wall-clock limit of the `coredumpctl` run.
pub const COREDUMPCTL_TIMEOUT: Duration = Duration::from_secs(15);
/// Time the source gets: the run plus the time to start and stop it.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(25);
/// Largest output kept.
const OUTPUT_MAX: Bytes = Bytes::kib(256);

/// `text` with every word that is an absolute path reduced to its last component:
/// `/opt/acme/app/bin/render` becomes `render`.
pub fn keep_basenames(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let mut rest = line;
        while !rest.is_empty() {
            let blank = rest.find([' ', '\t', '\n']).unwrap_or(rest.len());
            let (word, tail) = rest.split_at(blank);
            let base = word.trim_end_matches('/').rsplit('/').next().unwrap_or(word);
            if word.starts_with('/') && !base.is_empty() {
                out.push_str(base);
            } else {
                out.push_str(word);
            }
            let separators = tail.find(|c: char| !matches!(c, ' ' | '\t')).unwrap_or(tail.len());
            let (separator, after) = tail.split_at(separators);
            out.push_str(separator);
            if let Some(next) = after.strip_prefix('\n') {
                out.push('\n');
                rest = next;
            } else {
                rest = after;
            }
        }
    }
    out
}

/// The `coredumpctl` arguments: newest crash first, no pager, and the window when there is one.
pub fn coredumpctl_argv(since: Option<Duration>) -> Vec<String> {
    let mut argv: Vec<String> =
        ["coredumpctl", "list", "--no-pager", "--reverse"].iter().map(|s| (*s).to_owned()).collect();
    if let Some(since) = since {
        argv.push(format!("--since=-{}min", window_minutes(since)));
    }
    argv
}

/// Runs `coredumpctl list` and delivers the list with executable basenames only.
pub fn crash_list(rel_path: &str, since: Option<Duration>) -> Vec<Produced> {
    let argv = coredumpctl_argv(since);
    let result = run_child(&argv, COREDUMPCTL_TIMEOUT, OUTPUT_MAX);
    list_from(rel_path, &argv.join(" "), &result.outcome, &result.output, result.truncated)
}

/// [`crash_list`] for a finished run. `coredumpctl` exits 1 with "No coredumps found." when there
/// is none; that is a result, not a failure.
pub fn list_from(
    rel_path: &str,
    via: &str,
    outcome: &ChildOutcome,
    output: &[u8],
    truncated: bool,
) -> Vec<Produced> {
    let code = match outcome {
        ChildOutcome::NotFound => return vec![skipped(rel_path, "coredumpctl not installed")],
        ChildOutcome::SpawnFailed(error) => {
            let mut out = skipped(rel_path, format!("could not start coredumpctl: {error}"));
            out.status = Status::Failed;
            return vec![out];
        }
        ChildOutcome::TimedOut => {
            let mut out =
                skipped(rel_path, format!("did not finish within {} s", COREDUMPCTL_TIMEOUT.as_secs()));
            out.status = Status::TimedOut;
            return vec![out];
        }
        ChildOutcome::Exited(code) => *code,
    };
    if output.is_empty() {
        let mut out = skipped(rel_path, format!("exit code {code}"));
        if code != 0 {
            out.status = Status::Failed;
        } else {
            out.reason = "produced no output".to_owned();
        }
        return vec![out];
    }
    let text = keep_basenames(&String::from_utf8_lossy(output));
    let mut out = collected(rel_path, text, via);
    if truncated {
        out.status = Status::Truncated;
        out.reason = "larger than the size cap".to_owned();
    }
    vec![out]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "coredump_tests.rs"]
mod tests;
