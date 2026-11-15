// SPDX-License-Identifier: MIT
//! The list of recent user-space crashes (`coredumpctl list`), with the executable's directory
//! removed, and (`--full`) the crash reports of the newest crashes whose stack trace runs through
//! the GPU runtime.
//!
//! The executable column holds full paths such as `/opt/<company>/<project>/bin/app`; the program
//! name is what a triage needs and the directories can name an employer or a project. No core file
//! is read: the stack traces are the ones systemd-coredump wrote into the journal at crash time.

use std::time::Duration;

use crate::bundle::source::{Produced, Status};
use crate::procio::{ChildOutcome, ChildResult, run_child};
use crate::units::Bytes;

use super::debugfs::{collected, skipped};
use super::text::window_minutes;

/// Wall-clock limit of the `coredumpctl` run.
pub const COREDUMPCTL_TIMEOUT: Duration = Duration::from_secs(15);
/// Time the source gets: the run plus the time to start and stop it.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(25);
/// Largest output kept.
const OUTPUT_MAX: Bytes = Bytes::kib(256);
/// How many of the newest crashes are examined for a GPU runtime stack trace.
pub const MAX_BACKTRACES: usize = 3;
/// Wall-clock limit of one `coredumpctl info` run.
const INFO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest `coredumpctl info` output kept.
const INFO_MAX: Bytes = Bytes::kib(512);
/// Time the backtrace source gets: the list, every info run, and starting them.
pub const BACKTRACE_SOURCE_TIMEOUT: Duration = Duration::from_secs(60);
/// Library names whose presence in a stack frame makes a crash a GPU runtime crash.
pub const GPU_RUNTIME_FRAMES: &[&str] =
    &["libze_intel_gpu", "libze_loader", "libigc", "libigdrcl", "libOpenCL", "libigdfcl"];

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

/// The process ids of a `coredumpctl list` text, in its order (newest first with `--reverse`).
/// A row is `<weekday> <date> <time> [<zone>] <pid> <uid> ...`: the pid is the first number after
/// the time of day.
pub fn crash_pids(list: &str) -> Vec<u32> {
    let is_time = |word: &str| {
        let parts: Vec<&str> = word.split(':').collect();
        parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    list.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let at = words.iter().position(|word| is_time(word))?;
            words[at + 1..].iter().take(2).find_map(|word| word.parse::<u32>().ok())
        })
        .collect()
}

/// Whether a `coredumpctl info` text has a stack frame (`#<n> ...`) in a GPU runtime library.
pub fn has_gpu_frame(info: &str) -> bool {
    info.lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with('#'))
        .any(|frame| GPU_RUNTIME_FRAMES.iter().any(|library| frame.contains(library)))
}

/// A crash report as written to the bundle: the command line (arguments can name files, projects or
/// carry credentials) is replaced by `(omitted)` and absolute paths are reduced to their last
/// component, as in the crash list, including the module of a stack frame, which is written in
/// parentheses (`(/opt/acme/bin/app + 0x2f3d)`).
pub fn privacy_filtered(info: &str) -> String {
    let info = info.replace("(/", "( /");
    let lines: String = info
        .split_inclusive('\n')
        .map(|line| match line.split_once("Command Line:") {
            Some((indent, _)) if indent.trim().is_empty() => {
                let end = if line.ends_with('\n') { "\n" } else { "" };
                format!("{indent}Command Line: (omitted){end}")
            }
            _ => line.to_owned(),
        })
        .collect();
    keep_basenames(&lines).replace("( ", "(")
}

/// Runs `coredumpctl list` and `coredumpctl info` for the newest crashes and keeps the reports
/// with a GPU runtime stack frame as `tools/coredump-<n>.txt`. `pattern` names the source in the
/// skipped artifact when there is none.
pub fn gpu_backtraces(pattern: &str, since: Option<Duration>) -> Vec<Produced> {
    let argv = coredumpctl_argv(since);
    let list = run_child(&argv, COREDUMPCTL_TIMEOUT, OUTPUT_MAX);
    backtraces_from(pattern, &list.outcome, &list.output, |pid| {
        let argv: Vec<String> =
            ["coredumpctl", "info", "--no-pager", &pid.to_string()].iter().map(|s| (*s).to_owned()).collect();
        run_child(&argv, INFO_TIMEOUT, INFO_MAX)
    })
}

/// [`gpu_backtraces`] for a finished list run and an `info` runner.
pub fn backtraces_from(
    pattern: &str,
    outcome: &ChildOutcome,
    list: &[u8],
    info: impl Fn(u32) -> ChildResult,
) -> Vec<Produced> {
    match outcome {
        ChildOutcome::NotFound => return vec![skipped(pattern, "coredumpctl not installed")],
        ChildOutcome::TimedOut => {
            let mut out =
                skipped(pattern, format!("did not finish within {} s", COREDUMPCTL_TIMEOUT.as_secs()));
            out.status = Status::TimedOut;
            return vec![out];
        }
        ChildOutcome::SpawnFailed(error) => {
            let mut out = skipped(pattern, format!("could not start coredumpctl: {error}"));
            out.status = Status::Failed;
            return vec![out];
        }
        ChildOutcome::Exited(_) => {}
    }
    let pids = crash_pids(&String::from_utf8_lossy(list));
    let examined = pids.len().min(MAX_BACKTRACES);
    let mut out = Vec::new();
    for pid in pids.into_iter().take(MAX_BACKTRACES) {
        let result = info(pid);
        if result.outcome != ChildOutcome::Exited(0) {
            continue;
        }
        let text = String::from_utf8_lossy(&result.output);
        if !has_gpu_frame(&text) {
            continue;
        }
        let rel_path = format!("tools/coredump-{}.txt", out.len() + 1);
        let mut produced =
            collected(rel_path, privacy_filtered(&text), format!("coredumpctl info --no-pager {pid}"));
        if result.truncated {
            produced.status = Status::Truncated;
            produced.reason = "larger than the size cap".to_owned();
        }
        out.push(produced);
    }
    if out.is_empty() {
        let reason = if examined == 0 {
            "no recent crash".to_owned()
        } else {
            format!("none of the {examined} newest crashes has a stack frame in a GPU runtime library")
        };
        out.push(skipped(pattern, reason));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "coredump_tests.rs"]
mod tests;
