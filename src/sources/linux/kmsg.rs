// SPDX-License-Identifier: MIT
//! The kernel log: `journalctl` first, then `/dev/kmsg`, then `/var/log/kern.log`.
//!
//! The current boot tries the journal, then `/dev/kmsg`, then kern.log. The previous boot has only
//! the journal: nothing else survives a reboot. A window (`--since`) is read from the journal across
//! reboots; a journal that answered with no messages is a result ("no kernel messages in the last
//! ...") and no coarser log may stand in for it. `/dev/kmsg` then keeps the records of the window
//! that this boot holds.

use std::path::Path;
use std::time::Duration;

use crate::bundle::source::{Gate, Keep, Produced, ReadOutcome, Reader, Status};
use crate::procio::{ChildOutcome, ChildResult, read_nonblocking_bounded, run_child};
use crate::sys::unix::monotonic_now;
use crate::units::Bytes;

use super::debugfs::{collected, needs_text, skipped};
use super::text::{
    JournalVerdict, classify_journal, describe_window, format_kmsg_record, journal_argv, kmsg_timestamp,
};

/// The kernel ring buffer device.
pub const KMSG_PATH: &str = "/dev/kmsg";
/// The kernel log file some distributions keep.
pub const KERN_LOG_PATH: &str = "/var/log/kern.log";
/// Wall-clock limit of a per-boot `journalctl` run.
pub const JOURNAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Wall-clock limit of a windowed `journalctl` run: without `-n` it streams the whole window
/// (35 s for 30 days on a busy host).
pub const JOURNAL_WINDOW_TIMEOUT: Duration = Duration::from_secs(60);
/// Time the kernel log source gets beyond the journal run, for the `/dev/kmsg` and kern.log
/// fallbacks, so the builtin is not abandoned by its guard (which takes the source's timeout).
const SOURCE_MARGIN: Duration = Duration::from_secs(40);

/// The wall-clock limit of the `journalctl` run for `since`.
pub fn journal_timeout(since: Option<Duration>) -> Duration {
    if since.is_some() { JOURNAL_WINDOW_TIMEOUT } else { JOURNAL_TIMEOUT }
}

/// The time limit of a kernel log source: the journal run plus a margin for the fallbacks.
pub fn source_timeout(since: Option<Duration>) -> Duration {
    journal_timeout(since) + SOURCE_MARGIN
}
/// The most output kept from `journalctl` or `/dev/kmsg`.
pub const JOURNAL_MAX_OUTPUT: Bytes = Bytes::mib(64);
/// The most kept from kern.log.
const KERN_LOG_MAX: Bytes = Bytes::mib(16);

/// Which boot of the kernel log a source collects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boot {
    /// This boot.
    Current,
    /// The boot before it.
    Previous,
}

/// How reading `/dev/kmsg` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsgStatus {
    /// Read to the end of the ring.
    Read,
    /// EACCES or EPERM when opening.
    Denied,
    /// Any other failure to open.
    Failed,
}

/// The outcome of reading `/dev/kmsg` and the text it yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRead {
    pub status: KmsgStatus,
    /// The formatted lines, one `[%5u.%06u] message` per record.
    pub text: String,
}

/// Appends one record to `text` unless it is stamped before `not_before`.
fn append_record(text: &mut String, record: &[u8], not_before: Option<Duration>) {
    if let (Some(stamp), Some(not_before)) = (kmsg_timestamp(record), not_before)
        && stamp < not_before
    {
        return;
    }
    if let Some(line) = format_kmsg_record(record) {
        text.push_str(&line);
        text.push('\n');
    }
}

/// Appends every record of `data` (the concatenated reads of `/dev/kmsg`) to `text`. A record is
/// one line `pri,seq,usec,flags;message`; its continuation lines (key=value metadata) start with a
/// space, and newlines inside a message are escaped by the kernel, so a line that does not start
/// with a space starts a record.
fn append_records(text: &mut String, data: &[u8], not_before: Option<Duration>) {
    for line in data.split(|&b| b == b'\n') {
        if !line.is_empty() && line[0] != b' ' {
            append_record(text, line, not_before);
        }
    }
}

/// Reads the kernel ring buffer from `path` (`/dev/kmsg`), formatted like dmesg.
///
/// The read is non-blocking ([`read_nonblocking_bounded`]) so that it stops at the end of the
/// ring instead of waiting for new records, or after [`JOURNAL_MAX_OUTPUT`]. Records stamped before
/// `not_before` (time since boot) are dropped.
pub fn read_kmsg(path: &Path, not_before: Option<Duration>) -> KmsgRead {
    let read = read_nonblocking_bounded(path, JOURNAL_MAX_OUTPUT, Keep::Head);
    let mut result = KmsgRead { status: KmsgStatus::Read, text: String::new() };
    match read.outcome {
        ReadOutcome::Read => append_records(&mut result.text, &read.data, not_before),
        ReadOutcome::Denied => result.status = KmsgStatus::Denied,
        ReadOutcome::Missing | ReadOutcome::Failed => result.status = KmsgStatus::Failed,
    }
    result
}

/// The content of a kernel log whose time window holds no messages.
pub fn empty_window_note(since: Duration) -> String {
    format!("no kernel messages in the last {}\n", describe_window(since))
}

/// Why a journalctl run that did not exit normally produced nothing; empty when it exited.
pub fn journal_skip_reason(outcome: &ChildOutcome, timeout: Duration) -> String {
    match outcome {
        ChildOutcome::NotFound => "journalctl not installed".to_owned(),
        ChildOutcome::TimedOut => format!("journalctl did not finish within {} s", timeout.as_secs()),
        ChildOutcome::SpawnFailed(_) => "journalctl could not be started".to_owned(),
        ChildOutcome::Exited(_) => String::new(),
    }
}

/// Collects the kernel log of one boot, or of a time window, by running `journalctl` and falling
/// back as described in the module documentation.
///
/// Returns one artifact: Collected (a window without messages gives a one-line note), Truncated
/// (journal output capped, or kern.log tail only) or Skipped with the reason.
pub fn kernel_log(reader: &dyn Reader, rel_path: &str, boot: Boot, since: Option<Duration>) -> Vec<Produced> {
    let argv = journal_argv(since, boot == Boot::Previous);
    let journal = run_child(&argv, journal_timeout(since), JOURNAL_MAX_OUTPUT);
    let now = monotonic_now();
    kernel_log_with(reader, rel_path, boot, since, &argv, &journal, now, &|not_before| {
        read_kmsg(Path::new(KMSG_PATH), not_before)
    })
}

/// [`kernel_log`] with the journal result, the monotonic clock and the `/dev/kmsg` reader supplied.
#[allow(clippy::too_many_arguments)]
pub fn kernel_log_with(
    reader: &dyn Reader,
    rel_path: &str,
    boot: Boot,
    since: Option<Duration>,
    argv: &[String],
    journal: &ChildResult,
    monotonic: Duration,
    kmsg: &dyn Fn(Option<Duration>) -> KmsgRead,
) -> Vec<Produced> {
    let previous_boot = boot == Boot::Previous;
    let via = argv.join(" ");
    // A window that runs out of time has delivered its oldest lines: keep them, marked partial,
    // rather than let a coarser log stand in for the window.
    if journal.outcome == ChildOutcome::TimedOut
        && since.is_some()
        && classify_journal(0, &String::from_utf8_lossy(&journal.output)) == JournalVerdict::Ok
    {
        let mut out = collected(rel_path, journal.output.clone(), via);
        out.status = Status::Truncated;
        out.reason = format!(
            "journalctl did not finish within {} s; first lines only",
            journal_timeout(since).as_secs()
        );
        return vec![out];
    }
    if let ChildOutcome::Exited(code) = journal.outcome {
        let output = String::from_utf8_lossy(&journal.output);
        match classify_journal(code, &output) {
            JournalVerdict::Ok => {
                let mut out = collected(rel_path, journal.output.clone(), via);
                if journal.truncated {
                    // The cap bounds a long window; what it kept is the answer, not a reason to
                    // fall back to a coarser log.
                    out.status = Status::Truncated;
                    out.reason = format!(
                        "larger than the size cap: first {} MiB only",
                        JOURNAL_MAX_OUTPUT.get() / (1024 * 1024)
                    );
                }
                return vec![out];
            }
            JournalVerdict::NoEntries => {
                // A quiet window is a result; the journal answered, so no coarser log may stand in for it.
                if let Some(since) = since {
                    return vec![collected(rel_path, empty_window_note(since), via)];
                }
            }
            JournalVerdict::NoPersistentJournal => {
                if previous_boot {
                    return vec![skipped(rel_path, "no persistent journal")];
                }
            }
            JournalVerdict::Unusable => {}
        }
    }
    if previous_boot {
        let reason = journal_skip_reason(&journal.outcome, journal_timeout(since));
        return vec![skipped(rel_path, if reason.is_empty() { needs_text(Gate::KernelLog) } else { reason })];
    }

    // The kernel stamps records with a clock that does not advance while suspended (CLOCK_MONOTONIC).
    let not_before = match since {
        Some(since) if !monotonic.is_zero() => Some(monotonic.saturating_sub(since)),
        _ => None,
    };
    let ring = kmsg(not_before);
    if ring.status == KmsgStatus::Read && !ring.text.is_empty() {
        return vec![collected(rel_path, ring.text, KMSG_PATH)];
    }
    if ring.status == KmsgStatus::Read
        && let Some(since) = since
    {
        return vec![collected(rel_path, empty_window_note(since), KMSG_PATH)];
    }
    let kern = reader.read(Path::new(KERN_LOG_PATH), KERN_LOG_MAX, Keep::Tail);
    if kern.outcome == ReadOutcome::Read && !kern.data.is_empty() {
        let note = if since.is_some() {
            " (may include earlier boots; --since not applied)"
        } else {
            " (may include earlier boots)"
        };
        let mut out = collected(rel_path, kern.data, format!("{KERN_LOG_PATH}{note}"));
        if kern.truncated {
            out.status = Status::Truncated;
            out.reason = "tail only".to_owned();
        }
        return vec![out];
    }
    vec![skipped(rel_path, needs_text(Gate::KernelLog))]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "kmsg_tests.rs"]
mod tests;
