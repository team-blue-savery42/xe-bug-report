// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/kmsg.rs`.

use super::*;
use crate::bundle::source::ReadResult;
use std::sync::Mutex;

/// A reader that only knows kern.log and records every path asked for.
struct FakeReader {
    kern_log: Option<&'static str>,
    asked: Mutex<Vec<String>>,
}

impl FakeReader {
    fn sync(kern_log: Option<&'static str>) -> Self {
        Self { kern_log, asked: Mutex::new(Vec::new()) }
    }
}

impl Reader for FakeReader {
    fn read(&self, path: &Path, _max: Bytes, keep: Keep) -> ReadResult {
        self.asked.lock().unwrap().push(format!("{} {keep:?}", path.display()));
        match (path == Path::new(KERN_LOG_PATH), self.kern_log) {
            (true, Some(text)) => ReadResult {
                outcome: ReadOutcome::Read,
                data: text.as_bytes().to_vec(),
                ..Default::default()
            },
            _ => ReadResult { outcome: ReadOutcome::Missing, ..Default::default() },
        }
    }
}

fn journal(outcome: ChildOutcome, output: &str) -> ChildResult {
    ChildResult { outcome, output: output.as_bytes().to_vec(), truncated: false, elapsed: Duration::ZERO }
}

fn ring(status: KmsgStatus, text: &str) -> impl Fn(Option<Duration>) -> KmsgRead {
    let text = text.to_owned();
    move |_| KmsgRead { status, text: text.clone() }
}

fn run(
    reader: &FakeReader,
    boot: Boot,
    since: Option<Duration>,
    journal: &ChildResult,
    kmsg: &dyn Fn(Option<Duration>) -> KmsgRead,
) -> Produced {
    let argv = journal_argv(since, boot == Boot::Previous);
    let mut out = kernel_log_with(
        reader,
        "kernel/kmsg.txt",
        boot,
        since,
        &argv,
        journal,
        Duration::from_secs(1000),
        kmsg,
    );
    assert_eq!(out.len(), 1);
    out.remove(0)
}

const MIN30: Option<Duration> = Some(Duration::from_secs(30 * 60));

#[test]
fn a_journal_with_lines_is_the_log() {
    let reader = FakeReader::sync(None);
    let j = journal(ChildOutcome::Exited(0), "[    1.0] host kernel: hello\n");
    let out = run(&reader, Boot::Current, None, &j, &ring(KmsgStatus::Failed, ""));
    assert_eq!(out.status, Status::Collected);
    assert_eq!(out.data, b"[    1.0] host kernel: hello\n");
    assert_eq!(out.via, "journalctl -k -b 0 -n 200000 --no-pager -q -o short-monotonic");
    let mut capped = j.clone();
    capped.truncated = true;
    let out = run(&reader, Boot::Current, None, &capped, &ring(KmsgStatus::Failed, ""));
    assert_eq!(out.status, Status::Truncated);
    assert_eq!(out.reason, "larger than the size cap: first 64 MiB only");
}

#[test]
fn a_capped_or_unfinished_window_is_truncated_and_never_kern_log() {
    let reader = FakeReader::sync(Some("old kern.log contents\n"));
    let lines = "[    1.0] host kernel: hello\n";
    // The output cap bounds a long window.
    let mut capped = journal(ChildOutcome::Exited(0), lines);
    capped.truncated = true;
    let out = run(&reader, Boot::Current, MIN30, &capped, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.status, Status::Truncated);
    assert_eq!(out.reason, "larger than the size cap: first 64 MiB only");
    assert_eq!(out.data, lines.as_bytes());
    // A window that ran out of time keeps the lines it delivered.
    let slow = journal(ChildOutcome::TimedOut, lines);
    let out = run(&reader, Boot::Current, MIN30, &slow, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.status, Status::Truncated);
    assert_eq!(out.reason, "journalctl did not finish within 60 s; first lines only");
    assert_eq!(out.data, lines.as_bytes());
    assert!(reader.asked.lock().unwrap().is_empty(), "kern.log must not be read");
    // Without a window, or with no output, a timeout still falls back.
    let out = run(&reader, Boot::Current, None, &slow, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.data, b"ring\n");
    let empty = journal(ChildOutcome::TimedOut, "");
    let out = run(&reader, Boot::Current, MIN30, &empty, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.data, b"ring\n");
}

#[test]
fn the_source_outlives_the_journal_run() {
    assert_eq!(journal_timeout(None), Duration::from_secs(20));
    assert_eq!(journal_timeout(MIN30), Duration::from_secs(60));
    assert!(source_timeout(MIN30) >= journal_timeout(MIN30) + Duration::from_secs(30));
    assert!(source_timeout(None) >= journal_timeout(None) + Duration::from_secs(30));
}

#[test]
fn an_empty_window_is_a_result_and_never_kern_log() {
    let reader = FakeReader::sync(Some("old kern.log contents\n"));
    for output in ["", "-- No entries --\n"] {
        let j = journal(ChildOutcome::Exited(0), output);
        let out = run(&reader, Boot::Current, MIN30, &j, &ring(KmsgStatus::Read, "ring text\n"));
        assert_eq!(out.status, Status::Collected);
        assert_eq!(String::from_utf8_lossy(&out.data), "no kernel messages in the last 30 minutes\n");
        assert!(out.via.contains("_TRANSPORT=kernel"));
    }
    assert!(reader.asked.lock().unwrap().is_empty(), "kern.log must not be read");
    let j = journal(ChildOutcome::Exited(0), "");
    let day = Some(Duration::from_secs(86_400));
    let out = run(&reader, Boot::Current, day, &j, &ring(KmsgStatus::Read, ""));
    assert_eq!(String::from_utf8_lossy(&out.data), "no kernel messages in the last 1 day\n");
    let five = Some(Duration::from_secs(300));
    let out = run(&reader, Boot::Current, five, &j, &ring(KmsgStatus::Read, ""));
    assert_eq!(String::from_utf8_lossy(&out.data), "no kernel messages in the last 5 minutes\n");
}

#[test]
fn without_a_window_an_empty_journal_falls_back_to_the_ring() {
    let reader = FakeReader::sync(None);
    let j = journal(ChildOutcome::Exited(0), "");
    let out = run(&reader, Boot::Current, None, &j, &ring(KmsgStatus::Read, "[    1.000000] ring\n"));
    assert_eq!(out.data, b"[    1.000000] ring\n");
    assert_eq!(out.via, KMSG_PATH);
}

#[test]
fn the_ring_is_filtered_by_a_cutoff_on_the_monotonic_clock() {
    // The cutoff is the monotonic reading minus the window.
    let reader = FakeReader::sync(None);
    let j = journal(ChildOutcome::Exited(1), "boom");
    let seen = std::cell::Cell::new(None);
    let argv = journal_argv(MIN30, false);
    let kmsg = |nb: Option<Duration>| {
        seen.set(Some(nb));
        KmsgRead { status: KmsgStatus::Read, text: "x\n".into() }
    };
    let out =
        kernel_log_with(&reader, "k", Boot::Current, MIN30, &argv, &j, Duration::from_secs(5000), &kmsg);
    assert_eq!(out[0].status, Status::Collected);
    assert_eq!(seen.get(), Some(Some(Duration::from_secs(5000 - 1800))));
    // Shorter uptime than the window: the cutoff saturates at zero. No window: no cutoff.
    kernel_log_with(&reader, "k", Boot::Current, MIN30, &argv, &j, Duration::from_secs(60), &kmsg);
    assert_eq!(seen.get(), Some(Some(Duration::ZERO)));
    kernel_log_with(
        &reader,
        "k",
        Boot::Current,
        None,
        &journal_argv(None, false),
        &j,
        Duration::from_secs(60),
        &kmsg,
    );
    assert_eq!(seen.get(), Some(None));
    // An unreadable clock (zero) applies no cutoff instead of dropping everything.
    kernel_log_with(&reader, "k", Boot::Current, MIN30, &argv, &j, Duration::ZERO, &kmsg);
    assert_eq!(seen.get(), Some(None));
}

#[test]
fn records_before_the_cutoff_are_dropped() {
    let mut text = String::new();
    let cutoff = Some(Duration::from_secs(10));
    append_record(&mut text, b"6,1,5000000,-;too early\n", cutoff);
    append_record(&mut text, b"6,2,10000000,-;on the line\n", cutoff);
    append_record(&mut text, b"6,3,12500000,-;later\n SUBSYSTEM=x\n", cutoff);
    append_record(&mut text, b"garbage", cutoff);
    append_record(&mut text, b"6,4,1,-;kept without cutoff\n", None);
    assert_eq!(
        text,
        "[   10.000000] on the line\n[   12.500000] later\n[    0.000001] kept without cutoff\n"
    );
}

#[test]
fn concatenated_ring_reads_are_split_into_records() {
    let data = b"6,1,5000000,-;too early\n SUBSYSTEM=x\n6,2,12000000,-;kept\n DEVICE=y\n\n6,3,13000000,-;also kept\n";
    let mut text = String::new();
    append_records(&mut text, data, Some(Duration::from_secs(10)));
    assert_eq!(text, "[   12.000000] kept\n[   13.000000] also kept\n");
    let mut all = String::new();
    append_records(&mut all, data, None);
    assert_eq!(all.lines().count(), 3);
}

#[test]
fn the_previous_boot_has_only_the_journal() {
    let reader = FakeReader::sync(Some("kern.log\n"));
    let gone = journal(
        ChildOutcome::Exited(1),
        "Data from the specified boot (-1) is not available: No such boot ID\n",
    );
    let out = run(&reader, Boot::Previous, None, &gone, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!((out.status, out.reason.as_str()), (Status::Skipped, "no persistent journal"));
    // systemd 255 spelling of a boot that is not in the journal.
    let newer = journal(
        ChildOutcome::Exited(1),
        "No journal boot entry found from the specified boot offset (-1).\n",
    );
    let out = run(&reader, Boot::Previous, None, &newer, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!((out.status, out.reason.as_str()), (Status::Skipped, "no persistent journal"));
    let denied = journal(
        ChildOutcome::Exited(0),
        "Hint: You are currently not seeing messages from other users and the system.\n",
    );
    let out = run(&reader, Boot::Previous, None, &denied, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.status, Status::Skipped);
    assert!(out.reason.starts_with("needs root, CAP_SYSLOG"), "{}", out.reason);
    let missing = journal(ChildOutcome::NotFound, "");
    let out = run(&reader, Boot::Previous, None, &missing, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.reason, "journalctl not installed");
    let slow = journal(ChildOutcome::TimedOut, "");
    let out = run(&reader, Boot::Previous, None, &slow, &ring(KmsgStatus::Read, "ring\n"));
    assert_eq!(out.reason, "journalctl did not finish within 20 s");
    let failed = journal(ChildOutcome::SpawnFailed("x".into()), "");
    assert_eq!(
        run(&reader, Boot::Previous, None, &failed, &ring(KmsgStatus::Read, "")).reason,
        "journalctl could not be started"
    );
    assert!(reader.asked.lock().unwrap().is_empty());
}

#[test]
fn kern_log_is_the_last_resort_for_the_current_boot() {
    let reader = FakeReader::sync(Some("Nov 10 host kernel: line\n"));
    let j = journal(ChildOutcome::NotFound, "");
    let out = run(&reader, Boot::Current, None, &j, &ring(KmsgStatus::Denied, ""));
    assert_eq!(out.data, b"Nov 10 host kernel: line\n");
    assert_eq!(out.via, "/var/log/kern.log (may include earlier boots)");
    assert_eq!(reader.asked.lock().unwrap().as_slice(), ["/var/log/kern.log Tail"]);
    let out = run(&reader, Boot::Current, MIN30, &j, &ring(KmsgStatus::Failed, ""));
    assert_eq!(out.via, "/var/log/kern.log (may include earlier boots; --since not applied)");
    // Nothing readable at all: the gate is the kernel log.
    let none = FakeReader::sync(None);
    let out = run(&none, Boot::Current, None, &j, &ring(KmsgStatus::Denied, ""));
    assert_eq!(out.status, Status::Skipped);
    assert!(out.reason.starts_with("needs root, CAP_SYSLOG"));
}

#[test]
fn journal_failures_are_explained() {
    let t = Duration::from_secs(20);
    assert_eq!(journal_skip_reason(&ChildOutcome::NotFound, t), "journalctl not installed");
    assert_eq!(journal_skip_reason(&ChildOutcome::TimedOut, t), "journalctl did not finish within 20 s");
    assert_eq!(
        journal_skip_reason(&ChildOutcome::SpawnFailed("e".into()), t),
        "journalctl could not be started"
    );
    assert!(journal_skip_reason(&ChildOutcome::Exited(1), t).is_empty());
}

#[test]
fn a_missing_ring_device_is_failed_not_a_panic() {
    let read = read_kmsg(Path::new("/nonexistent/kmsg"), None);
    assert_eq!(read.status, KmsgStatus::Failed);
    assert!(read.text.is_empty());
}

fn log_artifact(status: Status, data: &str) -> Produced {
    Produced {
        rel_path: "kernel/kmsg.txt".to_owned(),
        status,
        data: data.as_bytes().to_vec(),
        ..Default::default()
    }
}

#[test]
fn the_extract_sits_next_to_its_log() {
    assert_eq!(extract_path("kernel/kmsg.txt"), "kernel/kmsg-extract.txt");
    assert_eq!(extract_path("kernel/kmsg-prev-boot.txt"), "kernel/kmsg-prev-boot-extract.txt");
    let log = [log_artifact(Status::Collected, "[1.0] xe: *ERROR* boom\n")];
    let extract = extract_artifact(&log, "kernel/kmsg.txt").unwrap();
    assert_eq!(extract.rel_path, "kernel/kmsg-extract.txt");
    assert_eq!(extract.status, Status::Collected);
    assert_eq!(extract.via, "derived from kernel/kmsg.txt");
    assert!(String::from_utf8_lossy(&extract.data).contains("*ERROR* boom"));
    let cut = [log_artifact(Status::Truncated, "[1.0] xe: *ERROR* boom\n")];
    let text = String::from_utf8_lossy(&extract_artifact(&cut, "kernel/kmsg.txt").unwrap().data).into_owned();
    assert!(text.contains("cut at its size limit"));
}

#[test]
fn no_extract_without_a_log_to_derive_it_from() {
    for log in [
        log_artifact(Status::Skipped, ""),
        log_artifact(Status::Collected, ""),
        log_artifact(Status::Collected, "no kernel messages in the last 30 minutes\n"),
    ] {
        assert!(extract_artifact(&[log], "kernel/kmsg.txt").is_none());
    }
    assert!(extract_artifact(&[], "kernel/kmsg.txt").is_none());
}
