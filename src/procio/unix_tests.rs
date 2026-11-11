// SPDX-License-Identifier: MIT
//! Unit tests for `src/procio/unix.rs`.

use super::super::{
    ChildOutcome, ChildResult, PrivateTempDir, read_file_bounded as read, read_nonblocking_bounded, run_child,
};
use super::*;
use std::os::unix::fs::symlink;
use std::process::Stdio;

const GENEROUS: Duration = Duration::from_secs(20);
/// How long after its timeout `run_child` may take to return (kill, 2 s reap, 0.2 s drain).
const SLACK: Duration = Duration::from_millis(2200);

fn run(argv: &[&str], timeout: Duration, cap: Bytes) -> ChildResult {
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    run_child(&argv, timeout, cap)
}

fn sh(script: &str) -> ChildResult {
    run(&["/bin/sh", "-c", script], GENEROUS, Bytes::mib(1))
}

fn process_gone(pid: i32) -> bool {
    if std::fs::metadata(format!("/proc/{pid}")).is_err() {
        return true;
    }
    // A killed process may linger as a zombie when nothing reaps it; it is dead all the same.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| s.rfind(')').and_then(|i| s.as_bytes().get(i + 2).copied()))
        .is_none_or(|state| state == b'Z')
}

fn wait_gone(pid: i32) -> bool {
    for _ in 0..100 {
        if process_gone(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---- run_child ----

#[test]
fn exit_code_and_interleaved_output() {
    let r = sh("echo out; echo err >&2; exit 3");
    assert_eq!(r.outcome, ChildOutcome::Exited(3));
    assert_eq!(r.output, b"out\nerr\n");
    assert!(!r.truncated);
}

#[test]
fn looks_the_program_up_on_path() {
    let r = run(&["true"], GENEROUS, Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::Exited(0));
}

#[test]
fn sets_lc_all_c_replacing_an_existing_value() {
    // The test process may have any LC_ALL; the child must always see C. Std's Command::env
    // overrides the inherited value, which `env` here shows through the child's own output.
    let r = sh("echo $LC_ALL");
    assert_eq!(r.outcome, ChildOutcome::Exited(0));
    assert_eq!(r.output, b"C\n");
}

#[test]
fn passes_the_rest_of_the_environment_through() {
    let r = sh("echo $PATH");
    assert_eq!(r.output, format!("{}\n", std::env::var("PATH").unwrap()).into_bytes());
}

#[test]
fn stdin_is_empty() {
    let r = run(&["cat"], Duration::from_secs(5), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::Exited(0));
    assert!(r.output.is_empty());
}

#[test]
fn death_by_signal_is_128_plus_signal() {
    assert_eq!(sh("kill -TERM $$").outcome, ChildOutcome::Exited(128 + 15));
    assert_eq!(sh("kill -KILL $$").outcome, ChildOutcome::Exited(128 + 9));
}

#[test]
fn timeout_kills_a_sleeping_child_within_the_deadline_plus_two_seconds() {
    let timeout = Duration::from_secs(1);
    let r = run(&["sleep", "30"], timeout, Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert!(r.elapsed >= timeout, "{:?}", r.elapsed);
    assert!(r.elapsed < timeout + SLACK, "{:?}", r.elapsed);
}

#[test]
fn timeout_keeps_the_output_produced_before_it() {
    let r = run(&["/bin/sh", "-c", "echo early; sleep 30"], Duration::from_secs(2), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert_eq!(r.output, b"early\n");
}

#[test]
fn times_out_a_child_that_closed_its_output_and_keeps_running() {
    let r = run(&["/bin/sh", "-c", "exec >&- 2>&-; sleep 30"], Duration::from_secs(1), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert!(r.elapsed < Duration::from_secs(1) + SLACK, "{:?}", r.elapsed);
}

#[test]
fn kills_the_whole_process_group_on_timeout() {
    let r = run(&["/bin/sh", "-c", "sleep 30 & echo $!; wait"], Duration::from_secs(2), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    let pid: i32 = String::from_utf8_lossy(&r.output).trim().parse().unwrap();
    assert!(pid > 1);
    assert!(wait_gone(pid), "the background sleep survived the group kill");
}

#[test]
fn a_background_grandchild_holding_the_pipe_open_cannot_hold_us_past_the_deadline() {
    // sh exits at once; the background sleep (same process group) keeps the pipe open.
    let r = run(&["/bin/sh", "-c", "sleep 30 & echo bg"], Duration::from_secs(2), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert_eq!(r.output, b"bg\n");
    assert!(r.elapsed >= Duration::from_secs(2), "{:?}", r.elapsed);
    assert!(r.elapsed < Duration::from_secs(2) + SLACK, "{:?}", r.elapsed);
}

#[test]
fn a_grandchild_in_another_session_holding_the_pipe_is_abandoned_not_waited_for() {
    if run(&["setsid", "--version"], Duration::from_secs(5), Bytes::kib(1)).outcome == ChildOutcome::NotFound
    {
        eprintln!("no setsid; skipped");
        return;
    }
    // The grandchild leaves the process group, so the group kill cannot free the pipe: the reader
    // thread must be abandoned, and the call must still return on time. The sleep ends by itself.
    let r = run(&["/bin/sh", "-c", "setsid sleep 4 & echo up"], Duration::from_secs(2), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert_eq!(r.output, b"up\n");
    assert!(r.elapsed < Duration::from_secs(2) + SLACK, "{:?}", r.elapsed);
}

#[test]
fn a_huge_timeout_does_not_overflow() {
    let r = run(&["true"], Duration::MAX, Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::Exited(0));
    // A zero timeout is already over: normally TimedOut, but a very fast child may win the race.
    let r = run(&["true"], Duration::ZERO, Bytes::kib(1));
    assert!(matches!(r.outcome, ChildOutcome::TimedOut | ChildOutcome::Exited(_)), "{:?}", r.outcome);
    assert!(r.elapsed < Duration::from_secs(2), "{:?}", r.elapsed);
}

#[test]
fn not_found_for_missing_programs() {
    assert_eq!(run(&["xe-no-such-program"], GENEROUS, Bytes::kib(1)).outcome, ChildOutcome::NotFound);
    assert_eq!(run(&["/nonexistent/dir/program"], GENEROUS, Bytes::kib(1)).outcome, ChildOutcome::NotFound);
}

#[test]
fn a_non_executable_file_is_a_spawn_failure() {
    let dir = PrivateTempDir::create("xe-noexec-").unwrap();
    let file = dir.path().join("script");
    std::fs::write(&file, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let r = run(&[file.to_str().unwrap()], GENEROUS, Bytes::kib(1));
    assert!(matches!(r.outcome, ChildOutcome::SpawnFailed(_)), "{:?}", r.outcome);
}

#[test]
fn an_argument_with_a_nul_byte_is_a_spawn_failure_not_a_panic() {
    let r = run(&["echo", "a\0b"], GENEROUS, Bytes::kib(1));
    assert!(matches!(r.outcome, ChildOutcome::SpawnFailed(_)), "{:?}", r.outcome);
}

#[test]
fn caps_the_output_and_keeps_draining() {
    let r = run(&["head", "-c", "1048576", "/dev/zero"], GENEROUS, Bytes::kib(4));
    assert_eq!(r.outcome, ChildOutcome::Exited(0));
    assert!(r.truncated);
    assert_eq!(r.output.len(), 4096);
    assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
}

#[test]
fn exact_fit_is_not_truncated() {
    let r = run(&["printf", "abcd"], GENEROUS, Bytes(4));
    assert_eq!(r.output, b"abcd");
    assert!(!r.truncated);
    let r = run(&["printf", "abcde"], GENEROUS, Bytes(4));
    assert_eq!(r.output, b"abcd");
    assert!(r.truncated);
}

#[test]
fn child_is_in_its_own_process_group() {
    let r = sh("ps -o pgid= -p $$; ps -o sid= -p $$");
    let nums: Vec<i64> =
        String::from_utf8_lossy(&r.output).split_whitespace().map(|t| t.parse().unwrap()).collect();
    assert_eq!(nums.len(), 2);
    assert_ne!(nums[0], i64::from(std::process::id()));
    assert_ne!(nums[0], 0);
}

// ---- SIGCHLD ignored by the parent ----

/// The body of the SIGCHLD test; does nothing unless the outer test started it in a process
/// whose SIGCHLD is ignored.
#[test]
fn sigchld_ignored_inner_body() {
    if std::env::var_os("XE_SIGCHLD_IGNORED_INNER").is_none() {
        return;
    }
    // The kernel reaps the child, so there is no wait status: Exited(-1), output complete.
    let r = sh("echo hi; exit 3");
    assert_eq!(r.outcome, ChildOutcome::Exited(-1));
    assert_eq!(r.output, b"hi\n");

    let r = run(&["sleep", "30"], Duration::from_secs(1), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::TimedOut);
    assert!(r.elapsed < Duration::from_secs(1) + SLACK, "{:?}", r.elapsed);

    // The child must not inherit the ignored SIGCHLD: its own wait() has to work.
    let r = sh("true & wait $!; echo rc=$?");
    assert_eq!(r.outcome, ChildOutcome::Exited(-1));
    assert_eq!(r.output, b"rc=0\n");

    // And SigIgn in the child shows neither SIGCHLD (17) nor SIGPIPE (13).
    let r = run(&["grep", "SigIgn", "/proc/self/status"], GENEROUS, Bytes::kib(1));
    let text = String::from_utf8_lossy(&r.output).into_owned();
    let mask = u64::from_str_radix(text.split(':').nth(1).unwrap().trim(), 16).unwrap();
    assert_eq!(mask & (1 << (libc::SIGCHLD - 1)), 0, "SIGCHLD leaked: {text}");
    assert_eq!(mask & (1 << (libc::SIGPIPE - 1)), 0, "SIGPIPE leaked: {text}");
}

/// Re-runs `sigchld_ignored_inner_body` in a copy of the test binary that ignores SIGCHLD (the
/// disposition survives exec). Ignoring SIGCHLD in the multi-threaded test process itself would
/// break every other test that waits for a child.
#[test]
fn parent_ignoring_sigchld_is_handled() {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        "procio::unix::tests::sigchld_ignored_inner_body",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("XE_SIGCHLD_IGNORED_INNER", "1")
    .stdin(Stdio::null());
    sys::unix::ignore_sigchld_in_child(&mut cmd);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "inner run failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "inner test did not run:\n{stdout}\n{stderr}");
}

// ---- descriptor leaks ----

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}

/// The body of the descriptor-leak test; does nothing unless the outer test started it as the
/// only test of a fresh process (other tests open descriptors in parallel and would add noise).
#[test]
fn fd_leak_inner_body() {
    if std::env::var_os("XE_FDLEAK_INNER").is_none() {
        return;
    }
    let before = open_fd_count();
    for _ in 0..20 {
        sh("echo hi");
        run(&["xe-no-such-program"], GENEROUS, Bytes::kib(1));
        run_child(&[], GENEROUS, Bytes::kib(1));
        run(&["sleep", "30"], Duration::from_millis(50), Bytes::kib(1));
        run(&["head", "-c", "1048576", "/dev/zero"], GENEROUS, Bytes(16));
        read(Path::new("/proc/self/status"), Bytes::kib(1), Keep::Head);
        read(Path::new("/proc/self/status"), Bytes::kib(1), Keep::Tail);
        read(Path::new("/nonexistent"), Bytes::kib(1), Keep::Head);
        read(Path::new("/proc"), Bytes::kib(1), Keep::Head);
        read_nonblocking_bounded(Path::new("/proc/self/status"), Bytes::kib(1), Keep::Head);
    }
    // The reader thread closes its end just after it sees EOF.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(open_fd_count(), before, "descriptors leaked");
}

#[test]
fn run_child_and_read_file_bounded_leak_no_descriptors() {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "procio::unix::tests::fd_leak_inner_body", "--nocapture", "--test-threads=1"])
        .env("XE_FDLEAK_INNER", "1")
        .stdin(Stdio::null());
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "inner run failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "inner test did not run:\n{stdout}\n{stderr}");
}

// ---- read_nonblocking_bounded ----

/// A FIFO whose writer wrote and then idles (keeping it open): a blocking read would wait for
/// more; the non-blocking one returns what is there.
#[test]
fn nonblocking_read_of_a_fifo_with_an_idle_writer_returns_the_data() {
    use std::sync::mpsc;
    let dir = PrivateTempDir::create("xe-nb-").unwrap();
    let fifo = dir.path().join("pipe");
    if !Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success()) {
        eprintln!("no mkfifo; skipped");
        return;
    }
    // Keep one read end open so the writer's open does not block and its data stays queued.
    let keep_alive = OpenOptions::new().read(true).custom_flags(sys::unix::O_NONBLOCK).open(&fifo).unwrap();
    let (written_tx, written_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let mut f = OpenOptions::new().write(true).open(writer_path).unwrap();
        f.write_all(b"hello\nworld\n").unwrap();
        written_tx.send(()).unwrap();
        let _ = done_rx.recv_timeout(Duration::from_secs(30)); // idle, still open
    });
    written_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    let guard = crate::guard::Guard::new(Duration::from_secs(10));
    let path = fifo.clone();
    let got = guard.bounded("nb", move || read_nonblocking_bounded(&path, Bytes::kib(1), Keep::Head));
    done_tx.send(()).unwrap();
    writer.join().unwrap();
    drop(keep_alive);
    let head = got.expect("the read hung instead of returning at EAGAIN");
    assert_eq!(head.outcome, ReadOutcome::Read, "{}", head.error);
    assert_eq!(head.data, b"hello\nworld\n");
    assert!(!head.truncated);
}

#[test]
fn nonblocking_read_clips_head_and_tail_and_classifies_errors() {
    let (_dir, file) = write_digits();
    let r = read_nonblocking_bounded(&file, Bytes(4), Keep::Head);
    assert_eq!((r.outcome, r.data.as_slice(), r.truncated), (ReadOutcome::Read, &b"0123"[..], true));
    let r = read_nonblocking_bounded(&file, Bytes(4), Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"6789"[..], true));
    let r = read_nonblocking_bounded(&file, Bytes(100), Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read_nonblocking_bounded(Path::new("/nonexistent/xe"), Bytes(4), Keep::Head);
    assert_eq!(r.outcome, ReadOutcome::Missing);
}

#[test]
fn nonblocking_read_of_dev_kmsg_returns_when_readable() {
    // The point is that it returns at EAGAIN instead of waiting for the next message.
    let r = read_nonblocking_bounded(Path::new("/dev/kmsg"), Bytes::kib(64), Keep::Tail);
    match r.outcome {
        ReadOutcome::Read => assert!(r.data.len() <= 64 * 1024),
        ReadOutcome::Denied | ReadOutcome::Missing => eprintln!("/dev/kmsg: {}; skipped", r.error),
        ReadOutcome::Failed => panic!("/dev/kmsg: {}", r.error),
    }
}

// ---- read_file_bounded ----

fn write_digits() -> (PrivateTempDir, PathBuf) {
    let dir = PrivateTempDir::create("xe-read-").unwrap();
    let file = dir.path().join("digits");
    std::fs::write(&file, "0123456789").unwrap();
    (dir, file)
}

#[test]
fn regular_file_head_and_tail() {
    let (_dir, file) = write_digits();
    let r = read(&file, Bytes::kib(100), Keep::Head);
    assert_eq!(
        (r.outcome, r.data.as_slice(), r.truncated, r.error.as_str()),
        (ReadOutcome::Read, &b"0123456789"[..], false, "")
    );
    let r = read(&file, Bytes(10), Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(&file, Bytes(4), Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123"[..], true));
    let r = read(&file, Bytes(0), Keep::Head);
    assert_eq!((r.outcome, r.data.as_slice(), r.truncated), (ReadOutcome::Read, &b""[..], true));
    let r = read(&file, Bytes::kib(100), Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(&file, Bytes(10), Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(&file, Bytes(4), Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"6789"[..], true));
    let r = read(&file, Bytes(0), Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b""[..], true));
}

#[test]
fn file_larger_than_one_chunk() {
    let dir = PrivateTempDir::create("xe-big-").unwrap();
    let content: Vec<u8> = (0..300_000usize).map(|i| b'a' + (i % 26) as u8).collect();
    let file = dir.path().join("big");
    std::fs::write(&file, &content).unwrap();
    let head = read(&file, Bytes(100_000), Keep::Head);
    assert_eq!(head.data, content[..100_000]);
    assert!(head.truncated);
    let tail = read(&file, Bytes(1000), Keep::Tail);
    assert_eq!(tail.data, content[content.len() - 1000..]);
    assert!(tail.truncated);
    let all = read(&file, Bytes::mib(1), Keep::Head);
    assert_eq!(all.data, content);
    assert!(!all.truncated);
}

#[test]
fn open_errors_are_classified() {
    let dir = PrivateTempDir::create("xe-err-").unwrap();
    let r = read(&dir.path().join("nope"), Bytes::kib(1), Keep::Head);
    assert_eq!(r.outcome, ReadOutcome::Missing);
    assert!(!r.error.is_empty());
    assert!(r.data.is_empty());

    let plain = dir.path().join("plain");
    std::fs::write(&plain, "x").unwrap();
    assert_eq!(read(&plain.join("child"), Bytes::kib(1), Keep::Head).outcome, ReadOutcome::Missing);

    let r = read(dir.path(), Bytes::kib(1), Keep::Head);
    assert_eq!(r.outcome, ReadOutcome::Failed);
    assert!(!r.error.is_empty());

    if sys::unix::euid() != 0 {
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "secret").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = read(&secret, Bytes::kib(1), Keep::Head);
        assert_eq!(r.outcome, ReadOutcome::Denied);
        assert!(!r.error.is_empty());
        assert!(r.data.is_empty());
    }
}

#[test]
fn procfs_pseudo_file() {
    let head = read(Path::new("/proc/self/status"), Bytes::mib(1), Keep::Head);
    assert_eq!(head.outcome, ReadOutcome::Read);
    assert!(head.data.starts_with(b"Name:"));
    assert!(!head.truncated);
    let capped = read(Path::new("/proc/self/status"), Bytes(16), Keep::Head);
    assert_eq!(capped.data, head.data[..16]);
    assert!(capped.truncated);
    let tail = read(Path::new("/proc/self/status"), Bytes(64), Keep::Tail);
    assert_eq!(tail.data.len(), 64);
    assert!(tail.truncated);
    assert_eq!(tail.data.last(), Some(&b'\n'));
}

/// sysfs attributes are regular files reporting size 4096 and zero blocks. Seeking to
/// `size - cap` would land past their real content, so the tail must be a rolling tail.
#[test]
fn sysfs_tail_does_not_seek() {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("card") && !name.contains('-') {
                candidates.push(e.path().join("device/vendor"));
            }
        }
    }
    candidates.push("/sys/kernel/mm/transparent_hugepage/enabled".into());
    candidates.push("/sys/devices/system/cpu/online".into());
    let Some(attr) = candidates.into_iter().find(|p| p.is_file()) else {
        eprintln!("no sysfs attribute to read; skipped");
        return;
    };
    let meta = std::fs::metadata(&attr).unwrap();
    assert_eq!(meta.blocks(), 0, "{} has blocks; not a pseudo-file", attr.display());

    let head = read(&attr, Bytes::kib(1), Keep::Head);
    assert_eq!(head.outcome, ReadOutcome::Read);
    assert!(head.data.len() > 2, "{}: {:?}", attr.display(), head.data);

    // A cap far below the reported 4096 but above the real length: a seek by size would skip
    // everything and return nothing.
    let whole = read(&attr, Bytes(100), Keep::Tail);
    assert_eq!(whole.data, head.data);
    assert!(!whole.truncated);
    let whole = read(&attr, Bytes::kib(100), Keep::Tail);
    assert_eq!(whole.data, head.data);

    let tail = read(&attr, Bytes(2), Keep::Tail);
    assert_eq!(tail.data, head.data[head.data.len() - 2..]);
    assert!(tail.truncated);
}

#[test]
fn rolling_tail_of_a_stream() {
    let dir = PrivateTempDir::create("xe-fifo-").unwrap();
    let fifo = dir.path().join("stream");
    // libc::mkfifo would be unsafe here; the mkfifo tool does the same.
    let made = Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("no mkfifo; skipped");
        return;
    }
    let content: Vec<u8> = (0..300_000usize).map(|i| b'a' + (i % 251 % 26) as u8).collect();
    let to_write = content.clone();
    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(writer_path) {
            let _ = f.write_all(&to_write);
        }
    });
    let r = read(&fifo, Bytes(1000), Keep::Tail);
    writer.join().unwrap();
    assert_eq!(r.outcome, ReadOutcome::Read);
    assert!(r.truncated);
    assert_eq!(r.data, content[content.len() - 1000..]);
}

// ---- find_in_path ----

fn make_exec(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

#[test]
fn find_in_dirs_needs_the_executable_bit() {
    let dir = PrivateTempDir::create("xe-path-").unwrap();
    let exec = make_exec(dir.path(), "tool", 0o755);
    make_exec(dir.path(), "plain", 0o644);
    let dirs = vec![dir.path().to_path_buf()];
    assert_eq!(find_in_dirs("tool", &dirs, is_executable_file), Some(exec));
    assert_eq!(find_in_dirs("plain", &dirs, is_executable_file), None);
    assert_eq!(find_in_dirs("absent", &dirs, is_executable_file), None);
    // A directory with an execute bit is not a program.
    std::fs::create_dir(dir.path().join("adir")).unwrap();
    assert_eq!(find_in_dirs("adir", &dirs, is_executable_file), None);
}

#[test]
fn find_in_dirs_prefers_earlier_entries_and_follows_symlinks() {
    let a = PrivateTempDir::create("xe-path-a-").unwrap();
    let b = PrivateTempDir::create("xe-path-b-").unwrap();
    make_exec(b.path(), "tool", 0o755);
    let first = make_exec(a.path(), "real", 0o755);
    symlink(&first, a.path().join("tool")).unwrap();
    let dirs = vec![a.path().to_path_buf(), b.path().to_path_buf()];
    assert_eq!(find_in_dirs("tool", &dirs, is_executable_file), Some(a.path().join("tool")));
}

#[test]
fn find_in_dirs_skips_empty_and_relative_entries() {
    // Empty and relative PATH entries are the current directory; they must never be probed.
    let seen = std::cell::RefCell::new(Vec::new());
    let dirs = vec![
        PathBuf::new(),
        PathBuf::from("."),
        PathBuf::from("./"),
        PathBuf::from("bin"),
        PathBuf::from("/xe-nowhere"),
    ];
    let got = find_in_dirs("tool", &dirs, |p| {
        seen.borrow_mut().push(p.to_path_buf());
        false
    });
    assert_eq!(got, None);
    assert_eq!(*seen.borrow(), [PathBuf::from("/xe-nowhere/tool")]);
}

#[test]
fn find_in_path_with_a_separator_checks_the_file() {
    let dir = PrivateTempDir::create("xe-sep-").unwrap();
    let exec = make_exec(dir.path(), "tool", 0o755);
    let plain = make_exec(dir.path(), "plain", 0o600);
    assert_eq!(find_in_path(exec.to_str().unwrap()), Some(exec));
    assert_eq!(find_in_path(plain.to_str().unwrap()), None);
    assert_eq!(find_in_path("/nonexistent/xe/tool"), None);
    assert_eq!(find_in_path(""), None);
}

#[test]
fn find_in_path_finds_sh_on_the_real_path() {
    let sh = find_in_path("sh").unwrap();
    assert!(sh.is_absolute());
    assert!(is_executable_file(&sh));
}

#[test]
fn started_pid_is_waited_so_no_zombies_pile_up() {
    let before = zombie_children();
    for _ in 0..5 {
        run(&["true"], GENEROUS, Bytes::kib(1));
        run(&["sleep", "30"], Duration::from_millis(50), Bytes::kib(1));
    }
    // Other tests run in parallel and spawn their own children; compare only against growth
    // caused by us, with slack for them.
    let after = zombie_children();
    assert!(after <= before + 5, "zombies before {before}, after {after}");
}

fn zombie_children() -> usize {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("stat")).ok())
        .filter(|s| {
            let Some(i) = s.rfind(')') else { return false };
            let mut f = s[i + 2..].split_whitespace();
            f.next() == Some("Z") && f.next().and_then(|p| p.parse::<u32>().ok()) == Some(me)
        })
        .count()
}
