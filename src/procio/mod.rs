// SPDX-License-Identifier: MIT
//! Bounded child processes, bounded file reads, private temp directories and PATH lookup.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::bundle::source::{Keep, ReadOutcome, ReadResult};
use crate::units::Bytes;

/// Size of one read from a pipe or file.
const IO_CHUNK: usize = 64 * 1024;
/// First and longest sleep between `try_wait` polls.
const POLL_START: Duration = Duration::from_millis(1);
const POLL_MAX: Duration = Duration::from_millis(10);
/// SIGKILL is not delivered to a child stuck in an uninterruptible driver call, so the wait for
/// it is bounded.
const KILL_REAP_GRACE: Duration = Duration::from_secs(2);
/// After a kill, how long the reader thread may take to see the pipe close.
const DRAIN_AFTER_KILL: Duration = Duration::from_millis(200);

/// How a child process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOutcome {
    /// Ran to completion with this exit code; death by signal is 128 + signal; -1 when the status
    /// is unavailable (SIGCHLD ignored, ECHILD) or cannot be decoded.
    Exited(i32),
    /// Killed with its process group (job object on Windows) at the deadline.
    TimedOut,
    /// `argv[0]` is not an executable on PATH.
    NotFound,
    /// Any other failure to start it; the OS error text.
    SpawnFailed(String),
}

/// The result of [`run_child`].
#[derive(Debug, Clone)]
pub struct ChildResult {
    pub outcome: ChildOutcome,
    /// stdout and stderr interleaved, at most the `max_output` passed in.
    pub output: Vec<u8>,
    /// Output reached `max_output`; the rest was drained and discarded.
    pub truncated: bool,
    /// Wall time from spawn to exit or kill.
    pub elapsed: Duration,
}

/// Runs `argv` with stdin null, stdout and stderr on one pipe, `LC_ALL=C`, in its own process
/// group (job object on Windows), killing it at `timeout`. `argv[0]` without a separator is looked
/// up with [`find_in_path`].
///
/// Once the child has started the call returns within `timeout` + about 2.2 s (a kill, a reap
/// bounded at 2 s, then 0.2 s for the output pipe to close). Starting a program can itself block on
/// a hung filesystem, before any timer runs: call this through
/// [`crate::guard::Guard::bounded_for`] with a limit of `timeout` + 3 s.
///
/// On Unix the call also waits for the output pipe to close (a descendant that keeps it open past
/// the deadline makes the result `TimedOut`, and the whole process group is killed). On Windows
/// descendants are killed with the job object once the child itself has exited.
pub fn run_child(argv: &[String], timeout: Duration, max_output: Bytes) -> ChildResult {
    let start = Instant::now();
    let deadline = deadline_after(start, timeout);
    let finish = |outcome: ChildOutcome, output: Vec<u8>, truncated: bool| ChildResult {
        outcome,
        output,
        truncated,
        elapsed: start.elapsed(),
    };
    let failed = |text: String| finish(ChildOutcome::SpawnFailed(text), Vec::new(), false);

    let Some(program) = argv.first().filter(|p| !p.is_empty()) else {
        return failed("empty command line".to_owned());
    };
    let resolved = if has_separator(program) {
        PathBuf::from(program)
    } else {
        match find_in_path(program) {
            Some(path) => path,
            None => return finish(ChildOutcome::NotFound, Vec::new(), false),
        }
    };

    let (reader, writer) = match io::pipe() {
        Ok(ends) => ends,
        Err(e) => return failed(e.to_string()),
    };
    let writer_for_stderr = match writer.try_clone() {
        Ok(w) => w,
        Err(e) => return failed(e.to_string()),
    };

    let mut cmd = std::process::Command::new(&resolved);
    cmd.args(&argv[1..])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(writer_for_stderr));
    imp::configure(&mut cmd, program);
    let spawned = cmd.spawn();
    // The Command owns the write ends; dropping it closes the parent's copies, so EOF on the read
    // end means every holder in the child tree has gone.
    drop(cmd);
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return finish(ChildOutcome::NotFound, Vec::new(), false);
        }
        Err(e) => return failed(e.to_string()),
    };
    let group = imp::Group::attach(&child);

    let capture = match Capture::start(reader, capacity(max_output)) {
        Ok(capture) => capture,
        Err(e) => {
            group.kill(&mut child);
            reap_within(&mut child, KILL_REAP_GRACE);
            return failed(format!("cannot start the output reader: {e}"));
        }
    };

    let (code, timed_out) = match wait_until(&mut child, deadline) {
        Waited::Deadline => (-1, true),
        Waited::Exited(code) => (code, !after_exit(&group, &capture, deadline)),
        Waited::Lost => (-1, !after_exit(&group, &capture, deadline)),
    };

    if timed_out {
        group.kill(&mut child);
        if reap_within(&mut child, KILL_REAP_GRACE) {
            capture.wait_eof(Instant::now() + DRAIN_AFTER_KILL);
        }
    }
    let (output, truncated) = capture.finish();
    let (output, truncated) = imp::finish_output(output, truncated, capacity(max_output));
    let outcome = if timed_out { ChildOutcome::TimedOut } else { ChildOutcome::Exited(code) };
    finish(outcome, output, truncated)
}

/// What to do once the child itself is gone: let the platform stop its descendants, then wait for
/// the output pipe to close. Returns false when the wait must count as a timeout.
fn after_exit(group: &imp::Group, capture: &Capture, deadline: Instant) -> bool {
    group.after_exit();
    match imp::EOF_GRACE {
        // The pipe must close by the deadline, or a descendant is holding the tool's output open.
        None => capture.wait_eof(deadline),
        Some(grace) => {
            capture.wait_eof(Instant::now() + grace);
            true
        }
    }
}

/// Reads at most `max` bytes of `path`, keeping the head or the tail. Never seeks for the tail
/// unless the file reports allocated blocks (sysfs files report size 4096 and zero blocks).
///
/// May block indefinitely on a FIFO or another node whose open or read blocks; callers that cannot
/// tolerate that run it through [`crate::guard::Guard`].
pub fn read_file_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    imp::read_file_bounded(path, max, keep)
}

/// Like [`read_file_bounded`] for nodes that must not be waited on: Unix opens with `O_NONBLOCK`,
/// so a read that would wait (`EAGAIN`) is the end of the data, and the open itself does not block
/// on a FIFO. Meant for `/dev/kmsg`, which returns one record per `read` and then `EAGAIN`.
///
/// Reads use the full 64 KiB chunk (a record is never cut by a small buffer, which `/dev/kmsg`
/// would refuse with `EINVAL`) and are clipped to `max` afterwards, keeping the head or the tail.
/// `EPIPE` from `/dev/kmsg` means records were overwritten before they were read; the read goes on
/// with the next record. On Windows this is [`read_file_bounded`].
pub fn read_nonblocking_bounded(path: &Path, max: Bytes, keep: Keep) -> ReadResult {
    imp::read_nonblocking_bounded(path, max, keep)
}

/// The full path of `program` on PATH (PATHEXT on Windows); never the current directory: empty and
/// relative PATH entries are skipped, so only absolute directories are searched. A `program`
/// containing a path separator is returned as-is when it is an executable file (so a caller that
/// wants a relative tool passes it with a separator).
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    imp::find_in_path(program)
}

/// The path of the running executable.
pub fn self_executable_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// A private temporary directory, removed with everything in it on drop.
///
/// Unix: created with mode 0700. Windows: created with a protected DACL (owner, Administrators and
/// SYSTEM only, nothing inherited from the parent), failing closed when that cannot be set.
/// Neither is removed by `std::process::exit`, which skips `Drop`.
#[derive(Debug)]
pub struct PrivateTempDir {
    #[cfg(unix)]
    dir: tempfile::TempDir,
    #[cfg(windows)]
    path: PathBuf,
}

impl PrivateTempDir {
    /// Creates a new directory under the system temporary directory; `prefix` starts its name and
    /// must not contain a path separator (`/`, `\`) or NUL (`InvalidInput` otherwise).
    pub fn create(prefix: &str) -> io::Result<Self> {
        if prefix.contains(['/', '\\', '\0']) || (cfg!(windows) && prefix.contains(':')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "temporary directory prefix must not contain a path separator",
            ));
        }
        Self::create_checked(prefix)
    }

    #[cfg(unix)]
    fn create_checked(prefix: &str) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        // tempfile creates directories with the default mode (0777 & ~umask); ask for 0700.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
        Ok(Self { dir: builder.tempdir()? })
    }

    #[cfg(windows)]
    fn create_checked(prefix: &str) -> io::Result<Self> {
        let base = std::path::absolute(std::env::temp_dir())?;
        for _ in 0..8 {
            let path = base.join(format!("{prefix}{}", random_suffix()));
            match crate::sys::windows::create_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        #[cfg(unix)]
        {
            self.dir.path()
        }
        #[cfg(windows)]
        {
            &self.path
        }
    }
}

#[cfg(windows)]
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 16 hex digits from the per-process random hasher keys, the time and a counter. Not a secret:
/// the directory is created exclusively and protected by its DACL.
#[cfg(any(windows, test))]
fn random_suffix() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    if let Ok(since_epoch) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.write_u128(since_epoch.as_nanos());
    }
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------------------------
// Shared building blocks (platform neutral, used by unix.rs and windows.rs)
// ---------------------------------------------------------------------------------------------

/// Whether `program` names a path (contains a directory separator) rather than a bare command.
fn has_separator(program: &str) -> bool {
    if cfg!(windows) { program.contains(['/', '\\']) } else { program.contains('/') }
}

/// `start + timeout`, or a point so far away it never arrives when that would overflow.
fn deadline_after(start: Instant, timeout: Duration) -> Instant {
    const TEN_YEARS: Duration = Duration::from_secs(10 * 365 * 24 * 3600);
    start.checked_add(timeout).or_else(|| start.checked_add(TEN_YEARS)).unwrap_or(start)
}

/// A byte limit as a `usize` that is safe to double.
fn capacity(limit: Bytes) -> usize {
    usize::try_from(limit.get()).unwrap_or(usize::MAX).min(usize::MAX / 2)
}

/// How a wait for a child ended.
enum Waited {
    /// The status was collected.
    Exited(i32),
    /// Still running at the deadline.
    Deadline,
    /// The status is gone: for example SIGCHLD is ignored and the kernel reaped the child (ECHILD).
    Lost,
}

/// Waits for `child` without blocking past `deadline`, polling `try_wait` at 1 ms growing to 10 ms.
fn wait_until(child: &mut Child, deadline: Instant) -> Waited {
    let mut pause = POLL_START;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Waited::Exited(exit_code(status)),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // ECHILD and anything else: there is no status to collect any more.
            Err(_) => return Waited::Lost,
        }
        let now = Instant::now();
        if now >= deadline {
            return Waited::Deadline;
        }
        thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(POLL_MAX);
    }
}

/// Waits up to `grace` for `child` to be collected. True when it was, or when there is nothing left
/// to collect; false when it is still running (a process in uninterruptible sleep never dies, so
/// it is abandoned).
fn reap_within(child: &mut Child, grace: Duration) -> bool {
    !matches!(wait_until(child, Instant::now() + grace), Waited::Deadline)
}

/// Decodes a wait status: the exit code, 128 + signal for a death by signal, otherwise -1.
fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return code;
        }
        status.signal().map_or(-1, |signal| 128 + signal)
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(-1)
    }
}

/// The state shared between a [`Capture`] and its reader thread.
#[derive(Debug, Default)]
struct CaptureState {
    data: Vec<u8>,
    truncated: bool,
    /// The reader reached EOF (or failed): the pipe has no writers left.
    eof: bool,
    /// The collector took the data; a reader still running must stop appending.
    abandoned: bool,
}

/// A child's output drained on a helper thread: keeps the first `cap` bytes and discards the rest,
/// so the child never blocks on a full pipe. The thread can be abandoned: [`Capture::finish`] takes
/// what is there and the thread, which may stay blocked in `read` as long as some process holds the
/// pipe open, is detached and never joined.
struct Capture {
    shared: Arc<(Mutex<CaptureState>, Condvar)>,
}

impl Capture {
    /// Starts draining `reader`.
    fn start<R: Read + Send + 'static>(reader: R, cap: usize) -> io::Result<Self> {
        let shared = Arc::new((Mutex::new(CaptureState::default()), Condvar::new()));
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("xe-pipe-reader".to_owned())
            .spawn(move || drain(reader, cap, &worker))?;
        Ok(Self { shared })
    }

    fn lock(&self) -> MutexGuard<'_, CaptureState> {
        self.shared.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the reader saw EOF or `until` passed; true when it saw EOF.
    fn wait_eof(&self, until: Instant) -> bool {
        let mut state = self.lock();
        while !state.eof {
            let now = Instant::now();
            if now >= until {
                return false;
            }
            state = match self.shared.1.wait_timeout(state, until - now) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        true
    }

    /// Takes the bytes read so far and tells the reader to stop appending.
    fn finish(&self) -> (Vec<u8>, bool) {
        let mut state = self.lock();
        state.abandoned = true;
        (std::mem::take(&mut state.data), state.truncated)
    }
}

/// The reader thread's loop.
fn drain<R: Read>(mut reader: R, cap: usize, shared: &(Mutex<CaptureState>, Condvar)) {
    let mut chunk = vec![0u8; IO_CHUNK];
    loop {
        let got = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let mut state = shared.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.abandoned {
            // Nobody wants the data any more; keep emptying the pipe so writers do not block.
            continue;
        }
        let room = cap.saturating_sub(state.data.len());
        let take = room.min(got);
        state.data.extend_from_slice(&chunk[..take]);
        if take < got {
            state.truncated = true;
        }
    }
    let mut state = shared.0.lock().unwrap_or_else(PoisonError::into_inner);
    state.eof = true;
    shared.1.notify_all();
}

/// Reads `source` to EOF keeping at most `cap` bytes: the first `cap` for [`Keep::Head`] (reading
/// one byte past the cap only to learn whether anything was left out), the last `cap` for
/// [`Keep::Tail`] with a rolling window. `result.truncated` may already be set (the tail was
/// entered by seeking). `result.outcome` is Read on success; on a read error it is Failed and the
/// bytes read so far stay in `data`.
///
/// With `records` (a non-blocking record device such as `/dev/kmsg`) every read gets the full
/// chunk and its result is taken as-is, `WouldBlock` is the end of the data and `BrokenPipe`
/// (records overwritten) is skipped.
fn read_stream<R: Read>(
    mut source: R,
    cap: usize,
    keep: Keep,
    records: bool,
    mut result: ReadResult,
) -> ReadResult {
    /// Skipped `BrokenPipe` reads before giving up; each one moves the device past a lost record.
    const MAX_OVERWRITTEN: u32 = 100_000;
    let mut overwritten = 0u32;
    let mut chunk = vec![0u8; IO_CHUNK];
    loop {
        // Head mode reads one byte past the cap, only to learn whether anything was left out.
        let want = match keep {
            Keep::Head if !records => chunk.len().min(cap - result.data.len() + 1),
            Keep::Head | Keep::Tail => chunk.len(),
        };
        let got = match source.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if records && e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if records && e.kind() == io::ErrorKind::BrokenPipe && overwritten < MAX_OVERWRITTEN => {
                overwritten += 1;
                continue;
            }
            Err(e) => {
                result.outcome = ReadOutcome::Failed;
                result.error = e.to_string();
                return result;
            }
        };
        match keep {
            Keep::Head => {
                let take = (cap - result.data.len()).min(got);
                result.data.extend_from_slice(&chunk[..take]);
                if take < got {
                    result.truncated = true;
                    break;
                }
            }
            Keep::Tail => {
                result.data.extend_from_slice(&chunk[..got]);
                // Trimming only past twice the cap keeps the copying amortised.
                if result.data.len() > 2 * cap {
                    let excess = result.data.len() - cap;
                    result.data.drain(..excess);
                    result.truncated = true;
                }
            }
        }
    }
    if keep == Keep::Tail && result.data.len() > cap {
        let excess = result.data.len() - cap;
        result.data.drain(..excess);
        result.truncated = true;
    }
    result.outcome = ReadOutcome::Read;
    result
}

/// Whether `bytes` is UTF-8, allowing an incomplete sequence at the very end (output cut at the
/// cap).
#[cfg(any(windows, test))]
fn is_utf8_allowing_cut_tail(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

/// The file names to try for `program` inside one PATH directory on Windows: `program` itself when
/// it already ends in one of the `pathext` extensions (case-insensitive), then `program` + each
/// extension in `pathext` order. PATH and PATHEXT only, never the current directory.
#[cfg(any(windows, test))]
fn pathext_candidates(dir: &Path, program: &str, pathext: &[String]) -> Vec<PathBuf> {
    let lower = program.to_ascii_lowercase();
    let mut out = Vec::new();
    if pathext.iter().any(|ext| !ext.is_empty() && lower.ends_with(&ext.to_ascii_lowercase())) {
        out.push(dir.join(program));
    }
    for ext in pathext.iter().filter(|e| !e.is_empty()) {
        out.push(dir.join(format!("{program}{ext}")));
    }
    out
}

/// The extensions in a PATHEXT value (`.COM;.EXE;...`), empty entries dropped.
#[cfg(any(windows, test))]
fn parse_pathext(value: &str) -> Vec<String> {
    value.split(';').map(str::trim).filter(|e| !e.is_empty()).map(str::to_owned).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
