// SPDX-License-Identifier: MIT
//! The collector: per-Spec handling, tree walk, caps, keep_lines and redaction.
//!
//! One collection thread walks the sources in order. Everything that can block on a wedged
//! driver or filesystem (a file read, a directory listing, a child process, a builtin) runs on a
//! helper thread through [`Guard`]; a call that misses its limit is abandoned and opens its group,
//! so the later sources of that group are skipped instead of hanging too.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::archive::zip::valid_entry_name;
use crate::bundle::source::{
    Content, Gate, Keep, Produced, ReadOutcome, ReadResult, Reader, Source, Spec, Status,
};
use crate::bundle::writer::Artifact;
use crate::error::Error;
use crate::guard::Guard;
use crate::procio::{ChildOutcome, PrivateTempDir, read_file_bounded, run_child};
use crate::redact;
use crate::units::Bytes;

/// How long one file read may block before its guard group is abandoned.
pub const FILE_READ_LIMIT: Duration = Duration::from_secs(5);

/// The guard group of the sources that do not belong to a device or a tool family.
const HOST_GROUP: &str = "host";

/// The reason of a source that was not started because the `--timeout` deadline had passed.
pub const DEADLINE_REASON: &str = "collector deadline reached";
/// The reason of an xpu-smi source when there is no xpu-smi executable.
pub const XPU_SMI_NOT_FOUND_REASON: &str = "xpu-smi not found";
/// The reason of an identifying source while redaction is on.
pub const REDACTION_REASON: &str = "withheld because it cannot be redacted; use --no-redact";
/// The reason of a command whose output holds the source's unsupported marker.
pub const UNSUPPORTED_REASON: &str = "not supported by this xpu-smi build";
/// The reason of an artifact whose entry could not be written to the archive.
pub const ARCHIVE_WRITE_REASON: &str = "could not write to the archive";

/// The entry the writer adds last; no source may use it.
const RESERVED_ENTRIES: &[&str] = &["manifest.json"];
/// The placeholder in command arguments for a private temporary directory.
const OUTDIR_TOKEN: &str = "{outdir}";
/// The prefix of that directory's name.
const OUTDIR_PREFIX: &str = "xe-bug-report-";
/// The entry (below the source's directory) that receives a command's own output.
const OUTDIR_STDOUT: &str = "stdout.txt";
/// How much of one file written by a command into its output directory is kept.
const OUTDIR_FILE_CAP: Bytes = Bytes::mib(64);
/// How much output a command may produce when its tail is kept.
const CHILD_TAIL_LIMIT: Bytes = Bytes::mib(64);
/// How much is read from a source that filters lines (the cap applies to what is kept).
const FILTER_READ_LIMIT: Bytes = Bytes::mib(64);
/// Time added to a child's own timeout before its helper thread is abandoned: starting a program
/// can block (a hung filesystem) before the child's timer runs.
const CHILD_GRACE: Duration = Duration::from_secs(3);
/// How deep a command's output directory is searched.
const OUTDIR_MAX_DEPTH: usize = 16;

/// What the collector needs besides the sources.
#[derive(Debug, Clone, Default)]
pub struct CollectOptions {
    /// Which identifiers to remove from text.
    pub rules: redact::Rules,
    /// This machine's names, for the rules.
    pub identity: redact::Context,
    /// The xpu-smi executable for `Spec::XpuSmi`; None: those sources are skipped "xpu-smi not found".
    pub xpu_smi: Option<PathBuf>,
    /// When reached, the remaining sources are skipped "collector deadline reached".
    pub deadline: Option<Instant>,
}

/// Receives each collected entry (name, bytes ready for the archive); an error stops collection.
pub type Sink<'a> = dyn FnMut(&str, &[u8]) -> Result<(), Error> + 'a;

/// Collects `sources` in order, passing each file (entry name, redacted bytes) to `sink`.
/// Returns one artifact per source (one per output for builtins). A sink error stops collection
/// and is returned.
///
/// The sources are shared (`Arc`) because a builtin runs on a helper thread that may outlive this
/// call when it is abandoned.
pub fn collect(
    sources: Arc<[Source]>,
    options: &CollectOptions,
    sink: &mut Sink<'_>,
) -> Result<Vec<Artifact>, Error> {
    collect_with_limit(sources, options, sink, FILE_READ_LIMIT)
}

/// [`collect`] with an explicit limit for one guarded read (tests shorten it).
fn collect_with_limit(
    sources: Arc<[Source]>,
    options: &CollectOptions,
    sink: &mut Sink<'_>,
    read_limit: Duration,
) -> Result<Vec<Artifact>, Error> {
    let count = sources.len();
    let mut collector = Collector {
        options,
        sink,
        sources,
        guard: Arc::new(Guard::new(read_limit)),
        read_limit,
        artifacts: Vec::new(),
        written: RESERVED_ENTRIES.iter().map(|name| (*name).to_owned()).collect(),
        error: None,
    };
    for index in 0..count {
        if collector.error.is_some() {
            break;
        }
        collector.collect_one(index);
    }
    match collector.error {
        Some(error) => Err(error),
        None => Ok(collector.artifacts),
    }
}

// ---- helpers shared with the tests -------------------------------------------------------------

/// Whether `pattern` (with `*` matching any run of characters) matches `name`; one path segment.
pub fn match_segment(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    let mut star_at: Option<usize> = None;
    let mut resume_at = 0;
    while n < name.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star_at = Some(p);
            p += 1;
            resume_at = n;
        } else if p < pattern.len() && pattern[p] == name[n] {
            p += 1;
            n += 1;
        } else if let Some(star) = star_at {
            p = star + 1;
            resume_at += 1;
            n = resume_at;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Keeps the lines of `text` that contain one of `needles` (ASCII case-insensitive). A line keeps
/// its newline; the last line may have none.
pub fn filter_lines(text: &[u8], needles: &[String]) -> Vec<u8> {
    let folded: Vec<Vec<u8>> =
        needles.iter().map(|needle| needle.to_ascii_lowercase().into_bytes()).collect();
    let lowered = text.to_ascii_lowercase();
    let mut kept = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let end = text[start..].iter().position(|&b| b == b'\n').map_or(text.len(), |at| start + at + 1);
        let line = &lowered[start..end];
        if folded.iter().any(|needle| contains_subslice(line, needle)) {
            kept.extend_from_slice(&text[start..end]);
        }
        start = end;
    }
    kept
}

/// Drops the partial line at the cut edge of capped text: everything up to and including the first
/// newline for a tail (`Keep::Tail`), everything after the last newline for a head. Text without a
/// newline is one partial line and becomes empty, so no fragment of a name can survive the cut.
pub fn drop_partial_line(data: &mut Vec<u8>, keep: Keep) {
    match keep {
        Keep::Tail => match data.iter().position(|&b| b == b'\n') {
            Some(at) => {
                data.drain(..=at);
            }
            None => data.clear(),
        },
        Keep::Head => match data.iter().rposition(|&b| b == b'\n') {
            Some(at) => data.truncate(at + 1),
            None => data.clear(),
        },
    }
}

/// The text of a file that may be redacted: UTF-16 with a byte order mark converted to UTF-8, or
/// UTF-8 itself; None when the content is not text (invalid UTF-8 or a NUL byte).
fn text_for_redaction(data: &[u8]) -> Option<Vec<u8>> {
    let utf16 = |little_endian: bool, body: &[u8]| -> Vec<u8> {
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| if little_endian { u16::from_le_bytes(pair) } else { u16::from_be_bytes(pair) })
            .collect();
        String::from_utf16_lossy(&units).into_bytes()
    };
    let text = match data {
        [0xFF, 0xFE, body @ ..] if body.len() & 1 == 0 => utf16(true, body),
        [0xFE, 0xFF, body @ ..] if body.len() & 1 == 0 => utf16(false, body),
        [0xFF, 0xFE, ..] | [0xFE, 0xFF, ..] => return None,
        _ => std::str::from_utf8(data).ok()?.as_bytes().to_vec(),
    };
    (!text.contains(&0)).then_some(text)
}

/// Whether `haystack` contains `needle` (an empty needle is contained everywhere).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

/// Maps a path segment to `[A-Za-z0-9._-]`: every other byte becomes `_`, and `.` and `..`
/// become `_`, so a name from outside can be an archive entry.
pub fn sanitize_segment(segment: &str) -> String {
    if segment == "." || segment == ".." {
        return "_".to_owned();
    }
    segment
        .bytes()
        .map(
            |b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') { char::from(b) } else { '_' }
            },
        )
        .collect()
}

/// A timeout as shown in reasons: "N s" for whole seconds, else "N ms".
fn duration_label(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{} s", duration.as_secs())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

/// Why a denied source was not collected: "needs <how to obtain it>", or "permission denied" when
/// the source has no gate.
fn needs_reason(gate: Gate) -> String {
    if gate == Gate::None { "permission denied".to_owned() } else { format!("needs {}", gate.describe()) }
}

/// "size cap <cap>".
fn cap_reason(cap: Bytes) -> String {
    format!("size cap {}", cap.cap_label())
}

/// `rel_path` ending in exactly one '/', or empty when it is empty.
fn dir_prefix(rel_path: &str) -> String {
    let mut prefix = rel_path.to_owned();
    if !prefix.is_empty() && !prefix.ends_with('/') {
        prefix.push('/');
    }
    prefix
}

/// Joins arguments with single spaces, for the manifest; the line is never run.
fn join_args(args: &[String]) -> String {
    args.join(" ")
}

/// How many bytes to read of `source`: a filtered source reads more than its cap, because the cap
/// applies to what is kept.
fn read_limit_of(source: &Source) -> Bytes {
    if source.keep_lines.is_empty() { source.max_bytes } else { source.max_bytes.max(FILTER_READ_LIMIT) }
}

/// Splits a tree pattern at '/'; empty when it has a `.` or `..` segment or no segment.
fn split_pattern(pattern: &str) -> Vec<String> {
    let mut segments = Vec::new();
    for segment in pattern.split('/') {
        if segment == "." || segment == ".." {
            return Vec::new();
        }
        if !segment.is_empty() {
            segments.push(segment.to_owned());
        }
    }
    segments
}

// ---- temporary directories ----------------------------------------------------------------------

/// Directories of running commands, so that an exit that skips `Drop` can still remove them.
static OUTSTANDING_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Removes every command output directory that is still in use. Meant for the code paths that end
/// the process with `std::process::exit`, which does not run destructors.
pub fn remove_outstanding_temp_dirs() {
    let dirs = std::mem::take(&mut *OUTSTANDING_DIRS.lock().unwrap_or_else(PoisonError::into_inner));
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A [`PrivateTempDir`] that is also recorded in [`OUTSTANDING_DIRS`] while it exists.
struct Outdir {
    dir: PrivateTempDir,
}

impl Outdir {
    fn create() -> io::Result<Self> {
        let dir = PrivateTempDir::create(OUTDIR_PREFIX)?;
        OUTSTANDING_DIRS.lock().unwrap_or_else(PoisonError::into_inner).push(dir.path().to_path_buf());
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Outdir {
    fn drop(&mut self) {
        let mut dirs = OUTSTANDING_DIRS.lock().unwrap_or_else(PoisonError::into_inner);
        dirs.retain(|path| path != self.dir.path());
    }
}

// ---- guarded calls ------------------------------------------------------------------------------

/// Why a guarded call produced no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hang {
    /// An earlier call of the group had already opened it; this one did not run.
    GroupOpen,
    /// This call missed the limit and opened the group.
    TimedOut,
    /// The call panicked; nothing is stuck.
    Panicked,
}

/// Runs `f` through `guard` in `group` with `limit`.
fn run_guarded<T: Send + 'static>(
    guard: &Guard,
    group: &str,
    limit: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Hang> {
    if guard.is_open(group) {
        return Err(Hang::GroupOpen);
    }
    match guard.bounded_for(group, limit, f) {
        Some(value) => Ok(value),
        None if guard.is_open(group) => Err(Hang::TimedOut),
        None => Err(Hang::Panicked),
    }
}

/// "an earlier read in this group did not return within N s".
fn earlier_read_reason(limit: Duration) -> String {
    format!("an earlier read in this group did not return within {}", duration_label(limit))
}

/// "did not return within N s".
fn read_timeout_reason(limit: Duration) -> String {
    format!("did not return within {}", duration_label(limit))
}

/// The status and reason of a source whose guarded call failed. `partial`: some of the source was
/// already collected, so an open group truncates it instead of skipping it.
fn hang_outcome(hang: Hang, limit: Duration, partial: bool) -> (Status, String) {
    match hang {
        Hang::GroupOpen => {
            (if partial { Status::Truncated } else { Status::Skipped }, earlier_read_reason(limit))
        }
        Hang::TimedOut => (Status::TimedOut, read_timeout_reason(limit)),
        Hang::Panicked => (Status::Failed, "error: the read panicked".to_owned()),
    }
}

/// The reader handed to builtins: reads go through the guard group of the builtin's source. An
/// open or hung group yields [`ReadOutcome::Failed`] instead of blocking.
struct GuardedReader {
    guard: Arc<Guard>,
    group: String,
    limit: Duration,
}

impl Reader for GuardedReader {
    fn read(&self, path: &Path, max: Bytes, keep: Keep) -> ReadResult {
        let path = path.to_path_buf();
        match run_guarded(&self.guard, &self.group, self.limit, move || read_file_bounded(&path, max, keep)) {
            Ok(result) => result,
            Err(hang) => ReadResult {
                outcome: ReadOutcome::Failed,
                error: hang_outcome(hang, self.limit, false).1,
                ..ReadResult::default()
            },
        }
    }
}

// ---- the collector ------------------------------------------------------------------------------

/// What happened to one entry given to [`Collector::deliver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliverStatus {
    /// The sink took it.
    Written,
    /// The entry name cannot be an archive entry.
    InvalidName,
    /// An entry of that name was written before.
    Duplicate,
    /// The sink refused; collection is aborted.
    SinkFailed,
}

/// The result of [`Collector::deliver`].
#[derive(Debug, Clone, Copy)]
struct Delivered {
    status: DeliverStatus,
    truncated: bool,
    bytes: Bytes,
}

/// What the walk of a tree found.
#[derive(Debug, Default)]
struct TreeTally {
    files: u32,
    denied: u32,
    bytes: u64,
    capped: bool,
    sink_failed: bool,
    /// Set when the walk ended early.
    stop: Option<(Status, String)>,
    first_error: String,
}

/// What `collect_outdir` added to the archive.
#[derive(Debug, Default)]
struct OutdirTally {
    files: u32,
    bytes: u64,
    /// Files that could not be read, named validly or added.
    failed: u32,
    capped: bool,
}

/// What a path is, without following a symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Regular,
    Directory,
    Other,
}

/// The kind of `path` itself (a symlink is `Other`); None when it cannot be inspected.
fn probe(path: &Path) -> Option<Kind> {
    let file_type = std::fs::symlink_metadata(path).ok()?.file_type();
    Some(if file_type.is_file() {
        Kind::Regular
    } else if file_type.is_dir() {
        Kind::Directory
    } else {
        Kind::Other
    })
}

/// The names in `dir` that are valid UTF-8.
fn list_names(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        if let Ok(name) = entry?.file_name().into_string() {
            names.push(name);
        }
    }
    Ok(names)
}

/// Every regular file below `root` (symbolic links are neither followed nor listed), sorted.
fn list_regular_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else { continue };
            if file_type.is_file() {
                found.push(entry.path());
            } else if file_type.is_dir() && depth < OUTDIR_MAX_DEPTH {
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    found.sort();
    found
}

/// The collector state.
struct Collector<'s, 't> {
    options: &'s CollectOptions,
    sink: &'s mut Sink<'t>,
    sources: Arc<[Source]>,
    guard: Arc<Guard>,
    read_limit: Duration,
    artifacts: Vec<Artifact>,
    /// Entry names already given to the sink.
    written: HashSet<String>,
    /// The sink's error; collection stops.
    error: Option<Error>,
}

impl Collector<'_, '_> {
    /// `own` clipped to the time left before the `--timeout` deadline; true when the clip applied.
    fn clip_to_deadline(&self, own: Duration) -> (Duration, bool) {
        match self.options.deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left < own { (left, true) } else { (own, false) }
            }
            None => (own, false),
        }
    }

    /// Whether the `--timeout` deadline has passed.
    fn deadline_passed(&self) -> bool {
        self.options.deadline.is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Collects the source at `index` and appends its artifacts; a panic becomes a Failed artifact.
    fn collect_one(&mut self, index: usize) {
        let sources = Arc::clone(&self.sources);
        let Some(source) = sources.get(index) else { return };
        let started = Instant::now();
        let produced = if self.deadline_passed() {
            vec![deadline_artifact(source)]
        } else {
            match catch_unwind(AssertUnwindSafe(|| self.run_source(index, source))) {
                Ok(produced) => produced,
                Err(_) => vec![failed_artifact(source, "error: internal error while collecting".to_owned())],
            }
        };
        let elapsed = started.elapsed();
        for mut artifact in produced {
            artifact.elapsed = elapsed;
            self.artifacts.push(artifact);
        }
    }

    /// Collects `source` by its kind, after the checks that apply to every kind.
    fn run_source(&mut self, index: usize, source: &Source) -> Vec<Artifact> {
        let mut artifact = make_artifact(source);
        if source.identifying && self.options.rules.any() {
            return vec![artifact.with(Status::Skipped, REDACTION_REASON)];
        }
        // A missing tool is "not found", never a missing privilege (so before the availability check).
        if matches!(source.spec, Spec::XpuSmi { .. }) && self.options.xpu_smi.is_none() {
            return vec![artifact.with(Status::Skipped, XPU_SMI_NOT_FOUND_REASON)];
        }
        if let Some(available) = source.available {
            match run_guarded(&self.guard, &source.group, self.read_limit, available) {
                Ok(true) => {}
                Ok(false) => {
                    deny(&mut artifact, source, Status::Skipped);
                    if source.gate == Gate::None {
                        artifact.reason = "not available".to_owned();
                    }
                    return vec![artifact];
                }
                Err(hang) => {
                    (artifact.status, artifact.reason) = hang_outcome(hang, self.read_limit, false);
                    return vec![artifact];
                }
            }
        }
        match &source.spec {
            Spec::File { path } => self.handle_file(source, path),
            Spec::Tree { root, patterns } => self.handle_tree(source, root, patterns),
            Spec::Command { argv } => {
                vec![self.run_command(source, argv.clone(), join_args(argv), argv_name(argv))]
            }
            Spec::XpuSmi { args } => {
                let Some(xpu_smi) = self.options.xpu_smi.as_deref() else {
                    return vec![failed_artifact(source, XPU_SMI_NOT_FOUND_REASON.to_owned())];
                };
                let mut argv = vec![xpu_smi.to_string_lossy().into_owned()];
                argv.extend(args.iter().cloned());
                vec![self.run_command(
                    source,
                    argv,
                    format!("xpu-smi {}", join_args(args)),
                    "xpu-smi".to_owned(),
                )]
            }
            Spec::Builtin(_) => self.handle_builtin(index, source),
        }
    }

    // ---- delivery ----

    /// Redacts text; `.json` entries are parsed and redacted by key, falling back to plain text.
    fn redact_data(&self, rel_path: &str, data: &[u8]) -> Vec<u8> {
        let options = self.options;
        if rel_path.ends_with(".json") {
            redact::redact_json_bytes(data, &options.rules, &options.identity)
        } else {
            redact::redact_text(data, &options.rules, &options.identity)
        }
    }

    /// Filters, caps and redacts `data`, then writes it to the sink. The order is keep_lines, size
    /// cap, redaction, sink. A name that is not valid in the archive is refused before anything else.
    fn deliver(
        &mut self,
        source: &Source,
        content: Content,
        rel_path: &str,
        mut data: Vec<u8>,
        already_truncated: bool,
        reader_cut: Option<Keep>,
    ) -> Delivered {
        if !valid_entry_name(rel_path) {
            return Delivered { status: DeliverStatus::InvalidName, truncated: false, bytes: Bytes(0) };
        }
        let text = content == Content::Text;
        if text && !source.keep_lines.is_empty() {
            data = filter_lines(&data, &source.keep_lines);
        }
        // A cut through a line can split a host or user name, which the whole-token rules would
        // then miss: text loses the partial line at every cut edge before it is redacted. The
        // reader or the child may already have cut (`reader_cut`: the end for a head read or a
        // child's output, the start for a tail read); a builtin's Truncated status is not a cut.
        if text && let Some(keep) = reader_cut {
            drop_partial_line(&mut data, keep);
        }
        let mut truncated = already_truncated;
        let cap = usize::try_from(source.max_bytes.get()).unwrap_or(usize::MAX);
        if data.len() > cap {
            match source.keep {
                Keep::Tail => {
                    data.drain(..data.len() - cap);
                }
                Keep::Head => data.truncate(cap),
            }
            truncated = true;
            if text {
                drop_partial_line(&mut data, source.keep);
            }
        }
        if text && self.options.rules.any() {
            data = self.redact_data(rel_path, &data);
        }
        self.write(rel_path, &data, truncated)
    }

    /// Gives one entry to the sink, once per name.
    fn write(&mut self, rel_path: &str, data: &[u8], truncated: bool) -> Delivered {
        if self.written.contains(rel_path) {
            return Delivered { status: DeliverStatus::Duplicate, truncated, bytes: Bytes(0) };
        }
        if let Err(error) = (self.sink)(rel_path, data) {
            self.error = Some(error);
            return Delivered { status: DeliverStatus::SinkFailed, truncated, bytes: Bytes(0) };
        }
        self.written.insert(rel_path.to_owned());
        Delivered { status: DeliverStatus::Written, truncated, bytes: Bytes(data.len() as u64) }
    }

    // ---- File ----

    /// Collects a single file.
    fn handle_file(&mut self, source: &Source, path: &Path) -> Vec<Artifact> {
        let mut artifact = make_artifact(source);
        match self.guarded_read(&source.group, path, read_limit_of(source), source.keep) {
            Err(hang) => (artifact.status, artifact.reason) = hang_outcome(hang, self.read_limit, false),
            Ok(read) => self.apply_read(&mut artifact, source, read),
        }
        vec![artifact]
    }

    /// A bounded read through the guard group of `group`.
    fn guarded_read(&self, group: &str, path: &Path, max: Bytes, keep: Keep) -> Result<ReadResult, Hang> {
        let path = path.to_path_buf();
        run_guarded(&self.guard, group, self.read_limit, move || read_file_bounded(&path, max, keep))
    }

    /// Turns the outcome of a file read into the artifact's status.
    fn apply_read(&mut self, artifact: &mut Artifact, source: &Source, read: ReadResult) {
        match read.outcome {
            ReadOutcome::Denied => deny(artifact, source, Status::Skipped),
            ReadOutcome::Missing => {
                artifact.status = Status::Skipped;
                artifact.reason = "not present".to_owned();
            }
            ReadOutcome::Failed => {
                artifact.status = Status::Failed;
                artifact.reason = read.error;
            }
            ReadOutcome::Read => {
                let delivered = self.deliver(
                    source,
                    source.content,
                    &source.rel_path,
                    read.data,
                    read.truncated,
                    read.truncated.then_some(source.keep),
                );
                mark_delivered(artifact, source, &delivered);
            }
        }
    }

    // ---- Tree ----

    /// Collects the files of a tree that match its patterns.
    fn handle_tree(&mut self, source: &Source, root: &Path, patterns: &[String]) -> Vec<Artifact> {
        let mut artifact = make_artifact(source);
        artifact.rel_path = dir_prefix(&source.rel_path);
        artifact.files = 0;

        let canonical = {
            let root = root.to_path_buf();
            run_guarded(&self.guard, &source.group, self.read_limit, move || std::fs::canonicalize(root))
        };
        let root = match canonical {
            Ok(Ok(root)) => root,
            Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                deny(&mut artifact, source, Status::Skipped);
                return vec![artifact];
            }
            Ok(Err(_)) => {
                return vec![artifact.with(Status::Skipped, "not present")];
            }
            Err(hang) => {
                (artifact.status, artifact.reason) = hang_outcome(hang, self.read_limit, false);
                return vec![artifact];
            }
        };
        let split: Vec<Vec<String>> = patterns
            .iter()
            .map(|pattern| split_pattern(pattern))
            .filter(|segments| !segments.is_empty())
            .collect();
        let tails: Vec<&[String]> = split.iter().map(Vec::as_slice).collect();

        let mut tally = TreeTally::default();
        self.walk_tree(source, &artifact.rel_path, &root, "", &tails, &mut tally);
        self.finish_tree(&mut artifact, source, &tally);
        vec![artifact]
    }

    /// Sets the status of a tree artifact from what the walk found.
    fn finish_tree(&self, artifact: &mut Artifact, source: &Source, tally: &TreeTally) {
        artifact.files = tally.files;
        artifact.denied = tally.denied;
        artifact.bytes = Bytes(tally.bytes);
        if tally.sink_failed {
            artifact.status = Status::Failed;
            artifact.reason = ARCHIVE_WRITE_REASON.to_owned();
        } else if let Some((status, reason)) = &tally.stop {
            artifact.status = *status;
            artifact.reason = reason.clone();
        } else if tally.denied > 0 {
            deny(artifact, source, if tally.files > 0 { Status::Truncated } else { Status::Skipped });
            if tally.files > 0 {
                artifact.reason = format!(
                    "{} of {} files denied; {}",
                    tally.denied,
                    tally.denied + tally.files,
                    needs_reason(source.gate)
                );
            }
        } else if tally.files == 0 {
            if tally.first_error.is_empty() {
                artifact.status = Status::Skipped;
                artifact.reason = "no matching files".to_owned();
            } else {
                artifact.status = Status::Failed;
                artifact.reason = tally.first_error.clone();
            }
        } else if tally.capped {
            artifact.status = Status::Truncated;
            artifact.reason = cap_reason(source.max_bytes);
        }
    }

    /// Visits the entries below `dir` that a pattern can match and reads the files. Lists a
    /// directory only when a pattern segment has a '*', and never descends into or reads a symlink.
    ///
    /// `rel` is `dir` relative to the root, ending in '/', or empty; `tails` are the remaining
    /// segments of the patterns that reach `dir`.
    fn walk_tree(
        &mut self,
        source: &Source,
        prefix: &str,
        dir: &Path,
        rel: &str,
        tails: &[&[String]],
        tally: &mut TreeTally,
    ) {
        let mut next: BTreeMap<String, Vec<&[String]>> = BTreeMap::new();
        let mut listing = false;
        for &tail in tails {
            let Some(first) = tail.first() else { continue };
            if first.contains('*') {
                listing = true;
            } else {
                next.entry(first.clone()).or_default().push(tail);
            }
        }
        if listing {
            let listed = {
                let dir = dir.to_path_buf();
                run_guarded(&self.guard, &source.group, self.read_limit, move || list_names(&dir))
            };
            match listed {
                // A directory that cannot be listed contributes nothing.
                Ok(Err(_)) => {}
                Ok(Ok(names)) => {
                    for name in names {
                        for &tail in tails {
                            if tail
                                .first()
                                .is_some_and(|first| first.contains('*') && match_segment(first, &name))
                            {
                                next.entry(name.clone()).or_default().push(tail);
                            }
                        }
                    }
                }
                Err(hang) => {
                    tally.stop = Some(hang_outcome(hang, self.read_limit, tally.files > 0));
                    return;
                }
            }
        }

        for (name, matched) in next {
            if self.error.is_some() || tally.stop.is_some() {
                return;
            }
            if self.deadline_passed() {
                let status = if tally.files > 0 { Status::Truncated } else { Status::Skipped };
                tally.stop = Some((status, DEADLINE_REASON.to_owned()));
                return;
            }
            if name.is_empty() || !valid_entry_name(&name) {
                continue;
            }
            let child = dir.join(&name);
            let kind = {
                let child = child.clone();
                run_guarded(&self.guard, &source.group, self.read_limit, move || probe(&child))
            };
            let kind = match kind {
                Ok(Some(kind)) => kind,
                Ok(None) => continue,
                Err(hang) => {
                    tally.stop = Some(hang_outcome(hang, self.read_limit, tally.files > 0));
                    return;
                }
            };
            match kind {
                Kind::Regular => {
                    if matched.iter().any(|tail| tail.len() == 1) {
                        self.read_tree_file(source, &format!("{prefix}{rel}{name}"), &child, tally);
                    }
                }
                Kind::Directory => {
                    let deeper: Vec<&[String]> =
                        matched.iter().filter(|tail| tail.len() > 1).map(|tail| &tail[1..]).collect();
                    if !deeper.is_empty() {
                        self.walk_tree(source, prefix, &child, &format!("{rel}{name}/"), &deeper, tally);
                    }
                }
                Kind::Other => {}
            }
        }
    }

    /// Reads one file of a tree and delivers it; a hang ends the walk.
    fn read_tree_file(&mut self, source: &Source, entry_name: &str, path: &Path, tally: &mut TreeTally) {
        let read = match self.guarded_read(&source.group, path, read_limit_of(source), source.keep) {
            Ok(read) => read,
            Err(hang) => {
                tally.stop = Some(hang_outcome(hang, self.read_limit, tally.files > 0));
                return;
            }
        };
        match read.outcome {
            ReadOutcome::Denied => tally.denied += 1,
            ReadOutcome::Missing => {}
            ReadOutcome::Failed => {
                if tally.first_error.is_empty() {
                    tally.first_error = read.error;
                }
            }
            ReadOutcome::Read => {
                let cut = read.truncated.then_some(source.keep);
                let delivered =
                    self.deliver(source, source.content, entry_name, read.data, read.truncated, cut);
                match delivered.status {
                    DeliverStatus::SinkFailed => tally.sink_failed = true,
                    DeliverStatus::Written => {
                        tally.files += 1;
                        tally.bytes += delivered.bytes.get();
                        tally.capped |= delivered.truncated;
                    }
                    DeliverStatus::InvalidName | DeliverStatus::Duplicate => {}
                }
            }
        }
    }

    // ---- Command and XpuSmi ----

    /// Runs a program with a timeout and collects its output and any "{outdir}" files.
    ///
    /// `via` is the command line as shown in the manifest and `name` how the program is called in
    /// reasons. The result is one artifact, a directory (rel_path ends in '/') when "{outdir}" is
    /// used. Skipped when the program is not installed or its output holds the unsupported marker
    /// (nothing is written), TimedOut at the deadline, Failed without output and a non-zero exit.
    fn run_command(&mut self, source: &Source, mut argv: Vec<String>, via: String, name: String) -> Artifact {
        let mut artifact = make_artifact(source);
        if argv.first().is_none_or(String::is_empty) {
            return failed_artifact(source, "empty command".to_owned());
        }
        let uses_outdir = argv.iter().any(|arg| arg.contains(OUTDIR_TOKEN));
        let mut outdir: Option<Outdir> = None;
        if uses_outdir {
            artifact.rel_path = dir_prefix(&source.rel_path);
            artifact.files = 0;
            let created = Outdir::create();
            let Ok(dir) = created else {
                return artifact.with(Status::Failed, "cannot create a temporary directory");
            };
            let Some(dir_text) = dir.path().to_str().map(str::to_owned) else {
                return artifact.with(Status::Failed, "cannot create a temporary directory");
            };
            for arg in &mut argv {
                *arg = arg.replace(OUTDIR_TOKEN, &dir_text);
            }
            outdir = Some(dir);
        }
        artifact.via = via;

        let limit = if source.keep == Keep::Tail { CHILD_TAIL_LIMIT } else { read_limit_of(source) };
        let (timeout, clipped) = self.clip_to_deadline(source.timeout);
        let overran = |own: Duration| {
            if clipped {
                DEADLINE_REASON.to_owned()
            } else {
                format!("did not finish within {}", duration_label(own))
            }
        };
        let child = {
            let argv = argv.clone();
            run_guarded(&self.guard, &source.group, timeout.saturating_add(CHILD_GRACE), move || {
                run_child(&argv, timeout, limit)
            })
        };
        let mut child = match child {
            Ok(child) => child,
            Err(Hang::TimedOut) => {
                return artifact.with(Status::TimedOut, overran(source.timeout));
            }
            Err(hang) => {
                (artifact.status, artifact.reason) = hang_outcome(hang, self.read_limit, false);
                return artifact;
            }
        };

        let code = match &child.outcome {
            ChildOutcome::NotFound => {
                return artifact.with(Status::Skipped, format!("{name} not installed"));
            }
            ChildOutcome::SpawnFailed(error) => {
                return artifact.with(Status::Failed, format!("could not start {name}: {error}"));
            }
            ChildOutcome::TimedOut => {
                artifact.status = Status::TimedOut;
                artifact.reason = overran(source.timeout);
                // A tool that ran into its limit is most likely stuck on a state its group-mates
                // share (a wedged device): they are skipped instead of each running to its limit.
                // The shared host group is not opened: its sources do not depend on one another.
                if !clipped && source.group != HOST_GROUP {
                    self.guard.open(&source.group);
                }
                return artifact;
            }
            ChildOutcome::Exited(code) => *code,
        };
        artifact.exit = Some(code);
        // A child killed by a signal produced no result, whatever it printed before it died.
        let crash = crash_reason(code);
        if let Some(marker) = &source.unsupported_marker
            && contains_subslice(&child.output, marker.as_bytes())
        {
            return artifact.with(Status::Skipped, UNSUPPORTED_REASON);
        }
        let marker_seen = source
            .denied_marker
            .as_ref()
            .is_some_and(|marker| contains_subslice(&child.output, marker.as_bytes()));
        let has_output = !child.output.is_empty();
        let mut capped = child.truncated;
        let mut unreadable = 0;
        if let Some(outdir) = &outdir {
            if has_output {
                let entry = format!("{}{OUTDIR_STDOUT}", artifact.rel_path);
                let delivered = self.deliver(
                    source,
                    Content::Text,
                    &entry,
                    std::mem::take(&mut child.output),
                    child.truncated,
                    child.truncated.then_some(Keep::Head),
                );
                if delivered.status == DeliverStatus::Written {
                    artifact.files += 1;
                    artifact.bytes = Bytes(artifact.bytes.get() + delivered.bytes.get());
                    capped = delivered.truncated;
                }
            }
            let tally = self.collect_outdir(source, outdir.path(), &artifact.rel_path);
            artifact.files += tally.files;
            artifact.bytes = Bytes(artifact.bytes.get() + tally.bytes);
            capped |= tally.capped;
            unreadable = tally.failed;
        } else if code != 0 && !has_output {
            return artifact.with(Status::Failed, crash.unwrap_or_else(|| format!("exit code {code}")));
        } else {
            let output = std::mem::take(&mut child.output);
            let cut = capped.then_some(Keep::Head);
            let delivered = self.deliver(source, source.content, &source.rel_path, output, capped, cut);
            mark_delivered(&mut artifact, source, &delivered);
            capped = false;
        }

        if self.error.is_some() {
            artifact.status = Status::Failed;
            artifact.reason = ARCHIVE_WRITE_REASON.to_owned();
        } else if uses_outdir && artifact.files == 0 {
            if code == 0 {
                artifact.status = Status::Skipped;
                artifact.reason = "produced no output".to_owned();
            } else {
                artifact.status = Status::Failed;
                artifact.reason = crash.unwrap_or_else(|| format!("exit code {code}"));
            }
        } else if marker_seen && artifact.status != Status::Failed {
            deny(&mut artifact, source, Status::Truncated);
        } else if let Some(reason) = crash {
            artifact.status = Status::Failed;
            artifact.reason = reason;
        } else if unreadable > 0 && artifact.status == Status::Collected {
            artifact.status = Status::Truncated;
            artifact.reason = format!("{unreadable} files could not be read");
        } else if capped && artifact.status == Status::Collected {
            artifact.status = Status::Truncated;
            artifact.reason = cap_reason(source.max_bytes);
        }
        artifact
    }

    /// Adds every regular file below `root` to the archive under `prefix` (ending in '/').
    ///
    /// File names are mapped to `[A-Za-z0-9._-]`; names that map alike get "-2", "-3" suffixes, and
    /// "stdout.txt" is reserved for the command's output.
    ///
    /// While redaction is on and the source is text, a file that is text (UTF-16 with a byte order
    /// mark is converted to UTF-8; then valid UTF-8 without a NUL byte) is redacted like any other
    /// text, `.json` files by key. Any other file (binary, e.g. a CPER record) is added verbatim.
    fn collect_outdir(&mut self, source: &Source, root: &Path, prefix: &str) -> OutdirTally {
        let mut tally = OutdirTally::default();
        let found = {
            let root = root.to_path_buf();
            run_guarded(&self.guard, &source.group, self.read_limit, move || list_regular_files(&root))
        };
        let Ok(found) = found else {
            tally.failed += 1;
            return tally;
        };
        let mut used: HashSet<String> = HashSet::from([OUTDIR_STDOUT.to_owned()]);
        for path in found {
            if self.error.is_some() {
                break;
            }
            let Ok(relative) = path.strip_prefix(root) else { continue };
            let segments: Vec<String> = relative
                .components()
                .map(|component| sanitize_segment(&component.as_os_str().to_string_lossy()))
                .filter(|segment| !segment.is_empty())
                .collect();
            if segments.is_empty() {
                continue;
            }
            let stem = segments.join("/");
            let mut name = stem.clone();
            let mut n = 2;
            while used.contains(&name) {
                name = format!("{stem}-{n}");
                n += 1;
            }
            used.insert(name.clone());
            let entry = format!("{prefix}{name}");
            let read = self.guarded_read(&source.group, &path, OUTDIR_FILE_CAP, Keep::Head);
            let read = match read {
                Ok(read) if read.outcome == ReadOutcome::Read && valid_entry_name(&entry) => read,
                _ => {
                    tally.failed += 1;
                    continue;
                }
            };
            let data = if source.content == Content::Text && self.options.rules.any() {
                match text_for_redaction(&read.data) {
                    Some(text) => self.redact_data(&entry, &text),
                    None => read.data,
                }
            } else {
                read.data
            };
            let delivered = self.write(&entry, &data, read.truncated);
            match delivered.status {
                DeliverStatus::Written => {
                    tally.files += 1;
                    tally.bytes += delivered.bytes.get();
                    tally.capped |= read.truncated;
                }
                DeliverStatus::SinkFailed => {}
                DeliverStatus::InvalidName | DeliverStatus::Duplicate => tally.failed += 1,
            }
        }
        tally
    }

    // ---- Builtin ----

    /// Runs a builtin producer on a helper thread with the source's timeout.
    ///
    /// The producer may be abandoned, so it owns a share of the sources and reads files only
    /// through the reader, which uses the guard group of the source.
    fn handle_builtin(&mut self, index: usize, source: &Source) -> Vec<Artifact> {
        let reader = GuardedReader {
            guard: Arc::clone(&self.guard),
            group: source.group.clone(),
            limit: self.read_limit,
        };
        let sources = Arc::clone(&self.sources);
        // A guard of its own: a hung producer must not stop the other builtins of its group.
        let (limit, clipped) = self.clip_to_deadline(source.timeout);
        let own_guard = Guard::new(limit);
        let outputs = run_guarded(&own_guard, "builtin", limit, move || match sources.get(index) {
            Some(Source { spec: Spec::Builtin(produce), .. }) => produce(&reader),
            _ => Vec::new(),
        });
        let outputs = match outputs {
            Ok(outputs) => outputs,
            Err(Hang::Panicked) => {
                return vec![failed_artifact(source, "error: the producer panicked".to_owned())];
            }
            Err(_) => {
                return vec![make_artifact(source).with(
                    Status::TimedOut,
                    if clipped {
                        DEADLINE_REASON.to_owned()
                    } else {
                        format!("did not finish within {}", duration_label(source.timeout))
                    },
                )];
            }
        };
        let mut result = Vec::new();
        for item in outputs {
            result.push(self.deliver_produced(source, item));
            if self.error.is_some() {
                break;
            }
        }
        result
    }

    /// Delivers one output of a builtin and describes it. The gate is set for a Skipped or
    /// Truncated output whose reason starts with "needs ".
    fn deliver_produced(&mut self, source: &Source, item: Produced) -> Artifact {
        let mut artifact = Artifact {
            rel_path: item.rel_path.clone(),
            status: item.status,
            reason: item.reason.clone(),
            via: item.via.clone(),
            files: 1,
            ..Artifact::default()
        };
        let writes =
            item.status == Status::Collected || (item.status == Status::Truncated && !item.data.is_empty());
        if writes {
            let truncated = item.status == Status::Truncated;
            // A partial builtin output may end in a fragment its own capped read or child left;
            // a trailing line without a newline is dropped like any other cut edge.
            let cut = (truncated && !item.data.ends_with(b"\n")).then_some(Keep::Head);
            let delivered = self.deliver(source, source.content, &item.rel_path, item.data, truncated, cut);
            mark_delivered(&mut artifact, source, &delivered);
        }
        let partial = matches!(item.status, Status::Skipped | Status::Truncated);
        if partial && item.reason.starts_with("needs ") {
            artifact.gate = source.gate;
        }
        artifact
    }
}

// ---- artifacts ----------------------------------------------------------------------------------

/// An artifact for `source` with the defaults of a single file: Collected until something says otherwise.
fn make_artifact(source: &Source) -> Artifact {
    Artifact { rel_path: source.rel_path.clone(), files: 1, ..Artifact::default() }
}

impl Artifact {
    /// `self` with its outcome set; for a source that ends early.
    fn with(mut self, status: Status, reason: impl Into<String>) -> Self {
        self.status = status;
        self.reason = reason.into();
        self
    }
}

/// A Failed artifact for `source`.
fn failed_artifact(source: &Source, reason: String) -> Artifact {
    Artifact { status: Status::Failed, reason, ..make_artifact(source) }
}

/// The artifact of a source that was not started because the deadline had passed.
fn deadline_artifact(source: &Source) -> Artifact {
    let mut artifact =
        Artifact { status: Status::Skipped, reason: DEADLINE_REASON.to_owned(), ..make_artifact(source) };
    if source.rel_path.ends_with('/') {
        artifact.files = 0;
    }
    artifact
}

/// Marks `artifact` as denied: `status` with the gate and reason of `source`.
fn deny(artifact: &mut Artifact, source: &Source, status: Status) {
    artifact.status = status;
    artifact.gate = source.gate;
    artifact.reason = needs_reason(source.gate);
}

/// Records the outcome of a delivery in `artifact`.
fn mark_delivered(artifact: &mut Artifact, source: &Source, delivered: &Delivered) {
    match delivered.status {
        DeliverStatus::Written => {
            artifact.bytes = delivered.bytes;
            if delivered.truncated {
                if artifact.status == Status::Collected {
                    artifact.status = Status::Truncated;
                }
                if artifact.reason.is_empty() {
                    artifact.reason = cap_reason(source.max_bytes);
                }
            }
        }
        DeliverStatus::InvalidName => {
            artifact.status = Status::Failed;
            artifact.reason = "invalid path in the bundle".to_owned();
        }
        DeliverStatus::Duplicate => {
            artifact.status = Status::Failed;
            artifact.reason = "duplicate path in the bundle".to_owned();
        }
        DeliverStatus::SinkFailed => {
            artifact.status = Status::Failed;
            artifact.reason = ARCHIVE_WRITE_REASON.to_owned();
        }
    }
}

/// The name of a signal number on Linux: `SIGSEGV` for 11; `signal 40` for one without a common name.
fn signal_label(signal: i32) -> String {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        31 => "SIGSYS",
        _ => return format!("signal {signal}"),
    };
    name.to_owned()
}

/// Why a child that exited with `code` counts as crashed: "killed by signal 11 (SIGSEGV)". The
/// process layer reports a death by signal as 128 + the signal number. None for an ordinary exit
/// and on Windows, where such codes mean something else.
pub fn crash_reason(code: i32) -> Option<String> {
    if !cfg!(unix) || !(129..=192).contains(&code) {
        return None;
    }
    let signal = code - 128;
    let label = signal_label(signal);
    Some(if label.starts_with("signal ") {
        format!("killed by {label}")
    } else {
        format!("killed by signal {signal} ({label})")
    })
}

/// How a command's program is named in reasons.
fn argv_name(argv: &[String]) -> String {
    argv.first().cloned().unwrap_or_default()
}

#[cfg(all(test, unix))]
#[path = "collect_tests.rs"]
mod tests;
