// SPDX-License-Identifier: MIT
//! Drives the collector into the zip writer and writes `manifest.json` last.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::archive::zip::{Compression, ZipWriter};
use crate::bundle::collect::{CollectOptions, collect, remove_outstanding_temp_dirs};
use crate::bundle::identity::{IDENTITY_LIMIT, resolve_identity};
use crate::bundle::manifest::{MANIFEST_INDENT, ManifestInput, XpuSmiInfo, json_text, manifest_json};
use crate::bundle::source::{Gate, Source, SourceOptions, Status};
use crate::error::Error;
use crate::guard::Guard;
use crate::redact;
use crate::sources;
use crate::timefmt;
use crate::units::Bytes;

/// The manifest entry; always the last one.
pub const MANIFEST_NAME: &str = "manifest.json";

/// How long after the deadline the backstop thread ends the process.
pub const BACKSTOP_GRACE: Duration = Duration::from_secs(60);

/// The process exit code of the backstop.
pub const BACKSTOP_EXIT_CODE: i32 = 124;

/// Time allowed for `xpu-smi -v` (its own limit is 10 s; starting it can block before that).
const XPU_SMI_VERSION_LIMIT: Duration = Duration::from_secs(13);
/// Time allowed for describing the OS.
const OS_DESCRIPTION_LIMIT: Duration = Duration::from_secs(5);
/// The text shown when `xpu-smi -v` gives no version line.
const UNKNOWN_VERSION: &str = "unknown";

/// What the user asked for.
#[derive(Debug, Clone)]
pub struct BundleRequest {
    /// The archive path.
    pub output: PathBuf,
    /// Profile, devices, samples, window, xpu-smi.
    pub options: SourceOptions,
    /// Which identifiers to redact.
    pub rules: redact::Rules,
    /// Collection deadline (`--timeout`); None disables it.
    pub deadline: Option<Instant>,
}

/// What happened to one source (or one builtin output).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifact {
    /// Entry name, or a directory ending in '/' for tree and {outdir} sources.
    pub rel_path: String,
    pub status: Status,
    /// Set when a denial made it Skipped or Truncated.
    pub gate: Gate,
    /// Why it is not Collected; our own text or OS error text.
    pub reason: String,
    /// The command or file that produced it.
    pub via: String,
    /// Exit code of the command, if one ran.
    pub exit: Option<i32>,
    /// Written to the archive, after the cap and redaction.
    pub bytes: Bytes,
    /// Tree and {outdir} sources: files written (1 otherwise).
    pub files: u32,
    /// Tree sources: files denied.
    pub denied: u32,
    /// Wall time of the whole source.
    pub elapsed: Duration,
}

/// The outcome of [`write_bundle`].
#[derive(Debug, Clone, Default)]
pub struct BundleResult {
    /// One per source, in order.
    pub artifacts: Vec<Artifact>,
    /// Size of the finished archive.
    pub archive_bytes: Bytes,
    /// How entries were stored.
    pub compression: Compression,
}

/// The default archive name: "xe-bug-report-YYYYMMDDTHHMMSSZ.zip" in UTC.
pub fn default_bundle_name(now: SystemTime) -> String {
    format!("xe-bug-report-{}.zip", timefmt::utc_compact(now))
}

/// The in-progress file of an archive: `<output>.partial`.
pub fn partial_path(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}

/// Collects every selected source into a zip at `request.output`.
///
/// The sources are the table of this OS for `request.options` ([`sources::sources`]). The archive
/// is only moved into place when it is complete; any error, a panic or the backstop leaves nothing
/// behind. A signal does: there is no signal handler, so SIGTERM, SIGINT or SIGHUP end the process
/// at once and leave `<output>.partial` (and a command output directory in `$TMPDIR`) behind.
pub fn write_bundle(request: &BundleRequest) -> Result<BundleResult, Error> {
    write_bundle_with(request, sources::sources(&request.options).into())
}

/// [`write_bundle`] for an explicit source list (the tests use fake sources).
///
/// `request.options.xpu_smi` is the xpu-smi executable to run (None: its sources are skipped) and
/// is recorded in the manifest with its version.
pub fn write_bundle_with(request: &BundleRequest, table: Arc<[Source]>) -> Result<BundleResult, Error> {
    let mut zip = ZipWriter::create(&request.output)?;
    let started = SystemTime::now();
    let created = timefmt::utc_iso8601(started);

    // Without rules nothing is replaced, so the name lookup would be wasted time.
    let (identity, identity_partial) = if request.rules.any() {
        let resolved = resolve_identity(IDENTITY_LIMIT);
        (resolved.context, resolved.partial)
    } else {
        (redact::Context::default(), false)
    };

    let options = CollectOptions {
        rules: request.rules,
        identity: identity.clone(),
        xpu_smi: request.options.xpu_smi.clone(),
        deadline: request.deadline,
    };
    let artifacts = {
        let mut sink = |name: &str, data: &[u8]| zip.add(name, data, started);
        collect(table, &options, &mut sink)?
    };

    let xpu_smi = request.options.xpu_smi.as_deref().map(|path| xpu_smi_info(path, request, &identity));
    let os = Guard::new(OS_DESCRIPTION_LIMIT).bounded("os", sources::os_description).unwrap_or_default();
    let compression = if ZipWriter::deflate_available() { Compression::Deflate } else { Compression::Stored };
    let document = manifest_json(&ManifestInput {
        artifacts: &artifacts,
        request,
        created: &created,
        compression,
        identity: &identity,
        identity_partial,
        xpu_smi: xpu_smi.as_ref(),
        os: &os,
    });
    let mut manifest = json_text(&document, MANIFEST_INDENT);
    manifest.push('\n');
    zip.add(MANIFEST_NAME, manifest.as_bytes(), started)?;
    let archive_bytes = zip.finish()?;
    Ok(BundleResult { artifacts, archive_bytes, compression })
}

/// The xpu-smi path and version line for the manifest. The version goes through the redaction
/// rules as well, in case a build embeds a host name.
fn xpu_smi_info(path: &Path, request: &BundleRequest, identity: &redact::Context) -> XpuSmiInfo {
    let owned = path.to_path_buf();
    let version = Guard::new(XPU_SMI_VERSION_LIMIT)
        .bounded("xpu-smi-version", move || sources::xpu_smi_version(&owned))
        .flatten()
        .map_or_else(
            || UNKNOWN_VERSION.to_owned(),
            |line| redact::redact_str(&line, &request.rules, identity),
        );
    XpuSmiInfo { path: path.to_path_buf(), version }
}

/// Starts a detached thread that calls `on_fire` once `grace` after `deadline` has passed, for the
/// case that the collection thread is stuck in code outside every guard. The caller's `on_fire`
/// ends the process (exit code [`BACKSTOP_EXIT_CODE`]); it is never called when the process ends
/// first. Returns `Ok(None)` when `deadline + grace` overflows (nothing to watch) and an error
/// only when the thread cannot be started.
pub fn spawn_backstop(
    deadline: Instant,
    grace: Duration,
    on_fire: impl FnOnce() + Send + 'static,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let Some(fire_at) = deadline.checked_add(grace) else { return Ok(None) };
    let handle = std::thread::Builder::new().name("xe-backstop".to_owned()).spawn(move || {
        loop {
            let now = Instant::now();
            if now >= fire_at {
                break;
            }
            std::thread::sleep(fire_at - now);
        }
        on_fire();
    })?;
    Ok(Some(handle))
}

/// Removes `<output>.partial`, the archive in progress.
pub fn remove_partial(output: &Path) {
    let _ = std::fs::remove_file(partial_path(output));
}

/// Removes what a process that is about to `exit` would leave behind because `exit` skips
/// destructors: the command output directories in use (all of them, process-wide) and
/// `<output>.partial`.
pub fn remove_leftovers(output: &Path) {
    remove_outstanding_temp_dirs();
    remove_partial(output);
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "writer_tests.rs"]
mod tests;
