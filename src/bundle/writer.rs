// SPDX-License-Identifier: MIT
//! Drives the collector into the zip writer and writes `manifest.json` last.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use crate::archive::zip::Compression;
use crate::bundle::source::{Gate, SourceOptions, Status};
use crate::error::Error;
use crate::redact;
use crate::units::Bytes;

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
    let _ = now;
    String::new()
}

/// Collects every selected source into a zip at `request.output`.
pub fn write_bundle(request: &BundleRequest) -> Result<BundleResult, Error> {
    let _ = request;
    Ok(BundleResult::default())
}
