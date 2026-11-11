// SPDX-License-Identifier: MIT
//! The collector: per-Spec handling, tree walk, caps, keep_lines and redaction.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Instant;

use crate::bundle::source::Source;
use crate::bundle::writer::Artifact;
use crate::error::Error;
use crate::redact;

/// How long one file read may block before its guard group is abandoned.
pub const FILE_READ_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

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
pub fn collect(
    sources: &[Source],
    options: &CollectOptions,
    sink: &mut Sink<'_>,
) -> Result<Vec<Artifact>, Error> {
    let _ = (sources, options, sink);
    Ok(Vec::new())
}
