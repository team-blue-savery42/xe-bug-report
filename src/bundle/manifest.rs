// SPDX-License-Identifier: MIT
//! The `manifest.json` model (schema 1).

use std::path::PathBuf;

use serde_json::Value;

use crate::archive::zip::Compression;
use crate::bundle::writer::{Artifact, BundleRequest};
use crate::redact;

/// The manifest schema version.
pub const MANIFEST_SCHEMA: u32 = 1;

/// The xpu-smi executable that was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XpuSmiInfo {
    pub path: PathBuf,
    /// The first line of `xpu-smi -v`.
    pub version: String,
}

/// Everything the manifest is built from.
#[derive(Debug, Clone, Copy)]
pub struct ManifestInput<'a> {
    pub artifacts: &'a [Artifact],
    /// The request: profile, devices, window, rules.
    pub request: &'a BundleRequest,
    /// ISO-8601 UTC time collection started.
    pub created: &'a str,
    /// How the entries were stored.
    pub compression: Compression,
    /// The names to redact `via`, `tool.path`, `os` and `xpu_smi.path` with.
    pub identity: &'a redact::Context,
    /// The identity lookup fell back to the lookup-free variant.
    pub identity_partial: bool,
    /// The xpu-smi used, if found.
    pub xpu_smi: Option<&'a XpuSmiInfo>,
    /// The OS description; omitted when empty.
    pub os: &'a str,
}

/// The manifest document, keys in the order of `tests/golden/manifest-keys.txt`.
pub fn manifest_json(input: &ManifestInput<'_>) -> Value {
    let _ = input;
    Value::Null
}

/// Serialises `doc`; `indent` spaces per level, 0 for compact. Never fails (strings are already UTF-8).
pub fn json_text(doc: &Value, indent: usize) -> String {
    let _ = (doc, indent);
    String::new()
}
