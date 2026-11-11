// SPDX-License-Identifier: MIT
//! The `manifest.json` model (schema 1).

use std::path::PathBuf;

use serde::Serialize;
use serde_json::ser::PrettyFormatter;
use serde_json::{Map, Value};

use crate::archive::zip::Compression;
use crate::build_info;
use crate::bundle::summary::display_path;
use crate::bundle::writer::{Artifact, BundleRequest};
use crate::redact;

/// The manifest schema version.
pub const MANIFEST_SCHEMA: u32 = 1;

/// Spaces per level in `manifest.json`; the writer adds the final newline.
pub const MANIFEST_INDENT: usize = 2;

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
///
/// `via`, `tool.path`, `os` and `xpu_smi.path` pass through redaction; reasons are our own text or
/// OS error text and are not redacted.
pub fn manifest_json(input: &ManifestInput<'_>) -> Value {
    let request = input.request;
    let redacted = |text: &str| redact::redact_str(text, &request.rules, input.identity);

    let mut manifest = Map::new();
    manifest.insert("schema".into(), MANIFEST_SCHEMA.into());

    let mut tool = Map::new();
    tool.insert("version".into(), build_info::VERSION.into());
    let mut set_if_present = |key: &str, value: &str| {
        if !value.is_empty() {
            tool.insert(key.into(), value.into());
        }
    };
    set_if_present("describe", build_info::DESCRIBE);
    set_if_present("commit", build_info::COMMIT);
    set_if_present("built", &build_info::built_human());
    if let Ok(path) = std::env::current_exe() {
        tool.insert("path".into(), redacted(&display_path(&path)).into());
    }
    manifest.insert("tool".into(), Value::Object(tool));

    manifest.insert("created".into(), input.created.into());
    if !input.os.is_empty() {
        manifest.insert("os".into(), redacted(input.os).into());
    }
    manifest.insert("profile".into(), request.options.profile.name().into());
    if let Some(since) = request.options.since {
        manifest.insert("since_minutes".into(), (since.as_secs() / 60).into());
    }
    if !request.options.devices.is_empty() {
        let devices = request.options.devices.iter().map(|device| Value::from(device.bdf.to_string()));
        manifest.insert("devices".into(), Value::Array(devices.collect()));
    }
    let rules = redact::rule_names(&request.rules).into_iter().map(Value::from);
    manifest.insert("redaction".into(), Value::Array(rules.collect()));
    manifest.insert("compression".into(), input.compression.name().into());
    if input.identity_partial {
        manifest.insert("identity".into(), "partial".into());
    }
    if let Some(xpu_smi) = input.xpu_smi {
        let mut entry = Map::new();
        entry.insert("path".into(), redacted(&display_path(&xpu_smi.path)).into());
        entry.insert("version".into(), xpu_smi.version.as_str().into());
        manifest.insert("xpu_smi".into(), Value::Object(entry));
    }

    let sources = input.artifacts.iter().map(|artifact| source_json(artifact, &redacted));
    manifest.insert("sources".into(), Value::Array(sources.collect()));
    Value::Object(manifest)
}

/// One entry of the `sources` array.
fn source_json(artifact: &Artifact, redacted: &dyn Fn(&str) -> String) -> Value {
    let mut entry = Map::new();
    entry.insert("path".into(), artifact.rel_path.as_str().into());
    entry.insert("status".into(), artifact.status.name().into());
    if !artifact.via.is_empty() {
        entry.insert("via".into(), redacted(&artifact.via).into());
    }
    if !artifact.gate.name().is_empty() {
        entry.insert("gate".into(), artifact.gate.name().into());
    }
    if !artifact.reason.is_empty() {
        entry.insert("reason".into(), artifact.reason.as_str().into());
    }
    if let Some(exit) = artifact.exit.filter(|&exit| exit != 0) {
        entry.insert("exit".into(), exit.into());
    }
    if artifact.bytes.get() != 0 {
        entry.insert("bytes".into(), artifact.bytes.get().into());
    }
    if artifact.files != 1 {
        entry.insert("files".into(), artifact.files.into());
    }
    if artifact.denied != 0 {
        entry.insert("denied".into(), artifact.denied.into());
    }
    let millis = u64::try_from(artifact.elapsed.as_millis()).unwrap_or(u64::MAX);
    entry.insert("ms".into(), millis.into());
    Value::Object(entry)
}

/// Serialises `doc`; `indent` spaces per level, 0 for compact. Never fails (strings are already UTF-8).
pub fn json_text(doc: &Value, indent: usize) -> String {
    if indent == 0 {
        return doc.to_string();
    }
    let indent_bytes = vec![b' '; indent];
    let mut out = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut out, PrettyFormatter::with_indent(&indent_bytes));
    if doc.serialize(&mut serializer).is_err() {
        // A `Value` always serialises; this only keeps the function total.
        return doc.to_string();
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "manifest_tests.rs"]
mod tests;
