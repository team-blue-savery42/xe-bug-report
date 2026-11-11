// SPDX-License-Identifier: MIT
//! The summary line, the notices, the `--list` table and the `--json` objects.
#![forbid(unsafe_code)]

use std::path::Path;

use serde_json::Value;

use crate::bundle::source::Source;
use crate::bundle::writer::{Artifact, BundleResult};

/// What the process may do, which decides whether re-running as root would help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Neither root nor CAP_SYS_ADMIN (Linux), not elevated (Windows).
    Unprivileged,
    /// Root or CAP_SYS_ADMIN (Linux), elevated (Windows).
    Privileged,
}

/// The `--list` table: `PROFILE  NEEDS  PATH  WHY`, two-space separated and padded.
pub fn format_source_list(sources: &[Source]) -> String {
    let _ = sources;
    String::new()
}

/// "Collected N of M sources (X KiB) into <path>[; K not collected, see manifest.json]".
pub fn format_summary(result: &BundleResult, output: &Path) -> String {
    let _ = (result, output);
    String::new()
}

/// One notice per gate that left sources out, in gate order, each starting "xe-bug-report: ".
pub fn skipped_notices(artifacts: &[Artifact], privilege: Privilege) -> Vec<String> {
    let _ = (artifacts, privilege);
    Vec::new()
}

/// The `--json` success object.
pub fn json_result(result: &BundleResult, output: &Path) -> Value {
    let _ = (result, output);
    Value::Null
}

/// The `--json` error object: `{"errno":1,"error":"<message>"}`.
pub fn json_error(message: &str) -> Value {
    let _ = message;
    Value::Null
}

/// A path as UTF-8 text for messages and JSON (lossy).
pub fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
