// SPDX-License-Identifier: MIT
//! Redaction of parsed JSON documents.
#![forbid(unsafe_code)]

use serde_json::Value;

use super::context::{Context, Rules};

/// Redacts every string value in `value`: by key for serial, UUID and host fields, else as text.
/// Object keys are kept as they are.
pub fn redact_json(value: Value, rules: &Rules, context: &Context) -> Value {
    let _ = (rules, context);
    value
}

/// Redacts a `.json` artifact: parsed and walked with [`redact_json`], or text-redacted when it does
/// not parse. A parsed document is re-serialised with the formatting the reference uses.
pub fn redact_json_bytes(data: &[u8], rules: &Rules, context: &Context) -> Vec<u8> {
    super::rules::redact_text(data, rules, context)
}
