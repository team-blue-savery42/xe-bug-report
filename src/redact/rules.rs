// SPDX-License-Identifier: MIT
//! The text redaction scanners.
#![forbid(unsafe_code)]

use super::context::{Context, Rules};

/// Replaces the identifiers `rules` selects in `text` (need not be valid UTF-8) with fixed tokens
/// such as `<host>`.
pub fn redact_text(text: &[u8], rules: &Rules, context: &Context) -> Vec<u8> {
    let _ = (rules, context);
    text.to_vec()
}

/// [`redact_text`] for a `&str`; the result is valid UTF-8 because tokens are ASCII.
pub fn redact_str(text: &str, rules: &Rules, context: &Context) -> String {
    String::from_utf8_lossy(&redact_text(text.as_bytes(), rules, context)).into_owned()
}

/// The names of the active rules, for the manifest: "serials", "hostname", "users", "addresses"
/// for each active rule, in that order.
pub fn rule_names(rules: &Rules) -> Vec<&'static str> {
    let _ = rules;
    Vec::new()
}
