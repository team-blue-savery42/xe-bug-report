// SPDX-License-Identifier: MIT
//! Removes personal and machine identifiers from diagnostic text before it leaves the host.
//! Port of `utility/redact/redact.cpp` of the reference.

mod bytes;
pub mod context;
pub mod json;
mod names;
pub mod rules;

#[cfg(test)]
mod tests;

pub use context::{Context, Rules};
pub use json::{redact_json, redact_json_bytes};
pub use rules::{ALL_RULES, Rule, redact_str, redact_text, rule_names};
