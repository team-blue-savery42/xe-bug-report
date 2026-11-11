// SPDX-License-Identifier: MIT
//! Removes personal and machine identifiers from diagnostic text before it leaves the host.
//! Port of `utility/redact/redact.cpp` of the reference.
#![forbid(unsafe_code)]

pub mod context;
pub mod json;
pub mod rules;

pub use context::{Context, Rules};
pub use json::redact_json;
pub use rules::{redact_str, redact_text, rule_names};
