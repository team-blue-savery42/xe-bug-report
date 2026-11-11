// SPDX-License-Identifier: MIT
//! Redaction of parsed JSON documents. Documents beyond serde_json's nesting limit (128) also fall back
//! to text redaction.

use serde_json::Value;

use super::bytes::{TOKEN_HOST, TOKEN_SERIAL, TOKEN_UUID};
use super::context::{Context, Rules};
use super::rules::redact_text;

/// Indent of a redacted `.json` artifact, in spaces (the reference dumps with indent 2).
pub const JSON_INDENT: usize = 2;

/// The token that replaces the value under `key`, if its class is selected.
///
/// Keys are compared without `_`, `-` and space and case-insensitively: `hostname`; names ending
/// in `uuid` or `uuids`; names ending in `serial`, `serials`, `serialnumber` or `serialnumbers`.
fn key_token(key: &str, rules: &Rules) -> Option<&'static [u8]> {
    let name: Vec<u8> =
        key.bytes().filter(|c| !matches!(c, b'_' | b'-' | b' ')).map(|c| c.to_ascii_lowercase()).collect();
    let (selected, token): (bool, &'static [u8]) = if name == b"hostname" {
        (rules.hostname, TOKEN_HOST)
    } else if name.ends_with(b"uuid") || name.ends_with(b"uuids") {
        (rules.serials, TOKEN_UUID)
    } else if name.ends_with(b"serial")
        || name.ends_with(b"serials")
        || name.ends_with(b"serialnumber")
        || name.ends_with(b"serialnumbers")
    {
        (rules.serials, TOKEN_SERIAL)
    } else {
        return None;
    };
    selected.then_some(token)
}

/// Replaces the identifier leaves under a serial, UUID or host key.
///
/// Non-empty strings and numbers become `token` (also inside arrays); objects are redacted as
/// ordinary data; empty strings, booleans and null are left alone.
fn replace_leaves(node: &mut Value, token: &[u8], rules: &Rules, context: &Context) {
    // The tokens are ASCII literals.
    let leaf = || Value::String(String::from_utf8_lossy(token).into_owned());
    match node {
        Value::Array(items) => {
            for item in items {
                replace_leaves(item, token, rules, context);
            }
        }
        Value::Number(_) => *node = leaf(),
        Value::String(text) if !text.is_empty() => *node = leaf(),
        Value::Object(_) => redact_node(node, rules, context),
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

/// Redacts a JSON value in place: by key for serial, UUID and host fields, else every string as
/// text.
fn redact_node(node: &mut Value, rules: &Rules, context: &Context) {
    match node {
        Value::String(text) => {
            let redacted = redact_text(text.as_bytes(), rules, context);
            *text = String::from_utf8_lossy(&redacted).into_owned();
        }
        Value::Array(items) => {
            for item in items {
                redact_node(item, rules, context);
            }
        }
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if let Some(token) = key_token(key, rules)
                    && !value.is_object()
                {
                    replace_leaves(value, token, rules, context);
                    continue;
                }
                redact_node(value, rules, context);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Redacts every string value in `value`: by key for serial, UUID and host fields, else as text.
/// Object keys are kept as they are.
pub fn redact_json(mut value: Value, rules: &Rules, context: &Context) -> Value {
    if rules.any() {
        redact_node(&mut value, rules, context);
    }
    value
}

/// Redacts a `.json` artifact: parsed and walked with [`redact_json`], or text-redacted when it does
/// not parse. A parsed document is re-serialised with the formatting the reference uses: two-space
/// indent, key order kept, one trailing newline.
pub fn redact_json_bytes(data: &[u8], rules: &Rules, context: &Context) -> Vec<u8> {
    let body = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => {
            let redacted = redact_json(value, rules, context);
            match serde_json::to_vec_pretty(&redacted) {
                Ok(mut out) => {
                    out.push(b'\n');
                    out
                }
                Err(_) => redact_text(data, rules, context),
            }
        }
        Err(_) => redact_text(data, rules, context),
    }
}
