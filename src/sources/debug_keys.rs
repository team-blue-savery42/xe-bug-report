// SPDX-License-Identifier: MIT
//! The compute runtime's debug key names, shared by the Linux and Windows environment reports.
//!
//! While `NEOReadDebugKeys` is set, the runtime reads its debug keys from environment variables
//! with their plain names (`PrintDebugMessages`, `EnableDirectSubmission`, ...), or with a
//! `NEO_OCL_`, `NEO_L0_` or `NEO_` prefix. Only variables whose name is on the list are recorded, so
//! unrelated variables, which may hold secrets or names, never are.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The debug key names, one per line: a snapshot of the runtime's key list. Keys added by a newer
/// runtime are not recorded.
pub const DEBUG_KEY_NAMES: &str = include_str!("debug_keys.txt");
/// The prefixes the runtime accepts before a debug key name, longest first.
const DEBUG_KEY_PREFIXES: &[&str] = &["NEO_OCL_", "NEO_L0_", "NEO_"];

/// The names in upper case, built once. The file is not sorted, so it is not searched in place.
fn names() -> &'static HashSet<String> {
    static NAMES: OnceLock<HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| DEBUG_KEY_NAMES.lines().map(str::to_ascii_uppercase).collect())
}

/// Whether `name` is a compute runtime debug key, bare or with a `NEO_OCL_`, `NEO_L0_` or `NEO_`
/// prefix (any letter case: Windows variable names are case-insensitive).
pub fn is_debug_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let bare = DEBUG_KEY_PREFIXES.iter().find_map(|prefix| upper.strip_prefix(prefix)).unwrap_or(&upper);
    !bare.is_empty() && names().contains(bare)
}

#[cfg(test)]
#[path = "debug_keys_tests.rs"]
mod tests;
