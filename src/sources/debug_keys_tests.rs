// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/debug_keys.rs`.

use super::*;

#[test]
fn the_list_is_clean() {
    assert!(DEBUG_KEY_NAMES.lines().count() > 100);
    assert!(
        DEBUG_KEY_NAMES.lines().all(|l| !l.is_empty() && l == l.trim() && !l.contains(char::is_whitespace))
    );
    assert!(DEBUG_KEY_NAMES.lines().any(|l| l == "PrintDebugMessages"));
}

#[test]
fn known_keys_match_bare_prefixed_and_in_any_case() {
    for name in [
        "PrintDebugMessages",
        "printdebugmessages",
        "NEO_PrintDebugMessages",
        "neo_ocl_PrintDebugMessages",
        "NEO_L0_PrintDebugMessages",
        "EnableDirectSubmission",
        "ForceCsrFlushing",
        "DumpKernels",
        "AUBDumpAllocations",
    ] {
        assert!(is_debug_key(name), "{name}");
    }
}

#[test]
fn other_variables_never_match() {
    for name in [
        "",
        "NEO_",
        "NEO_OCL_",
        "GithubPat",
        "AcmeCorpVpnUser",
        "OpenAIKey",
        "NoDefaultCurrentDirectoryInExePath",
        "MyEmployerProxy",
        "AWS_ACCESS_KEY_ID",
        "HOME",
        "PrintDebugMessagesX",
    ] {
        assert!(!is_debug_key(name), "{name}");
    }
}
