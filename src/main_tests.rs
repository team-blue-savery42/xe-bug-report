// SPDX-License-Identifier: MIT
//! Unit tests for `src/main.rs`.

use super::*;

#[test]
fn plain_errors_have_the_prefix_and_json_errors_the_object() {
    assert_eq!(error_report(false, "x.zip already exists"), "xe-bug-report: x.zip already exists\n");
    assert_eq!(
        error_report(true, "x.zip already exists"),
        "{\n    \"errno\": 1,\n    \"error\": \"x.zip already exists\"\n}\n"
    );
}

#[test]
fn a_missing_explicit_xpu_smi_is_none() {
    assert_eq!(resolve_xpu_smi(Some(Path::new("/nonexistent/xpu-smi"))), None);
    assert_eq!(resolve_xpu_smi(Some(Path::new("xe-bug-report-no-such-tool"))), None);
}

#[test]
fn an_existing_explicit_xpu_smi_is_used() {
    let sh = Path::new("/bin/sh");
    if sh.is_file() {
        assert_eq!(resolve_xpu_smi(Some(sh)), Some(sh.to_path_buf()));
    }
}

#[test]
fn the_deadline_is_absolute_and_optional() {
    let none = Args { timeout: None, ..Args::default() };
    assert_eq!(deadline_of(&none), None);
    let some = Args { timeout: Some(Duration::from_secs(5)), ..Args::default() };
    assert!(deadline_of(&some).is_some_and(|d| d > Instant::now()));
    let huge = Args { timeout: Some(Duration::MAX), ..Args::default() };
    assert_eq!(deadline_of(&huge), None);
}
