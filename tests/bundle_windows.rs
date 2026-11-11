// SPDX-License-Identifier: MIT
//! End-to-end tests of the binary on Windows.
//!
//! The same checks as `bundle_linux.rs` that make sense here. They need no Intel GPU and no
//! xpu-smi. Locally this file is only type-checked (`cargo check --target
//! x86_64-pc-windows-msvc --all-targets`); the Windows CI runner runs it.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use common::{Invocation, Zip};
use serde_json::Value;

/// The per-run deadline passed to every bundle run; PowerShell and event log queries are slow.
const TIMEOUT: &str = "300";

/// Runs `--minimal` into `dir\b.zip` with extra arguments and parses the result.
fn minimal_bundle_with(invocation: Invocation, dir: &Path, extra: &[&str]) -> (common::Run, Zip) {
    let output = dir.join("b.zip");
    let run = invocation
        .args(["--minimal", "--samples", "0", "--timeout", TIMEOUT, "--output"])
        .args([output.as_os_str()])
        .args(extra)
        .run();
    assert_eq!(run.code, 0, "stdout: {}\nstderr: {}", run.stdout, run.stderr);
    let zip = Zip::open(&output).expect("the archive parses");
    (run, zip)
}

fn minimal_bundle(dir: &Path, extra: &[&str]) -> (common::Run, Zip) {
    minimal_bundle_with(Invocation::new(), dir, extra)
}

fn sources_of(manifest: &Value) -> &Vec<Value> {
    manifest["sources"].as_array().expect("sources is an array")
}

#[test]
fn help_and_version_exit_zero() {
    for flag in ["--help", "-h"] {
        let run = common::run([flag]);
        assert_eq!(run.code, 0, "{flag}: {}", run.stderr);
        assert!(run.stdout.contains("Usage: xe-bug-report"), "{flag}: {}", run.stdout);
        assert!(run.stdout.contains("--output"), "{flag}: {}", run.stdout);
    }
    for flag in ["--version", "-v"] {
        let run = common::run([flag]);
        assert_eq!(run.code, 0, "{flag}: {}", run.stderr);
        let expected = format!("xe-bug-report {}", env!("CARGO_PKG_VERSION"));
        assert!(run.stdout.starts_with(&expected), "{flag}: {}", run.stdout);
    }
}

#[test]
fn bad_arguments_exit_one_plain_and_as_json() {
    let cases: &[&[&str]] =
        &[&["--bogus"], &["--samples", "abc"], &["--since", "0m"], &["--minimal", "--full"]];
    for args in cases {
        let run = common::run(*args);
        assert_eq!(run.code, 1, "{args:?}: {}{}", run.stdout, run.stderr);
        assert!(run.stdout.is_empty(), "{args:?}: stdout {:?}", run.stdout);
        assert!(run.stderr.starts_with("xe-bug-report: "), "{args:?}: {}", run.stderr);

        let run = common::run(args.iter().copied().chain(["--json"]));
        assert_eq!(run.code, 1, "{args:?}: {}{}", run.stdout, run.stderr);
        let doc: Value =
            serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", run.stdout));
        assert_eq!(doc.as_object().unwrap().keys().collect::<Vec<_>>(), ["errno", "error"]);
        assert_eq!(doc["errno"], 1);
    }
}

#[test]
fn list_full_names_only_known_paths() {
    let golden: Vec<&str> = include_str!("golden/windows-sources.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let run = common::run(["--list", "--full"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let rows = common::parse_table(&run.stdout).expect("the list parses");
    for row in &rows {
        let known = golden.contains(&row.path.as_str()) || row.path.starts_with("xpu-smi/");
        assert!(known, "{} is not in tests/golden/windows-sources.txt", row.path);
        assert!(!row.why.is_empty(), "{} has no reason", row.path);
    }
    for path in golden.iter().filter(|p| !p.starts_with("xpu-smi/")) {
        assert!(rows.iter().any(|r| r.path == *path), "{path} is missing from --list --full");
    }
    assert!(rows.iter().any(|r| r.path == "xpu-smi/version.txt"));

    let minimal = common::run(["--list", "--minimal"]);
    assert_eq!(minimal.code, 0);
    let minimal_rows = common::parse_table(&minimal.stdout).unwrap();
    assert!(!minimal_rows.is_empty() && minimal_rows.len() < rows.len());
    assert!(minimal_rows.iter().all(|r| r.profile == "minimal"));
}

#[test]
fn a_minimal_bundle_is_a_valid_zip_with_the_manifest_last() {
    let dir = common::temp_dir();
    let (run, zip) = minimal_bundle(dir.path(), &[]);
    assert_eq!(common::check_archive(&zip), Vec::<String>::new());
    assert_eq!(zip.entries.last().map(|e| e.name.as_str()), Some("manifest.json"));

    let manifest = zip.manifest().expect("the manifest parses");
    common::check_manifest(&manifest).expect("the manifest follows tests/golden/manifest-keys.txt");
    assert_eq!(manifest["profile"], "minimal");
    assert_eq!(manifest["tool"]["version"], env!("CARGO_PKG_VERSION"));

    let sources = sources_of(&manifest);
    let complete = sources.iter().filter(|s| s["status"].as_str() == Some("collected")).count();
    assert!(run.stdout.starts_with("Wrote "), "{}", run.stdout);
    let expected = format!("  {} sources: {complete} complete", sources.len());
    assert!(run.stdout.contains(&expected), "{} (expected {expected})", run.stdout);
    assert!(!dir.path().join("b.zip.partial").exists());
}

#[test]
fn an_existing_output_is_refused_and_left_alone() {
    let dir = common::temp_dir();
    let target = dir.path().join("b.zip");
    std::fs::write(&target, b"keep me").unwrap();
    let args: [&std::ffi::OsStr; 3] = ["--minimal".as_ref(), "--output".as_ref(), target.as_os_str()];
    let run = common::run(args);
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert!(run.stderr.contains("already exists"), "{}", run.stderr);
    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
}

#[test]
fn json_errors_survive_an_unpaired_surrogate_in_the_path() {
    let dir = common::temp_dir();
    // "b", a lone high surrogate, ".zip": not valid UTF-16, so not valid Unicode.
    let name = std::ffi::OsString::from_wide(&[0x62, 0xD800, 0x2E, 0x7A, 0x69, 0x70]);
    let output = dir.path().join(name);
    std::fs::write(&output, b"x").unwrap();
    let run = Invocation::new().args(["--minimal", "--json", "--output"]).args([output.as_os_str()]).run();
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    let doc: Value = serde_json::from_str(&run.stdout).expect("the error is valid JSON");
    assert_eq!(doc["errno"], 1);
    assert!(doc["error"].as_str().is_some_and(|e| e.contains("already exists")), "{doc}");
}

fn assert_xpu_smi_skipped(manifest: &Value) {
    let rows: Vec<&Value> =
        sources_of(manifest).iter().filter(|s| s["path"].as_str().unwrap().starts_with("xpu-smi/")).collect();
    assert!(!rows.is_empty(), "the manifest lists no xpu-smi source");
    for row in rows {
        assert_eq!(row["status"], "skipped", "{row}");
        assert_eq!(row["reason"], "xpu-smi not found", "{row}");
    }
    assert!(manifest.get("xpu_smi").is_none(), "xpu_smi is present although none was found");
}

#[test]
fn an_explicit_xpu_smi_that_does_not_exist_skips_the_xpu_smi_sources() {
    let dir = common::temp_dir();
    let missing = dir.path().join("no-such-xpu-smi.exe");
    let (_, zip) = minimal_bundle(dir.path(), &["--xpu-smi", missing.to_str().unwrap()]);
    assert_xpu_smi_skipped(&zip.manifest().unwrap());
}

/// The current PATH without every directory that holds an `xpu-smi.exe`, so PowerShell and the
/// other tools are still found.
fn path_without_xpu_smi() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<_> =
        std::env::split_paths(&path).filter(|dir| !dir.join("xpu-smi.exe").is_file()).collect();
    std::env::join_paths(kept).expect("rejoin PATH")
}

#[test]
fn without_xpu_smi_on_path_every_xpu_smi_source_is_skipped() {
    let dir = common::temp_dir();
    let invocation = Invocation::new().env("PATH", path_without_xpu_smi());
    let (_, zip) = minimal_bundle_with(invocation, dir.path(), &[]);
    assert!(common::check_archive(&zip).is_empty());
    assert_xpu_smi_skipped(&zip.manifest().unwrap());
}

/// Names that identify no one; the rules leave them alone.
const GENERIC_NAMES: &[&str] = &[
    "root",
    "nobody",
    "daemon",
    "system",
    "administrator",
    "local service",
    "network service",
    "localhost",
    "localhost.localdomain",
];

#[test]
fn the_host_and_user_names_appear_nowhere_in_a_redacted_bundle() {
    let names: Vec<String> = ["COMPUTERNAME", "USERNAME"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| name.len() >= 2 && !GENERIC_NAMES.contains(&name.to_ascii_lowercase().as_str()))
        .collect();
    if names.is_empty() {
        eprintln!("host and user names are generic here; nothing to look for");
        return;
    }
    let dir = common::temp_dir();
    let (_, zip) = minimal_bundle(dir.path(), &[]);
    for (name, data) in zip.read_all().expect("every entry inflates") {
        for secret in &names {
            assert!(
                !common::contains_name(name.as_bytes(), secret),
                "{secret:?} is in the entry name {name}"
            );
            assert!(!common::contains_name(&data, secret), "{secret:?} survives in {name}");
        }
    }
}
