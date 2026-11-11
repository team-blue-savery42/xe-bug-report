// SPDX-License-Identifier: MIT
//! End-to-end tests of the binary on Linux.
//!
//! They need no Intel GPU and no xpu-smi: the sources that depend on either are skipped with a
//! reason, which is itself part of what is tested. Every bundle run uses `--minimal --samples 0`
//! and an explicit `--timeout`, so a run takes a few seconds.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::{Invocation, ListRow, Zip};
use serde_json::Value;

/// The generous per-run deadline passed to every bundle run.
const TIMEOUT: &str = "120";

/// Runs `--minimal` into `dir/b.zip` with extra arguments and parses the result.
fn minimal_bundle(dir: &Path, extra: &[&str]) -> (common::Run, Zip) {
    minimal_bundle_with(Invocation::new(), dir, extra)
}

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

fn sources_of(manifest: &Value) -> &Vec<Value> {
    manifest["sources"].as_array().expect("sources is an array")
}

// ---- help, version, bad arguments ----

#[test]
fn help_and_version_exit_zero() {
    for flag in ["--help", "-h"] {
        let run = common::run([flag]);
        assert_eq!(run.code, 0, "{flag}: {}", run.stderr);
        assert!(run.stdout.contains("Usage: xe-bug-report"), "{flag}: {}", run.stdout);
        for option in ["--output", "--device", "--minimal", "--full", "--list", "--json", "--timeout"] {
            assert!(run.stdout.contains(option), "{flag}: help does not mention {option}");
        }
    }
    for flag in ["--version", "-v"] {
        let run = common::run([flag]);
        assert_eq!(run.code, 0, "{flag}: {}", run.stderr);
        let expected = format!("xe-bug-report {}", env!("CARGO_PKG_VERSION"));
        assert!(run.stdout.starts_with(&expected), "{flag}: {}", run.stdout);
    }
}

#[test]
fn bad_arguments_exit_one_with_a_plain_message() {
    let cases: &[&[&str]] = &[
        &["--bogus"],
        &["--samples", "abc"],
        &["--samples", "3601"],
        &["--since", "0m"],
        &["--since", "400d"],
        &["--timeout", "-1"],
        &["--device", "not-an-address"],
        &["--minimal", "--full"],
        &["positional"],
    ];
    for args in cases {
        let run = common::run(*args);
        assert_eq!(run.code, 1, "{args:?}: {}{}", run.stdout, run.stderr);
        assert!(run.stdout.is_empty(), "{args:?}: stdout {:?}", run.stdout);
        assert!(run.stderr.starts_with("xe-bug-report: "), "{args:?}: {}", run.stderr);
        assert!(run.stderr.contains("--help"), "{args:?}: {}", run.stderr);
    }
}

#[test]
fn bad_arguments_with_json_print_an_error_object() {
    let cases: &[&[&str]] =
        &[&["--bogus"], &["--samples", "abc"], &["--since", "0m"], &["--minimal", "--full"]];
    for args in cases {
        let run = common::run(args.iter().copied().chain(["--json"]));
        assert_eq!(run.code, 1, "{args:?}: {}{}", run.stdout, run.stderr);
        let doc: Value =
            serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", run.stdout));
        let object = doc.as_object().expect("an object");
        assert_eq!(object.keys().collect::<Vec<_>>(), ["errno", "error"], "{args:?}");
        assert_eq!(object["errno"], 1);
        assert!(object["error"].as_str().is_some_and(|e| !e.is_empty()), "{args:?}: {doc}");
    }
}

#[test]
fn an_absent_device_is_an_error_naming_it() {
    // No machine has a GPU at this address.
    let run = common::run(["--device", "ffff:ff:1f.7", "--json"]);
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    let doc: Value = serde_json::from_str(&run.stdout).expect("valid JSON");
    assert_eq!(doc["errno"], 1);
    assert!(doc["error"].as_str().is_some_and(|e| e.contains("ffff:ff:1f.7")), "{doc}");
}

// ---- --list ----

fn golden_rows() -> Vec<ListRow> {
    common::parse_table(include_str!("golden/linux-sources.txt")).expect("the golden table parses")
}

/// The golden rows' alternatives, one entry per ` | `-separated path.
fn golden_keys() -> Vec<(String, String, String)> {
    let mut keys = Vec::new();
    for row in golden_rows() {
        for alternative in row.path.split(" | ") {
            let generic = common::generic_path(&alternative.replace("<bridge>", "<dev>"));
            keys.push((row.profile.clone(), row.needs.clone(), generic));
        }
    }
    keys
}

fn list(args: &[&str]) -> Vec<ListRow> {
    let run = common::run(args.iter().copied().chain(["--list"]));
    assert_eq!(run.code, 0, "{args:?}: {}", run.stderr);
    assert!(run.stdout.starts_with("PROFILE  NEEDS"), "{}", run.stdout);
    common::parse_table(&run.stdout).expect("the list parses")
}

#[test]
fn list_full_matches_the_golden_table() {
    let rows = list(&["--full"]);
    assert!(rows.len() >= 30, "only {} rows", rows.len());
    let golden = golden_keys();
    let mut last_golden = 0;
    for row in &rows {
        let key = (row.profile.clone(), row.needs.clone(), common::generic_path(&row.path));
        let Some(position) = golden.iter().position(|g| *g == key) else {
            panic!("{key:?} is not in tests/golden/linux-sources.txt (and is not a per-device row)");
        };
        assert!(position >= last_golden, "{key:?} is out of the golden order");
        last_golden = position;
        assert!(!row.why.is_empty(), "{key:?} has no reason");
    }
    // Rows that need nothing about this host are always listed.
    for path in ["system/os-release", "kernel/kmsg.txt", "xpu-smi/version.txt", "xpu-smi/discovery.json"] {
        assert!(rows.iter().any(|r| r.path == path), "{path} is missing from --list --full");
    }
}

#[test]
fn list_profiles_nest() {
    let paths =
        |rows: Vec<ListRow>| rows.into_iter().map(|r| r.path).collect::<std::collections::BTreeSet<_>>();
    let minimal = paths(list(&["--minimal"]));
    let default = paths(list(&[]));
    let full = paths(list(&["--full"]));
    assert!(!minimal.is_empty());
    assert!(minimal.is_subset(&default), "minimal has paths the default list lacks");
    assert!(default.is_subset(&full), "the default list has paths --full lacks");
    assert!(minimal.len() < default.len() && default.len() < full.len());
    assert!(list(&["--minimal"]).iter().all(|r| r.profile == "minimal"));
}

// ---- the bundle ----

#[test]
fn a_minimal_bundle_is_a_valid_zip_with_the_manifest_last() {
    let dir = common::temp_dir();
    let (run, zip) = minimal_bundle(dir.path(), &[]);

    assert_eq!(common::check_archive(&zip), Vec::<String>::new());
    assert_eq!(zip.entries.last().map(|e| e.name.as_str()), Some("manifest.json"));

    let manifest = zip.manifest().expect("the manifest parses");
    common::check_manifest(&manifest).expect("the manifest follows tests/golden/manifest-keys.txt");
    assert_eq!(manifest["profile"], "minimal");
    assert_eq!(manifest["redaction"], serde_json::json!(["serials", "hostname", "users", "addresses"]));
    assert!(manifest.get("since_minutes").is_none());
    let created = manifest["created"].as_str().expect("created is a string");
    assert!(created.len() == 20 && created.ends_with('Z') && created.as_bytes()[10] == b'T', "{created}");
    assert_eq!(manifest["tool"]["version"], env!("CARGO_PKG_VERSION"));

    // The compression field describes the entries.
    let deflated = zip.entries.iter().any(|e| e.method == 8);
    assert_eq!(manifest["compression"], if deflated { "deflate" } else { "stored" });

    // Every source that was collected as a file has its entry; every entry belongs to a source.
    let sources = sources_of(&manifest);
    let names = zip.names();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        let status = source["status"].as_str().unwrap();
        if status == "collected" && !path.ends_with('/') {
            assert!(names.contains(&path), "{path} is collected but has no entry");
        }
        if status == "skipped" {
            assert!(source.get("reason").is_some(), "{path} is skipped without a reason");
        }
    }
    for name in names.iter().filter(|n| **n != "manifest.json") {
        let owned = sources.iter().any(|s| {
            let path = s["path"].as_str().unwrap();
            path == *name || (path.ends_with('/') && name.starts_with(path))
        });
        assert!(owned, "entry {name} belongs to no manifest source");
    }

    // The report agrees with the manifest.
    let count = |status: &str| sources.iter().filter(|s| s["status"].as_str() == Some(status)).count();
    let (complete, partial) = (count("collected"), count("truncated"));
    let missing = sources.len() - complete - partial;
    // The path is shell-quoted in the report when it holds unusual characters, so it is not
    // compared literally.
    assert!(run.stdout.starts_with("Wrote ") && run.stdout.contains("b.zip"), "{}", run.stdout);
    let mut counts = format!("  {} sources: {complete} complete", sources.len());
    if partial > 0 {
        counts.push_str(&format!(", {partial} partial"));
    }
    if missing > 0 {
        counts.push_str(&format!(", {missing} not collected"));
    }
    assert!(run.stdout.contains(&counts), "{} (expected {counts})", run.stdout);
    if partial + missing > 0 {
        assert!(
            run.stdout.contains("Details: unzip -p ") && run.stdout.contains("manifest.json"),
            "{}",
            run.stdout
        );
    }
    // Warnings (for example a slow enumeration on a loaded host) may appear; nothing else may.
    for line in run.stderr.lines() {
        assert!(line.starts_with("xe-bug-report: "), "unexpected stderr line {line:?}");
    }

    // Nothing else was left in the directory, in particular no .partial.
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["b.zip"]);
}

#[test]
fn unzip_accepts_the_archive() {
    if !common::on_path("unzip") {
        eprintln!("unzip is not installed; skipping");
        return;
    }
    let dir = common::temp_dir();
    minimal_bundle(dir.path(), &[]);
    let output = std::process::Command::new("unzip")
        .arg("-t")
        .arg(dir.path().join("b.zip"))
        .output()
        .expect("run unzip");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "unzip -t failed: {text}{}", String::from_utf8_lossy(&output.stderr));
    assert!(text.contains("No errors detected"), "{text}");
}

#[test]
fn an_existing_output_is_refused_and_left_alone() {
    let dir = common::temp_dir();
    let target = dir.path().join("b.zip");
    std::fs::write(&target, b"keep me").unwrap();
    let args: [&std::ffi::OsStr; 5] =
        ["--minimal".as_ref(), "--samples".as_ref(), "0".as_ref(), "--output".as_ref(), target.as_os_str()];

    let run = common::run(args);
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert!(run.stderr.contains("already exists"), "{}", run.stderr);
    assert!(run.stderr.contains(&target.display().to_string()), "{}", run.stderr);

    let run = common::run(args.into_iter().chain(["--json".as_ref()]));
    assert_eq!(run.code, 1);
    let doc: Value = serde_json::from_str(&run.stdout).expect("valid JSON");
    assert_eq!(doc["errno"], 1);
    assert!(doc["error"].as_str().is_some_and(|e| e.contains("already exists")), "{doc}");

    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    assert!(!dir.path().join("b.zip.partial").exists());
}

#[test]
fn json_output_survives_a_non_utf8_path() {
    let dir = common::temp_dir();
    let name = std::ffi::OsStr::from_bytes(b"b-\xff\xfe.zip");
    let output = dir.path().join(name);

    // An error naming the path.
    std::fs::write(&output, b"x").unwrap();
    let run = Invocation::new().args(["--minimal", "--json", "--output"]).args([output.as_os_str()]).run();
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    let doc: Value = serde_json::from_str(&run.stdout).expect("the error is valid JSON");
    assert_eq!(doc["errno"], 1);
    assert!(doc["error"].as_str().is_some_and(|e| e.contains("already exists")), "{doc}");
    std::fs::remove_file(&output).unwrap();

    // The success object naming the path.
    let run = Invocation::new()
        .args(["--minimal", "--samples", "0", "--timeout", TIMEOUT, "--json", "--output"])
        .args([output.as_os_str()])
        .run();
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let doc: Value = serde_json::from_str(&run.stdout).expect("the result is valid JSON");
    let object = doc.as_object().expect("an object");
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        ["status", "file", "collected", "truncated", "skipped", "timed_out", "failed", "bytes"]
    );
    assert_eq!(object["status"], "OK");
    assert!(object["file"].as_str().is_some_and(|f| f.contains('\u{FFFD}')), "{doc}");
    assert!(object["collected"].as_u64().unwrap() > 0);
    assert!(object["bytes"].as_u64().unwrap() > 0);
    let zip = Zip::open(&output).expect("the archive is where the path said");
    assert!(common::check_archive(&zip).is_empty());
}

// ---- xpu-smi ----

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
fn without_xpu_smi_on_path_every_xpu_smi_source_is_skipped() {
    let empty = common::temp_dir();
    let dir = common::temp_dir();
    let invocation = Invocation::new().env("PATH", empty.path());
    let (_, zip) = minimal_bundle_with(invocation, dir.path(), &[]);
    assert!(common::check_archive(&zip).is_empty());
    assert_xpu_smi_skipped(&zip.manifest().unwrap());
}

#[test]
fn an_explicit_xpu_smi_that_does_not_exist_skips_the_xpu_smi_sources() {
    let dir = common::temp_dir();
    let missing = dir.path().join("no-such-xpu-smi");
    let (_, zip) = minimal_bundle(dir.path(), &["--xpu-smi", missing.to_str().unwrap()]);
    assert_xpu_smi_skipped(&zip.manifest().unwrap());
}

#[test]
fn a_stub_xpu_smi_is_run_and_recorded_in_the_manifest() {
    let dir = common::temp_dir();
    let stub = dir.path().join("xpu-smi-stub");
    std::fs::write(&stub, "#!/bin/sh\necho 'Version: 9.9.9.stub'\necho 'second line'\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = common::temp_dir();
    let (_, zip) = minimal_bundle(out.path(), &["--xpu-smi", stub.to_str().unwrap()]);
    let manifest = zip.manifest().unwrap();
    common::check_manifest(&manifest).unwrap();
    assert_eq!(manifest["xpu_smi"]["version"], "Version: 9.9.9.stub");
    // The stub path is under the temp dir, whose name holds no user name worth redacting.
    assert!(manifest["xpu_smi"]["path"].as_str().is_some_and(|p| p.ends_with("xpu-smi-stub")));
    let version = String::from_utf8(zip.read_named("xpu-smi/version.txt").unwrap()).unwrap();
    assert!(version.contains("Version: 9.9.9.stub"), "{version}");
}

// ---- redaction ----

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

fn identifying(name: &str) -> bool {
    name.len() >= 2 && !GENERIC_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

#[test]
fn the_host_and_user_names_appear_nowhere_in_a_redacted_bundle() {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    let names: Vec<String> =
        [hostname.trim().to_owned(), user.trim().to_owned()].into_iter().filter(|n| identifying(n)).collect();
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

#[test]
fn no_redact_empties_the_rule_list() {
    let dir = common::temp_dir();
    let (_, zip) = minimal_bundle(dir.path(), &["--no-redact"]);
    let manifest = zip.manifest().unwrap();
    common::check_manifest(&manifest).unwrap();
    assert_eq!(manifest["redaction"], serde_json::json!([]));
    assert!(common::check_archive(&zip).is_empty());
}
