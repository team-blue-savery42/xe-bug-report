// SPDX-License-Identifier: MIT
//! Tests of the collector, with fake sources in temporary directories.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;
use crate::bundle::source::Profile;
use crate::redact::{Context, Rules};

/// A read limit short enough for the hang tests.
const SHORT_LIMIT: Duration = Duration::from_millis(400);

struct Collection {
    artifacts: Vec<Artifact>,
    files: BTreeMap<String, Vec<u8>>,
    order: Vec<String>,
}

impl Collection {
    fn text(&self, name: &str) -> String {
        String::from_utf8_lossy(&self.files[name]).into_owned()
    }
}

fn plain_options() -> CollectOptions {
    CollectOptions { rules: Rules::none(), ..CollectOptions::default() }
}

fn collect_with(sources: Vec<Source>, options: &CollectOptions, limit: Duration) -> Collection {
    let mut files = BTreeMap::new();
    let mut order = Vec::new();
    let artifacts = {
        let mut sink = |name: &str, data: &[u8]| {
            files.insert(name.to_owned(), data.to_vec());
            order.push(name.to_owned());
            Ok(())
        };
        collect_with_limit(sources.into(), options, &mut sink, limit).unwrap()
    };
    Collection { artifacts, files, order }
}

fn run(sources: Vec<Source>) -> Collection {
    collect_with(sources, &plain_options(), FILE_READ_LIMIT)
}

fn run_one(source: Source) -> Artifact {
    let out = run(vec![source]);
    assert_eq!(out.artifacts.len(), 1, "{:?}", out.artifacts);
    out.artifacts.into_iter().next().unwrap()
}

fn file_source(rel: &str, path: &Path) -> Source {
    Source::file(rel, path, Profile::Minimal, "test")
}

fn sh_source(rel: &str, script: &str) -> Source {
    Source::command(rel, &["/bin/sh", "-c", script], Profile::Minimal, "test")
}

/// A command whose script receives the output directory as `$0`.
fn outdir_source(rel: &str, script: &str) -> Source {
    Source::command(rel, &["/bin/sh", "-c", script, "{outdir}"], Profile::Minimal, "test")
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Removes all permissions; false when that has no effect (the tests run as root).
fn deny_access(path: &Path) -> bool {
    fs::set_permissions(path, fs::Permissions::from_mode(0o0)).unwrap();
    fs::File::open(path).is_err()
}

fn sh_options() -> CollectOptions {
    CollectOptions { xpu_smi: Some(PathBuf::from("/bin/sh")), ..plain_options() }
}

fn redacting_options() -> CollectOptions {
    CollectOptions {
        rules: Rules::default(),
        identity: Context { hostnames: vec!["myhost-x".into()], user_names: vec!["alice".into()] },
        ..CollectOptions::default()
    }
}

// ---- helpers ----

#[test]
fn match_segment_handles_wildcards() {
    assert!(match_segment("*", "anything"));
    assert!(match_segment("hwmon*", "hwmon12"));
    assert!(match_segment("*_freq", "min_freq"));
    assert!(match_segment("a*b*c", "aXXbYYc"));
    assert!(match_segment("vendor", "vendor"));
    assert!(!match_segment("vendor", "vendors"));
    assert!(!match_segment("hwmon*", "xhwmon1"));
    assert!(!match_segment("a*b", "ac"));
    assert!(match_segment("*", ""));
    assert!(!match_segment("a", ""));
}

#[test]
fn filter_lines_is_case_insensitive_and_keeps_newlines() {
    let needles = vec!["INTEL".to_owned(), "xe".to_owned()];
    assert_eq!(filter_lines(b"a\nIntel gpu\nb\nlibXE\nlast xe", &needles), b"Intel gpu\nlibXE\nlast xe");
    assert!(filter_lines(b"nothing\n", &needles).is_empty());
    assert!(filter_lines(b"", &needles).is_empty());
    assert_eq!(filter_lines(b"\xff xe \xfe\nx\n", &needles), b"\xff xe \xfe\n");
}

#[test]
fn sanitize_segment_maps_everything_else_to_underscore() {
    assert_eq!(sanitize_segment("a b:c"), "a_b_c");
    assert_eq!(sanitize_segment("ok-1._x"), "ok-1._x");
    assert_eq!(sanitize_segment(".."), "_");
    assert_eq!(sanitize_segment("."), "_");
    assert_eq!(sanitize_segment("a\\b"), "a_b");
    assert_eq!(sanitize_segment("a/b"), "a_b");
    assert_eq!(sanitize_segment("n\u{e9}"), "n__");
}

#[test]
fn labels_and_reasons_use_the_documented_texts() {
    assert_eq!(duration_label(Duration::from_secs(5)), "5 s");
    assert_eq!(duration_label(Duration::from_millis(200)), "200 ms");
    assert_eq!(needs_reason(Gate::None), "permission denied");
    assert_eq!(needs_reason(Gate::Root), "needs root");
    assert_eq!(cap_reason(Bytes::mib(16)), "size cap 16 MiB");
    assert_eq!(cap_reason(Bytes(10)), "size cap 10 B");
    assert_eq!(
        earlier_read_reason(FILE_READ_LIMIT),
        "an earlier read in this group did not return within 5 s"
    );
    assert_eq!(read_timeout_reason(FILE_READ_LIMIT), "did not return within 5 s");
    assert_eq!(dir_prefix("a/b"), "a/b/");
    assert_eq!(dir_prefix("a/b/"), "a/b/");
    assert_eq!(dir_prefix(""), "");
    assert_eq!(split_pattern("a//b/hwmon*"), ["a", "b", "hwmon*"]);
    assert!(split_pattern("a/../b").is_empty());
    assert!(split_pattern("").is_empty());
}

// ---- file sources ----

#[test]
fn a_file_is_collected() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("one.txt"), "hello\nworld\n");
    let out = run(vec![file_source("system/one.txt", &tmp.path().join("one.txt"))]);
    assert_eq!(out.artifacts.len(), 1);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.status, Status::Collected);
    assert_eq!(artifact.bytes, Bytes(12));
    assert_eq!(artifact.files, 1);
    assert_eq!(artifact.rel_path, "system/one.txt");
    assert_eq!(out.text("system/one.txt"), "hello\nworld\n");
}

#[test]
fn a_missing_file_is_skipped_not_present() {
    let tmp = tempfile::tempdir().unwrap();
    let artifact = run_one(file_source("system/none.txt", &tmp.path().join("none.txt")));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "not present");
    assert_eq!(artifact.gate, Gate::None);
}

#[test]
fn a_denied_file_is_skipped_with_its_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = tmp.path().join("secret");
    write(&secret, "x");
    if !deny_access(&secret) {
        return;
    }
    let artifact = run_one(file_source("kernel/secret", &secret).gate(Gate::Root));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.gate, Gate::Root);
    assert_eq!(artifact.reason, "needs root");
    let plain = run_one(file_source("kernel/secret", &secret));
    assert_eq!(plain.reason, "permission denied");
    assert_eq!(plain.gate, Gate::None);
}

#[test]
fn keep_lines_filters_before_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("one.txt"), "hello\nworld\n");
    let source = file_source("system/one.txt", &tmp.path().join("one.txt")).keep_lines(&["WOR"]);
    let out = run(vec![source]);
    assert_eq!(out.text("system/one.txt"), "world\n");
    assert_eq!(out.artifacts[0].status, Status::Collected);

    write(&tmp.path().join("pkgs"), "skip me\nkeep aaaa\nskip\nkeep bbbb\n");
    let source = file_source("packages/p", &tmp.path().join("pkgs")).keep_lines(&["keep"]).cap(Bytes(10));
    let out = run(vec![source]);
    assert_eq!(out.text("packages/p"), "keep aaaa\n");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
}

#[test]
fn a_filtered_source_reads_more_than_its_cap() {
    let tmp = tempfile::tempdir().unwrap();
    // The wanted line sits past the first 8 bytes, which the cap alone would have kept.
    write(&tmp.path().join("long"), "0123456789\nwanted\n");
    let source = file_source("p", &tmp.path().join("long")).keep_lines(&["wanted"]).cap(Bytes(8));
    let out = run(vec![source]);
    assert_eq!(out.text("p"), "wanted\n");
    assert_eq!(out.artifacts[0].status, Status::Collected);
}

#[test]
fn the_head_cap_keeps_the_start_and_names_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("long"), "01234\n6789abcdefghij0123456789");
    let out = run(vec![file_source("system/long", &tmp.path().join("long")).cap(Bytes(10))]);
    // Cut to 10 bytes, then the partial last line is dropped (text).
    assert_eq!(out.text("system/long"), "01234\n");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
    assert_eq!(out.artifacts[0].reason, "size cap 10 B");
    assert_eq!(out.artifacts[0].bytes, Bytes(6));
    // Binary content is cut exactly at the cap.
    let out = run(vec![file_source("system/long", &tmp.path().join("long")).cap(Bytes(10)).binary()]);
    assert_eq!(out.text("system/long"), "01234\n6789");
}

#[test]
fn the_tail_cap_keeps_the_end() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("long"), "0123456789abcde\nghij");
    let out = run(vec![file_source("system/long", &tmp.path().join("long")).cap(Bytes(7)).tail()]);
    // The last 7 bytes are "bcde\nghij"[..]; the partial first line goes.
    assert_eq!(out.text("system/long"), "ghij");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
    assert_eq!(out.artifacts[0].reason, "size cap 7 B");
}

#[test]
fn the_cap_reason_uses_the_cap_label() {
    let tmp = tempfile::tempdir().unwrap();
    let big = tmp.path().join("big");
    fs::write(&big, vec![b'x'; 2048]).unwrap();
    let artifact = run_one(file_source("b", &big).cap(Bytes::kib(1)));
    assert_eq!(artifact.reason, "size cap 1 KiB");
    assert_eq!(artifact.status, Status::Truncated);
}

#[test]
fn unavailable_sources_are_skipped_with_the_gate() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("one.txt"), "x");
    let source = file_source("system/one.txt", &tmp.path().join("one.txt"))
        .gate(Gate::DeviceAccess)
        .available(|| false);
    let artifact = run_one(source);
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.gate, Gate::DeviceAccess);
    assert_eq!(artifact.reason, "needs membership of the 'render' group, or root");

    let ungated = run_one(file_source("system/one.txt", &tmp.path().join("one.txt")).available(|| false));
    assert_eq!(ungated.reason, "not available");
    assert_eq!(ungated.gate, Gate::None);

    let available = run_one(file_source("system/one.txt", &tmp.path().join("one.txt")).available(|| true));
    assert_eq!(available.status, Status::Collected);
}

#[test]
fn a_second_source_with_the_same_path_fails_without_reaching_the_sink() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("one.txt"), "x");
    let one = || file_source("system/one.txt", &tmp.path().join("one.txt"));
    let out = run(vec![one(), one()]);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.artifacts[1].status, Status::Failed);
    assert_eq!(out.artifacts[1].reason, "duplicate path in the bundle");
    assert_eq!(out.order, ["system/one.txt"]);
}

#[test]
fn invalid_and_reserved_paths_fail_without_poisoning_the_archive() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("one.txt"), "x");
    let path = tmp.path().join("one.txt");
    let out = run(vec![
        file_source("../escape", &path),
        file_source("a//b", &path),
        file_source("manifest.json", &path),
        file_source("ok", &path),
    ]);
    assert_eq!(out.artifacts[0].status, Status::Failed);
    assert_eq!(out.artifacts[0].reason, "invalid path in the bundle");
    assert_eq!(out.artifacts[1].status, Status::Failed);
    assert_eq!(out.artifacts[2].status, Status::Failed);
    assert_eq!(out.artifacts[2].reason, "duplicate path in the bundle");
    assert_eq!(out.artifacts[3].status, Status::Collected);
    assert_eq!(out.order, ["ok"]);
}

#[test]
fn every_artifact_records_its_elapsed_time() {
    let out = run(vec![sh_source("a", "sleep 0.2; echo x")]);
    assert!(out.artifacts[0].elapsed >= Duration::from_millis(150), "{:?}", out.artifacts[0].elapsed);
}

// ---- trees ----

fn tree_fixture(tmp: &Path) -> PathBuf {
    let root = tmp.join("root");
    write(&root.join("a/vendor"), "0x8086\n");
    write(&root.join("a/sub/x1"), "x1");
    write(&root.join("a/sub/y"), "y");
    write(&root.join("a/other"), "other");
    write(&root.join("b/hwmon0/temp"), "40");
    write(&root.join("b/hwmon1/temp"), "41");
    write(&root.join("b/hwmon1/fan"), "1");
    symlink(root.join("a"), root.join("link")).unwrap();
    symlink(&root, root.join("a/sub/up")).unwrap();
    symlink(root.join("a/vendor"), root.join("a/vendor-link")).unwrap();
    root
}

fn tree_source(rel: &str, root: &Path, patterns: &[&str]) -> Source {
    Source::tree(rel, root, patterns, Profile::Minimal, "test")
}

#[test]
fn a_tree_expands_patterns_and_never_follows_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    let patterns = ["a/vendor", "a/sub/*", "b/hwmon*/temp", "link/*", "a/vendor-link", "a/sub/up/*"];
    let out = run(vec![tree_source("devices/d/sysfs/", &root, &patterns)]);
    assert_eq!(out.artifacts.len(), 1);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.rel_path, "devices/d/sysfs/");
    assert_eq!(artifact.status, Status::Collected, "{}", artifact.reason);
    assert_eq!(artifact.files, 5);
    assert_eq!(artifact.denied, 0);
    assert_eq!(artifact.bytes, Bytes(7 + 2 + 1 + 2 + 2));
    assert_eq!(out.text("devices/d/sysfs/a/vendor"), "0x8086\n");
    assert_eq!(out.text("devices/d/sysfs/a/sub/x1"), "x1");
    assert_eq!(out.text("devices/d/sysfs/b/hwmon1/temp"), "41");
    assert_eq!(out.files.len(), 5);
    assert!(!out.files.contains_key("devices/d/sysfs/b/hwmon1/fan"));
    assert!(!out.files.contains_key("devices/d/sysfs/a/other"));
    // Sorted, the order a person would read.
    let mut sorted = out.order.clone();
    sorted.sort();
    assert_eq!(out.order, sorted);
}

#[test]
fn a_tree_without_a_trailing_slash_still_produces_a_directory_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    let out = run(vec![tree_source("t", &root, &["a/vendor"])]);
    assert_eq!(out.artifacts[0].rel_path, "t/");
    assert!(out.files.contains_key("t/a/vendor"));
}

#[test]
fn a_root_that_is_a_symlink_is_canonicalised() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    symlink(&root, tmp.path().join("rootlink")).unwrap();
    let out = run(vec![tree_source("t", &tmp.path().join("rootlink"), &["a/vendor"])]);
    assert_eq!(out.artifacts[0].rel_path, "t/");
    assert!(out.files.contains_key("t/a/vendor"));
}

#[test]
fn a_missing_tree_root_is_not_present() {
    let tmp = tempfile::tempdir().unwrap();
    let artifact = run_one(tree_source("t/", &tmp.path().join("absent"), &["*"]));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "not present");
    assert_eq!(artifact.files, 0);
}

#[test]
fn a_tree_root_that_cannot_be_searched_is_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let locked = tmp.path().join("locked");
    write(&locked.join("inner/f"), "x");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o0)).unwrap();
    let can_search = fs::metadata(locked.join("inner")).is_ok();
    let artifact = run_one(tree_source("t/", &locked.join("inner"), &["*"]).gate(Gate::Root));
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    if can_search {
        return;
    }
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.gate, Gate::Root);
    assert_eq!(artifact.reason, "needs root");
}

#[test]
fn a_tree_without_matches_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    let artifact = run_one(tree_source("t/", &root, &["zzz/*", "../escape"]));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "no matching files");
    assert_eq!(artifact.files, 0);
}

#[test]
fn a_denied_file_makes_the_tree_truncated_and_only_denied_files_skip_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    write(&root.join("c/secret"), "s");
    if !deny_access(&root.join("c/secret")) {
        return;
    }
    let artifact = run_one(tree_source("t/", &root, &["a/vendor", "c/*"]).gate(Gate::Root));
    assert_eq!(artifact.status, Status::Truncated);
    assert_eq!(artifact.denied, 1);
    assert_eq!(artifact.files, 1);
    assert_eq!(artifact.gate, Gate::Root);
    assert_eq!(artifact.reason, "1 of 2 files denied; needs root");

    let artifact = run_one(tree_source("t/", &root, &["c/*"]).gate(Gate::Root));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.denied, 1);
    assert_eq!(artifact.files, 0);
    assert_eq!(artifact.gate, Gate::Root);
    assert_eq!(artifact.reason, "needs root");
}

#[test]
fn a_size_cap_on_one_file_truncates_the_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    let artifact = run_one(tree_source("t/", &root, &["a/sub/*"]).cap(Bytes(1)));
    assert_eq!(artifact.status, Status::Truncated);
    assert_eq!(artifact.reason, "size cap 1 B");
}

#[test]
fn names_that_are_not_utf8_are_left_out_of_a_tree() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    write(&root.join("good"), "g");
    fs::write(root.join(OsStr::from_bytes(b"bad\xff")), "b").unwrap();
    let out = run(vec![tree_source("t/", &root, &["*"])]);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.order, ["t/good"]);
}

#[test]
fn a_tree_is_redacted_per_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    write(&root.join("a.txt"), "on myhost-x\n");
    write(&root.join("b.json"), r#"{"hostname":"myhost-x"}"#);
    let out = collect_with(vec![tree_source("t/", &root, &["*"])], &redacting_options(), FILE_READ_LIMIT);
    assert_eq!(out.text("t/a.txt"), "on <host>\n");
    assert!(out.text("t/b.json").contains("<host>"));
}

// ---- commands ----

#[test]
fn a_command_records_exit_code_via_and_output() {
    let out = run(vec![sh_source("tools/c.txt", "echo hi; exit 3")]);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.status, Status::Collected);
    assert_eq!(artifact.exit, Some(3));
    assert_eq!(artifact.via, "/bin/sh -c echo hi; exit 3");
    assert_eq!(out.text("tools/c.txt"), "hi\n");
}

#[test]
fn a_failing_command_without_output_is_failed() {
    let artifact = run_one(sh_source("tools/c.txt", "exit 4"));
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "exit code 4");
    assert_eq!(artifact.exit, Some(4));
}

#[test]
fn a_command_killed_by_a_signal_is_failed_and_names_the_signal() {
    // Its partial output is kept: it can say why it died.
    let out = run(vec![sh_source("tools/c.txt", "echo partial; kill -KILL $$")]);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "killed by signal 9 (SIGKILL)");
    assert_eq!(artifact.exit, Some(137));
    assert_eq!(out.text("tools/c.txt"), "partial\n");
    // Without output the reason is the same.
    let artifact = run_one(sh_source("tools/c.txt", "kill -TERM $$"));
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "killed by signal 15 (SIGTERM)");
}

#[test]
fn a_denied_marker_outranks_a_crash() {
    // A tool that crashes after printing that it lacks a privilege is reported as needing it.
    let source = sh_source("tools/c.txt", "echo 'cannot access tables'; kill -KILL $$")
        .denied_marker("cannot access tables")
        .gate(Gate::Root);
    let artifact = run_one(source);
    assert_eq!(artifact.status, Status::Truncated);
    assert_eq!(artifact.gate, Gate::Root);
}

#[test]
fn an_outdir_command_killed_by_a_signal_names_the_signal() {
    let artifact = run_one(outdir_source("xpu-smi/d/crashlog/", "kill -KILL $$"));
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "killed by signal 9 (SIGKILL)");
}

#[test]
fn a_tool_that_times_out_skips_the_later_tools_of_its_group_but_not_the_host_group() {
    let in_group = |rel: &str, script: &str| {
        sh_source(rel, script).group("usermode").timeout(Duration::from_millis(200))
    };
    let started = Instant::now();
    let out = run(vec![
        in_group("tools/a.txt", "sleep 5"),
        in_group("tools/b.txt", "echo b"),
        sh_source("system/h1.txt", "sleep 5").timeout(Duration::from_millis(200)),
        sh_source("system/h2.txt", "echo h2"),
    ]);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[1].status, Status::Skipped);
    assert!(
        out.artifacts[1].reason.starts_with("an earlier read in this group did not return"),
        "{}",
        out.artifacts[1].reason
    );
    // A timed-out host command leaves the shared host group alone.
    assert_eq!(out.artifacts[2].status, Status::TimedOut);
    assert_eq!(out.artifacts[3].status, Status::Collected);
    assert_eq!(out.text("system/h2.txt"), "h2\n");
}

#[test]
fn crash_reasons_name_common_signals() {
    assert_eq!(crash_reason(139).as_deref(), Some("killed by signal 11 (SIGSEGV)"));
    assert_eq!(crash_reason(134).as_deref(), Some("killed by signal 6 (SIGABRT)"));
    assert_eq!(crash_reason(129).as_deref(), Some("killed by signal 1 (SIGHUP)"));
    assert_eq!(crash_reason(168).as_deref(), Some("killed by signal 40"));
    for ordinary in [0, 1, 2, 4, 127, 128, 193, 255, -1] {
        assert_eq!(crash_reason(ordinary), None, "{ordinary}");
    }
}

#[test]
fn a_command_that_overruns_is_timed_out() {
    let started = Instant::now();
    let artifact = run_one(sh_source("tools/c.txt", "sleep 5").timeout(Duration::from_millis(200)));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(artifact.status, Status::TimedOut);
    assert_eq!(artifact.reason, "did not finish within 200 ms");
    let started = Instant::now();
    let artifact = run_one(sh_source("tools/c.txt", "sleep 5").timeout(Duration::from_secs(1)));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(artifact.reason, "did not finish within 1 s");
}

#[test]
fn a_missing_tool_is_skipped_as_not_installed() {
    let artifact = run_one(Source::command(
        "tools/c.txt",
        &["xe-bug-report-no-such-tool-0x1"],
        Profile::Minimal,
        "test",
    ));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "xe-bug-report-no-such-tool-0x1 not installed");
    assert_eq!(artifact.gate, Gate::None);
}

#[test]
fn a_program_that_cannot_start_is_failed() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("noexec"), "x");
    let path = tmp.path().join("noexec");
    let argv = [path.to_str().unwrap()];
    let artifact = run_one(Source::command("tools/c.txt", &argv, Profile::Minimal, "test"));
    assert_eq!(artifact.status, Status::Failed);
    assert!(
        artifact.reason.starts_with(&format!("could not start {}", path.display())),
        "{}",
        artifact.reason
    );
}

#[test]
fn an_empty_command_is_failed() {
    let artifact = run_one(Source::command("t", &[""], Profile::Minimal, "test"));
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "empty command");
}

#[test]
fn the_denied_marker_truncates_with_the_gate() {
    let source = sh_source("pci/lspci.txt", "echo 'Capabilities: <access denied>'")
        .denied_marker("<access denied>")
        .gate(Gate::SysAdmin);
    let out = run(vec![source]);
    assert_eq!(out.artifacts[0].status, Status::Truncated);
    assert_eq!(out.artifacts[0].gate, Gate::SysAdmin);
    assert_eq!(out.artifacts[0].reason, "needs root or CAP_SYS_ADMIN");
    assert!(out.files.contains_key("pci/lspci.txt"));
}

#[test]
fn the_unsupported_marker_skips_without_a_gate_and_writes_nothing() {
    let script = "echo '[Error] No valid metrics matched: x' >&2; echo partial";
    let source = || {
        sh_source("xpu-smi/ras.csv", script)
            .unsupported_marker("No valid metrics matched")
            .gate(Gate::DeviceAccess)
    };
    let out = run(vec![source()]);
    assert_eq!(out.artifacts[0].status, Status::Skipped);
    assert_eq!(out.artifacts[0].reason, "not supported by this xpu-smi build");
    assert_eq!(out.artifacts[0].gate, Gate::None);
    assert!(out.files.is_empty());

    let mut other = source();
    other.unsupported_marker = Some("not in the output".to_owned());
    assert_eq!(run_one(other).status, Status::Collected);
    let mut none = source();
    none.unsupported_marker = None;
    assert_eq!(run_one(none).status, Status::Collected);

    // A failing run whose output holds the marker is unsupported too, and keeps its exit code.
    let failing = sh_source("xpu-smi/ras.csv", "echo 'No valid metrics matched' >&2; exit 4")
        .unsupported_marker("No valid metrics matched");
    let artifact = run_one(failing);
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.exit, Some(4));
}

#[test]
fn output_caps_keep_the_head_or_the_tail() {
    let out = run(vec![sh_source("tools/c.txt", "printf '01\\n3456789abcdef'").cap(Bytes(4))]);
    assert_eq!(out.text("tools/c.txt"), "01\n");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
    assert_eq!(out.artifacts[0].reason, "size cap 4 B");

    let out = run(vec![sh_source("tools/c.txt", "printf '012345\\n789'").cap(Bytes(5)).tail()]);
    assert_eq!(out.text("tools/c.txt"), "789");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
}

#[test]
fn command_output_is_redacted_and_json_is_parsed() {
    let out = collect_with(
        vec![
            sh_source("tools/net.txt", "echo on myhost-x for alice"),
            sh_source("xpu-smi/d.json", r#"echo '{"hostname":"myhost-x","note":"on myhost-x","n":3}'"#),
        ],
        &redacting_options(),
        FILE_READ_LIMIT,
    );
    assert_eq!(out.text("tools/net.txt"), "on <host> for <user>\n");
    let json: serde_json::Value = serde_json::from_slice(&out.files["xpu-smi/d.json"]).unwrap();
    assert_eq!(json["hostname"], "<host>");
    assert_eq!(json["note"], "on <host>");
    assert_eq!(json["n"], 3);
    // Two-space indent and a final newline.
    assert!(out.text("xpu-smi/d.json").starts_with("{\n  \"hostname\""));
    assert!(out.text("xpu-smi/d.json").ends_with("}\n"));
}

// ---- xpu-smi ----

#[test]
fn an_xpu_smi_source_without_the_executable_is_skipped_not_found() {
    let source = Source::xpu_smi("xpu-smi/discovery.json", &["discovery".to_owned()], Profile::Minimal, "t")
        .gate(Gate::DeviceAccess)
        .available(|| false);
    let artifact = run_one(source);
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "xpu-smi not found");
    assert_eq!(artifact.gate, Gate::None);
    assert_eq!(artifact.files, 1);
}

#[test]
fn an_xpu_smi_source_runs_the_executable_and_shows_it_by_name() {
    let args = ["-c".to_owned(), "echo version 1".to_owned()];
    let source = Source::xpu_smi("xpu-smi/version.txt", &args, Profile::Minimal, "t");
    let out = collect_with(vec![source], &sh_options(), FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.artifacts[0].via, "xpu-smi -c echo version 1");
    assert_eq!(out.text("xpu-smi/version.txt"), "version 1\n");
}

#[test]
fn a_nonexistent_xpu_smi_executable_fails_to_start() {
    let options =
        CollectOptions { xpu_smi: Some(PathBuf::from("/nonexistent/dir/xpu-smi")), ..plain_options() };
    let source = Source::xpu_smi("x", &[], Profile::Minimal, "t");
    let out = collect_with(vec![source], &options, FILE_READ_LIMIT);
    let artifact = &out.artifacts[0];
    // A path with a separator is spawned as it is: not found is "not installed".
    assert_eq!(artifact.status, Status::Skipped, "{}", artifact.reason);
    assert_eq!(artifact.reason, "xpu-smi not installed");
}

// ---- {outdir} ----

const OUTDIR_SCRIPT: &str =
    "mkdir \"$0/sub\"; echo one > \"$0/a b:c\"; echo two > \"$0/sub/two.txt\"; echo out";

#[test]
fn an_outdir_command_collects_stdout_and_the_files_it_wrote() {
    let out = run(vec![outdir_source("xpu-smi/d/raslog", OUTDIR_SCRIPT)]);
    assert_eq!(out.artifacts.len(), 1);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.rel_path, "xpu-smi/d/raslog/");
    assert_eq!(artifact.status, Status::Collected);
    assert_eq!(artifact.files, 3);
    assert_eq!(artifact.bytes, Bytes(4 + 4 + 4));
    assert_eq!(out.text("xpu-smi/d/raslog/stdout.txt"), "out\n");
    assert_eq!(out.text("xpu-smi/d/raslog/a_b_c"), "one\n");
    assert_eq!(out.text("xpu-smi/d/raslog/sub/two.txt"), "two\n");
    assert_eq!(out.files.len(), 3);
    assert!(artifact.via.ends_with("{outdir}"), "{}", artifact.via);
}

#[test]
fn an_xpu_smi_outdir_source_uses_the_executable() {
    let args = ["-c".to_owned(), OUTDIR_SCRIPT.to_owned(), "{outdir}".to_owned()];
    let source = Source::xpu_smi("xpu-smi/x/", &args, Profile::Minimal, "t");
    let out = collect_with(vec![source], &sh_options(), FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.artifacts[0].files, 3);
    assert_eq!(out.artifacts[0].via, format!("xpu-smi -c {OUTDIR_SCRIPT} {{outdir}}"));
    assert!(out.files.contains_key("xpu-smi/x/a_b_c"));
    assert!(out.files.contains_key("xpu-smi/x/sub/two.txt"));
}

#[test]
fn the_output_directory_is_removed_and_unregistered() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("dir");
    let script = format!("echo \"$0\" > {}; echo ok > \"$0/f\"", marker.display());
    let out = run(vec![outdir_source("d/", &script)]);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    let dir = PathBuf::from(fs::read_to_string(&marker).unwrap().trim());
    assert!(!dir.exists(), "{} was not removed", dir.display());
    let dirs = OUTSTANDING_DIRS.lock().unwrap();
    assert!(!dirs.contains(&dir));
}

#[test]
fn an_outdir_is_registered_while_it_exists() {
    let dir = Outdir::create().unwrap();
    let path = dir.path().to_path_buf();
    assert!(OUTSTANDING_DIRS.lock().unwrap().contains(&path));
    drop(dir);
    assert!(!OUTSTANDING_DIRS.lock().unwrap().contains(&path));
    assert!(!path.exists());
}

#[test]
fn outdir_text_is_redacted_json_by_key_and_binary_is_verbatim() {
    let options = CollectOptions {
        rules: Rules::default(),
        identity: Context { hostnames: vec!["secrethost".into()], user_names: vec!["alice".into()] },
        ..CollectOptions::default()
    };
    let script = concat!(
        "echo 'host=secrethost user=alice' > \"$0/f.txt\"; ",
        "echo '{\"serial_number\":\"S123\",\"note\":\"on secrethost\"}' > \"$0/x.json\"; ",
        "printf 'secrethost\\000\\001' > \"$0/bin.dat\"; ",
        "printf '\\377\\376h\\000i\\000 \\000s\\000e\\000c\\000r\\000e\\000t\\000h\\000o\\000s\\000t\\000\\n\\000' > \"$0/u16.txt\"; ",
        "printf '\\200abc' > \"$0/bad.dat\"; ",
        "printf '\\377\\376\\377' > \"$0/odd.dat\""
    );
    let out = collect_with(vec![outdir_source("d/", script)], &options, FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Collected, "{:?}", out.artifacts[0]);
    assert_eq!(out.text("d/f.txt"), "host=<host> user=<user>\n");
    let json: serde_json::Value = serde_json::from_slice(&out.files["d/x.json"]).unwrap();
    assert_eq!(json["serial_number"], "<serial>");
    assert_eq!(json["note"], "on <host>");
    // Binary content (a NUL byte, or not UTF-8) is written as it is.
    assert_eq!(out.files["d/bin.dat"], b"secrethost\0\x01");
    assert_eq!(out.files["d/bad.dat"], b"\x80abc");
    assert_eq!(out.files["d/odd.dat"], b"\xff\xfe\xff");
    // UTF-16 with a byte order mark becomes redacted UTF-8.
    assert_eq!(out.text("d/u16.txt"), "hi <host>\n");
}

#[test]
fn outdir_files_are_verbatim_without_redaction_and_for_binary_sources() {
    let script = "echo secrethost > \"$0/f.txt\"";
    let out = run(vec![outdir_source("d/", script)]);
    assert_eq!(out.text("d/f.txt"), "secrethost\n");
    let options = CollectOptions {
        rules: Rules::default(),
        identity: Context { hostnames: vec!["secrethost".into()], user_names: vec![] },
        ..CollectOptions::default()
    };
    let out = collect_with(vec![outdir_source("d/", script).binary()], &options, FILE_READ_LIMIT);
    assert_eq!(out.text("d/f.txt"), "secrethost\n");
}

#[test]
fn the_unsupported_marker_applies_to_outdir_sources_too() {
    let script = "echo \"'raslog' is not a valid subcommand.\"; echo usage; exit 2";
    let source = outdir_source("xpu-smi/raslog/", script).unsupported_marker("is not a valid subcommand");
    let out = run(vec![source]);
    let artifact = &out.artifacts[0];
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "not supported by this xpu-smi build");
    assert_eq!(artifact.exit, Some(2));
    assert_eq!(artifact.rel_path, "xpu-smi/raslog/");
    assert!(out.files.is_empty());
}

#[test]
fn a_file_named_like_the_stdout_entry_gets_another_name() {
    let source = outdir_source("d/", "echo mine > \"$0/stdout.txt\"; echo out");
    let out = run(vec![source]);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.artifacts[0].files, 2);
    assert_eq!(out.text("d/stdout.txt"), "out\n");
    assert_eq!(out.text("d/stdout.txt-2"), "mine\n");
}

#[test]
fn names_that_sanitise_alike_get_numbered_suffixes() {
    let source = outdir_source("d/", "echo 1 > \"$0/a b\"; echo 2 > \"$0/a:b\"; echo 3 > \"$0/a?b\"");
    let out = run(vec![source]);
    assert_eq!(out.artifacts[0].files, 3);
    assert!(out.files.contains_key("d/a_b"));
    assert!(out.files.contains_key("d/a_b-2"));
    assert!(out.files.contains_key("d/a_b-3"));
}

#[test]
fn an_unreadable_outdir_file_makes_the_artifact_truncated() {
    let source = outdir_source("d/", "echo ok > \"$0/ok\"; echo no > \"$0/secret\"; chmod 0 \"$0/secret\"");
    let out = run(vec![source]);
    let artifact = &out.artifacts[0];
    if artifact.files == 2 {
        return; // running as root: nothing is unreadable
    }
    assert_eq!(artifact.status, Status::Truncated);
    assert_eq!(artifact.reason, "1 files could not be read");
    assert_eq!(artifact.files, 1);
    assert!(out.files.contains_key("d/ok"));
}

#[test]
fn an_outdir_command_without_output_is_skipped_or_failed() {
    let artifact = run_one(outdir_source("d/", "true"));
    assert_eq!(artifact.status, Status::Skipped);
    assert_eq!(artifact.reason, "produced no output");
    assert_eq!(artifact.files, 0);
    let artifact = run_one(outdir_source("d/", "exit 2"));
    assert_eq!(artifact.status, Status::Failed);
    assert_eq!(artifact.reason, "exit code 2");
}

#[test]
fn outdir_files_are_not_cut_by_the_source_cap_but_stdout_is() {
    let source = outdir_source("d/", "echo 0123456789 > \"$0/f\"; printf '01\\n3456789'").cap(Bytes(4));
    let out = run(vec![source]);
    assert_eq!(out.text("d/stdout.txt"), "01\n");
    assert_eq!(out.text("d/f"), "0123456789\n");
    assert_eq!(out.artifacts[0].status, Status::Truncated);
}

// ---- builtins ----

fn builtin(rel: &str, f: impl Fn(&dyn Reader) -> Vec<Produced> + Send + Sync + 'static) -> Source {
    Source::builtin(rel, Box::new(f), Profile::Minimal, "test")
}

fn produced(rel: &str, status: Status, data: &str, reason: &str) -> Produced {
    Produced {
        rel_path: rel.to_owned(),
        status,
        data: data.as_bytes().to_vec(),
        reason: reason.to_owned(),
        via: String::new(),
    }
}

#[test]
fn a_builtin_yields_one_artifact_per_output_with_gates() {
    let source = builtin("kernel/kmsg.txt", |_| {
        let mut one = produced("kernel/one.txt", Status::Collected, "1", "");
        one.via = "somewhere".to_owned();
        vec![
            one,
            produced("kernel/two.txt", Status::Skipped, "", "needs something"),
            produced("kernel/three.txt", Status::Truncated, "t\n", "needs more"),
            produced("kernel/four.txt", Status::Skipped, "", "not present"),
        ]
    })
    .gate(Gate::KernelLog);
    let out = run(vec![source]);
    assert_eq!(out.artifacts.len(), 4);
    assert_eq!(out.artifacts[0].rel_path, "kernel/one.txt");
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.artifacts[0].via, "somewhere");
    assert_eq!(out.artifacts[0].gate, Gate::None);
    assert_eq!(out.artifacts[0].files, 1);
    assert_eq!(out.artifacts[1].status, Status::Skipped);
    assert_eq!(out.artifacts[1].gate, Gate::KernelLog);
    assert_eq!(out.artifacts[2].status, Status::Truncated);
    assert_eq!(out.artifacts[2].gate, Gate::KernelLog);
    assert_eq!(out.artifacts[2].reason, "needs more");
    assert_eq!(out.artifacts[3].gate, Gate::None);
    assert_eq!(out.text("kernel/one.txt"), "1");
    assert_eq!(out.text("kernel/three.txt"), "t\n");
    assert!(!out.files.contains_key("kernel/two.txt"));
}

#[test]
fn a_builtin_reads_files_through_the_reader() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "from reader");
    let path = tmp.path().join("f");
    let missing = tmp.path().join("missing");
    let source = builtin("a/b.txt", move |reader| {
        let read = reader.read(&path, Bytes::kib(1), Keep::Head);
        assert_eq!(read.outcome, ReadOutcome::Read);
        let gone = reader.read(&missing, Bytes::kib(1), Keep::Head);
        assert_eq!(gone.outcome, ReadOutcome::Missing);
        let cut = reader.read(&path, Bytes(4), Keep::Tail);
        assert!(cut.truncated);
        assert_eq!(cut.data, b"ader");
        vec![Produced { rel_path: "a/b.txt".into(), data: read.data, ..Produced::default() }]
    });
    let out = run(vec![source]);
    assert_eq!(out.text("a/b.txt"), "from reader");
}

#[test]
fn a_builtin_output_with_an_invalid_path_fails_that_output() {
    let source = builtin("a/b.txt", |_| vec![produced("a/../../b.txt", Status::Collected, "x", "")]);
    let out = run(vec![source]);
    assert_eq!(out.artifacts.len(), 1);
    assert_eq!(out.artifacts[0].status, Status::Failed);
    assert!(out.files.is_empty());
}

#[test]
fn a_builtin_output_is_capped_filtered_and_redacted_like_a_file() {
    let source = builtin("a.txt", |_| {
        vec![produced("a.txt", Status::Collected, "skip\nmyhost-x up\nmore myhost-x\n", "")]
    })
    .keep_lines(&["myhost"])
    .cap(Bytes(10));
    let out = collect_with(vec![source], &redacting_options(), FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Truncated);
    assert_eq!(out.artifacts[0].reason, "size cap 10 B");
    // Filtered to "myhost-x up\nmore myhost-x\n", cut to 10 bytes, the partial line dropped
    // (nothing whole is left), then redacted.
    assert_eq!(out.text("a.txt"), "");
}

#[test]
fn a_panicking_builtin_fails_the_source_and_the_rest_goes_on() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let out = run(vec![
        builtin("a/b.txt", |_| panic!("boom (expected by the test)")),
        file_source("system/after", &tmp.path().join("f")),
    ]);
    assert_eq!(out.artifacts[0].status, Status::Failed);
    assert!(out.artifacts[0].reason.contains("panicked"), "{}", out.artifacts[0].reason);
    assert_eq!(out.artifacts[1].status, Status::Collected);
}

#[test]
fn a_builtin_that_never_returns_times_out_and_is_abandoned() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let hang = builtin("kernel/hang.txt", |_| {
        std::thread::sleep(Duration::from_secs(30));
        Vec::new()
    })
    .timeout(Duration::from_millis(300));
    let started = Instant::now();
    let out = run(vec![hang, file_source("system/after", &tmp.path().join("f"))]);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert_eq!(out.artifacts.len(), 2);
    assert_eq!(out.artifacts[0].rel_path, "kernel/hang.txt");
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[0].reason, "did not finish within 300 ms");
    assert_eq!(out.artifacts[1].status, Status::Collected);
}

#[test]
fn a_hung_builtin_does_not_open_the_group_of_the_others() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let hang = builtin("a", |_| {
        std::thread::sleep(Duration::from_secs(30));
        Vec::new()
    })
    .timeout(Duration::from_millis(200))
    .group("device:0000:03:00.0");
    let same_group = file_source("b", &tmp.path().join("f")).group("device:0000:03:00.0");
    let out = run(vec![hang, same_group]);
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[1].status, Status::Collected);
}

// ---- blocked reads ----

fn make_fifo(path: &Path) -> bool {
    std::process::Command::new("mkfifo").arg(path).status().is_ok_and(|status| status.success())
}

/// Releases a thread blocked in `open(fifo)`: opening it read-write never blocks.
fn release_fifo(path: &Path) {
    if let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(path) {
        std::thread::sleep(Duration::from_millis(100));
        drop(file);
    }
}

#[test]
fn a_blocked_read_opens_its_group_only() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("fifo");
    if !make_fifo(&fifo) {
        return;
    }
    write(&tmp.path().join("plain"), "plain");
    let group = "device:0000:03:00.0";
    let blocking = |rel: &str| {
        let fifo = fifo.clone();
        let rel_owned = rel.to_owned();
        builtin(rel, move |reader| {
            let read = reader.read(&fifo, Bytes::kib(1), Keep::Head);
            let mut item = Produced { rel_path: rel_owned.clone(), ..Produced::default() };
            if read.outcome != ReadOutcome::Read {
                item.status = Status::Failed;
                item.reason = read.error;
            }
            vec![item]
        })
        .group(group)
    };
    let plain = tmp.path().join("plain");
    let sources = vec![
        blocking("devices/x/fifo.txt"),
        file_source("devices/x/second.txt", &plain).group(group),
        blocking("devices/x/again.txt"),
        sh_source("devices/x/cmd.txt", "echo hi").group(group),
        tree_source("devices/x/tree/", tmp.path(), &["plain"]).group(group),
        file_source("system/other.txt", &plain),
    ];
    let started = Instant::now();
    let out = collect_with(sources, &plain_options(), Duration::from_millis(300));
    let took = started.elapsed();
    release_fifo(&fifo);

    let earlier = "an earlier read in this group did not return within 300 ms";
    assert_eq!(out.artifacts.len(), 6);
    assert_eq!(out.artifacts[0].status, Status::Failed);
    assert_eq!(out.artifacts[0].reason, "did not return within 300 ms");
    assert_eq!(out.artifacts[1].status, Status::Skipped);
    assert_eq!(out.artifacts[1].reason, earlier);
    assert_eq!(out.artifacts[2].status, Status::Failed);
    assert_eq!(out.artifacts[2].reason, earlier);
    assert_eq!(out.artifacts[3].status, Status::Skipped);
    assert_eq!(out.artifacts[3].reason, earlier);
    assert_eq!(out.artifacts[4].status, Status::Skipped);
    assert_eq!(out.artifacts[4].reason, earlier);
    assert_eq!(out.artifacts[5].status, Status::Collected);
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn a_file_source_that_blocks_is_timed_out() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("fifo");
    if !make_fifo(&fifo) {
        return;
    }
    let out = collect_with(vec![file_source("a", &fifo)], &plain_options(), SHORT_LIMIT);
    release_fifo(&fifo);
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[0].reason, "did not return within 400 ms");
}

#[test]
fn a_tree_whose_read_blocks_stops_with_what_it_has() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    write(&root.join("a"), "first");
    let fifo = root.join("b");
    if !make_fifo(&fifo) {
        return;
    }
    write(&root.join("c"), "third");
    // The FIFO is neither a regular file nor a directory: the walk skips it, so it never blocks.
    let out = collect_with(vec![tree_source("t/", &root, &["*"])], &plain_options(), SHORT_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Collected);
    assert_eq!(out.order, ["t/a", "t/c"]);
}

#[test]
fn a_hung_available_check_is_not_waited_for() {
    let source = file_source("a", Path::new("/proc/self/comm")).available(|| {
        std::thread::sleep(Duration::from_secs(30));
        true
    });
    let started = Instant::now();
    let out = collect_with(vec![source], &plain_options(), SHORT_LIMIT);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
}

// ---- redaction and identifying sources ----

#[test]
fn identifying_sources_are_skipped_while_redacting_only() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("serial"), "SERIAL");
    let source = || file_source("system/dmi-serials/serial", &tmp.path().join("serial")).identifying();
    let options = CollectOptions { rules: Rules::default(), ..CollectOptions::default() };
    let out = collect_with(vec![source()], &options, FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Skipped);
    assert_eq!(out.artifacts[0].reason, "withheld because it cannot be redacted; use --no-redact");
    assert!(out.files.is_empty());
    assert_eq!(run_one(source()).status, Status::Collected);
    // One rule is enough to withhold it.
    let one = CollectOptions { rules: Rules { users: true, ..Rules::none() }, ..CollectOptions::default() };
    let out = collect_with(vec![source()], &one, FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Skipped);
}

#[test]
fn text_and_json_are_redacted_and_bad_json_falls_back_to_text() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("net.txt"), "Linux myhost-x 6.1 on myhost-x\nuser=alice\n");
    write(&tmp.path().join("d.json"), r#"{"hostname":"myhost-x","note":"booted on myhost-x","n":3}"#);
    write(&tmp.path().join("bad.json"), "not json on myhost-x");
    let out = collect_with(
        vec![
            file_source("system/net.txt", &tmp.path().join("net.txt")),
            file_source("xpu-smi/d.json", &tmp.path().join("d.json")),
            file_source("xpu-smi/bad.json", &tmp.path().join("bad.json")),
        ],
        &redacting_options(),
        FILE_READ_LIMIT,
    );
    assert!(!out.text("system/net.txt").contains("myhost-x"));
    assert!(out.text("system/net.txt").contains("<host>"));
    assert!(!out.text("system/net.txt").contains("alice"));
    let json: serde_json::Value = serde_json::from_slice(&out.files["xpu-smi/d.json"]).unwrap();
    assert_eq!(json["hostname"], "<host>");
    assert_eq!(json["note"], "booted on <host>");
    assert_eq!(json["n"], 3);
    assert!(!out.text("xpu-smi/bad.json").contains("myhost-x"));
}

#[test]
fn binary_content_is_not_redacted_or_filtered() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("bin"), "myhost-x");
    let source = file_source("system/bin", &tmp.path().join("bin")).binary().keep_lines(&["nomatch"]);
    let out = collect_with(vec![source], &redacting_options(), FILE_READ_LIMIT);
    assert_eq!(out.text("system/bin"), "myhost-x");
}

#[test]
fn the_filter_runs_before_redaction() {
    let tmp = tempfile::tempdir().unwrap();
    // After redaction "myhost-x" is "<host>", which would no longer match the needle.
    write(&tmp.path().join("f"), "line myhost-x\nother\n");
    let source = file_source("f", &tmp.path().join("f")).keep_lines(&["myhost-x"]);
    let out = collect_with(vec![source], &redacting_options(), FILE_READ_LIMIT);
    assert_eq!(out.text("f"), "line <host>\n");
}

// ---- the sink ----

#[test]
fn a_failing_sink_stops_collection_and_is_returned() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("serial"), "SERIAL");
    let path = tmp.path().join("serial");
    let sources: Vec<Source> = ["a", "b", "c"].iter().map(|rel| file_source(rel, &path)).collect();
    let mut calls = 0;
    let mut sink = |_: &str, _: &[u8]| {
        calls += 1;
        if calls < 2 { Ok(()) } else { Err(Error::Io(io::Error::other("disk full"))) }
    };
    let result = collect_with_limit(sources.into(), &plain_options(), &mut sink, FILE_READ_LIMIT);
    assert_eq!(result.unwrap_err().to_string(), "disk full");
    assert_eq!(calls, 2);
}

#[test]
fn a_failing_sink_in_a_tree_or_command_stops_too() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tree_fixture(tmp.path());
    let sources = vec![tree_source("t/", &root, &["a/*"]), sh_source("c", "echo x")];
    let mut calls = 0;
    let mut sink = |_: &str, _: &[u8]| {
        calls += 1;
        Err(Error::Io(io::Error::other("full")))
    };
    let result = collect_with_limit(sources.into(), &plain_options(), &mut sink, FILE_READ_LIMIT);
    assert!(result.is_err());
    assert_eq!(calls, 1);
}

// ---- the deadline ----

#[test]
fn sources_after_the_deadline_are_skipped_and_the_rest_still_reported() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let sources = vec![
        file_source("system/a", &tmp.path().join("f")),
        tree_source("t/", tmp.path(), &["*"]),
        sh_source("tools/c", "echo x"),
        builtin("kernel/b", |_| panic!("must not run")),
        Source::xpu_smi("xpu-smi/v", &[], Profile::Minimal, "t"),
    ];
    let options = CollectOptions { deadline: Some(Instant::now()), ..plain_options() };
    let out = collect_with(sources, &options, FILE_READ_LIMIT);
    assert_eq!(out.artifacts.len(), 5);
    for artifact in &out.artifacts {
        assert_eq!(artifact.status, Status::Skipped, "{artifact:?}");
        assert_eq!(artifact.reason, "collector deadline reached");
        assert_eq!(artifact.gate, Gate::None);
    }
    assert_eq!(out.artifacts[0].files, 1);
    assert_eq!(out.artifacts[1].files, 0);
    assert!(out.files.is_empty());
}

#[test]
fn the_deadline_is_checked_between_sources() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let path = tmp.path().join("f");
    let options = CollectOptions {
        deadline: Instant::now().checked_add(Duration::from_millis(100)),
        ..plain_options()
    };
    // A file read is not clipped; the slow sink makes the first source end after the deadline.
    let mut sink = |_: &str, _: &[u8]| {
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    };
    let sources = vec![file_source("system/a", &path), sh_source("tools/after", "echo x")];
    let artifacts = collect_with_limit(sources.into(), &options, &mut sink, FILE_READ_LIMIT).unwrap();
    assert_eq!(artifacts[0].status, Status::Collected);
    assert_eq!(artifacts[1].status, Status::Skipped);
    assert_eq!(artifacts[1].reason, "collector deadline reached");
}

#[test]
fn a_deadline_in_the_future_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let options =
        CollectOptions { deadline: Instant::now().checked_add(Duration::from_secs(600)), ..plain_options() };
    let out = collect_with(vec![file_source("a", &tmp.path().join("f"))], &options, FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].status, Status::Collected);
}

#[test]
fn the_public_collect_uses_the_default_read_limit() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("f"), "x");
    let sources: Arc<[Source]> = vec![file_source("a", &tmp.path().join("f"))].into();
    let mut names = Vec::new();
    let mut sink = |name: &str, _: &[u8]| {
        names.push(name.to_owned());
        Ok(())
    };
    let artifacts = collect(sources, &plain_options(), &mut sink).unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(names, ["a"]);
}

// ---- the deadline clips running sources ----

#[test]
fn a_child_is_clipped_to_the_deadline() {
    let options =
        CollectOptions { deadline: Instant::now().checked_add(Duration::from_secs(1)), ..plain_options() };
    let slow = sh_source("tools/slow", "sleep 30").timeout(Duration::from_secs(30));
    let started = Instant::now();
    let out = collect_with(vec![slow, sh_source("tools/after", "echo x")], &options, FILE_READ_LIMIT);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[0].reason, "collector deadline reached");
    assert_eq!(out.artifacts[1].status, Status::Skipped);
    assert_eq!(out.artifacts[1].reason, "collector deadline reached");
}

#[test]
fn a_child_within_the_deadline_keeps_its_own_timeout_reason() {
    let options =
        CollectOptions { deadline: Instant::now().checked_add(Duration::from_secs(60)), ..plain_options() };
    let slow = sh_source("tools/slow", "sleep 30").timeout(Duration::from_millis(300));
    let out = collect_with(vec![slow], &options, FILE_READ_LIMIT);
    assert_eq!(out.artifacts[0].reason, "did not finish within 300 ms");
}

#[test]
fn a_builtin_is_clipped_to_the_deadline() {
    let options = CollectOptions {
        deadline: Instant::now().checked_add(Duration::from_millis(500)),
        ..plain_options()
    };
    let hang = builtin("kernel/hang", |_| {
        std::thread::sleep(Duration::from_secs(30));
        Vec::new()
    })
    .timeout(Duration::from_secs(30));
    let started = Instant::now();
    let out = collect_with(vec![hang], &options, FILE_READ_LIMIT);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert_eq!(out.artifacts[0].status, Status::TimedOut);
    assert_eq!(out.artifacts[0].reason, "collector deadline reached");
}

#[test]
fn a_tree_walk_stops_at_the_deadline_with_what_it_has() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir_all(&root).unwrap();
    for i in 0..1500 {
        fs::write(root.join(format!("f{i:04}")), "x").unwrap();
    }
    let options = CollectOptions {
        deadline: Instant::now().checked_add(Duration::from_millis(150)),
        ..plain_options()
    };
    let started = Instant::now();
    let out = collect_with(vec![tree_source("t/", &root, &["*"])], &options, FILE_READ_LIMIT);
    let artifact = &out.artifacts[0];
    if started.elapsed() < Duration::from_millis(150) {
        return; // a very fast machine finished the whole tree
    }
    assert_eq!(artifact.reason, "collector deadline reached");
    assert!(artifact.files < 1500);
    let expected = if artifact.files > 0 { Status::Truncated } else { Status::Skipped };
    assert_eq!(artifact.status, expected);
}

#[test]
fn a_cut_drops_the_partial_line_at_its_edge() {
    let mut tail = b"t-host-x kernel: a\nline two\n".to_vec();
    drop_partial_line(&mut tail, Keep::Tail);
    assert_eq!(tail, b"line two\n");
    let mut head = b"line one\nline two myho".to_vec();
    drop_partial_line(&mut head, Keep::Head);
    assert_eq!(head, b"line one\n");
    let mut lone = b"no newline at all".to_vec();
    drop_partial_line(&mut lone, Keep::Tail);
    assert!(lone.is_empty());
}

#[test]
fn a_tail_cap_through_a_host_name_leaks_no_fragment() {
    // The cap lands inside "myhost-x" on the first kept line; the fragment "host-x" would not match
    // the whole-token host rule, so the partial line must go before redaction.
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    write(&log, "[1] myhost-x kernel: one\n[2] myhost-x kernel: two\n");
    let cap = "host-x kernel: one\n[2] myhost-x kernel: two\n".len() as u64;
    let source = file_source("kernel/kmsg.txt", &log).cap(Bytes(cap)).tail();
    let out = collect_with(vec![source], &redacting_options(), FILE_READ_LIMIT);
    let text = out.text("kernel/kmsg.txt");
    assert_eq!(text, "[2] <host> kernel: two\n");
    assert!(!text.contains("host-x"));
    assert_eq!(out.artifacts[0].status, Status::Truncated);
}

#[test]
fn a_truncated_builtin_loses_a_trailing_fragment() {
    let source =
        builtin("k.txt", |_| vec![produced("k.txt", Status::Truncated, "line myhost-x\nmyho", "cap")]);
    let out = collect_with(vec![source], &redacting_options(), FILE_READ_LIMIT);
    assert_eq!(out.text("k.txt"), "line <host>\n");
    let whole = builtin("w.txt", |_| vec![produced("w.txt", Status::Truncated, "t", "needs more")]);
    let out = run(vec![whole]);
    assert_eq!(out.text("w.txt"), "");
}
