// SPDX-License-Identifier: MIT
//! Unit tests for `src/bundle/summary.rs`.

use super::*;
use crate::bundle::manifest::json_text;
use crate::bundle::source::Profile;
use crate::units::Bytes;

fn artifact_of(status: Status, gate: Gate) -> Artifact {
    Artifact { status, gate, files: 1, ..Artifact::default() }
}

fn result_of(statuses: &[Status], archive_bytes: u64) -> BundleResult {
    BundleResult {
        artifacts: statuses.iter().map(|&status| artifact_of(status, Gate::None)).collect(),
        archive_bytes: Bytes(archive_bytes),
        ..BundleResult::default()
    }
}

fn gated(status: Status, gate: Gate, path: &str, reason: &str) -> Artifact {
    Artifact { status, gate, rel_path: path.into(), reason: reason.into(), ..Artifact::default() }
}

fn host_like_run() -> BundleResult {
    // The shape of a normal-user run on a GPU host: 6 + 5 denials, 6 of them partial.
    let mut artifacts = vec![artifact_of(Status::Collected, Gate::None); 39];
    artifacts.push(gated(Status::Skipped, Gate::None, "system/dmi-serials/", "withheld while redacting"));
    artifacts.push(gated(Status::Truncated, Gate::Root, "kernel/xe-parameters/", "45 of 60 files denied"));
    artifacts.push(gated(Status::Skipped, Gate::Root, "kernel/drm-debug.txt", "needs root"));
    artifacts.push(gated(Status::Truncated, Gate::Root, "devices/d/sysfs/", "4 of 156 files denied"));
    artifacts.push(gated(Status::Skipped, Gate::Root, "devices/d/debugfs/", "needs root"));
    artifacts.push(gated(Status::Skipped, Gate::Root, "dumps/d/pmt-crashlog1.bin", "needs root"));
    artifacts.push(gated(Status::Skipped, Gate::Root, "dumps/d/pmt-crashlog2.bin", "needs root"));
    artifacts.push(gated(Status::Skipped, Gate::None, "devices/d/ras-counters.json", "no drm-ras"));
    for n in 0..4 {
        artifacts.push(gated(Status::Truncated, Gate::SysAdmin, &format!("pci/{n}.txt"), "needs CAP"));
    }
    artifacts.push(gated(Status::Skipped, Gate::SysAdmin, "pci/x.txt", "needs CAP"));
    artifacts.push(gated(Status::Skipped, Gate::None, "xpu-smi/raslog/", "not supported"));
    BundleResult { artifacts, archive_bytes: Bytes(730_600), ..BundleResult::default() }
}

#[test]
fn report_counts_add_up_and_name_each_missing_privilege_once() {
    let text = format_report(&host_like_run(), Path::new("b.zip"), Privilege::Unprivileged, false);
    assert_eq!(
        text,
        "Wrote b.zip (713.5 KiB)\n\
             \x20 53 sources: 39 complete, 6 partial, 8 not collected\n\
             \x20 needs root: 4 not collected, 2 partial\n\
             \x20 needs root or CAP_SYS_ADMIN: 1 not collected, 4 partial\n\
             \x20 other reasons: 3 not collected\n\
             Re-run with sudo for the full bundle.\n\
             Details: unzip -p b.zip manifest.json (or run with --verbose)\n"
    );
}

#[test]
fn a_complete_run_is_two_lines() {
    let result = result_of(&[Status::Collected], 812);
    assert_eq!(
        format_report(&result, Path::new("b.zip"), Privilege::Unprivileged, false),
        "Wrote b.zip (812 B)\n  1 source: 1 complete\n"
    );
    assert!(
        format_report(&BundleResult::default(), Path::new("b.zip"), Privilege::Unprivileged, false)
            .contains("0 sources: 0 complete")
    );
}

#[test]
fn timeouts_and_failures_are_named_and_need_no_sudo_hint() {
    let result = result_of(&[Status::Collected, Status::TimedOut, Status::Failed, Status::Skipped], 1536);
    let text = format_report(&result, Path::new("b.zip"), Privilege::Unprivileged, false);
    assert!(text.contains("4 sources: 1 complete, 3 not collected (1 timed out, 1 failed)\n"), "{text}");
    assert!(text.contains("  other reasons: 3 not collected\n"), "{text}");
    assert!(!text.contains("sudo"), "{text}");
    assert!(text.contains("(1.5 KiB)"));
}

#[test]
fn verbose_lists_every_incomplete_source_with_its_reason() {
    let text = format_report(&host_like_run(), Path::new("b.zip"), Privilege::Unprivileged, true);
    assert!(text.contains("Not complete:\n"), "{text}");
    assert!(text.contains("  partial        kernel/xe-parameters/"), "{text}");
    assert!(text.contains("  not collected  kernel/drm-debug.txt"), "{text}");
    assert!(text.contains("45 of 60 files denied\n"), "{text}");
    assert_eq!(text.matches("  partial  ").count() + text.matches("  not collected  ").count(), 14);
    assert!(text.ends_with("Details: unzip -p b.zip manifest.json\n"), "{text}");
}

#[test]
fn gates_are_reported_in_gate_order_with_their_hints() {
    let artifacts = vec![
        gated(Status::Skipped, Gate::Elevated, "a", ""),
        gated(Status::Skipped, Gate::Root, "b", ""),
        gated(Status::Skipped, Gate::KernelLog, "c", ""),
        gated(Status::Skipped, Gate::DeviceAccess, "d", ""),
    ];
    let result = BundleResult { artifacts, ..BundleResult::default() };
    let text = format_report(&result, Path::new("b.zip"), Privilege::Unprivileged, false);
    let at = |needle: &str| text.find(needle).unwrap();
    assert!(at("needs root, CAP_SYSLOG") < at("needs membership of the 'render'"));
    assert!(at("needs membership of the 'render'") < at("needs root: 1"));
    assert!(at("needs root: 1") < at("needs an elevated (Administrator) prompt: 1 not collected"));
    assert!(text.contains("Re-run with sudo for the full bundle.\n"));
    assert!(text.contains("Re-run from an elevated prompt for the full bundle.\n"));
}

#[test]
fn privileged_process_is_not_told_to_use_sudo() {
    let text = format_report(&host_like_run(), Path::new("b.zip"), Privilege::Privileged, false);
    assert!(
        text.contains(
            "  denied even with root privileges (kernel lockdown, container or security policy): \
                 5 not collected, 6 partial\n"
        ),
        "{text}"
    );
    assert!(!text.contains("needs root"), "{text}");
    assert!(!text.contains("sudo"), "{text}");
}

#[test]
fn the_details_command_quotes_odd_paths() {
    let result = result_of(&[Status::Skipped], 1);
    let text = format_report(&result, Path::new("/tmp/my bundle's.zip"), Privilege::Unprivileged, false);
    assert!(text.contains("Details: unzip -p '/tmp/my bundle'\\''s.zip' manifest.json"), "{text}");
    assert_eq!(shell_quote("/tmp/x-1.zip"), "/tmp/x-1.zip");
    assert_eq!(shell_quote(""), "''");
}

#[test]
fn json_objects_have_the_documented_keys_in_order() {
    let result = result_of(
        &[Status::Collected, Status::Collected, Status::Truncated, Status::Skipped, Status::Failed],
        4096,
    );
    let doc = json_result(&result, Path::new("/tmp/a b.zip"));
    assert_eq!(
        json_text(&doc, 0),
        r#"{"status":"OK","file":"/tmp/a b.zip","collected":2,"truncated":1,"skipped":1,"timed_out":0,"failed":1,"bytes":4096}"#
    );
    assert_eq!(
        json_text(&json_error("x.zip already exists"), 0),
        r#"{"errno":1,"error":"x.zip already exists"}"#
    );
    let pretty = json_text(&json_error("m"), JSON_INDENT);
    assert_eq!(pretty, "{\n    \"errno\": 1,\n    \"error\": \"m\"\n}");
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_do_not_break_json() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(OsStr::from_bytes(b"bad\xff.zip"));
    assert_eq!(display_path(path), "bad\u{fffd}.zip");
    let doc = json_result(&BundleResult::default(), path);
    let text = json_text(&doc, 0);
    assert!(serde_json::from_str::<Value>(&text).is_ok(), "{text}");
    assert_eq!(display_path(Path::new("/tmp/a b.zip")), "/tmp/a b.zip");
}

#[test]
fn source_list_pads_the_first_three_columns() {
    let kmsg = Source::file("kernel/kmsg.txt", "/dev/kmsg", Profile::Default, "the kernel log")
        .gate(Gate::KernelLog);
    let uname = Source::file("system/uname.txt", "/x", Profile::Minimal, "kernel release");
    assert_eq!(
        format_source_list(&[kmsg, uname]),
        "PROFILE  NEEDS       PATH              WHY\n\
             default  kernel_log  kernel/kmsg.txt   the kernel log\n\
             minimal  -           system/uname.txt  kernel release\n"
    );
    assert_eq!(format_source_list(&[]), "PROFILE  NEEDS  PATH  WHY\n");
}

/// Rebuilds the Linux golden table from its own columns and requires the same text back, so the
/// header and the padding rule are both checked.
#[test]
fn source_list_reproduces_the_golden_table() {
    let golden = include_str!("../../tests/golden/linux-sources.txt");
    let lines: Vec<&str> = golden.lines().collect();
    let header = lines[0];
    let needs_at = header.find("NEEDS").unwrap();
    let path_at = header.find("PATH").unwrap();
    let why_at = header.find("WHY").unwrap();
    assert_eq!(header, "PROFILE  NEEDS          PATH                                         WHY");
    assert_eq!(&header[..needs_at], "PROFILE  ");
    let cut = |line: &str, from: usize, to: usize| line[from..to].trim_end().to_owned();
    let mut sources = Vec::new();
    for line in &lines[1..] {
        let profile = match cut(line, 0, needs_at).trim() {
            "minimal" => Profile::Minimal,
            "default" => Profile::Default,
            "full" => Profile::Full,
            other => panic!("profile {other:?}"),
        };
        let gate = Gate::ALL
            .into_iter()
            .find(|gate| {
                let needs = cut(line, needs_at, path_at);
                if gate.name().is_empty() { needs.trim() == "-" } else { needs.trim() == gate.name() }
            })
            .unwrap();
        let path = cut(line, path_at, why_at);
        let why: &'static str = Box::leak(line[why_at..].to_owned().into_boxed_str());
        sources.push(Source::file(path.trim_end(), "/x", profile, why).gate(gate));
    }
    assert_eq!(sources.len(), lines.len() - 1);
    assert_eq!(format_source_list(&sources), golden);
}
