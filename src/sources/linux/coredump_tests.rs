// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/coredump.rs`.

use super::*;

const LIST: &str = "TIME                            PID  UID  GID SIG     COREFILE  EXE                                 SIZE\n\
Wed 2026-11-11 10:00:00 UTC    1234 1000 1000 SIGSEGV present   /opt/acme-corp/project-x/bin/render  1.2M\n\
Wed 2026-11-11 09:00:00 UTC    1235 1000 1000 SIGABRT missing   /usr/lib/x86_64-linux-gnu/libvulkan_intel.so -\n";

#[test]
fn only_the_program_name_of_each_path_is_kept() {
    let out = keep_basenames(LIST);
    assert!(out.contains("SIGSEGV present   render  1.2M\n"), "{out}");
    assert!(out.contains("SIGABRT missing   libvulkan_intel.so -\n"), "{out}");
    assert!(!out.contains("acme") && !out.contains("project-x") && !out.contains("/usr"), "{out}");
    // The header, the times and the columns are untouched.
    assert!(out.starts_with("TIME                            PID  UID  GID SIG     COREFILE  EXE"), "{out}");
    assert!(out.contains("Wed 2026-11-11 10:00:00 UTC    1234 1000 1000"));
    assert_eq!(out.lines().count(), LIST.lines().count());
}

#[test]
fn text_without_paths_and_odd_input_pass_through() {
    assert_eq!(keep_basenames("No coredumps found.\n"), "No coredumps found.\n");
    assert_eq!(keep_basenames(""), "");
    assert_eq!(keep_basenames("no newline /a/b"), "no newline b");
    assert_eq!(keep_basenames("a /x/ b"), "a x b");
    assert_eq!(keep_basenames("/ and /\n"), "/ and /\n");
}

#[test]
fn the_window_and_order_are_in_the_arguments() {
    assert_eq!(coredumpctl_argv(None), ["coredumpctl", "list", "--no-pager", "--reverse"]);
    assert_eq!(coredumpctl_argv(Some(Duration::from_secs(1800))).last().unwrap(), "--since=-30min");
}

#[test]
fn a_finished_run_maps_to_an_artifact() {
    let run = |outcome: ChildOutcome, output: &[u8], truncated: bool| {
        list_from("tools/coredumpctl.txt", "coredumpctl list", &outcome, output, truncated).remove(0)
    };
    let ok = run(ChildOutcome::Exited(0), LIST.as_bytes(), false);
    assert_eq!(ok.status, Status::Collected);
    assert!(!String::from_utf8_lossy(&ok.data).contains("acme"));
    // "No coredumps found." with exit 1 is a result.
    let none = run(ChildOutcome::Exited(1), b"No coredumps found.\n", false);
    assert_eq!(none.status, Status::Collected);
    assert_eq!(run(ChildOutcome::Exited(0), LIST.as_bytes(), true).status, Status::Truncated);
    assert_eq!(run(ChildOutcome::NotFound, b"", false).reason, "coredumpctl not installed");
    assert_eq!(run(ChildOutcome::TimedOut, b"", false).status, Status::TimedOut);
    assert_eq!(run(ChildOutcome::Exited(1), b"", false).status, Status::Failed);
    assert_eq!(run(ChildOutcome::Exited(0), b"", false).status, Status::Skipped);
    assert_eq!(run(ChildOutcome::SpawnFailed("x".to_owned()), b"", false).status, Status::Failed);
}
