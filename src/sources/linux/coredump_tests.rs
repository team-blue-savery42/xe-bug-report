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

const INFO_GPU: &str = "           PID: 1234 (render)
  Command Line: /opt/acme-corp/project-x/bin/render --input /home/someone/secret.spv --token=abc
    Executable: /opt/acme-corp/project-x/bin/render
        Signal: 11 (SEGV)
       Message: Process 1234 (render) of user 1000 dumped core.

                Stack trace of thread 1234:
                #0  0x00007f50cae4504b n/a (libze_intel_gpu.so.1 + 0x4504b)
                #1  0x00007f50cb550a9d zeCommandListAppendLaunchKernel (libze_loader.so.1 + 0x50a9d)
                #2  0x000055719d6d6045 _start (render + 0x1045)
                #3  0x000055719d6d6045 n/a (/opt/acme-corp/project-x/bin/render + 0x2f3d)
";

const INFO_OTHER: &str = "           PID: 1235 (python3)
                Stack trace of thread 1235:
                #0  0x00007f50cae4504b kill (libc.so.6 + 0x4504b)
                Module libigc.so.2 from rpm intel-igc-2.41
";

fn exited(output: &str) -> ChildResult {
    ChildResult {
        outcome: ChildOutcome::Exited(0),
        output: output.as_bytes().to_vec(),
        truncated: false,
        elapsed: Duration::ZERO,
    }
}

#[test]
fn crash_pids_come_from_the_list_rows() {
    assert_eq!(crash_pids(LIST), [1234, 1235]);
    // No time zone column, and lines that are not rows.
    assert_eq!(
        crash_pids("TIME PID UID\nWed 2026-11-11 10:00:00 77 0 0 SIGSEGV\nNo coredumps found.\n"),
        [77]
    );
    assert!(crash_pids("").is_empty());
}

#[test]
fn only_stack_frames_in_the_gpu_runtime_count() {
    assert!(has_gpu_frame(INFO_GPU));
    // A module list entry is not a frame.
    assert!(!has_gpu_frame(INFO_OTHER));
    for library in GPU_RUNTIME_FRAMES {
        assert!(has_gpu_frame(&format!("    #3  0x1 n/a ({library}.so + 0x10)\n")), "{library}");
    }
}

#[test]
fn the_command_line_and_directories_are_not_kept() {
    let text = privacy_filtered(INFO_GPU);
    assert!(text.contains("  Command Line: (omitted)\n"), "{text}");
    assert!(text.contains("    Executable: render\n"), "{text}");
    assert!(!text.contains("acme") && !text.contains("secret") && !text.contains("token"), "{text}");
    assert!(text.contains("#0  0x00007f50cae4504b n/a (libze_intel_gpu.so.1 + 0x4504b)"), "{text}");
    assert!(text.contains("#3  0x000055719d6d6045 n/a (render + 0x2f3d)\n"), "{text}");
}

#[test]
fn up_to_three_newest_crashes_are_examined_and_gpu_ones_kept() {
    let list = "TIME PID\n\
Wed 2026-11-11 10:00:04 UTC 5 0\nWed 2026-11-11 10:00:03 UTC 4 0\n\
Wed 2026-11-11 10:00:02 UTC 3 0\nWed 2026-11-11 10:00:01 UTC 2 0\n";
    let asked = std::sync::Mutex::new(Vec::new());
    let out = backtraces_from("tools/coredump-*.txt", &ChildOutcome::Exited(0), list.as_bytes(), |pid| {
        asked.lock().unwrap().push(pid);
        exited(if pid == 4 || pid == 2 { INFO_GPU } else { INFO_OTHER })
    });
    assert_eq!(*asked.lock().unwrap(), [5, 4, 3]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rel_path, "tools/coredump-1.txt");
    assert_eq!(out[0].status, Status::Collected);
    assert_eq!(out[0].via, "coredumpctl info --no-pager 4");
}

#[test]
fn nothing_to_keep_is_a_skip_with_a_reason() {
    let none = backtraces_from("tools/coredump-*.txt", &ChildOutcome::Exited(0), LIST.as_bytes(), |_| {
        exited(INFO_OTHER)
    });
    assert_eq!(none.len(), 1);
    assert_eq!((none[0].rel_path.as_str(), none[0].status), ("tools/coredump-*.txt", Status::Skipped));
    assert_eq!(none[0].reason, "none of the 2 newest crashes has a stack frame in a GPU runtime library");
    let empty = backtraces_from("p", &ChildOutcome::Exited(1), b"No coredumps found.\n", |_| unreachable!());
    assert_eq!(empty[0].reason, "no recent crash");
    let missing = backtraces_from("p", &ChildOutcome::NotFound, b"", |_| unreachable!());
    assert_eq!(missing[0].reason, "coredumpctl not installed");
    assert_eq!(
        backtraces_from("p", &ChildOutcome::TimedOut, b"", |_| unreachable!())[0].status,
        Status::TimedOut
    );
    // A failed info run is passed over.
    let failed = backtraces_from("p", &ChildOutcome::Exited(0), LIST.as_bytes(), |_| ChildResult {
        outcome: ChildOutcome::TimedOut,
        ..exited(INFO_GPU)
    });
    assert_eq!(failed[0].status, Status::Skipped);
}
