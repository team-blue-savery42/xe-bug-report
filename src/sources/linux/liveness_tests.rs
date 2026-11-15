// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/liveness.rs`. No GPU: the child is a shell script that prints
//! the protocol.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

const HEAD: &str = "loader\tok\ninit\t0\ndrivers\t0\t1\ndevices\t0\t0\t1\n\
device\t0.0\tIntel(R) Arc(TM) Pro B70 Graphics\t0xe223\t32530182144\n";

fn steps(results: &[(usize, ZeResult)]) -> String {
    results.iter().map(|(step, code)| format!("step\t0.0\t{}\t{code}\t3\n", STEPS[*step])).collect()
}

fn all_ok() -> String {
    format!("{HEAD}{}end\n", steps(&[(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)]))
}

fn report_text(output: &str, outcome: &ChildOutcome) -> String {
    let report = parse_report(output);
    format_report(&report, &child_end(outcome, report.ended), CHILD_DEADLINE)
}

fn result_line(text: &str) -> &str {
    text.lines().find_map(|line| line.strip_prefix("result: ")).unwrap_or_default()
}

#[test]
fn the_protocol_parses() {
    let report = parse_report(&all_ok());
    assert_eq!(report.loader, Some(Ok(())));
    assert_eq!(report.init, Some(0));
    assert_eq!(report.drivers, Some((0, 1)));
    assert_eq!(report.device_lists, [("0".to_owned(), 0, 1)]);
    assert!(report.ended);
    let device = &report.devices[0];
    assert_eq!(device.name, "Intel(R) Arc(TM) Pro B70 Graphics");
    assert_eq!(device.device_id, "0xe223");
    assert_eq!(device.max_mem_alloc_size, Some(32_530_182_144));
    assert_eq!(device.steps.len(), 6);
    assert_eq!(device.steps[4], ("zeCommandListHostSynchronize".to_owned(), 0, 3));
    // Noise and malformed lines are ignored.
    let noisy = parse_report("garbage\ninit\tx\nstep\t0.0\tzeX\tnope\t1\n\n");
    assert_eq!(noisy, ProbeReport::default());
}

#[test]
fn a_healthy_gpu_is_ok() {
    let text = report_text(&all_ok(), &ChildOutcome::Exited(0));
    assert_eq!(result_line(&text), "ok: 1 of 1 devices completed the fill");
    assert!(text.contains(
        "device 0.0: Intel(R) Arc(TM) Pro B70 Graphics (device id 0xe223, maxMemAllocSize 32530182144 = "
    ));
    assert!(text.contains("  zeCommandListHostSynchronize: ZE_RESULT_SUCCESS (3 ms)\n"), "{text}");
    assert!(text.contains("  result: ok\n"), "{text}");
    assert!(!text.contains("was killed") && !text.contains("ended before"), "{text}");
}

#[test]
fn a_fill_that_never_completes_is_a_timeout() {
    let output =
        format!("{HEAD}{}end\n", steps(&[(0, 0), (1, 0), (2, 0), (3, 0), (4, ZE_RESULT_NOT_READY), (5, 0)]));
    let text = report_text(&output, &ChildOutcome::Exited(0));
    assert!(
        result_line(&text)
            .starts_with("device 0.0: TIMEOUT: the fill was accepted but did not complete within 5 s")
    );
    assert!(text.contains("zeCommandListHostSynchronize: 0x00000001 (ZE_RESULT_NOT_READY)"), "{text}");
}

#[test]
fn an_error_names_the_function_and_the_code() {
    let output = format!("{HEAD}{}end\n", steps(&[(0, 0), (1, 0x7000_0001)]));
    let text = report_text(&output, &ChildOutcome::Exited(0));
    assert_eq!(
        result_line(&text),
        "device 0.0: error: zeMemAllocDevice returned 0x70000001 (ZE_RESULT_ERROR_DEVICE_LOST)"
    );
    let lost = format!("{HEAD}{}end\n", steps(&[(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0x7000_0001)]));
    assert_eq!(
        result_line(&report_text(&lost, &ChildOutcome::Exited(0))),
        "device 0.0: error: the fill completed but zeDeviceGetStatus returned 0x70000001 (ZE_RESULT_ERROR_DEVICE_LOST)"
    );
    // A code without a name is still shown.
    assert_eq!(describe_result(0x7123_4567), "0x71234567");
    assert_eq!(describe_result(0), "ZE_RESULT_SUCCESS");
}

#[test]
fn early_ends_say_where_the_child_was() {
    let missing = "loader\terror\tlibze_loader.so.1: cannot open shared object file\nend\n";
    let text = report_text(missing, &ChildOutcome::Exited(0));
    assert_eq!(
        result_line(&text),
        "loader not found: libze_loader.so.1: libze_loader.so.1: cannot open shared object file"
    );

    let init = "loader\tok\ninit\t2013265921\nend\n";
    assert_eq!(
        result_line(&report_text(init, &ChildOutcome::Exited(0))),
        "error: zeInit returned 0x78000001 (ZE_RESULT_ERROR_UNINITIALIZED)"
    );
    assert_eq!(
        result_line(&report_text("loader\tok\n", &ChildOutcome::TimedOut)),
        "killed at the 10 s deadline while in zeInit"
    );
    assert_eq!(
        result_line(&report_text("", &ChildOutcome::Exited(139))),
        "the probe ended in loading libze_loader.so.1: killed by signal 11 (SIGSEGV)"
    );
    let no_devices = "loader\tok\ninit\t0\ndrivers\t0\t0\nend\n";
    assert_eq!(result_line(&report_text(no_devices, &ChildOutcome::Exited(0))), "no Level Zero device found");
    let crashed = format!("{HEAD}{}", steps(&[(0, 0), (1, 0), (2, 0)]));
    assert_eq!(
        result_line(&report_text(&crashed, &ChildOutcome::Exited(134))),
        "device 0.0: the probe ended in zeCommandListAppendMemoryFill: killed by signal 6 (SIGABRT)"
    );
}

/// A probe child that prints `output` and then sleeps far past any deadline.
fn hanging_child(dir: &Path, output: &str) -> Vec<String> {
    let script = dir.join("probe-child");
    let printf: String = output.replace('\t', "\\t").replace('\n', "\\n");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '{printf}'\nsleep 30\n")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    vec![script.to_string_lossy().into_owned()]
}

#[test]
fn a_child_stuck_past_the_deadline_is_killed_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let output = format!("{HEAD}{}", steps(&[(0, 0), (1, 0), (2, 0), (3, 0)]));
    let argv = hanging_child(dir.path(), &output);
    let started = Instant::now();
    let produced = probe_with("devices/probe.txt", &argv, Duration::from_secs(1));
    // The deadline, a kill and a reap: well under the 30 s the child would sleep.
    assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
    assert_eq!(produced.status, Status::Collected);
    let text = String::from_utf8(produced.data).unwrap();
    assert_eq!(
        result_line(&text),
        "device 0.0: killed at the 1 s deadline while in zeCommandListHostSynchronize"
    );
    assert!(text.contains("The child did not finish within 1 s and was killed."), "{text}");
    assert!(text.contains("zeCommandListAppendMemoryFill: ZE_RESULT_SUCCESS"), "{text}");
}

#[test]
fn a_child_that_does_not_start_fails_the_source() {
    let produced =
        probe_with("devices/probe.txt", &["/nonexistent/xe-bug-report".to_owned()], Duration::from_secs(1));
    assert_eq!(produced.status, Status::Failed);
    assert_eq!(produced.reason, "the probe child: the executable was not found");
}
