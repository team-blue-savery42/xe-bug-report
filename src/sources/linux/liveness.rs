// SPDX-License-Identifier: MIT
//! `--probe`: does each GPU still complete the work it accepts?
//!
//! After a GPU page fault a device can enter a state where submissions are accepted but never
//! complete: the next process's first wait never returns. Nothing in sysfs or the kernel log has to
//! say so. The probe submits the smallest piece of real work, a 4 KiB memory fill through Level
//! Zero, and waits a bounded time for it.
//!
//! The work runs in a child process, this executable started again with [`CHILD_ARG`], so that a
//! driver call that never returns costs the child and not the collector: the child gets
//! [`CHILD_DEADLINE`] and is then killed with its process group. The child loads
//! `libze_loader.so.1` at run time (the collector itself links no GPU library) and prints one
//! tab-separated line per step, flushed at once, so the parent knows how far it got even when it
//! has to kill it:
//!
//! ```text
//! loader  ok | error <dlerror text>
//! init    <code>
//! drivers <code> <count>
//! devices <driver> <code> <count>
//! device  <id> <name> <device id> <maxMemAllocSize>
//! step    <id> <function> <code> <milliseconds>
//! end
//! ```

use std::fmt::Write as _;
use std::io::Write;
use std::time::{Duration, Instant};

use crate::bundle::collect::crash_reason;
use crate::bundle::source::{Produced, Status};
use crate::procio::{ChildOutcome, run_child, self_executable_path};
use crate::sys::unix::level_zero::{
    Device, Driver, LOADER, LevelZero, ZE_INIT_FLAG_GPU_ONLY, ZE_RESULT_NOT_READY, ZE_RESULT_SUCCESS,
    ZeResult,
};
use crate::units::Bytes;

use super::debugfs::{collected, skipped};

/// The argument that makes the executable run the probe child instead of a collection.
pub const CHILD_ARG: &str = "--level-zero-probe-child";
/// How long the child may run before it is killed with its process group.
pub const CHILD_DEADLINE: Duration = Duration::from_secs(10);
/// How long the child waits for each fill to complete.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(5);
/// Time the source gets: the child's deadline, the kill and reap, and starting it.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(20);
/// Bytes filled on each device.
const FILL_BYTES: usize = 4096;
/// Largest child output kept.
const OUTPUT_MAX: Bytes = Bytes::kib(64);

/// The per-device steps, in the order the child runs them.
pub const STEPS: [&str; 6] = [
    "zeContextCreate",
    "zeMemAllocDevice",
    "zeCommandListCreateImmediate",
    "zeCommandListAppendMemoryFill",
    "zeCommandListHostSynchronize",
    "zeDeviceGetStatus",
];

// ---- the child ----------------------------------------------------------------------------------

/// A text field of a protocol line: tabs and line breaks become blanks.
fn field(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

/// Writes one protocol line and flushes it, so a kill loses nothing written before.
fn emit(out: &mut dyn Write, line: &str) {
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The probe child: loads Level Zero, runs the fill on every device and writes the protocol to
/// `out`. Returns the exit code (0 whenever the protocol was written to the end).
pub fn child_main(out: &mut dyn Write) -> i32 {
    let ze = match LevelZero::load() {
        Ok(ze) => ze,
        Err(error) => {
            emit(out, &format!("loader\terror\t{}", field(&error)));
            emit(out, "end");
            return 0;
        }
    };
    emit(out, "loader\tok");
    let result = ze.init(ZE_INIT_FLAG_GPU_ONLY);
    emit(out, &format!("init\t{result}"));
    if result != ZE_RESULT_SUCCESS {
        emit(out, "end");
        return 0;
    }
    let drivers = match ze.drivers() {
        Ok(drivers) => drivers,
        Err(result) => {
            emit(out, &format!("drivers\t{result}\t0"));
            emit(out, "end");
            return 0;
        }
    };
    emit(out, &format!("drivers\t0\t{}", drivers.len()));
    for (d, driver) in drivers.into_iter().enumerate() {
        let devices = match ze.devices(driver) {
            Ok(devices) => devices,
            Err(result) => {
                emit(out, &format!("devices\t{d}\t{result}\t0"));
                continue;
            }
        };
        emit(out, &format!("devices\t{d}\t0\t{}", devices.len()));
        for (n, device) in devices.into_iter().enumerate() {
            probe_device(&ze, driver, device, &format!("{d}.{n}"), out);
        }
    }
    emit(out, "end");
    0
}

/// Writes a `step` line; true when the step succeeded.
fn emit_step(out: &mut dyn Write, id: &str, function: &str, result: ZeResult, started: Instant) -> bool {
    emit(out, &format!("step\t{id}\t{function}\t{result}\t{}", started.elapsed().as_millis()));
    result == ZE_RESULT_SUCCESS
}

/// Runs the fill on one device and writes its lines. Every object is freed in reverse order of
/// creation, except after a fill that did not complete (see below).
fn probe_device(ze: &LevelZero, driver: Driver, device: Device, id: &str, out: &mut dyn Write) {
    let started = Instant::now();
    match ze.device_properties(device) {
        Ok(properties) => emit(
            out,
            &format!(
                "device\t{id}\t{}\t{:#06x}\t{}",
                field(&properties.name),
                properties.device_id,
                properties.max_mem_alloc_size
            ),
        ),
        Err(result) => {
            emit_step(out, id, "zeDeviceGetProperties", result, started);
            return;
        }
    }
    let started = Instant::now();
    let context = match ze.create_context(driver) {
        Ok(context) => context,
        Err(result) => {
            emit_step(out, id, STEPS[0], result, started);
            return;
        }
    };
    emit_step(out, id, STEPS[0], ZE_RESULT_SUCCESS, started);
    let started = Instant::now();
    let memory = match context.alloc_device(device, FILL_BYTES, FILL_BYTES) {
        Ok(memory) => memory,
        Err(result) => {
            emit_step(out, id, STEPS[1], result, started);
            return;
        }
    };
    emit_step(out, id, STEPS[1], ZE_RESULT_SUCCESS, started);
    let started = Instant::now();
    let list = match context.create_immediate_list(device, 0) {
        Ok(list) => list,
        Err(result) => {
            emit_step(out, id, STEPS[2], result, started);
            return;
        }
    };
    emit_step(out, id, STEPS[2], ZE_RESULT_SUCCESS, started);
    let started = Instant::now();
    if !emit_step(out, id, STEPS[3], list.fill(&memory), started) {
        return;
    }
    let started = Instant::now();
    let timeout_ns = u64::try_from(SYNC_TIMEOUT.as_nanos()).unwrap_or(u64::MAX);
    let completed = emit_step(out, id, STEPS[4], list.host_synchronize(timeout_ns), started);
    let started = Instant::now();
    emit_step(out, id, STEPS[5], ze.device_status(device), started);
    if !completed {
        // The fill may still be pending: destroying the list or freeing its memory could wait for
        // it. They are left to the process exit, which does not run the driver's exit handlers.
        std::mem::forget(list);
        std::mem::forget(memory);
        std::mem::forget(context);
    }
}

// ---- the parent ---------------------------------------------------------------------------------

/// One device as the child reported it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceReport {
    /// `<driver>.<device>`.
    pub id: String,
    pub name: String,
    pub device_id: String,
    pub max_mem_alloc_size: Option<u64>,
    /// (function, result, milliseconds) in the order run.
    pub steps: Vec<(String, ZeResult, u64)>,
}

/// What the child printed, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeReport {
    /// None: no loader line; Some(Err(text)): `dlopen` failed.
    pub loader: Option<Result<(), String>>,
    pub init: Option<ZeResult>,
    /// (result, count) of `zeDriverGet`.
    pub drivers: Option<(ZeResult, u32)>,
    /// (driver, result, count) of each `zeDeviceGet`.
    pub device_lists: Vec<(String, ZeResult, u32)>,
    pub devices: Vec<DeviceReport>,
    /// The child wrote its last line.
    pub ended: bool,
}

/// Parses the child's output; unknown and malformed lines are ignored.
pub fn parse_report(text: &str) -> ProbeReport {
    let mut report = ProbeReport::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["loader", "ok"] => report.loader = Some(Ok(())),
            ["loader", "error", error] => report.loader = Some(Err((*error).to_owned())),
            ["init", code] => report.init = code.parse().ok(),
            ["drivers", code, count] => {
                if let (Ok(code), Ok(count)) = (code.parse(), count.parse()) {
                    report.drivers = Some((code, count));
                }
            }
            ["devices", driver, code, count] => {
                if let (Ok(code), Ok(count)) = (code.parse(), count.parse()) {
                    report.device_lists.push(((*driver).to_owned(), code, count));
                }
            }
            ["device", id, name, device_id, max_alloc] => report.devices.push(DeviceReport {
                id: (*id).to_owned(),
                name: (*name).to_owned(),
                device_id: (*device_id).to_owned(),
                max_mem_alloc_size: max_alloc.parse().ok(),
                steps: Vec::new(),
            }),
            ["step", id, function, code, ms] => {
                let (Ok(code), Ok(ms)) = (code.parse(), ms.parse()) else { continue };
                // A device whose properties could not be read has no device line of its own.
                if !report.devices.last().is_some_and(|device| device.id == *id) {
                    report.devices.push(DeviceReport { id: (*id).to_owned(), ..DeviceReport::default() });
                }
                if let Some(device) = report.devices.last_mut() {
                    device.steps.push(((*function).to_owned(), code, ms));
                }
            }
            ["end"] => report.ended = true,
            _ => {}
        }
    }
    report
}

/// The `ZE_RESULT_*` name of a code, for the codes a probe can meet.
pub fn result_name(code: ZeResult) -> Option<&'static str> {
    Some(match code {
        0 => "ZE_RESULT_SUCCESS",
        1 => "ZE_RESULT_NOT_READY",
        0x7000_0001 => "ZE_RESULT_ERROR_DEVICE_LOST",
        0x7000_0002 => "ZE_RESULT_ERROR_OUT_OF_HOST_MEMORY",
        0x7000_0003 => "ZE_RESULT_ERROR_OUT_OF_DEVICE_MEMORY",
        0x7000_0006 => "ZE_RESULT_ERROR_DEVICE_REQUIRES_RESET",
        0x7000_0007 => "ZE_RESULT_ERROR_DEVICE_IN_LOW_POWER_STATE",
        0x7001_0000 => "ZE_RESULT_ERROR_INSUFFICIENT_PERMISSIONS",
        0x7001_0001 => "ZE_RESULT_ERROR_NOT_AVAILABLE",
        0x7002_0000 => "ZE_RESULT_ERROR_DEPENDENCY_UNAVAILABLE",
        0x7800_0001 => "ZE_RESULT_ERROR_UNINITIALIZED",
        0x7800_0002 => "ZE_RESULT_ERROR_UNSUPPORTED_VERSION",
        0x7800_0003 => "ZE_RESULT_ERROR_UNSUPPORTED_FEATURE",
        0x7800_0004 => "ZE_RESULT_ERROR_INVALID_ARGUMENT",
        0x7800_0005 => "ZE_RESULT_ERROR_INVALID_NULL_HANDLE",
        0x7800_0006 => "ZE_RESULT_ERROR_HANDLE_OBJECT_IN_USE",
        0x7800_0007 => "ZE_RESULT_ERROR_INVALID_NULL_POINTER",
        0x7800_0008 => "ZE_RESULT_ERROR_INVALID_SIZE",
        0x7800_0009 => "ZE_RESULT_ERROR_UNSUPPORTED_SIZE",
        0x7800_000a => "ZE_RESULT_ERROR_UNSUPPORTED_ALIGNMENT",
        0x7800_000b => "ZE_RESULT_ERROR_INVALID_SYNCHRONIZATION_OBJECT",
        0x7800_000c => "ZE_RESULT_ERROR_INVALID_ENUMERATION",
        0x7800_000d => "ZE_RESULT_ERROR_UNSUPPORTED_ENUMERATION",
        0x7800_0020 => "ZE_RESULT_ERROR_SURVIVABILITY_MODE_DETECTED",
        0x7fff_fffe => "ZE_RESULT_ERROR_UNKNOWN",
        _ => return None,
    })
}

/// A result code as written: `ZE_RESULT_SUCCESS`, or `0x78000004 (ZE_RESULT_ERROR_INVALID_ARGUMENT)`
/// for a failure, or the bare hex value when the name is unknown.
pub fn describe_result(code: ZeResult) -> String {
    match (code, result_name(code)) {
        (ZE_RESULT_SUCCESS, Some(name)) => name.to_owned(),
        (_, Some(name)) => format!("{code:#010x} ({name})"),
        (_, None) => format!("{code:#010x}"),
    }
}

/// How the child ended, as the parent saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildEnd {
    /// It wrote its last line (whatever it did after).
    Finished,
    /// It was killed at the deadline before finishing.
    Killed,
    /// It exited before finishing; the reason.
    Ended(String),
}

/// What became of the child, from its outcome and whether it wrote `end`.
pub fn child_end(outcome: &ChildOutcome, ended: bool) -> ChildEnd {
    if ended {
        return ChildEnd::Finished;
    }
    match outcome {
        ChildOutcome::TimedOut => ChildEnd::Killed,
        ChildOutcome::Exited(code) => {
            ChildEnd::Ended(crash_reason(*code).unwrap_or_else(|| format!("exit code {code}")))
        }
        ChildOutcome::NotFound => ChildEnd::Ended("the executable was not found".to_owned()),
        ChildOutcome::SpawnFailed(error) => ChildEnd::Ended(format!("could not start: {error}")),
    }
}

/// The verdict of one device.
fn device_verdict(device: &DeviceReport, end: &ChildEnd, last: bool, deadline: Duration) -> String {
    if let Some((function, code, _)) = device.steps.iter().find(|(_, code, _)| *code != ZE_RESULT_SUCCESS) {
        if function == STEPS[4] && *code == ZE_RESULT_NOT_READY {
            return format!(
                "TIMEOUT: the fill was accepted but did not complete within {} s; the GPU takes work and \
                 does not finish it",
                SYNC_TIMEOUT.as_secs()
            );
        }
        if function != STEPS[5] {
            return format!("error: {function} returned {}", describe_result(*code));
        }
    }
    let done = device.steps.iter().filter(|(function, _, _)| STEPS.contains(&function.as_str())).count();
    let complete = done == STEPS.len();
    if !complete && last {
        let next = STEPS.get(done).copied().unwrap_or("the next step");
        return match end {
            ChildEnd::Killed => format!("killed at the {} s deadline while in {next}", deadline.as_secs()),
            ChildEnd::Ended(reason) => format!("the probe ended in {next}: {reason}"),
            ChildEnd::Finished => format!("incomplete: stopped before {next}"),
        };
    }
    match device.steps.iter().find(|(function, _, _)| function == STEPS[5]) {
        Some((_, code, _)) if *code != ZE_RESULT_SUCCESS => {
            format!("error: the fill completed but zeDeviceGetStatus returned {}", describe_result(*code))
        }
        _ if complete => "ok".to_owned(),
        _ => "incomplete".to_owned(),
    }
}

/// Where a child that stopped before any device was in its sequence.
fn stuck_before_devices(report: &ProbeReport) -> &'static str {
    if report.loader.is_none() {
        "loading libze_loader.so.1"
    } else if report.init.is_none() {
        "zeInit"
    } else if report.drivers.is_none() {
        "zeDriverGet"
    } else {
        "zeDeviceGet"
    }
}

/// The overall result line (without the `result: ` prefix) and the per-device verdicts.
fn verdicts(report: &ProbeReport, end: &ChildEnd, deadline: Duration) -> (String, Vec<String>) {
    let per_device: Vec<String> = report
        .devices
        .iter()
        .enumerate()
        .map(|(at, device)| device_verdict(device, end, at + 1 == report.devices.len(), deadline))
        .collect();
    if let Some(Err(error)) = &report.loader {
        return (format!("loader not found: {LOADER}: {error}"), per_device);
    }
    if let Some(code) = report.init.filter(|code| *code != ZE_RESULT_SUCCESS) {
        return (format!("error: zeInit returned {}", describe_result(code)), per_device);
    }
    if let Some((code, _)) = report.drivers.filter(|(code, _)| *code != ZE_RESULT_SUCCESS) {
        return (format!("error: zeDriverGet returned {}", describe_result(code)), per_device);
    }
    if let Some((at, verdict)) = per_device.iter().enumerate().find(|(_, verdict)| *verdict != "ok") {
        return (format!("device {}: {verdict}", report.devices[at].id), per_device);
    }
    let summary = match end {
        ChildEnd::Killed if report.devices.is_empty() => format!(
            "killed at the {} s deadline while in {}",
            deadline.as_secs(),
            stuck_before_devices(report)
        ),
        ChildEnd::Ended(reason) if report.devices.is_empty() => {
            format!("the probe ended in {}: {reason}", stuck_before_devices(report))
        }
        _ if report.devices.is_empty() => "no Level Zero device found".to_owned(),
        ChildEnd::Killed => format!("killed at the {} s deadline after the last device", deadline.as_secs()),
        ChildEnd::Ended(reason) => format!("the probe ended after the last device: {reason}"),
        ChildEnd::Finished => {
            format!("ok: {} of {} devices completed the fill", per_device.len(), per_device.len())
        }
    };
    (summary, per_device)
}

/// The text of `devices/probe.txt`.
pub fn format_report(report: &ProbeReport, end: &ChildEnd, deadline: Duration) -> String {
    let (summary, per_device) = verdicts(report, end, deadline);
    let mut text = format!(
        "Level Zero liveness probe: a {FILL_BYTES}-byte memory fill on each device, waited for up to {} s, in a \
         child process killed after {} s.\n\nresult: {summary}\n",
        SYNC_TIMEOUT.as_secs(),
        deadline.as_secs()
    );
    let _ = writeln!(
        text,
        "\nloader: {}",
        match &report.loader {
            None => "(no answer)".to_owned(),
            Some(Ok(())) => format!("{LOADER} loaded"),
            Some(Err(error)) => format!("{LOADER} not loaded: {error}"),
        }
    );
    if let Some(code) = report.init {
        let _ = writeln!(text, "zeInit(ZE_INIT_FLAG_GPU_ONLY): {}", describe_result(code));
    }
    if let Some((code, count)) = report.drivers {
        let _ = writeln!(text, "zeDriverGet: {}, {count} drivers", describe_result(code));
    }
    for (driver, code, count) in &report.device_lists {
        let _ = writeln!(text, "zeDeviceGet (driver {driver}): {}, {count} devices", describe_result(*code));
    }
    for (device, verdict) in report.devices.iter().zip(&per_device) {
        let _ = write!(text, "\ndevice {}:", device.id);
        if !device.name.is_empty() {
            let _ = write!(text, " {} (device id {}", device.name, device.device_id);
            if let Some(size) = device.max_mem_alloc_size {
                let _ = write!(text, ", maxMemAllocSize {size} = {}", Bytes(size).human());
            }
            text.push(')');
        }
        text.push('\n');
        for (function, code, ms) in &device.steps {
            let _ = writeln!(text, "  {function}: {} ({ms} ms)", describe_result(*code));
        }
        let _ = writeln!(text, "  result: {verdict}");
    }
    match end {
        ChildEnd::Finished => {}
        ChildEnd::Killed => {
            let _ =
                writeln!(text, "\nThe child did not finish within {} s and was killed.", deadline.as_secs());
        }
        ChildEnd::Ended(reason) => {
            let _ = writeln!(text, "\nThe child ended before finishing: {reason}.");
        }
    }
    text
}

/// Runs `argv` as the probe child with `deadline` and turns what it printed into the report.
pub fn probe_with(rel_path: &str, argv: &[String], deadline: Duration) -> Produced {
    let result = run_child(argv, deadline, OUTPUT_MAX);
    if let ChildEnd::Ended(reason) = child_end(&result.outcome, false)
        && matches!(result.outcome, ChildOutcome::NotFound | ChildOutcome::SpawnFailed(_))
    {
        let mut out = skipped(rel_path, format!("the probe child: {reason}"));
        out.status = Status::Failed;
        return out;
    }
    let report = parse_report(&String::from_utf8_lossy(&result.output));
    let end = child_end(&result.outcome, report.ended);
    collected(
        rel_path,
        format_report(&report, &end, deadline),
        format!("xe-bug-report {CHILD_ARG} ({LOADER})"),
    )
}

/// The `devices/probe.txt` source: runs this executable as the probe child.
pub fn liveness_probe(rel_path: &str) -> Vec<Produced> {
    let Some(executable) = self_executable_path() else {
        let mut out = skipped(rel_path, "cannot locate the xe-bug-report executable to run the probe");
        out.status = Status::Failed;
        return vec![out];
    };
    vec![probe_with(
        rel_path,
        &[executable.to_string_lossy().into_owned(), CHILD_ARG.to_owned()],
        CHILD_DEADLINE,
    )]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "liveness_tests.rs"]
mod tests;
