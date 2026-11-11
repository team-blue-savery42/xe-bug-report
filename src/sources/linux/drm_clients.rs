// SPDX-License-Identifier: MIT
//! The processes that hold a DRM device node open, with the usage statistics the driver publishes
//! for each open file (`drm-*` lines of `/proc/<pid>/fdinfo/<fd>`): memory per region, engine time.
//!
//! This answers who is using the GPU: which client exhausts VRAM, which one is leaked after a crash
//! or still holds the device when a reset or rebind is attempted. Only the `drm-*` lines are kept;
//! command lines and environments are not read.
//!
//! Every fdinfo and `comm` read goes through the [`Reader`], because the driver computes engine
//! usage when the file is read and a wedged device can make that read block. Listing a
//! descriptor directory and reading a link do not enter the driver. The scan stops at a time budget.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::bundle::source::{Produced, Reader, Status};
use crate::units::Bytes;

use super::debugfs::collected;
use super::probes::{read_text, read_value};

/// The most time the scan takes before it reports what it found so far.
pub const SCAN_BUDGET: Duration = Duration::from_secs(5);
/// The most clients listed.
pub const CLIENTS_MAX: usize = 256;
/// The most `drm-*` lines kept per client.
const LINES_MAX: usize = 64;
/// The longest line kept, in bytes.
const LINE_MAX: usize = 200;
/// Size cap of one fdinfo file.
const FDINFO_MAX: Bytes = Bytes::kib(8);

/// Whether a descriptor's link target is a GPU or accelerator device node.
pub fn is_drm_node(target: &str) -> bool {
    let target = target.strip_suffix(" (deleted)").unwrap_or(target);
    ["/dev/dri/card", "/dev/dri/renderD", "/dev/accel/accel"].iter().any(|p| target.starts_with(p))
}

/// The `drm-*` lines of an fdinfo text, each cut to [`LINE_MAX`] bytes, at most [`LINES_MAX`].
pub fn drm_lines(fdinfo: &str) -> Vec<String> {
    fdinfo
        .lines()
        .filter(|l| l.starts_with("drm-"))
        .take(LINES_MAX)
        .map(|l| {
            let mut end = l.len().min(LINE_MAX);
            while !l.is_char_boundary(end) {
                end -= 1;
            }
            // `key:<tab>value` is written `key: value`.
            match l[..end].split_once(':') {
                Some((key, value)) => format!("{key}: {}", value.trim()),
                None => l[..end].trim_end().to_owned(),
            }
        })
        .collect()
}

/// The value of a `key: value` line in `lines`.
fn value_of<'a>(lines: &'a [String], key: &str) -> Option<&'a str> {
    lines.iter().find_map(|l| l.strip_prefix(key)?.strip_prefix(':').map(str::trim))
}

/// What the scan found.
#[derive(Debug, Default)]
pub struct Scan {
    /// The report body: one block per client.
    pub clients: String,
    /// Clients listed.
    pub count: usize,
    /// Processes looked at.
    pub processes: usize,
    /// Processes whose descriptors the caller may not list.
    pub denied: usize,
    /// The scan stopped at its time budget or at [`CLIENTS_MAX`].
    pub stopped: Option<&'static str>,
}

/// Scans the process directories below `proc_root` for open DRM nodes.
pub fn scan(reader: &dyn Reader, proc_root: &Path, budget: Duration) -> Scan {
    let start = Instant::now();
    let mut pids: Vec<u32> = fs::read_dir(proc_root)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    pids.sort_unstable();
    let mut result = Scan::default();
    'processes: for pid in pids {
        if start.elapsed() >= budget {
            result.stopped = Some("the scan stopped at its time budget");
            break;
        }
        let process = proc_root.join(pid.to_string());
        let fds = match fs::read_dir(process.join("fd")) {
            Ok(fds) => fds,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                result.denied += 1;
                continue;
            }
            Err(_) => continue,
        };
        result.processes += 1;
        let mut fds: Vec<(u32, String)> = fds
            .filter_map(Result::ok)
            .filter_map(|e| {
                let fd = e.file_name().to_string_lossy().parse().ok()?;
                let target = fs::read_link(e.path()).ok()?.to_string_lossy().into_owned();
                is_drm_node(&target).then_some((fd, target))
            })
            .collect();
        fds.sort_unstable();
        let mut seen_clients: Vec<String> = Vec::new();
        for (fd, node) in fds {
            if result.count >= CLIENTS_MAX {
                result.stopped = Some("the client limit was reached");
                break 'processes;
            }
            let info = read_text(reader, &process.join("fdinfo").join(fd.to_string()), FDINFO_MAX)
                .unwrap_or_default();
            let lines = drm_lines(&info);
            // A descriptor duplicated within a process shares one client.
            if let Some(id) = value_of(&lines, "drm-client-id") {
                if seen_clients.iter().any(|s| s == id) {
                    continue;
                }
                seen_clients.push(id.to_owned());
            }
            let comm = read_value(reader, &process.join("comm")).unwrap_or_else(|| "?".to_owned());
            result.count += 1;
            let _ = writeln!(result.clients, "pid {pid} ({comm}) fd {fd} {node}");
            if lines.is_empty() {
                result.clients.push_str(
                    "  (no drm-* statistics: the driver does not publish them, or the file was unreadable)\n",
                );
            }
            for line in lines {
                let _ = writeln!(result.clients, "  {line}");
            }
        }
    }
    result
}

/// The report for a finished scan: a status line, then the clients. Truncated with the reason
/// `needs root` when some processes could not be listed, or when the scan stopped early.
pub fn report(scan: &Scan, rel_path: &str) -> Produced {
    let mut text = format!("# {} processes looked at, {} DRM clients found\n", scan.processes, scan.count);
    if scan.denied > 0 {
        let _ = writeln!(
            text,
            "# {} other processes could not be listed (their descriptors need root)",
            scan.denied
        );
    }
    if let Some(why) = scan.stopped {
        let _ = writeln!(text, "# {why}");
    }
    if scan.count == 0 {
        text.push_str("(no process holds a DRM device node open)\n");
    }
    text.push_str(&scan.clients);
    let mut out = collected(rel_path, text, "/proc/*/fdinfo");
    if scan.denied > 0 {
        out.status = Status::Truncated;
        out.reason = "needs root".to_owned();
    } else if let Some(why) = scan.stopped {
        out.status = Status::Truncated;
        out.reason = why.to_owned();
    }
    out
}

/// The DRM clients of the host at `/proc`.
pub fn drm_clients(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    vec![report(&scan(reader, Path::new("/proc"), SCAN_BUDGET), rel_path)]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "drm_clients_tests.rs"]
mod tests;
