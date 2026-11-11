// SPDX-License-Identifier: MIT
//! Platform context from sysfs class directories: the management engine devices (and so the GSC
//! firmware version), the flash partitions and telemetry regions a GPU exposes, the performance
//! counter events the driver registers, and the host power setup.
//!
//! Every function takes the sysfs root, so tests can build a small tree. Files are read through
//! the [`Reader`]. The serial numbers and model names of batteries are never read.

use std::fmt::Write as _;
use std::path::Path;

use crate::bundle::source::{Produced, Reader};

use super::debugfs::collected;
use super::probes::{list_names, list_prefixed, read_value};

/// Most thermal zones listed.
const THERMAL_ZONES_MAX: usize = 32;
/// Most entries of any other class listed.
const CLASS_ENTRIES_MAX: usize = 32;

/// A file's value on one line (line breaks become spaces), or `(absent)`.
fn one_line(reader: &dyn Reader, path: &Path) -> String {
    read_value(reader, path)
        .map_or_else(|| "(absent)".to_owned(), |v| v.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The last two components of the target of the `device` link of a class device, e.g.
/// `0000:03:00.0/xe.mei-gscfi.768`: which function and which auxiliary device it belongs to.
fn owner(class_device: &Path) -> String {
    let Ok(target) = std::fs::canonicalize(class_device.join("device")) else {
        return "(unknown)".to_owned();
    };
    let parts: Vec<String> =
        target.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    parts[parts.len().saturating_sub(2)..].join("/")
}

/// The management engine devices: kind, firmware version, firmware status registers and state. The
/// `gscfi` one that belongs to a GPU gives the GSC firmware version without root.
pub fn mei_section(reader: &dyn Reader, sys: &Path) -> String {
    let class = sys.join("class/mei");
    let mut text = String::from("[mei]\n");
    let names = list_prefixed(&class, "mei");
    if names.is_empty() {
        text.push_str("(none)\n");
    }
    for name in names.iter().take(CLASS_ENTRIES_MAX) {
        let dir = class.join(name);
        let _ = writeln!(
            text,
            "{name}: kind={} dev_state={} hbm_ver={} device={}",
            one_line(reader, &dir.join("kind")),
            one_line(reader, &dir.join("dev_state")),
            one_line(reader, &dir.join("hbm_ver")),
            owner(&dir),
        );
        let _ = writeln!(text, "  fw_ver: {}", one_line(reader, &dir.join("fw_ver")));
        let _ = writeln!(text, "  fw_status: {}", one_line(reader, &dir.join("fw_status")));
    }
    text
}

/// The flash partitions the GPU exposes (descriptor, GSC firmware, option ROM, ...), by name and
/// size. The device nodes are never opened.
pub fn mtd_section(reader: &dyn Reader, sys: &Path) -> String {
    let class = sys.join("class/mtd");
    let mut text = String::from("[mtd]\n");
    let mut shown = 0;
    for name in list_prefixed(&class, "mtd").into_iter().filter(|n| !n.ends_with("ro")) {
        let dir = class.join(&name);
        let owner = owner(&dir);
        // The platform's own firmware flash is not the GPU's.
        if !owner.contains("nvm") {
            continue;
        }
        let _ = writeln!(
            text,
            "{name}: {} size={} device={owner}",
            one_line(reader, &dir.join("name")),
            one_line(reader, &dir.join("size"))
        );
        shown += 1;
        if shown >= CLASS_ENTRIES_MAX {
            break;
        }
    }
    if shown == 0 {
        text.push_str("(none)\n");
    }
    text
}

/// The platform monitoring telemetry and crash log regions: which decoder applies (`guid`), how
/// large the region is and which function owns it. The contents are not read here.
pub fn pmt_section(reader: &dyn Reader, sys: &Path) -> String {
    let class = sys.join("class/intel_pmt");
    let mut text = String::from("[intel_pmt]\n");
    let names = list_names(&class);
    if names.is_empty() {
        text.push_str("(none)\n");
    }
    for name in names.iter().take(CLASS_ENTRIES_MAX) {
        let dir = class.join(name);
        let _ = writeln!(
            text,
            "{name}: guid={} size={} device={}",
            one_line(reader, &dir.join("guid")),
            one_line(reader, &dir.join("size")),
            owner(&dir),
        );
    }
    text
}

/// The performance counter events the GPU driver registers, as names only. No event is opened:
/// that needs CAP_PERFMON and starts counting.
pub fn pmu_section(sys: &Path) -> String {
    let devices = sys.join("bus/event_source/devices");
    let mut text = String::from("[perf events of the GPU]\n");
    let mut any = false;
    for name in list_names(&devices).into_iter().filter(|n| n.starts_with("xe_") || n.starts_with("i915")) {
        let events: Vec<String> = list_names(&devices.join(&name).join("events"))
            .into_iter()
            .filter(|e| !e.ends_with(".unit") && !e.ends_with(".scale"))
            .collect();
        let _ = writeln!(text, "{name}: {}", events.join(" "));
        any = true;
    }
    if !any {
        text.push_str("(none)\n");
    }
    text
}

/// The firmware-facing platform devices of the host in one file.
pub fn platform_devices(reader: &dyn Reader, sys: &Path, rel_path: &str) -> Vec<Produced> {
    let text =
        [mei_section(reader, sys), mtd_section(reader, sys), pmt_section(reader, sys), pmu_section(sys)]
            .join("\n");
    vec![collected(rel_path, text, "")]
}

/// `label: value` lines for the attributes of one class device that exist.
fn attributes(reader: &dyn Reader, dir: &Path, names: &[&str], indent: &str) -> String {
    let mut text = String::new();
    for name in names {
        let path = dir.join(name);
        if path.exists() {
            let _ = writeln!(text, "{indent}{name}: {}", one_line(reader, &path));
        }
    }
    text
}

/// The power setup of the host that decides how far a GPU may clock: the power supplies and
/// whether they are online, the platform profile, the package power limits, the temperatures and
/// the CPU governor. Batteries' serial numbers and model names are not read.
pub fn power_context(reader: &dyn Reader, sys: &Path, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    text.push_str("[power_supply]\n");
    let supplies = list_names(&sys.join("class/power_supply"));
    if supplies.is_empty() {
        text.push_str("(none)\n");
    }
    for name in supplies.iter().take(CLASS_ENTRIES_MAX) {
        let _ = writeln!(text, "{name}:");
        text.push_str(&attributes(
            reader,
            &sys.join("class/power_supply").join(name),
            &["type", "online", "status", "capacity"],
            "  ",
        ));
    }
    text.push_str("\n[platform_profile]\n");
    let profiles = list_names(&sys.join("class/platform-profile"));
    if profiles.is_empty() {
        text.push_str("(none)\n");
    }
    for name in &profiles {
        let _ = writeln!(text, "{name}:");
        text.push_str(&attributes(
            reader,
            &sys.join("class/platform-profile").join(name),
            &["name", "profile", "choices"],
            "  ",
        ));
    }
    text.push_str("\n[powercap]\n");
    let zones = list_names(&sys.join("class/powercap"));
    let mut shown = 0;
    for name in zones.iter().filter(|n| n.starts_with("intel-rapl")) {
        let dir = sys.join("class/powercap").join(name);
        // The control type itself (`intel-rapl`) has no zone name and no limits.
        if !dir.join("name").exists() {
            continue;
        }
        let _ = writeln!(text, "{name}: {}", one_line(reader, &dir.join("name")));
        for constraint in 0..4 {
            let attrs = [
                format!("constraint_{constraint}_name"),
                format!("constraint_{constraint}_power_limit_uw"),
                format!("constraint_{constraint}_time_window_us"),
            ];
            let names: Vec<&str> = attrs.iter().map(String::as_str).collect();
            text.push_str(&attributes(reader, &dir, &names, "  "));
        }
        shown += 1;
        if shown >= CLASS_ENTRIES_MAX {
            break;
        }
    }
    if shown == 0 {
        text.push_str("(none)\n");
    }
    text.push_str("\n[thermal_zone]\n");
    let thermal = list_prefixed(&sys.join("class/thermal"), "thermal_zone");
    if thermal.is_empty() {
        text.push_str("(none)\n");
    }
    for name in thermal.iter().take(THERMAL_ZONES_MAX) {
        let dir = sys.join("class/thermal").join(name);
        let _ = writeln!(
            text,
            "{name}: {} temp={}",
            one_line(reader, &dir.join("type")),
            one_line(reader, &dir.join("temp"))
        );
    }
    text.push_str("\n[cpu0 cpufreq]\n");
    let cpufreq = sys.join("devices/system/cpu/cpu0/cpufreq");
    let cpu = attributes(
        reader,
        &cpufreq,
        &["scaling_driver", "scaling_governor", "energy_performance_preference"],
        "",
    );
    text.push_str(if cpu.is_empty() { "(none)\n" } else { &cpu });
    text.push_str("\n[backlight]\n");
    let backlights = list_names(&sys.join("class/backlight"));
    if backlights.is_empty() {
        text.push_str("(none)\n");
    }
    for name in &backlights {
        let _ = writeln!(text, "{name}:");
        text.push_str(&attributes(
            reader,
            &sys.join("class/backlight").join(name),
            &["type", "brightness", "actual_brightness", "max_brightness"],
            "  ",
        ));
    }
    vec![collected(rel_path, text, "")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "platform_tests.rs"]
mod tests;
