// SPDX-License-Identifier: MIT
//! Kernel and module state that changes how a report reads: the taint flags, the driver build, the
//! suspend counters, the kernel build configuration, the modprobe configuration, memory limits and
//! a one-block-per-kind CPU summary.
//!
//! Everything here is a small world-readable file read through the [`Reader`].

use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

use crate::bundle::source::{Keep, Produced, Reader};
use crate::units::Bytes;

use super::debugfs::{collected, skipped};
use super::probes::{attribute_line, list_names, read_text, read_value};
use super::system::Probe;
use super::text::{safe_path_value, trim};

/// The compressed kernel configuration.
pub const PROC_CONFIG_GZ: &str = "/proc/config.gz";
/// The directory with the configuration the installed kernel was built from.
pub const BOOT_DIR: &str = "/boot";
/// Size cap of the compressed kernel configuration.
const CONFIG_GZ_MAX: Bytes = Bytes::mib(2);
/// Size cap of the kernel configuration after decompression.
const CONFIG_MAX: Bytes = Bytes::mib(8);
/// Size cap of one modprobe configuration file.
const MODPROBE_FILE_MAX: Bytes = Bytes::kib(64);
/// Size cap of `/proc/cpuinfo`.
const CPUINFO_MAX: Bytes = Bytes::mib(4);
/// Most distinct CPU blocks printed.
const CPU_BLOCKS_MAX: usize = 8;

/// The kernel taint flags: bit number, letter, meaning (Documentation/admin-guide/tainted-kernels).
pub const TAINT_FLAGS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary module loaded"),
    (1, 'F', "module force loaded"),
    (2, 'S', "CPU out of specification"),
    (3, 'R', "module force unloaded"),
    (4, 'M', "machine check exception"),
    (5, 'B', "bad page referenced"),
    (6, 'U', "taint requested by user space"),
    (7, 'D', "kernel died recently (oops or BUG)"),
    (8, 'A', "ACPI table overridden"),
    (9, 'W', "kernel warning issued"),
    (10, 'C', "staging driver loaded"),
    (11, 'I', "firmware workaround applied"),
    (12, 'O', "out-of-tree module loaded"),
    (13, 'E', "unsigned module loaded"),
    (14, 'L', "soft lockup occurred"),
    (15, 'K', "kernel live patched"),
    (16, 'X', "auxiliary taint"),
    (17, 'T', "kernel built with randstruct"),
    (18, 'N', "test taint"),
    (19, 'J', "firmware control device used"),
];

/// The set flags of a `tainted` value as `S (CPU out of specification), W (kernel warning issued)`;
/// `none` for 0.
pub fn describe_taint(mask: u64) -> String {
    let set: Vec<String> = TAINT_FLAGS
        .iter()
        .filter(|(bit, _, _)| mask >> bit & 1 == 1)
        .map(|(_, letter, meaning)| format!("{letter} ({meaning})"))
        .collect();
    if set.is_empty() { "none".to_owned() } else { set.join(", ") }
}

/// The files of the kernel state report, labelled by what they are.
pub fn state_probes() -> Vec<Probe> {
    let fixed: [(&str, &str); 13] = [
        ("kernel.tainted", "/proc/sys/kernel/tainted"),
        ("kernel.panic_on_warn", "/proc/sys/kernel/panic_on_warn"),
        ("kernel.panic", "/proc/sys/kernel/panic"),
        ("kernel.core_pattern", "/proc/sys/kernel/core_pattern"),
        ("xe module srcversion", "/sys/module/xe/srcversion"),
        ("xe module initstate", "/sys/module/xe/initstate"),
        ("xe module refcnt", "/sys/module/xe/refcnt"),
        ("xe module taint", "/sys/module/xe/taint"),
        ("devcoredump disabled", "/sys/class/devcoredump/disabled"),
        ("power state", "/sys/power/state"),
        ("power mem_sleep", "/sys/power/mem_sleep"),
        ("power disk", "/sys/power/disk"),
        ("power pm_async", "/sys/power/pm_async"),
    ];
    const SUSPEND_STATS: &[&str] = &[
        "success",
        "fail",
        "failed_freeze",
        "failed_prepare",
        "failed_suspend",
        "failed_suspend_late",
        "failed_suspend_noirq",
        "failed_resume",
        "failed_resume_early",
        "failed_resume_noirq",
        "last_failed_dev",
        "last_failed_errno",
        "last_failed_step",
    ];
    let mut out: Vec<Probe> = fixed
        .iter()
        .map(|(label, path)| Probe { label: (*label).to_owned(), path: (*path).to_owned() })
        .collect();
    out.extend(SUSPEND_STATS.iter().map(|name| Probe {
        label: format!("suspend_stats {name}"),
        path: format!("/sys/power/suspend_stats/{name}"),
    }));
    out
}

/// The kernel and driver state: the version line, the probes with the taint flags spelled out.
pub fn state_report(
    reader: &dyn Reader,
    rel_path: &str,
    probes: &[Probe],
    version_path: &Path,
) -> Vec<Produced> {
    let mut text = String::new();
    text.push_str(&attribute_line(reader, "kernel version", version_path));
    text.push('\n');
    for probe in probes {
        if probe.label == "kernel.core_pattern"
            && let Some(pattern) = read_value(reader, Path::new(&probe.path))
        {
            // A pattern can name a crash directory or a handler under a user or project directory.
            let (pipe, target) = pattern.strip_prefix('|').map_or(("", pattern.as_str()), |t| ("|", t));
            // A bare name is kept; so is a pattern whose first word (the directory or handler) is in
            // a system directory.
            let first_word = target.split(' ').next().unwrap_or("");
            let shown = if !target.contains('/') || safe_path_value(first_word) == first_word {
                target.to_owned()
            } else {
                "<path>".to_owned()
            };
            let _ = writeln!(text, "{}: {pipe}{shown}", probe.label);
            continue;
        }
        text.push_str(&attribute_line(reader, &probe.label, Path::new(&probe.path)));
        text.push('\n');
        if probe.label == "kernel.tainted"
            && let Some(mask) = read_value(reader, Path::new(&probe.path)).and_then(|v| v.parse::<u64>().ok())
        {
            let _ = writeln!(text, "kernel.tainted flags: {}", describe_taint(mask));
        }
    }
    vec![collected(rel_path, text, "")]
}

/// The memory limits that matter to unified shared memory and allocation failures.
pub fn memory_context(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    for (label, path) in [
        ("pressure memory", "/proc/pressure/memory"),
        ("pressure io", "/proc/pressure/io"),
        ("transparent_hugepage enabled", "/sys/kernel/mm/transparent_hugepage/enabled"),
        ("vm.max_map_count", "/proc/sys/vm/max_map_count"),
    ] {
        text.push_str(&attribute_line(reader, label, Path::new(path)));
        text.push('\n');
    }
    let limits = read_text(reader, Path::new("/proc/self/limits"), Bytes::kib(8)).unwrap_or_default();
    match limits.lines().find(|l| l.starts_with("Max locked memory")) {
        Some(line) => {
            let _ = writeln!(text, "limits: {}", line.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        None => text.push_str("limits: Max locked memory (unavailable)\n"),
    }
    vec![collected(rel_path, text, "")]
}

/// The configuration symbols worth keeping: name prefixes after `CONFIG_`.
pub const CONFIG_KEEP: &[&str] = &[
    "DRM_XE",
    "DRM_I915",
    "DRM_GPUVM",
    "DRM_GPUSVM",
    "DRM_DEBUG",
    "INTEL_IOMMU",
    "IOMMU_DEFAULT",
    "PCIEAER",
    "PCIEASPM",
    "PCI_IOV",
    "DEV_COREDUMP",
    "KASAN",
    "PROVE_LOCKING",
    "LOCKDEP",
    "DEBUG_ATOMIC_SLEEP",
    "KFENCE",
    "FAULT_INJECTION",
    "INTEL_VSEC",
    "INTEL_MEI",
    "X86_PAT",
    "HMM_MIRROR",
    "ZONE_DEVICE",
    "DEVICE_PRIVATE",
    "PREEMPT",
    "HZ",
    "LOCALVERSION",
    "CC_VERSION_TEXT",
    "VFIO_PCI",
    "MODULE_SIG_FORCE",
    "SECURITY_LOCKDOWN_LSM",
];

/// The symbol name of a configuration line: `CONFIG_X=y` and `# CONFIG_X is not set` both give `X`.
fn config_symbol(line: &str) -> Option<&str> {
    let line = line.strip_prefix("# ").unwrap_or(line);
    let rest = line.strip_prefix("CONFIG_")?;
    let end = rest.find(['=', ' ']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The lines of a kernel configuration that [`CONFIG_KEEP`] names, in file order.
pub fn filter_config(config: &str) -> String {
    let mut out = String::new();
    for line in config.lines() {
        if config_symbol(line).is_some_and(|symbol| CONFIG_KEEP.iter().any(|keep| symbol.starts_with(keep))) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Inflates a gzip stream; None when it is not one, cut at `max` bytes.
pub fn gunzip_capped(data: &[u8], max: Bytes) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(data).take(max.get()).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

/// The build configuration of the running kernel, reduced to the symbols that change how a GPU
/// report reads: from `/proc/config.gz`, else the `config-<release>` file in `boot_dir`.
pub fn kernel_config(
    reader: &dyn Reader,
    rel_path: &str,
    config_gz: &Path,
    boot_dir: &Path,
    release: &str,
) -> Vec<Produced> {
    let compressed = reader.read(config_gz, CONFIG_GZ_MAX, Keep::Head).data;
    let (origin, config) = match gunzip_capped(&compressed, CONFIG_MAX) {
        Some(config) => {
            (config_gz.to_string_lossy().into_owned(), String::from_utf8_lossy(&config).into_owned())
        }
        None => {
            let file = boot_dir.join(format!("config-{release}"));
            match read_text(reader, &file, CONFIG_MAX) {
                Some(config) if !release.is_empty() => (file.to_string_lossy().into_owned(), config),
                _ => {
                    return vec![skipped(
                        rel_path,
                        format!(
                            "the kernel configuration is not readable: no {} and no {}",
                            config_gz.display(),
                            file.display()
                        ),
                    )];
                }
            }
        }
    };
    let kept = filter_config(&config);
    let text =
        format!("# from {origin}: {} of {} lines\n{kept}", kept.lines().count(), config.lines().count());
    vec![collected(rel_path, text, origin)]
}

/// The directories that hold modprobe and module-load configuration, in precedence order.
pub const MODPROBE_DIRS: &[&str] = &[
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/local/lib/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
    "/etc/modules-load.d",
    "/run/modules-load.d",
    "/usr/lib/modules-load.d",
];
/// The module names whose configuration lines are kept.
const MODPROBE_MODULES: &[&str] =
    &["xe", "i915", "drm", "vfio", "vfio_pci", "vfio-pci", "intel_vsec", "mei_gsc"];

/// Whether a configuration line is about one of the GPU modules: one of its words is the module name.
pub fn mentions_gpu_module(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .any(|word| MODPROBE_MODULES.contains(&word))
}

/// The xe configfs attributes that can be read without a side effect.
const CONFIGFS_ATTRIBUTES: &[&str] =
    &["survivability_mode", "gt_types_allowed", "engines_allowed", "enable_psmi"];

/// The module configuration that decides what an unprivileged run cannot read from the driver:
/// the modprobe options and blacklists that mention the GPU modules, the firmware search path and
/// the xe configfs tree (names and the attributes known to be plain values; nothing is written).
pub fn module_configuration(
    reader: &dyn Reader,
    rel_path: &str,
    config_dirs: &[&Path],
    configfs_xe: &Path,
    firmware_path: &Path,
) -> Vec<Produced> {
    let mut text = String::new();
    let mut files = 0;
    for dir in config_dirs {
        for name in list_names(dir).into_iter().filter(|n| n.ends_with(".conf")) {
            let Some(content) = read_text(reader, &dir.join(&name), MODPROBE_FILE_MAX) else {
                continue;
            };
            files += 1;
            for line in content.lines().map(trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                if mentions_gpu_module(line) {
                    let _ = writeln!(text, "{}/{name}: {line}", dir.display());
                }
            }
        }
    }
    let lines = text.lines().count();
    let _ = writeln!(text, "# {files} configuration files read, {lines} lines about the GPU modules");
    text.push_str(&attribute_line(reader, "firmware_class path", firmware_path));
    text.push('\n');
    let devices = list_names(configfs_xe);
    if devices.is_empty() {
        text.push_str("configfs xe: (empty or not mounted)\n");
    }
    for device in devices {
        let dir = configfs_xe.join(&device);
        let _ = writeln!(text, "configfs xe/{device}:");
        for attribute in CONFIGFS_ATTRIBUTES {
            if dir.join(attribute).exists() {
                let _ = writeln!(text, "  {}", attribute_line(reader, attribute, &dir.join(attribute)));
            }
        }
        let max_vfs = dir.join("sriov/max_vfs");
        if max_vfs.exists() {
            let _ = writeln!(text, "  {}", attribute_line(reader, "sriov/max_vfs", &max_vfs));
        }
    }
    vec![collected(rel_path, text, "")]
}

/// Lines of a `/proc/cpuinfo` block that differ per logical CPU and say nothing about the model.
const CPU_VOLATILE_KEYS: &[&str] = &[
    "processor",
    "core id",
    "apicid",
    "initial apicid",
    "cpu mhz",
    "bogomips",
    "physical id",
    "cpu cores",
    "siblings",
];

/// The CPU blocks of `/proc/cpuinfo` that differ in more than their number, each printed once with
/// the logical CPUs that share it; hybrid parts show one block per core type.
pub fn summarize_cpuinfo(cpuinfo: &str) -> String {
    let mut groups: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut total = 0;
    for block in cpuinfo.split("\n\n").map(str::trim).filter(|b| !b.is_empty()) {
        total += 1;
        let key_of =
            |line: &str| line.split(':').next().map(|k| trim(k).to_ascii_lowercase()).unwrap_or_default();
        let processor = block
            .lines()
            .find(|l| key_of(l) == "processor")
            .and_then(|l| l.split_once(':'))
            .map_or_else(|| total.to_string(), |(_, v)| trim(v).to_owned());
        let stable: String = block
            .lines()
            .filter(|l| !CPU_VOLATILE_KEYS.contains(&key_of(l).as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        match groups.iter_mut().find(|(key, _, _)| *key == stable) {
            Some((_, _, cpus)) => cpus.push(processor),
            None => groups.push((stable, block.to_owned(), vec![processor])),
        }
    }
    let mut text = format!("logical CPUs: {total}\n");
    for (_, block, cpus) in groups.iter().take(CPU_BLOCKS_MAX) {
        let _ = writeln!(text, "\n# {} logical CPUs like this: processor {}", cpus.len(), cpu_list(cpus));
        text.push_str(block);
        text.push('\n');
    }
    if groups.len() > CPU_BLOCKS_MAX {
        let _ = writeln!(text, "\n# {} more kinds of CPU not shown", groups.len() - CPU_BLOCKS_MAX);
    }
    text
}

/// Processor numbers as ranges: `0-3,8`.
fn cpu_list(cpus: &[String]) -> String {
    let mut numbers: Vec<u64> = cpus.iter().filter_map(|c| c.parse().ok()).collect();
    numbers.sort_unstable();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < numbers.len() {
        let start = numbers[i];
        let mut end = start;
        while i + 1 < numbers.len() && numbers[i + 1] == end + 1 {
            i += 1;
            end = numbers[i];
        }
        parts.push(if start == end { start.to_string() } else { format!("{start}-{end}") });
        i += 1;
    }
    parts.join(",")
}

/// `/proc/cpuinfo` reduced by [`summarize_cpuinfo`].
pub fn cpuinfo_summary(reader: &dyn Reader, rel_path: &str, path: &Path) -> Vec<Produced> {
    match read_text(reader, path, CPUINFO_MAX) {
        Some(cpuinfo) => {
            vec![collected(rel_path, summarize_cpuinfo(&cpuinfo), path.to_string_lossy().into_owned())]
        }
        None => vec![skipped(rel_path, "not readable")],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "state_tests.rs"]
mod tests;
