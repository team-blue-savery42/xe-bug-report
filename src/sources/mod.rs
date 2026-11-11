// SPDX-License-Identifier: MIT
//! The diagnostic sources of this OS, and the host facts they depend on.
//!
//! [`sources`] is the one table the collector, the manifest and `--list` share: the xpu-smi
//! version row, the platform table, then the xpu-smi views, filtered by profile and in that order.

pub mod debug_keys;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(any(windows, test))]
pub mod windows;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bundle::source::{Gate, GpuDevice, Profile, Source, SourceOptions};
use crate::bundle::summary::Privilege;
use crate::pci::PciAddress;
use crate::procio::{ChildOutcome, find_in_path, run_child, self_executable_path};
use crate::redact;
use crate::units::Bytes;

/// What the RAS counter query prints when this xpu-smi does not know the fields.
pub const RAS_COUNTERS_UNSUPPORTED_MARKER: &str = "No valid metrics matched";

/// What an xpu-smi that does not know a subcommand (an older build without `raslog` or
/// `crashlog`) prints: "'raslog' is not a valid subcommand." followed by its usage text.
pub const UNKNOWN_SUBCOMMAND_MARKER: &str = "is not a valid subcommand";

/// What a detailed `xpu-smi discovery` prints when the DMI tables are not readable.
pub const DMI_DENIED_MARKER: &str = "Cannot access DMI tables";

/// The query fields of the RAS error counters: every `ras.*` and `ecc.errors.*` field of xpu-smi.
/// A field this xpu-smi does not know makes the query print [`RAS_COUNTERS_UNSUPPORTED_MARKER`], and
/// the source is then skipped as "not supported by this xpu-smi".
pub const RAS_QUERY_FIELDS: &[&str] = &[
    "ecc.errors.corrected.aggregate.total",
    "ecc.errors.uncorrected.aggregate.total",
    "ecc.errors.aggregate.total",
    "ras.reset",
    "ras.programming.errors",
    "ras.driver.errors",
    "ras.cache.errors.correctable",
    "ras.cache.errors.uncorrectable",
    "ras.non_compute.errors.correctable",
    "ras.non_compute.errors.uncorrectable",
    "ras.non_compute.errors.total",
    "ras.memory.errors.correctable",
    "ras.memory.errors.uncorrectable",
    "ras.pcie.errors.correctable",
    "ras.pcie.errors.uncorrectable",
    "ras.soc_internal.errors.correctable",
    "ras.soc_internal.errors.uncorrectable",
    "ras.compute.errors.correctable",
    "ras.compute.errors.uncorrectable",
    "ras.fabric.errors.correctable",
    "ras.fabric.errors.uncorrectable",
    "ras.scale.errors.correctable",
    "ras.scale.errors.uncorrectable",
];

/// Wall-clock limit of an xpu-smi view.
const XPU_SMI_TIMEOUT: Duration = Duration::from_secs(30);
/// Wall-clock limit of the firmware crash log extraction.
const CRASHLOG_TIMEOUT: Duration = Duration::from_secs(60);
/// Time added to the sample count for the `dump` source's limit.
const SAMPLE_OVERHEAD: Duration = Duration::from_secs(20);
/// Wall-clock limit of `xpu-smi -v` when asking for the manifest.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The xpu-smi arguments that print the RAS counters of `bdf` as CSV:
/// `--query-gpu=<fields>`, `--id=<address>`, `--format=csv`.
pub fn ras_counters_args(bdf: &PciAddress) -> Vec<String> {
    vec![
        format!("--query-gpu={}", RAS_QUERY_FIELDS.join(",")),
        format!("--id={bdf}"),
        "--format=csv".to_owned(),
    ]
}

/// The xpu-smi executable: `explicit` when given and a file, else `xpu-smi` on PATH, else next to
/// this executable. None when there is none.
pub fn find_xpu_smi(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.is_file().then(|| path.to_path_buf());
    }
    let name = format!("xpu-smi{}", std::env::consts::EXE_SUFFIX);
    find_in_path("xpu-smi").or_else(|| {
        let beside = self_executable_path()?.parent()?.join(name);
        beside.is_file().then_some(beside)
    })
}

/// The version line of `xpu-smi -v`: the first non-blank line that contains "version" (any case),
/// else the first non-blank line. None when it does not run or exits non-zero.
pub fn xpu_smi_version(xpu_smi: &Path) -> Option<String> {
    let argv = vec![xpu_smi.to_string_lossy().into_owned(), "-v".to_owned()];
    let result = run_child(&argv, VERSION_TIMEOUT, Bytes::kib(64));
    if result.outcome != ChildOutcome::Exited(0) {
        return None;
    }
    version_line(&String::from_utf8_lossy(&result.output))
}

/// The first line of `text` that mentions "version" (ASCII case-insensitive), else the first
/// non-blank line, trimmed.
fn version_line(text: &str) -> Option<String> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines.next()?;
    let line = std::iter::once(first)
        .chain(lines)
        .find(|l| l.to_ascii_lowercase().contains("version"))
        .unwrap_or(first);
    Some(line.to_owned())
}

/// Which optional tools are installed on the host, one flag per tool of that name (`dpkg` is
/// `dpkg-query`, `sycl_ls` is `sycl-ls`). A missing tool is "not installed", never a privilege
/// problem, so its source exists only when the tool does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tools {
    pub dpkg: bool,
    pub rpm: bool,
    /// Firmware crash log extraction.
    pub iclg: bool,
    pub vulkaninfo: bool,
    pub eglinfo: bool,
    pub sycl_ls: bool,
    pub intel_gpu_top: bool,
    pub icpx: bool,
    pub coredumpctl: bool,
}

impl Tools {
    /// Looks for the tools on PATH.
    pub fn detect() -> Self {
        let present = |name: &str| find_in_path(name).is_some();
        Self {
            dpkg: present("dpkg-query"),
            rpm: present("rpm"),
            iclg: present("iclg"),
            vulkaninfo: present("vulkaninfo"),
            eglinfo: present("eglinfo"),
            sycl_ls: present("sycl-ls"),
            intel_gpu_top: present("intel_gpu_top"),
            icpx: present("icpx"),
            coredumpctl: present("coredumpctl"),
        }
    }
}

/// The row that records the xpu-smi build, first in the table.
fn xpu_smi_version_source() -> Source {
    Source::xpu_smi(
        "xpu-smi/version.txt",
        &["-v".to_owned()],
        Profile::Minimal,
        "build provenance and the Level Zero loader in use",
    )
    .timeout(XPU_SMI_TIMEOUT)
}

/// A view that needs a GPU: on Linux gated by [`Gate::DeviceAccess`] and skipped when no render
/// node is accessible.
fn gpu_view(source: Source) -> Source {
    #[cfg(target_os = "linux")]
    {
        source.gate(Gate::DeviceAccess).available(linux::system::any_render_node_accessible)
    }
    #[cfg(not(target_os = "linux"))]
    {
        source
    }
}

/// The xpu-smi views, per OS. They run the xpu-smi executable
/// named by [`SourceOptions::xpu_smi`]; the rows exist even when it is None, and the collector then
/// skips them as "xpu-smi not found".
///
/// Linux: discovery, topology, then per device discovery, statistics, configuration, health, the
/// processes using the device and RAS counters, then the CPER RAS log, the firmware crash logs (only where `iclg` exists) and the
/// metric samples. Windows: discovery, topology, then per device discovery, statistics,
/// configuration, RAS counters and metric samples (no health, RAS log or crash log).
pub fn xpu_smi_views(options: &SourceOptions, tools: &Tools) -> Vec<Source> {
    views_for(options, tools, cfg!(target_os = "linux"))
}

/// [`xpu_smi_views`] for the Linux (`linux`) or the Windows table, so both shapes are testable on
/// either OS. The gates and availability checks follow the OS this is compiled for.
fn views_for(options: &SourceOptions, tools: &Tools, linux: bool) -> Vec<Source> {
    // The views are worded differently per OS.
    let why_for =
        |on_linux: &'static str, on_windows: &'static str| if linux { on_linux } else { on_windows };
    let args = |parts: &[&str]| -> Vec<String> { parts.iter().map(|p| (*p).to_owned()).collect() };
    let view = |rel_path: &str, args: &[String], profile: Profile, why: &'static str| {
        gpu_view(Source::xpu_smi(rel_path, args, profile, why).timeout(XPU_SMI_TIMEOUT))
    };
    let samples_row = |device: &GpuDevice| {
        view(
            &format!("xpu-smi/{}/samples.csv", device.bdf.dir_name()),
            &args(&[
                "dump",
                "-d",
                &device.bdf.to_string(),
                "--metrics",
                "POWER,TEMPERATURE,CLOCK,UTILIZATION,MEMORY",
                "--interval",
                "1",
                "--number",
                &options.samples.to_string(),
            ]),
            Profile::Default,
            why_for("Metric samples taken one second apart.", "xpu-smi metric samples, one second apart"),
        )
        .timeout(Duration::from_secs(u64::from(options.samples)) + SAMPLE_OVERHEAD)
        .group(&device_group(device))
    };
    let mut out = vec![
        view(
            "xpu-smi/discovery.json",
            &args(&["discovery", "-j"]),
            Profile::Minimal,
            why_for("Devices as the driver reports them.", "xpu-smi device discovery"),
        ),
        view(
            "xpu-smi/topology.txt",
            &args(&["topology", "-m"]),
            Profile::Default,
            why_for("GPU, NIC and CPU affinity matrix.", "xpu-smi topology matrix"),
        ),
    ];
    for device in &options.devices {
        let dir = format!("xpu-smi/{}/", device.bdf.dir_name());
        let bdf = device.bdf.to_string();
        let group = device_group(device);
        let mut add = |source: Source| out.push(source.group(&group));
        let discovery = view(
            &format!("{dir}discovery.json"),
            &args(&["discovery", "-d", &bdf, "-j"]),
            Profile::Default,
            why_for("Detailed properties of the device.", "xpu-smi discovery of one device"),
        );
        // On Linux the detailed discovery reads the DMI tables, which only root may read; without
        // that it prints a message and can crash, and the firmware inventory is missing.
        add(if linux { discovery.gate(Gate::Root).denied_marker(DMI_DENIED_MARKER) } else { discovery });
        add(view(
            &format!("{dir}stats.json"),
            &args(&["stats", "-d", &bdf, "-j"]),
            Profile::Default,
            why_for("Current power, temperature, clocks and memory.", "xpu-smi statistics of one device"),
        ));
        add(view(
            &format!("{dir}config.txt"),
            &args(&["config", "-d", &bdf]),
            Profile::Default,
            why_for(
                "Frequency, power, scheduler and standby settings.",
                "xpu-smi configuration of one device",
            ),
        ));
        if linux {
            add(view(
                &format!("{dir}health.json"),
                &args(&["health", "-d", &bdf, "-j"]),
                Profile::Default,
                "Component health status.",
            ));
        }
        if linux {
            add(view(
                &format!("{dir}ps.json"),
                &args(&["ps", "-d", &bdf, "-j"]),
                Profile::Default,
                "Processes using the device, as the driver reports them.",
            ));
        }
        add(view(
            &format!("{dir}ras-counters.csv"),
            &ras_counters_args(&device.bdf),
            Profile::Default,
            why_for(
                "RAS error counters as the query fields report them.",
                "xpu-smi RAS error counters of one device",
            ),
        )
        .unsupported_marker(RAS_COUNTERS_UNSUPPORTED_MARKER));
        // Windows samples sit inside the per-device group, after the RAS counters.
        if !linux && options.samples > 0 {
            out.push(samples_row(device));
        }
    }
    if linux && !options.devices.is_empty() {
        out.push(
            view(
                "xpu-smi/raslog/",
                &args(&["raslog", "-f", "{outdir}/raslog.cper", "-j"]),
                Profile::Default,
                "Hardware RAS error records (CPER) of all devices.",
            )
            .unsupported_marker(UNKNOWN_SUBCOMMAND_MARKER),
        );
    }
    // The crash log source exists only where iclg is installed, so a missing tool is not reported
    // as a missing privilege.
    if linux && tools.iclg {
        for device in &options.devices {
            out.push(
                view(
                    &format!("xpu-smi/{}/crashlog/", device.bdf.dir_name()),
                    &args(&[
                        "crashlog",
                        "--extract",
                        "-d",
                        &device.bdf.to_string(),
                        "--output",
                        "{outdir}",
                        "--decode",
                    ]),
                    Profile::Default,
                    "Firmware crash log records.",
                )
                .gate(Gate::Root)
                .timeout(CRASHLOG_TIMEOUT)
                .unsupported_marker(UNKNOWN_SUBCOMMAND_MARKER)
                .group(&device_group(device)),
            );
        }
    }
    if linux && options.samples > 0 {
        for device in &options.devices {
            out.push(samples_row(device));
        }
    }
    out
}

/// The circuit-breaker group of a device's sources.
fn device_group(device: &GpuDevice) -> String {
    format!("device:{}", device.bdf)
}

/// Sources common to every OS (the xpu-smi version row and views), before profile filtering. In
/// [`sources`] the version row comes first and the views last; this returns them together.
pub fn common_sources(options: &SourceOptions) -> Vec<Source> {
    let tools = Tools::detect();
    let mut out = vec![xpu_smi_version_source()];
    out.extend(xpu_smi_views(options, &tools));
    out
}

/// The platform table (everything between the version row and the xpu-smi views), unfiltered.
fn platform_table(options: &SourceOptions, tools: &Tools) -> Vec<Source> {
    #[cfg(target_os = "linux")]
    {
        linux::table(options, tools)
    }
    #[cfg(windows)]
    {
        // The Windows table has no xpu-smi rows: `xpu_smi_views` supplies them after it.
        let _ = tools;
        windows::table(options)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (options, tools);
        Vec::new()
    }
}

/// [`sources`] for given host tools: version row, platform table, xpu-smi views, filtered by
/// profile, in table order.
pub fn sources_with(options: &SourceOptions, tools: &Tools) -> Vec<Source> {
    let mut all = vec![xpu_smi_version_source()];
    all.extend(platform_table(options, tools));
    all.extend(xpu_smi_views(options, tools));
    all.retain(|source| source.profile <= options.profile);
    all
}

/// Common + platform sources, profile-filtered, in table order.
pub fn sources(options: &SourceOptions) -> Vec<Source> {
    sources_with(options, &Tools::detect())
}

/// The Intel GPUs the OS sees, without any driver call, in BDF order.
pub fn gpus_from_os() -> Vec<GpuDevice> {
    #[cfg(target_os = "linux")]
    {
        linux::gpus::gpus_from_os()
    }
    #[cfg(windows)]
    {
        windows::gpus_from_os()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Vec::new()
    }
}

/// This machine's host names and user names; may do name-service lookups.
pub fn local_identity() -> redact::Context {
    #[cfg(target_os = "linux")]
    {
        linux::identity::local_identity()
    }
    #[cfg(windows)]
    {
        windows::local_identity()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        redact::Context::default()
    }
}

/// This machine's names without any lookup; never blocks.
pub fn local_identity_without_lookups() -> redact::Context {
    #[cfg(target_os = "linux")]
    {
        linux::identity::local_identity_without_lookups()
    }
    #[cfg(windows)]
    {
        windows::local_identity_without_lookups()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        redact::Context::default()
    }
}

/// One line naming the OS, e.g. "Ubuntu 24.04.3 LTS, Linux 7.2.0 x86_64".
pub fn os_description() -> String {
    #[cfg(target_os = "linux")]
    {
        linux::identity::os_description()
    }
    #[cfg(windows)]
    {
        windows::os_description()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        String::new()
    }
}

/// The privilege of this process: root or `CAP_SYS_ADMIN` on Linux, elevated on Windows.
pub fn current_privilege() -> Privilege {
    #[cfg(target_os = "linux")]
    {
        linux::system::current_privilege()
    }
    #[cfg(windows)]
    {
        windows::current_privilege()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Privilege::Unprivileged
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod unit_tests;
