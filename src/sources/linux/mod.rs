// SPDX-License-Identifier: MIT
//! The Linux source table and host facts.
//!
//! One table row is one [`Source`]. Rows follow the order of the reference `--list --full` output
//! (`tests/golden/linux-sources.txt`): system, kernel, per-device, PCI, packages and tools. The
//! xpu-smi views are appended by [`crate::sources`], after this table.
#![forbid(unsafe_code)]

pub mod debugfs;
pub mod drm_ras;
pub mod gpus;
pub mod identity;
pub mod kmsg;
pub mod packages;
pub mod pmt;
pub mod system;
pub mod text;

use std::path::Path;
use std::time::Duration;

use crate::bundle::source::{Gate, Profile, Reader, Source, SourceOptions};
use crate::procio::find_in_path;
use crate::sources::{Tools, device_group};
use crate::units::Bytes;

use self::kmsg::{Boot, kernel_log};
use self::pmt::{PMT_CLASS_DIR, PmtPart, pmt_crashlogs};
use self::text::{split_words, upstream_bridges};

/// Wall-clock limit of the kernel log sources.
/// Wall-clock limit of the OpenCL and VA tools.
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);
/// Size cap of the host system log.
const SYSLOG_MAX: Bytes = Bytes::mib(8);

/// The sysfs attribute patterns of one device, verbatim. `*` matches within one path component.
/// Nothing that can change state or leak the firmware image is on the list (no `config`, `rom`,
/// `remove`, `rescan`, `reset`, `driver_override` or `resource*`).
const DEVICE_SYSFS_PATTERNS: &str = "vendor device revision class subsystem_vendor subsystem_device \
current_link_speed current_link_width max_link_speed max_link_width \
numa_node local_cpulist power_state reset_method d3cold_allowed enable irq \
uevent modalias boot_vga sriov_numvfs sriov_totalvfs sriov_drivers_autoprobe \
aer_dev_correctable aer_dev_fatal aer_dev_nonfatal survivability_mode \
vram_d3cold_threshold lb_* auto_link_downgrade_* \
power/runtime_status power/control power/runtime_active_time power/runtime_suspended_time \
tile*/physical_vram_size_bytes \
tile*/gt*/ccs_mode tile*/gt*/num_cslices \
tile*/gt*/freq0/*_freq tile*/gt*/freq0/power_profile tile*/gt*/freq0/throttle/* \
tile*/gt*/gtidle/* \
tile*/gt*/engines/*/* \
hwmon/hwmon*/* \
drm/card*/dev drm/renderD*/dev";

/// The argv[0] for a tool that usually lives in an sbin directory: `name` when it is on PATH,
/// else `/usr/sbin/<name>` or `/sbin/<name>` when executable. Ordinary users often have no sbin
/// directory on PATH (modinfo, dkms and ldconfig live there).
fn sbin_tool(name: &str) -> String {
    if find_in_path(name).is_some() {
        return name.to_owned();
    }
    for dir in ["/usr/sbin/", "/sbin/"] {
        let path = format!("{dir}{name}");
        if is_executable(Path::new(&path)) {
            return path;
        }
    }
    name.to_owned()
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// A command source whose argv is built at run time.
fn command(rel_path: &str, argv: &[String], profile: Profile, why: &'static str) -> Source {
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    Source::command(rel_path, &argv, profile, why)
}

/// A builtin source that owns what it needs.
fn builtin(
    rel_path: &str,
    produce: impl Fn(&dyn Reader) -> Vec<crate::bundle::source::Produced> + Send + Sync + 'static,
    profile: Profile,
    why: &'static str,
) -> Source {
    Source::builtin(rel_path, Box::new(produce), profile, why)
}

/// The host-wide system sources: OS, CPU, environment, containers, DMI and loader.
fn system_sources() -> Vec<Source> {
    let mut out = Vec::new();
    if Path::new("/etc/os-release").exists() {
        out.push(Source::file(
            "system/os-release",
            "/etc/os-release",
            Profile::Minimal,
            "Distribution identification.",
        ));
    } else {
        out.push(builtin(
            "system/os-release",
            |reader| system::os_release_fallback_builtin(reader, "system/os-release"),
            Profile::Minimal,
            "Distribution identification.",
        ));
    }
    out.push(builtin(
        "system/uname.txt",
        |reader| system::uname_builtin(reader, "system/uname.txt"),
        Profile::Minimal,
        "Kernel release and machine type.",
    ));
    out.push(Source::file("system/cmdline", "/proc/cmdline", Profile::Minimal, "Kernel command line."));
    out.push(Source::file("system/modules", "/proc/modules", Profile::Minimal, "Loaded kernel modules."));
    for name in ["cpuinfo", "meminfo", "interrupts", "iomem"] {
        out.push(Source::file(
            &format!("system/{name}"),
            format!("/proc/{name}"),
            Profile::Default,
            "Host CPU, memory and interrupt layout.",
        ));
    }
    out.push(builtin(
        "system/env.txt",
        |_| system::env_builtin("system/env.txt"),
        Profile::Minimal,
        "Environment variables that change GPU runtime behaviour.",
    ));
    out.push(builtin(
        "system/id.txt",
        |reader| system::id_builtin(reader, "system/id.txt"),
        Profile::Minimal,
        "Which user, groups and capabilities the collection ran with.",
    ));
    out.push(builtin(
        "system/container.txt",
        |reader| system::container_builtin(reader, "system/container.txt"),
        Profile::Minimal,
        "Whether the collection ran inside a container.",
    ));
    out.push(Source::command(
        "system/virt.txt",
        &["systemd-detect-virt"],
        Profile::Default,
        "Virtualisation the host runs under.",
    ));
    out.push(builtin(
        "system/security.txt",
        |reader| system::probe_builtin(reader, "system/security.txt", &system::security_probes()),
        Profile::Minimal,
        "Kernel and LSM settings that restrict GPU and log access.",
    ));
    out.push(builtin(
        "system/dev-dri.txt",
        |reader| system::dev_dri_builtin(reader, "system/dev-dri.txt"),
        Profile::Minimal,
        "Ownership and permissions of the GPU device nodes.",
    ));
    out.push(builtin(
        "system/dmi.txt",
        |reader| system::probe_builtin(reader, "system/dmi.txt", &system::dmi_probes()),
        Profile::Minimal,
        "Platform vendor, model and BIOS version.",
    ));
    out.push(
        Source::tree(
            "system/dmi-serials/",
            "/sys/class/dmi/id",
            &["product_serial", "product_uuid", "board_serial", "chassis_serial"],
            Profile::Minimal,
            "Platform serial numbers and UUID; omitted while redacting.",
        )
        .gate(Gate::Root)
        .identifying(),
    );
    out.push(
        command(
            "system/ldconfig.txt",
            &[sbin_tool("ldconfig"), "-p".to_owned()],
            Profile::Minimal,
            "Which GPU runtime libraries the loader can find.",
        )
        .keep_lines(&["libze_", "libigc", "libigdgmm", "libOpenCL", "libva", "libigsc", "libmetee"]),
    );
    out
}

/// The kernel sources: kernel logs, driver versions, firmware and module parameters.
fn kernel_sources(options: &SourceOptions) -> Vec<Source> {
    let mut out = Vec::new();
    // A time window reaches back over reboots, so it replaces the separate previous-boot log.
    let boots: &[Boot] =
        if options.since.is_some() { &[Boot::Current] } else { &[Boot::Current, Boot::Previous] };
    for &boot in boots {
        let previous = boot == Boot::Previous;
        let rel_path = if previous { "kernel/kmsg-prev-boot.txt" } else { "kernel/kmsg.txt" };
        let why = if previous {
            "Kernel log of the previous boot, for crashes and hangs."
        } else if options.since.is_some() {
            "Kernel log of the --since window, from the journal, across reboots."
        } else {
            "Kernel log of the current boot, with driver and GPU messages."
        };
        let since = options.since;
        let path = rel_path.to_owned();
        out.push(
            builtin(
                rel_path,
                move |reader| kernel_log(reader, &path, boot, since),
                if previous { Profile::Default } else { Profile::Minimal },
                why,
            )
            .gate(Gate::KernelLog)
            .timeout(kmsg::source_timeout(since))
            .tail(),
        );
    }
    out.push(command(
        "kernel/modinfo-xe.txt",
        &[sbin_tool("modinfo"), "xe".to_owned()],
        Profile::Minimal,
        "Version and parameters of the xe kernel driver.",
    ));
    out.push(command(
        "kernel/modinfo-i915.txt",
        &[sbin_tool("modinfo"), "i915".to_owned()],
        Profile::Default,
        "Version and parameters of the i915 kernel driver.",
    ));
    out.push(command(
        "kernel/dkms.txt",
        &[sbin_tool("dkms"), "status".to_owned()],
        Profile::Default,
        "Out-of-tree kernel modules.",
    ));
    out.push(builtin(
        "kernel/firmware.txt",
        |_| system::firmware_builtin("kernel/firmware.txt"),
        Profile::Default,
        "GPU firmware blobs installed on the host.",
    ));
    out.push(
        Source::tree(
            "kernel/xe-parameters/",
            "/sys/module/xe/parameters",
            &["*"],
            Profile::Default,
            "Current xe driver module parameters.",
        )
        .gate(Gate::Root),
    );
    out.push(
        Source::file(
            "kernel/drm-debug.txt",
            "/sys/module/drm/parameters/debug",
            Profile::Default,
            "DRM debug message mask.",
        )
        .gate(Gate::Root),
    );
    out
}

/// The per-device sysfs, link, debugfs, coredump, firmware crash log and RAS counter sources.
fn device_sources(options: &SourceOptions) -> Vec<Source> {
    let mut out = Vec::new();
    for device in &options.devices {
        let dir = device.bdf.dir_name();
        let patterns = split_words(DEVICE_SYSFS_PATTERNS);
        let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
        // A few attributes (late-binding firmware versions, link downgrade status) are owner-only.
        out.push(
            Source::tree(
                &format!("devices/{dir}/sysfs/"),
                &device.os_path,
                &patterns,
                Profile::Minimal,
                "PCI, power, link, frequency and engine attributes from sysfs.",
            )
            .gate(Gate::Root)
            .group(&device_group(device)),
        );
    }
    for device in &options.devices {
        let rel_path = format!("devices/{}/links.txt", device.bdf.dir_name());
        let (path, os_path) = (rel_path.clone(), device.os_path.clone());
        out.push(
            builtin(
                &rel_path,
                move |_| system::links_builtin(&path, &os_path),
                Profile::Minimal,
                "Driver binding, IOMMU group and parent function of the device.",
            )
            .group(&device_group(device)),
        );
    }
    let guc_log = options.profile == Profile::Full;
    for device in &options.devices {
        let rel_dir = format!("devices/{}/debugfs/", device.bdf.dir_name());
        let (dir, bdf) = (rel_dir.clone(), device.bdf);
        out.push(
            builtin(
                &rel_dir,
                move |reader| {
                    debugfs::debugfs_builtin(reader, Path::new(debugfs::DEBUGFS_DRI), &dir, &bdf, guc_log)
                },
                Profile::Default,
                "Driver internals: engines, topology, firmware state.",
            )
            .gate(Gate::Root)
            .group(&device_group(device)),
        );
    }
    for device in &options.devices {
        let dir_rel = format!("dumps/{}/", device.bdf.dir_name());
        let (dir, bdf) = (dir_rel.clone(), device.bdf);
        out.push(
            builtin(
                &dir_rel,
                move |reader| {
                    debugfs::devcoredump_builtin(
                        reader,
                        Path::new(debugfs::DEVCOREDUMP_CLASS_DIR),
                        &dir,
                        &bdf,
                    )
                },
                Profile::Minimal,
                "Device coredumps the driver captured after a hang or crash.",
            )
            .gate(Gate::Root)
            .group(&device_group(device))
            .cap(debugfs::DEVCOREDUMP_MAX),
        );
    }
    // The binary and the text are separate sources because redaction applies to a whole source.
    for device in &options.devices {
        let dir_rel = format!("dumps/{}/", device.bdf.dir_name());
        for (suffix, part, why) in [
            (".bin", PmtPart::Binary, "Raw firmware crash log regions of the platform telemetry interface."),
            (".txt", PmtPart::Info, "Identity and state of each firmware crash log region."),
        ] {
            let (dir, os_path) = (dir_rel.clone(), device.os_path.clone());
            let mut source = builtin(
                &format!("{dir_rel}pmt-crashlog*{suffix}"),
                move |reader| pmt_crashlogs(reader, Path::new(PMT_CLASS_DIR), &dir, &os_path, part),
                Profile::Default,
                why,
            )
            .gate(Gate::Root)
            .group(&device_group(device));
            if part == PmtPart::Binary {
                source = source.binary();
            }
            out.push(source);
        }
    }
    for device in &options.devices {
        let rel_path = format!("devices/{}/ras-counters.json", device.bdf.dir_name());
        let (path, bdf) = (rel_path.clone(), device.bdf);
        out.push(
            builtin(
                &rel_path,
                move |_| vec![drm_ras::counters_artifact(&path, &drm_ras::read_counters(&bdf))],
                Profile::Minimal,
                "Error counters of the device from the kernel's drm-ras interface.",
            )
            .gate(Gate::Root)
            .group(&device_group(device)),
        );
    }
    out
}

/// The lspci sources: the host listings and, per device, the device and its upstream bridges.
fn pci_sources(options: &SourceOptions) -> Vec<Source> {
    let mut out = vec![
        Source::command(
            "pci/lspci-nn.txt",
            &["lspci", "-nn"],
            Profile::Default,
            "PCI devices with numeric ids.",
        ),
        Source::command("pci/lspci-tree.txt", &["lspci", "-tv"], Profile::Default, "PCI topology as a tree."),
    ];
    for device in &options.devices {
        let dir = format!("pci/{}/", device.bdf.dir_name());
        let mut targets = vec![(device.bdf, Profile::Minimal)];
        targets
            .extend(upstream_bridges(&device.os_path).into_iter().map(|bridge| (bridge, Profile::Default)));
        for (bdf, profile) in targets {
            let why = if bdf == device.bdf {
                "PCI capabilities, link state and errors of the GPU."
            } else {
                "PCI capabilities and link state of an upstream bridge."
            };
            out.push(
                command(
                    &format!("{dir}lspci-vvv-{}.txt", bdf.dir_name()),
                    &[
                        "lspci".to_owned(),
                        "-vvv".to_owned(),
                        "-nn".to_owned(),
                        "-s".to_owned(),
                        bdf.to_string(),
                    ],
                    profile,
                    why,
                )
                .gate(Gate::SysAdmin)
                .denied_marker("<access denied>")
                .group(&device_group(device)),
            );
        }
    }
    for device in &options.devices {
        out.push(
            command(
                &format!("pci/{}/lspci-xxxx.txt", device.bdf.dir_name()),
                &["lspci".to_owned(), "-xxxx".to_owned(), "-s".to_owned(), device.bdf.to_string()],
                Profile::Default,
                "Raw PCI configuration space, including extended capabilities.",
            )
            .gate(Gate::SysAdmin)
            .group(&device_group(device))
            .available(system::has_sys_admin),
        );
    }
    out
}

/// The host log and OpenCL/VA tool sources (Full profile).
fn tool_sources() -> Vec<Source> {
    let mut out = vec![
        Source::file("system/syslog", "/var/log/syslog", Profile::Full, "Host system log.")
            .gate(Gate::KernelLog)
            .tail()
            .cap(SYSLOG_MAX),
    ];
    for (tool, why) in
        [("clinfo", "OpenCL platforms and devices."), ("vainfo", "Video acceleration capabilities.")]
    {
        out.push(
            Source::command(&format!("tools/{tool}.txt"), &[tool], Profile::Full, why)
                .gate(Gate::DeviceAccess)
                .timeout(TOOL_TIMEOUT),
        );
    }
    out
}

/// The Linux table for `options` and the tools installed on the host, in order, before profile
/// filtering. The xpu-smi views follow it ([`crate::sources::xpu_smi_views`]).
pub fn table(options: &SourceOptions, tools: &Tools) -> Vec<Source> {
    let mut all = system_sources();
    all.extend(kernel_sources(options));
    all.extend(device_sources(options));
    all.extend(pci_sources(options));
    all.extend(packages::package_sources(tools));
    all.extend(tool_sources());
    all
}
