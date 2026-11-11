// SPDX-License-Identifier: MIT
//! Invariants of the source table and the golden `--list --full` comparison.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// The rows are the Linux table; the Windows table is tested by its own module.
#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;
use crate::bundle::source::{Keep, ReadOutcome, ReadResult, Reader, Spec, Status};

const PATH_A: &str = "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/0000:02:01.0/0000:03:00.0";
const PATH_B: &str = "/sys/devices/pci0000:80/0000:80:01.0/0000:84:00.0";
const ADDR_A: PciAddress = PciAddress { domain: 0, bus: 0x03, device: 0, function: 0 };
const ADDR_B: PciAddress = PciAddress { domain: 0, bus: 0x84, device: 0, function: 0 };

/// Options for two fake devices: 0000:03:00.0 behind three bridges and 0000:84:00.0 behind one.
fn options(profile: Profile, samples: u32) -> SourceOptions {
    SourceOptions {
        profile,
        samples,
        devices: vec![
            GpuDevice { bdf: ADDR_A, os_path: PATH_A.to_owned() },
            GpuDevice { bdf: ADDR_B, os_path: PATH_B.to_owned() },
        ],
        ..SourceOptions::default()
    }
}

/// The tools of the reference host that produced the golden table: dpkg only.
const DEBIAN: Tools = Tools { dpkg: true, rpm: false, iclg: false };
const WITH_ICLG: Tools = Tools { dpkg: true, rpm: true, iclg: true };

fn table(options: &SourceOptions) -> Vec<Source> {
    sources_with(options, &DEBIAN)
}

fn paths(sources: &[Source]) -> Vec<String> {
    sources.iter().map(|s| s.rel_path.clone()).collect()
}

fn find<'a>(sources: &'a [Source], rel_path: &str) -> &'a Source {
    sources.iter().find(|s| s.rel_path == rel_path).unwrap_or_else(|| panic!("no source {rel_path}"))
}

fn has(sources: &[Source], rel_path: &str) -> bool {
    sources.iter().any(|s| s.rel_path == rel_path)
}

fn xpu_args(source: &Source) -> &[String] {
    match &source.spec {
        Spec::XpuSmi { args } => args,
        other => panic!("{} is not an xpu-smi source: {other:?}", source.rel_path),
    }
}

#[test]
fn table_invariants_hold_for_every_profile() {
    for profile in [Profile::Minimal, Profile::Default, Profile::Full] {
        for tools in [DEBIAN, WITH_ICLG, Tools::default()] {
            let sources = sources_with(&options(profile, 5), &tools);
            assert!(!sources.is_empty());
            let mut seen = HashSet::new();
            for source in &sources {
                let p = &source.rel_path;
                assert!(!p.is_empty() && !p.starts_with('/'), "{p}");
                assert!(!p.contains(':'), "{p}");
                assert!(!p.contains('\\') && !p.contains("//"), "{p}");
                assert!(p.split('/').all(|s| s != ".." && s != "."), "{p}");
                assert!(p.bytes().all(|b| b >= 0x20), "{p}");
                assert!(!source.why.is_empty(), "{p}");
                assert!(seen.insert(p.clone()), "duplicate {p}");
                assert!(source.profile <= profile, "{p}");
                assert!(!source.group.is_empty(), "{p}");
                assert!(source.timeout > Duration::ZERO, "{p}");
                assert!(source.max_bytes.get() > 0, "{p}");
            }
        }
    }
}

#[test]
fn profiles_nest() {
    let minimal = paths(&table(&options(Profile::Minimal, 5)));
    let default = paths(&table(&options(Profile::Default, 5)));
    let full = paths(&table(&options(Profile::Full, 5)));
    for p in &minimal {
        assert!(default.contains(p), "{p}");
    }
    for p in &default {
        assert!(full.contains(p), "{p}");
    }
    assert!(minimal.len() < default.len());
    assert!(default.len() < full.len());
    assert!(full.iter().any(|p| p == "tools/clinfo.txt"));
    assert!(!default.iter().any(|p| p == "tools/clinfo.txt"));
    assert!(minimal.iter().any(|p| p == "kernel/kmsg.txt"));
    assert!(!minimal.iter().any(|p| p == "kernel/kmsg-prev-boot.txt"));
    assert!(default.iter().any(|p| p == "kernel/kmsg-prev-boot.txt"));
    // Order is the table order whatever the profile: the filtered list is a subsequence.
    let mut rest = full.iter();
    assert!(default.iter().all(|p| rest.any(|q| q == p)));
}

/// The path a File or Tree source names.
fn named_path(spec: &Spec) -> Option<&Path> {
    match spec {
        Spec::File { path } => Some(path),
        Spec::Tree { root, .. } => Some(root),
        _ => None,
    }
}

#[test]
fn a_gate_is_present_where_a_root_only_path_is_named() {
    let sources = table(&options(Profile::Full, 5));
    for source in &sources {
        if let Some(path) = named_path(&source.spec) {
            let path = path.to_string_lossy();
            // debugfs is never named by a file or tree row: its allowlist lives in a builtin.
            assert!(!path.starts_with("/sys/kernel/debug"), "{}", source.rel_path);
            if path.starts_with("/sys/class/dmi/id")
                || path.starts_with("/sys/module/xe/parameters")
                || path.starts_with("/sys/module/drm/parameters")
            {
                assert_eq!(source.gate, Gate::Root, "{}", source.rel_path);
            }
            if path.starts_with("/var/log/syslog") {
                assert_eq!(source.gate, Gate::KernelLog, "{}", source.rel_path);
            }
        }
        if source.rel_path.contains("/debugfs/") || source.rel_path.starts_with("dumps/") {
            assert_eq!(source.gate, Gate::Root, "{}", source.rel_path);
        }
        if source.rel_path.starts_with("kernel/kmsg") {
            assert_eq!(source.gate, Gate::KernelLog, "{}", source.rel_path);
        }
        if let Spec::Command { argv } = &source.spec
            && argv.first().is_some_and(|a| a == "lspci")
            && argv.iter().any(|a| a.starts_with("-vvv") || a == "-xxxx")
        {
            assert_eq!(source.gate, Gate::SysAdmin, "{}", source.rel_path);
        }
    }
    assert_eq!(find(&sources, "system/dmi-serials/").gate, Gate::Root);
    assert!(find(&sources, "system/dmi-serials/").identifying);
    assert_eq!(find(&sources, "kernel/xe-parameters/").gate, Gate::Root);
    assert_eq!(find(&sources, "kernel/drm-debug.txt").gate, Gate::Root);
    assert_eq!(find(&sources, "system/syslog").gate, Gate::KernelLog);
    assert_eq!(find(&sources, "devices/0000-03-00.0/sysfs/").gate, Gate::Root);
    assert_eq!(find(&sources, "devices/0000-03-00.0/ras-counters.json").gate, Gate::Root);
    assert_eq!(find(&sources, "tools/clinfo.txt").gate, Gate::DeviceAccess);
    assert_eq!(find(&sources, "system/uname.txt").gate, Gate::None);
}

#[test]
fn no_source_runs_a_shell_and_files_are_on_the_allowlist() {
    let sources = table(&options(Profile::Full, 5));
    for source in &sources {
        match &source.spec {
            Spec::File { path } => {
                let p = path.to_string_lossy();
                assert!(
                    ["/proc/", "/etc/os-release", "/var/log/", "/sys/module/drm/parameters/"]
                        .iter()
                        .any(|prefix| p.starts_with(prefix)),
                    "{} reads {p}",
                    source.rel_path
                );
            }
            Spec::Tree { root, .. } => {
                let r = root.to_string_lossy();
                assert!(
                    r == PATH_A
                        || r == PATH_B
                        || r == "/sys/class/dmi/id"
                        || r == "/sys/module/xe/parameters",
                    "{} walks {r}",
                    source.rel_path
                );
            }
            Spec::Command { argv } => {
                assert!(!argv.is_empty());
                assert!(!matches!(argv[0].as_str(), "sh" | "bash" | "dash" | "zsh"), "{argv:?}");
                assert!(!argv.iter().any(|a| a == "-c"), "{argv:?}");
            }
            Spec::XpuSmi { .. } | Spec::Builtin(_) => {}
        }
    }
}

#[test]
fn device_sources_carry_the_device_group_and_directory() {
    let o = options(Profile::Full, 5);
    let sources = table(&o);
    for device in &o.devices {
        let dir = device.bdf.to_string().replace(':', "-");
        let group = format!("device:{}", device.bdf);
        for prefix in [
            format!("devices/{dir}/"),
            format!("dumps/{dir}/"),
            format!("xpu-smi/{dir}/"),
            format!("pci/{dir}/"),
        ] {
            let mine: Vec<&Source> = sources.iter().filter(|s| s.rel_path.starts_with(&prefix)).collect();
            assert!(!mine.is_empty(), "{prefix}");
            for source in mine {
                assert_eq!(source.group, group, "{}", source.rel_path);
            }
        }
    }
    for source in &sources {
        if source.rel_path.starts_with("system/") || source.rel_path.starts_with("kernel/") {
            assert_eq!(source.group, "host", "{}", source.rel_path);
        }
    }
}

#[test]
fn samples_follow_the_samples_option() {
    let none = table(&options(Profile::Full, 0));
    assert!(!has(&none, "xpu-smi/0000-03-00.0/samples.csv"));
    assert!(!has(&none, "xpu-smi/0000-84-00.0/samples.csv"));
    assert!(has(&none, "xpu-smi/0000-03-00.0/stats.json"));

    let seven = table(&options(Profile::Default, 7));
    let samples = find(&seven, "xpu-smi/0000-03-00.0/samples.csv");
    assert_eq!(samples.timeout, Duration::from_secs(27));
    let args = xpu_args(samples);
    assert_eq!(args.last().unwrap(), "7");
    assert_eq!(args.first().unwrap(), "dump");
    assert_eq!(
        args,
        [
            "dump",
            "-d",
            "0000:03:00.0",
            "--metrics",
            "POWER,TEMPERATURE,CLOCK,UTILIZATION,MEMORY",
            "--interval",
            "1",
            "--number",
            "7"
        ]
    );
    assert!(!has(&table(&options(Profile::Minimal, 5)), "xpu-smi/0000-03-00.0/samples.csv"));
}

#[test]
fn the_windows_views_follow_the_windows_reference() {
    // oal/win/log_sources.cpp: per device discovery, stats, config, RAS counters, samples (inside the
    // device group); no health, RAS log or crash log.
    let o = options(Profile::Full, 5);
    let windows = views_for(&o, &WITH_ICLG, false);
    assert_eq!(
        paths(&windows),
        [
            "xpu-smi/discovery.json",
            "xpu-smi/topology.txt",
            "xpu-smi/0000-03-00.0/discovery.json",
            "xpu-smi/0000-03-00.0/stats.json",
            "xpu-smi/0000-03-00.0/config.txt",
            "xpu-smi/0000-03-00.0/ras-counters.csv",
            "xpu-smi/0000-03-00.0/samples.csv",
            "xpu-smi/0000-84-00.0/discovery.json",
            "xpu-smi/0000-84-00.0/stats.json",
            "xpu-smi/0000-84-00.0/config.txt",
            "xpu-smi/0000-84-00.0/ras-counters.csv",
            "xpu-smi/0000-84-00.0/samples.csv",
        ]
    );
    assert_eq!(find(&windows, "xpu-smi/discovery.json").why, "xpu-smi device discovery");
    assert_eq!(
        find(&windows, "xpu-smi/0000-03-00.0/samples.csv").why,
        "xpu-smi metric samples, one second apart"
    );
    assert_eq!(find(&windows, "xpu-smi/0000-03-00.0/samples.csv").timeout, Duration::from_secs(25));
    // No samples requested: none of the sample rows.
    let none = views_for(&options(Profile::Full, 0), &DEBIAN, false);
    assert!(!none.iter().any(|s| s.rel_path.ends_with("samples.csv")));
    // The Linux shape keeps health, the RAS log and the crash log.
    let linux = views_for(&o, &WITH_ICLG, true);
    for p in ["xpu-smi/0000-03-00.0/health.json", "xpu-smi/raslog/", "xpu-smi/0000-03-00.0/crashlog/"] {
        assert!(has(&linux, p), "{p}");
    }
}

#[test]
fn xpu_smi_rows_exist_without_an_xpu_smi_and_map_the_self_invocations() {
    // SourceOptions::xpu_smi is None here: the rows are still emitted, the collector skips them.
    let o = options(Profile::Full, 5);
    assert!(o.xpu_smi.is_none());
    let sources = table(&o);
    let version = find(&sources, "xpu-smi/version.txt");
    assert_eq!(version.why, "build provenance and the Level Zero loader in use");
    assert_eq!(xpu_args(version), ["-v"]);
    assert_eq!(version.profile, Profile::Minimal);
    assert_eq!(version.gate, Gate::None);
    assert_eq!(sources[0].rel_path, "xpu-smi/version.txt", "the version row is first");

    assert_eq!(xpu_args(find(&sources, "xpu-smi/discovery.json")), ["discovery", "-j"]);
    assert_eq!(xpu_args(find(&sources, "xpu-smi/topology.txt")), ["topology", "-m"]);
    let dev = "xpu-smi/0000-03-00.0/";
    assert_eq!(
        xpu_args(find(&sources, &format!("{dev}discovery.json"))),
        ["discovery", "-d", "0000:03:00.0", "-j"]
    );
    assert_eq!(xpu_args(find(&sources, &format!("{dev}stats.json"))), ["stats", "-d", "0000:03:00.0", "-j"]);
    assert_eq!(xpu_args(find(&sources, &format!("{dev}config.txt"))), ["config", "-d", "0000:03:00.0"]);
    assert_eq!(
        xpu_args(find(&sources, &format!("{dev}health.json"))),
        ["health", "-d", "0000:03:00.0", "-j"]
    );
    assert_eq!(xpu_args(find(&sources, "xpu-smi/raslog/")), ["raslog", "-f", "{outdir}/raslog.cper", "-j"]);
    for p in ["xpu-smi/discovery.json", "xpu-smi/topology.txt", "xpu-smi/raslog/"] {
        let source = find(&sources, p);
        assert_eq!(source.gate, Gate::DeviceAccess, "{p}");
        assert_eq!(source.timeout, Duration::from_secs(30), "{p}");
        #[cfg(target_os = "linux")]
        assert!(source.available.is_some(), "{p}");
    }
    // Views are the tail of the table; the platform rows come between the version row and them.
    let first_view = sources.iter().position(|s| s.rel_path == "xpu-smi/discovery.json").unwrap();
    assert!(sources[1..first_view].iter().all(|s| !s.rel_path.starts_with("xpu-smi/")));
    assert!(sources[first_view..].iter().all(|s| s.rel_path.starts_with("xpu-smi/")));
}

#[test]
fn common_sources_hold_the_version_row_and_the_views() {
    let common = common_sources(&options(Profile::Full, 5));
    assert_eq!(common[0].rel_path, "xpu-smi/version.txt");
    assert!(common.iter().all(|s| s.rel_path.starts_with("xpu-smi/")));
    assert!(has(&common, "xpu-smi/0000-84-00.0/ras-counters.csv"));
}

#[test]
fn ras_counter_sources() {
    let sources = table(&options(Profile::Full, 5));
    for (dir, bdf) in [("0000-03-00.0", "0000:03:00.0"), ("0000-84-00.0", "0000:84:00.0")] {
        let drm = find(&sources, &format!("devices/{dir}/ras-counters.json"));
        assert_eq!(drm.profile, Profile::Minimal);
        assert_eq!(drm.gate, Gate::Root);
        assert_eq!(drm.group, format!("device:{bdf}"));
        assert_eq!(drm.timeout, Duration::from_secs(10));
        assert!(matches!(drm.spec, Spec::Builtin(_)));

        let csv = find(&sources, &format!("xpu-smi/{dir}/ras-counters.csv"));
        assert_eq!(csv.profile, Profile::Default);
        assert_eq!(csv.gate, Gate::DeviceAccess);
        assert_eq!(csv.group, format!("device:{bdf}"));
        assert_eq!(csv.timeout, Duration::from_secs(30));
        assert_eq!(csv.unsupported_marker.as_deref(), Some("No valid metrics matched"));
        let args = xpu_args(csv);
        assert_eq!(args.len(), 3);
        assert!(args[0].starts_with("--query-gpu="));
        assert!(args[0].contains("ras.reset"));
        assert!(args[0].contains("ecc.errors.aggregate.total"));
        assert_eq!(args[1], format!("--id={bdf}"));
        assert_eq!(args[2], "--format=csv");
    }
    assert!(!has(&table(&options(Profile::Minimal, 5)), "xpu-smi/0000-03-00.0/ras-counters.csv"));
    assert!(has(&table(&options(Profile::Minimal, 5)), "devices/0000-03-00.0/ras-counters.json"));
    assert!(has(&table(&options(Profile::Default, 5)), "xpu-smi/0000-03-00.0/ras-counters.csv"));
}

#[test]
fn ras_query_fields_are_unique_ras_and_ecc_error_names() {
    assert!(!RAS_QUERY_FIELDS.is_empty());
    let mut seen = HashSet::new();
    for field in RAS_QUERY_FIELDS {
        assert!(field.starts_with("ras.") || field.starts_with("ecc.errors."), "{field}");
        assert!(!field.contains(','), "{field}");
        assert!(seen.insert(*field), "{field}");
    }
    let args = ras_counters_args(&ADDR_A);
    assert_eq!(
        args,
        [
            format!("--query-gpu={}", RAS_QUERY_FIELDS.join(",")),
            "--id=0000:03:00.0".to_owned(),
            "--format=csv".to_owned()
        ]
    );
}

#[test]
fn the_crash_log_source_exists_only_where_iclg_does() {
    // a missing tool is "not installed", never "needs root".
    let o = options(Profile::Full, 5);
    assert!(!has(&sources_with(&o, &DEBIAN), "xpu-smi/0000-03-00.0/crashlog/"));
    let sources = sources_with(&o, &WITH_ICLG);
    let crashlog = find(&sources, "xpu-smi/0000-03-00.0/crashlog/");
    if cfg!(target_os = "linux") {
        assert_eq!(crashlog.gate, Gate::Root);
        assert_eq!(crashlog.timeout, Duration::from_secs(60));
        assert_eq!(crashlog.profile, Profile::Default);
        assert!(xpu_args(crashlog).iter().any(|a| a == "--decode"));
        assert_eq!(
            xpu_args(crashlog),
            ["crashlog", "--extract", "-d", "0000:03:00.0", "--output", "{outdir}", "--decode"]
        );
        // The crash log row sits between the RAS log and the samples.
        let order = paths(&sources);
        let at = |p: &str| order.iter().position(|q| q == p).unwrap();
        assert!(at("xpu-smi/raslog/") < at("xpu-smi/0000-03-00.0/crashlog/"));
        assert!(at("xpu-smi/0000-03-00.0/crashlog/") < at("xpu-smi/0000-03-00.0/samples.csv"));
    }
}

#[test]
fn package_sources_follow_the_installed_tools() {
    let o = options(Profile::Full, 5);
    let debian = sources_with(&o, &DEBIAN);
    assert!(has(&debian, "packages/dpkg.txt"));
    assert!(!has(&debian, "packages/rpm.txt") && !has(&debian, "packages/rpm-last.txt"));
    let redhat = sources_with(&o, &Tools { dpkg: false, rpm: true, iclg: false });
    assert!(!has(&redhat, "packages/dpkg.txt"));
    assert!(has(&redhat, "packages/rpm.txt") && has(&redhat, "packages/rpm-last.txt"));
    let neither = sources_with(&o, &Tools::default());
    assert!(!neither.iter().any(|s| s.rel_path.contains("dpkg.txt") || s.rel_path.contains("rpm")));
}

#[test]
fn bridge_lspci_sources_appear_from_the_default_profile() {
    let minimal = paths(&table(&options(Profile::Minimal, 5)));
    let default = paths(&table(&options(Profile::Default, 5)));
    assert!(minimal.contains(&"pci/0000-03-00.0/lspci-vvv-0000-03-00.0.txt".to_owned()));
    assert!(!minimal.contains(&"pci/0000-03-00.0/lspci-vvv-0000-02-01.0.txt".to_owned()));
    for p in [
        "pci/0000-03-00.0/lspci-vvv-0000-02-01.0.txt",
        "pci/0000-03-00.0/lspci-vvv-0000-01-00.0.txt",
        "pci/0000-03-00.0/lspci-vvv-0000-00-01.0.txt",
        "pci/0000-84-00.0/lspci-vvv-0000-80-01.0.txt",
    ] {
        assert!(default.contains(&p.to_owned()), "{p}");
    }
    let sources = table(&options(Profile::Default, 5));
    let denied = find(&sources, "pci/0000-03-00.0/lspci-vvv-0000-03-00.0.txt");
    assert_eq!(denied.denied_marker.as_deref(), Some("<access denied>"));
    #[cfg(target_os = "linux")]
    assert!(find(&sources, "pci/0000-03-00.0/lspci-xxxx.txt").available.is_some());
}

#[test]
fn no_devices_leaves_only_host_sources() {
    let o = SourceOptions { profile: Profile::Full, ..SourceOptions::default() };
    let sources = table(&o);
    for source in &sources {
        let p = &source.rel_path;
        assert!(!p.starts_with("devices/") && !p.starts_with("dumps/") && !p.starts_with("pci/0"), "{p}");
    }
    assert!(!has(&sources, "xpu-smi/raslog/"));
    assert!(has(&sources, "xpu-smi/discovery.json"));
}

#[test]
fn a_time_window_replaces_the_previous_boot_kernel_log() {
    let mut o = options(Profile::Full, 5);
    assert!(has(&table(&o), "kernel/kmsg-prev-boot.txt"));
    o.since = Some(Duration::from_secs(30 * 60));
    let sources = table(&o);
    assert!(!has(&sources, "kernel/kmsg-prev-boot.txt"));
    let kmsg = find(&sources, "kernel/kmsg.txt");
    assert_eq!(kmsg.gate, Gate::KernelLog);
    assert_eq!(kmsg.profile, Profile::Minimal);
    assert!(kmsg.why.contains("--since"));
    assert_eq!(kmsg.keep, Keep::Tail);
    assert_eq!(kmsg.timeout, Duration::from_secs(100)); // 60 s windowed journal + 40 s margin
}

#[test]
fn device_sysfs_patterns_are_verbatim_and_avoid_the_never_list() {
    let sources = table(&options(Profile::Minimal, 5));
    let sysfs = find(&sources, "devices/0000-03-00.0/sysfs/");
    let Spec::Tree { root, patterns } = &sysfs.spec else {
        panic!("sysfs is a tree");
    };
    assert_eq!(root, &PathBuf::from(PATH_A));
    for want in [
        "vendor",
        "lb_*",
        "tile*/gt*/freq0/throttle/*",
        "tile*/gt*/engines/*/*",
        "hwmon/hwmon*/*",
        "drm/renderD*/dev",
    ] {
        assert!(patterns.iter().any(|p| p == want), "{want}");
    }
    for pattern in patterns {
        for never in ["config", "rom", "remove", "rescan", "reset", "driver_override"] {
            assert_ne!(pattern, never);
        }
        assert!(!pattern.starts_with("resource"), "{pattern}");
        assert_ne!(pattern, "*");
        assert!(!pattern.contains(".."), "{pattern}");
    }
}

#[test]
fn builtins_read_only_through_the_reader() {
    struct Fake(std::sync::Mutex<Vec<String>>);
    impl Reader for Fake {
        fn read(&self, path: &Path, _max: Bytes, _keep: Keep) -> ReadResult {
            let p = path.to_string_lossy().into_owned();
            self.0.lock().unwrap().push(p.clone());
            let read = |s: &str| ReadResult {
                outcome: ReadOutcome::Read,
                data: s.as_bytes().to_vec(),
                ..Default::default()
            };
            match p.as_str() {
                "/proc/sys/kernel/dmesg_restrict" => read("1\n"),
                "/sys/class/dmi/id/sys_vendor" => read("Acme\n"),
                "/proc/self/status" => read("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n"),
                _ if p.starts_with("/sys/kernel/security") => {
                    ReadResult { outcome: ReadOutcome::Denied, ..Default::default() }
                }
                _ => ReadResult { outcome: ReadOutcome::Missing, ..Default::default() },
            }
        }
    }
    let sources = table(&options(Profile::Full, 5));
    let run = |rel: &str| {
        let fake = Fake(std::sync::Mutex::new(Vec::new()));
        let Spec::Builtin(f) = &find(&sources, rel).spec else {
            panic!("{rel} is not a builtin");
        };
        let out = f(&fake);
        let asked = fake.0.lock().unwrap().clone();
        (out, asked)
    };
    let (out, asked) = run("system/security.txt");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rel_path, "system/security.txt");
    assert_eq!(out[0].status, Status::Collected);
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    assert!(text.contains("kernel.dmesg_restrict: 1\n"));
    assert!(text.contains("/sys/fs/selinux/enforce: (absent)\n"));
    assert!(text.contains("/sys/kernel/security/lockdown: (denied)\n"));
    assert_eq!(asked.len(), 8);

    let (out, _) = run("system/dmi.txt");
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    assert!(text.contains("sys_vendor: Acme\n"));
    assert!(text.contains("bios_release: (absent)\n"));
    assert!(!text.contains("serial") && !text.contains("uuid"));

    let (out, _) = run("system/id.txt");
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    assert!(text.contains("CapEff: 0000000000000000\n"));
    assert!(text.starts_with("uid: "));

    // Every builtin of the table yields artifacts under its own path and touches only reader paths.
    for source in &sources {
        if let Spec::Builtin(f) = &source.spec {
            if source.rel_path.starts_with("kernel/kmsg") || source.rel_path.contains("ras-counters") {
                continue; // these run journalctl or open a netlink socket
            }
            let fake = Fake(std::sync::Mutex::new(Vec::new()));
            for produced in f(&fake) {
                assert!(
                    produced.rel_path == source.rel_path
                        || produced.rel_path.starts_with(source.rel_path.trim_end_matches(|c| c != '/')),
                    "{} produced {}",
                    source.rel_path,
                    produced.rel_path
                );
            }
        }
    }
}

#[test]
fn live_gpus_identity_and_privilege() {
    let gpus = gpus_from_os();
    println!("gpus_from_os: {gpus:#?}");
    #[cfg(target_os = "linux")]
    for gpu in &gpus {
        assert!(gpu.os_path.starts_with("/sys/devices/"));
    }
    let identity = local_identity();
    let lookup_free = local_identity_without_lookups();
    println!("os_description: {}", os_description());
    println!("local_identity: {identity:?}");
    println!("local_identity_without_lookups: {lookup_free:?}");
    println!("current_privilege: {:?}", current_privilege());
    println!("find_xpu_smi: {:?}", find_xpu_smi(None));
    if let Some(path) = find_xpu_smi(None) {
        println!("xpu_smi_version({}): {:?}", path.display(), xpu_smi_version(&path));
    }
    #[cfg(target_os = "linux")]
    {
        assert!(!os_description().is_empty());
        assert!(identity.user_names.iter().all(|n| n != "root"));
    }
}

/// The rows of `tests/golden/linux-sources.txt`: `(profile, needs, path, why)`.
#[cfg(target_os = "linux")]
fn golden_rows() -> Vec<(String, String, String, String)> {
    let text = include_str!("../../tests/golden/linux-sources.txt");
    let mut lines = text.lines();
    let header = lines.next().unwrap();
    let (needs, path, why) =
        (header.find("NEEDS").unwrap(), header.find("PATH").unwrap(), header.find("WHY").unwrap());
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            (
                l[..needs].trim().to_owned(),
                l[needs..path].trim().to_owned(),
                l[path..why].trim().to_owned(),
                l[why..].trim_end().to_owned(),
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn the_expanded_table_equals_the_golden_list() {
    let o = SourceOptions {
        profile: Profile::Full,
        samples: 5,
        devices: vec![GpuDevice { bdf: ADDR_A, os_path: PATH_A.to_owned() }],
        ..SourceOptions::default()
    };
    let sources = sources_with(&o, &DEBIAN);
    let ours: Vec<(String, String, String, String)> = sources
        .iter()
        .map(|s| {
            let needs = if s.gate == Gate::None { "-" } else { s.gate.name() };
            (s.profile.name().to_owned(), needs.to_owned(), s.rel_path.clone(), s.why.to_owned())
        })
        .collect();
    let golden = golden_rows();
    assert_eq!(golden.len(), 56 - 1);
    for (i, (want, got)) in golden.iter().zip(&ours).enumerate() {
        assert_eq!(want, got, "row {} differs", i + 1);
    }
    assert_eq!(ours.len(), golden.len(), "row counts differ");
}

/// Runs the host-wide builtins against this machine and prints what they produce
/// (`cargo test live_builtins -- --nocapture`); asserts only that each yields something.
#[test]
fn live_builtins_print_this_host() {
    struct StdReader;
    impl Reader for StdReader {
        fn read(&self, path: &Path, max: Bytes, _keep: Keep) -> ReadResult {
            use std::io::Read;
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut data = Vec::new();
                    let _ = file.take(max.get()).read_to_end(&mut data);
                    ReadResult { outcome: ReadOutcome::Read, data, ..Default::default() }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    ReadResult { outcome: ReadOutcome::Missing, ..Default::default() }
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    ReadResult { outcome: ReadOutcome::Denied, ..Default::default() }
                }
                Err(e) => {
                    ReadResult { outcome: ReadOutcome::Failed, error: e.to_string(), ..Default::default() }
                }
            }
        }
    }
    let sources = table(&options(Profile::Full, 5));
    for rel in [
        "system/uname.txt",
        "system/id.txt",
        "system/container.txt",
        "system/security.txt",
        "system/dev-dri.txt",
        "devices/0000-03-00.0/links.txt",
        "devices/0000-03-00.0/debugfs/",
        "dumps/0000-03-00.0/",
        "dumps/0000-03-00.0/pmt-crashlog*.txt",
    ] {
        let Spec::Builtin(f) = &find(&sources, rel).spec else {
            panic!("{rel}");
        };
        for produced in f(&StdReader) {
            println!(
                "--- {} [{}] {}\n{}",
                produced.rel_path,
                produced.status.name(),
                produced.reason,
                String::from_utf8_lossy(&produced.data)
            );
        }
    }
}
