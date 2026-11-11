// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/mod.rs`.

use super::*;
use crate::bundle::source::{Content, Keep, Spec};
use std::path::PathBuf;
use std::time::Duration;

fn rows(options: &SourceOptions) -> Vec<Source> {
    table_for(
        options,
        Path::new("C:\\Windows"),
        Path::new("C:\\ProgramData"),
        Some(Path::new("C:\\Users\\me\\AppData\\Local")),
    )
}

fn row<'a>(sources: &'a [Source], rel: &str) -> &'a Source {
    sources.iter().find(|s| s.rel_path == rel).unwrap_or_else(|| panic!("no row {rel}"))
}

fn argv(s: &Source) -> &[String] {
    match &s.spec {
        Spec::Command { argv } => argv,
        other => panic!("not a command: {other:?}"),
    }
}

#[test]
fn covers_the_golden_paths_in_order() {
    let golden: Vec<&str> = include_str!("../../../tests/golden/windows-sources.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("xpu-smi/") && !l.is_empty())
        .collect();
    let sources = rows(&SourceOptions::default());
    let paths: Vec<&str> = sources.iter().map(|s| s.rel_path.as_str()).collect();
    for g in &golden {
        assert!(paths.contains(g), "missing {g}");
    }
    assert_eq!(paths.len(), golden.len());
    // bundle order, with the additions grouped by directory
    assert_eq!(
        paths,
        [
            "system/os.txt",
            "system/systeminfo.txt",
            "system/env.txt",
            "system/id.txt",
            "system/wmi-video.txt",
            "system/wmi-display-drivers.txt",
            "system/monitors.txt",
            "system/power-sleep-states.txt",
            "system/power-scheme.txt",
            "system/power-pcie.txt",
            "system/power-requests.txt",
            "system/gpu-counters.txt",
            "system/isolation.txt",
            "system/bcdedit.txt",
            "devices/pnputil-devices.txt",
            "devices/pnputil-drivers.txt",
            "devices/display-class-registry.txt",
            "devices/directx-registry.txt",
            "devices/gpu-preference-registry.txt",
            "devices/intel-igfx-registry-machine.txt",
            "devices/intel-igfx-registry-user.txt",
            "devices/khronos-icd.txt",
            "kernel/graphicsdrivers-registry.txt",
            "kernel/crashcontrol-registry.txt",
            "kernel/localdumps-registry.txt",
            "kernel/system-events.txt",
            "kernel/application-events.txt",
            "kernel/graphics-channel-events.txt",
            "kernel/etw-providers.txt",
            "kernel/",
            "kernel/setupapi.dev.log",
            "dumps/listings.txt",
            "dumps/wer-kernel-reports.txt",
            "dumps/user-crashdumps.txt",
            "packages/driverquery.csv",
            "packages/umd-versions.txt",
            "packages/intel-software.txt",
            "tools/dxdiag/",
        ]
    );
}

#[test]
fn every_row_is_described_and_unique() {
    let sources = rows(&SourceOptions::default());
    for s in &sources {
        assert!(!s.why.is_empty(), "{}", s.rel_path);
        assert!(!s.rel_path.starts_with('/') && !s.rel_path.contains('\\'), "{}", s.rel_path);
        assert_eq!(s.group, "host");
    }
    let mut paths: Vec<_> = sources.iter().map(|s| s.rel_path.clone()).collect();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), sources.len());
}

#[test]
fn profiles_are_as_documented() {
    let sources = rows(&SourceOptions::default());
    let profile = |rel: &str| row(&sources, rel).profile;
    for rel in [
        "system/os.txt",
        "system/env.txt",
        "system/id.txt",
        "system/wmi-video.txt",
        "system/wmi-display-drivers.txt",
        "devices/pnputil-devices.txt",
        "kernel/graphicsdrivers-registry.txt",
        "kernel/crashcontrol-registry.txt",
        "kernel/system-events.txt",
    ] {
        assert_eq!(profile(rel), Profile::Minimal, "{rel}");
    }
    for rel in [
        "system/systeminfo.txt",
        "devices/pnputil-drivers.txt",
        "devices/display-class-registry.txt",
        "kernel/application-events.txt",
        "kernel/setupapi.dev.log",
        "dumps/listings.txt",
        "packages/driverquery.csv",
        "system/monitors.txt",
        "system/power-sleep-states.txt",
        "system/power-scheme.txt",
        "system/power-pcie.txt",
        "system/power-requests.txt",
        "system/gpu-counters.txt",
        "system/isolation.txt",
        "system/bcdedit.txt",
        "devices/directx-registry.txt",
        "devices/gpu-preference-registry.txt",
        "devices/intel-igfx-registry-machine.txt",
        "devices/intel-igfx-registry-user.txt",
        "devices/khronos-icd.txt",
        "kernel/localdumps-registry.txt",
        "kernel/graphics-channel-events.txt",
        "kernel/etw-providers.txt",
        "dumps/wer-kernel-reports.txt",
        "dumps/user-crashdumps.txt",
        "packages/umd-versions.txt",
        "packages/intel-software.txt",
    ] {
        assert_eq!(profile(rel), Profile::Default, "{rel}");
    }
    assert_eq!(profile("kernel/"), Profile::Full);
    assert_eq!(profile("tools/dxdiag/"), Profile::Full);
}

#[test]
fn timeouts_caps_and_flags_are_as_documented() {
    let sources = rows(&SourceOptions::default());
    let t = |rel: &str| row(&sources, rel).timeout;
    assert_eq!(t("system/os.txt"), Duration::from_secs(30));
    assert_eq!(t("system/systeminfo.txt"), Duration::from_secs(60));
    assert_eq!(t("system/id.txt"), Duration::from_secs(10));
    assert_eq!(t("system/wmi-video.txt"), Duration::from_secs(30));
    assert_eq!(t("system/wmi-display-drivers.txt"), Duration::from_secs(60));
    assert_eq!(t("devices/pnputil-devices.txt"), Duration::from_secs(30));
    assert_eq!(t("devices/pnputil-drivers.txt"), Duration::from_secs(30));
    assert_eq!(t("devices/display-class-registry.txt"), Duration::from_secs(30));
    assert_eq!(t("kernel/graphicsdrivers-registry.txt"), Duration::from_secs(10));
    assert_eq!(t("kernel/system-events.txt"), Duration::from_secs(60));
    assert_eq!(t("kernel/application-events.txt"), Duration::from_secs(60));
    assert_eq!(t("kernel/"), Duration::from_secs(120));
    assert_eq!(t("packages/driverquery.csv"), Duration::from_secs(30));
    assert_eq!(t("tools/dxdiag/"), Duration::from_secs(120));
    for rel in [
        "system/monitors.txt",
        "system/power-sleep-states.txt",
        "system/power-scheme.txt",
        "system/power-pcie.txt",
        "system/power-requests.txt",
        "system/isolation.txt",
        "system/bcdedit.txt",
        "devices/directx-registry.txt",
        "devices/khronos-icd.txt",
        "kernel/etw-providers.txt",
        "packages/umd-versions.txt",
    ] {
        assert_eq!(t(rel), Duration::from_secs(30), "{rel}");
    }
    for rel in
        ["system/gpu-counters.txt", "kernel/graphics-channel-events.txt", "packages/intel-software.txt"]
    {
        assert_eq!(t(rel), Duration::from_secs(60), "{rel}");
    }
    for rel in [
        "devices/gpu-preference-registry.txt",
        "devices/intel-igfx-registry-machine.txt",
        "devices/intel-igfx-registry-user.txt",
        "kernel/crashcontrol-registry.txt",
        "kernel/localdumps-registry.txt",
    ] {
        assert_eq!(t(rel), Duration::from_secs(10), "{rel}");
    }
    assert_eq!(row(&sources, "devices/directx-registry.txt").max_bytes, Bytes::mib(2));
    for rel in ["devices/intel-igfx-registry-machine.txt", "devices/intel-igfx-registry-user.txt"] {
        assert_eq!(row(&sources, rel).max_bytes, Bytes::mib(1), "{rel}");
    }
    assert_eq!(t("dumps/wer-kernel-reports.txt"), Duration::from_secs(30));

    assert_eq!(row(&sources, "devices/display-class-registry.txt").max_bytes, Bytes::mib(8));
    let evtx = row(&sources, "kernel/");
    assert_eq!(evtx.max_bytes, Bytes::mib(64));
    assert_eq!(evtx.content, Content::Binary);
    assert!(evtx.identifying);
    let setupapi = row(&sources, "kernel/setupapi.dev.log");
    assert_eq!(setupapi.max_bytes, Bytes::mib(4));
    assert_eq!(setupapi.keep, Keep::Tail);
    match &setupapi.spec {
        Spec::File { path } => {
            assert!(path.to_string_lossy().starts_with("C:\\Windows"));
            assert!(path.to_string_lossy().ends_with("setupapi.dev.log"));
        }
        other => panic!("{other:?}"),
    }
    assert!(sources.iter().filter(|s| s.identifying).count() == 1);
}

#[test]
fn only_the_rows_that_need_elevation_are_gated() {
    let elevated = [
        "dumps/listings.txt",
        "dumps/wer-kernel-reports.txt",
        "system/power-requests.txt",
        "system/bcdedit.txt",
    ];
    let sources = rows(&SourceOptions::default());
    for s in &sources {
        let expected = if elevated.contains(&s.rel_path.as_str()) { Gate::Elevated } else { Gate::None };
        assert_eq!(s.gate, expected, "{}", s.rel_path);
        // A command that needs elevation is skipped up front when the process is not elevated.
        assert_eq!(
            s.available.is_some(),
            matches!(s.rel_path.as_str(), "system/power-requests.txt" | "system/bcdedit.txt"),
            "{}",
            s.rel_path
        );
    }
    for rel in
        ["dumps/listings.txt", "dumps/wer-kernel-reports.txt", "dumps/user-crashdumps.txt", "system/env.txt"]
    {
        assert!(matches!(row(&sources, rel).spec, Spec::Builtin(_)), "{rel}");
    }
}

#[test]
fn powershell_scripts_survive_command_line_quoting() {
    let sources = rows(&SourceOptions::default());
    let mut seen = 0;
    for s in &sources {
        let Spec::Command { argv } = &s.spec else { continue };
        if argv[0] != "powershell.exe" {
            continue;
        }
        seen += 1;
        let script = &argv[4];
        assert!(!script.contains('"'), "{}", s.rel_path);
        assert!(!script.ends_with('\\'), "{}", s.rel_path);
    }
    assert_eq!(seen, 10);
}

#[test]
fn commands() {
    let sources = rows(&SourceOptions::default());
    assert_eq!(argv(row(&sources, "system/systeminfo.txt")), ["systeminfo"]);
    assert_eq!(argv(row(&sources, "system/id.txt")), ["whoami", "/user", "/groups", "/priv", "/fo", "list"]);
    assert_eq!(
        argv(row(&sources, "devices/pnputil-devices.txt")),
        ["pnputil", "/enum-devices", "/class", "Display", "/drivers"]
    );
    assert_eq!(
        argv(row(&sources, "devices/pnputil-drivers.txt")),
        ["pnputil", "/enum-drivers", "/class", "Display"]
    );
    assert_eq!(
        argv(row(&sources, "devices/display-class-registry.txt")),
        [
            "reg",
            "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}",
            "/s"
        ]
    );
    assert_eq!(
        argv(row(&sources, "kernel/graphicsdrivers-registry.txt")),
        ["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", "/s"]
    );
    assert_eq!(argv(row(&sources, "packages/driverquery.csv")), ["driverquery", "/v", "/fo", "csv"]);
    assert_eq!(argv(row(&sources, "tools/dxdiag/")), ["dxdiag", "/whql:off", "/t", "{outdir}\\dxdiag.txt"]);
    let os = argv(row(&sources, "system/os.txt"));
    assert_eq!(&os[..4], ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]);
    assert!(os[4].starts_with(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-CimInstance Win32_OperatingSystem"
    ));
    let drivers = argv(row(&sources, "system/wmi-display-drivers.txt"));
    assert!(drivers[4].ends_with(
        "Format-List DeviceName,DriverVersion,DriverDate,InfName,DeviceID,Manufacturer,IsSigned,Signer"
    ));
    assert!(drivers[4].contains("$_.DeviceClass -eq 'DISPLAY'"));
}

#[test]
fn the_added_commands() {
    let sources = rows(&SourceOptions::default());
    assert_eq!(argv(row(&sources, "system/power-requests.txt")), ["powercfg", "/requests"]);
    assert_eq!(argv(row(&sources, "system/power-sleep-states.txt")), ["powercfg", "/a"]);
    assert_eq!(argv(row(&sources, "system/power-scheme.txt")), ["powercfg", "/getactivescheme"]);
    assert_eq!(
        argv(row(&sources, "system/power-pcie.txt")),
        ["powercfg", "/query", "SCHEME_CURRENT", "SUB_PCIEXPRESS"]
    );
    assert_eq!(
        argv(row(&sources, "devices/intel-igfx-registry-machine.txt")),
        ["reg", "query", "HKLM\\SOFTWARE\\Intel\\IGFX", "/s"]
    );
    assert_eq!(
        argv(row(&sources, "devices/intel-igfx-registry-user.txt")),
        ["reg", "query", "HKCU\\Software\\Intel\\IGFX", "/s"]
    );
    assert_eq!(argv(row(&sources, "system/bcdedit.txt")), ["bcdedit", "/enum", "{current}"]);
    assert_eq!(
        argv(row(&sources, "devices/directx-registry.txt")),
        ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\DirectX", "/s"]
    );
    assert_eq!(
        argv(row(&sources, "devices/gpu-preference-registry.txt")),
        ["reg", "query", "HKCU\\Software\\Microsoft\\DirectX\\UserGpuPreferences"]
    );
    assert_eq!(
        argv(row(&sources, "kernel/crashcontrol-registry.txt")),
        ["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl", "/s"]
    );
    assert_eq!(
        argv(row(&sources, "kernel/localdumps-registry.txt")),
        ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "/s"]
    );
    assert_eq!(argv(row(&sources, "kernel/etw-providers.txt")), ["logman", "query", "providers"]);
    assert_eq!(row(&sources, "kernel/etw-providers.txt").keep_lines, ["intel", "igfx", "dxgkrnl", "display"]);
}

#[test]
fn the_channel_script_uses_the_window() {
    let options = SourceOptions { since: Some(Duration::from_secs(3600)), ..SourceOptions::default() };
    let sources = rows(&options);
    let channels = argv(row(&sources, "kernel/graphics-channel-events.txt"));
    assert!(channels[4].contains("AddMilliseconds(-3600000)"), "{}", channels[4]);
}

#[test]
fn event_queries_use_the_window() {
    let default = rows(&SourceOptions::default());
    let sys = argv(row(&default, "kernel/system-events.txt"));
    assert_eq!(&sys[..3], ["wevtutil", "qe", "System"]);
    assert!(sys[3].ends_with("TimeCreated[timediff(@SystemTime) <= 259200000]]]"), "{}", sys[3]);
    assert_eq!(&sys[4..], ["/f:text", "/rd:true", "/c:5000"]);

    let options = SourceOptions { since: Some(Duration::from_secs(24 * 3600)), ..SourceOptions::default() };
    let sources = rows(&options);
    let app = argv(row(&sources, "kernel/application-events.txt"));
    assert_eq!(&app[..3], ["wevtutil", "qe", "Application"]);
    assert!(app[3].ends_with("<= 86400000]]]"), "{}", app[3]);
    assert_eq!(&app[4..], ["/f:text", "/rd:true", "/c:2000"]);
    let evtx = argv(row(&sources, "kernel/"));
    assert_eq!(&evtx[..4], ["wevtutil", "epl", "System", "{outdir}\\System.evtx"]);
    assert_eq!(evtx[4], "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]");
}

#[test]
fn table_does_not_depend_on_devices() {
    let options = SourceOptions {
        devices: vec![GpuDevice { bdf: Default::default(), os_path: "PCI\\VEN_8086".into() }],
        xpu_smi: Some(PathBuf::from("xpu-smi")),
        ..SourceOptions::default()
    };
    assert_eq!(rows(&options).len(), rows(&SourceOptions::default()).len());
}
