// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/platform.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put, text_of};

/// A class device whose `device` link points at `devices/<owner>`.
fn class_device(sys: &Path, class: &str, name: &str, owner: &str, files: &[(&str, &str)]) {
    let target = sys.join("devices").join(owner);
    std::fs::create_dir_all(&target).unwrap();
    for (file, contents) in files {
        put(sys, &format!("class/{class}/{name}/{file}"), contents);
    }
    std::os::unix::fs::symlink(&target, sys.join(format!("class/{class}/{name}/device"))).unwrap();
}

fn tree() -> PrivateTempDir {
    let dir = PrivateTempDir::create("platform").unwrap();
    let sys = dir.path();
    class_device(
        sys,
        "mei",
        "mei1",
        "pci0000:00/0000:00:01.0/0000:03:00.0/xe.mei-gscfi.768",
        &[
            ("kind", "gscfi\n"),
            ("fw_ver", "0:203.0.0.1197\n0:0.0.0.0\n0:203.0.0.1197\n"),
            ("fw_status", "00000355\n80210408\n"),
            ("dev_state", "ENABLED"),
            ("hbm_ver", "2.2\n"),
        ],
    );
    class_device(
        sys,
        "mei",
        "mei0",
        "pci0000:00/0000:00:16.0",
        &[("kind", "mei\n"), ("fw_ver", "0:16.1.25.2020\n")],
    );
    class_device(sys, "mei", "mei10", "pci0000:00/0000:00:17.0", &[("kind", "mei\n")]);
    class_device(
        sys,
        "mtd",
        "mtd0",
        "pci0000:00/0000:00:1f.5/spi0.0",
        &[("name", "BIOS\n"), ("size", "8388608\n")],
    );
    class_device(
        sys,
        "mtd",
        "mtd2",
        "pci0000:00/0000:03:00.0/xe.nvm.768",
        &[("name", "xe.nvm.768.GSC\n"), ("size", "5558272\n")],
    );
    class_device(sys, "mtd", "mtd2ro", "pci0000:00/0000:03:00.0/xe.nvm.768", &[("name", "ignored\n")]);
    class_device(
        sys,
        "intel_pmt",
        "crashlog1",
        "pci0000:00/0000:03:00.0/intel_vsec.crashlog.2",
        &[("guid", "0xe2f8200\n"), ("size", "2048\n")],
    );
    put(sys, "bus/event_source/devices/xe_0000_03_00.0/events/gt-c6-residency", "event=0x2\n");
    put(sys, "bus/event_source/devices/xe_0000_03_00.0/events/gt-c6-residency.unit", "ms\n");
    put(sys, "bus/event_source/devices/xe_0000_03_00.0/events/engine-active-ticks", "event=0x1\n");
    put(sys, "bus/event_source/devices/cpu_core/events/x", "");
    dir
}

#[test]
fn the_mei_section_shows_the_firmware_version_and_the_owner() {
    let dir = tree();
    let text = mei_section(&FsReader::default(), dir.path());
    assert!(
        text.starts_with(
            "[mei]\nmei0: kind=mei dev_state=(absent) hbm_ver=(absent) device=pci0000:00/0000:00:16.0\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("mei1: kind=gscfi dev_state=ENABLED hbm_ver=2.2 device=0000:03:00.0/xe.mei-gscfi.768\n  fw_ver: 0:203.0.0.1197 0:0.0.0.0 0:203.0.0.1197\n  fw_status: 00000355 80210408\n"),
        "{text}"
    );
    // Natural order: mei10 after mei1.
    assert!(text.find("mei1:").unwrap() < text.find("mei10:").unwrap());
    assert_eq!(mei_section(&FsReader::default(), &dir.path().join("empty")), "[mei]\n(none)\n");
}

#[test]
fn only_the_gpu_flash_partitions_are_listed() {
    let dir = tree();
    let text = mtd_section(&FsReader::default(), dir.path());
    assert!(text.contains("mtd2: xe.nvm.768.GSC size=5558272 device=0000:03:00.0/xe.nvm.768\n"), "{text}");
    assert!(!text.contains("BIOS") && !text.contains("ignored"), "{text}");
    assert_eq!(mtd_section(&FsReader::default(), &dir.path().join("empty")), "[mtd]\n(none)\n");
}

#[test]
fn telemetry_regions_and_perf_events_are_listed_by_name() {
    let dir = tree();
    let pmt = pmt_section(&FsReader::default(), dir.path());
    assert!(
        pmt.contains("crashlog1: guid=0xe2f8200 size=2048 device=0000:03:00.0/intel_vsec.crashlog.2\n"),
        "{pmt}"
    );
    let pmu = pmu_section(dir.path());
    assert_eq!(pmu, "[perf events of the GPU]\nxe_0000_03_00.0: engine-active-ticks gt-c6-residency\n");
    assert_eq!(pmu_section(&dir.path().join("empty")), "[perf events of the GPU]\n(none)\n");
}

#[test]
fn the_platform_file_has_every_section() {
    let dir = tree();
    let out = platform_devices(&FsReader::default(), dir.path(), "system/platform-devices.txt");
    let text = text_of(&out[0].data);
    for heading in ["[mei]", "[mtd]", "[intel_pmt]", "[perf events of the GPU]"] {
        assert!(text.contains(heading), "{heading}");
    }
}

#[test]
fn power_context_reads_supplies_without_serials() {
    let dir = PrivateTempDir::create("power").unwrap();
    let sys = dir.path();
    put(sys, "class/power_supply/AC/type", "Mains\n");
    put(sys, "class/power_supply/AC/online", "1\n");
    put(sys, "class/power_supply/BAT0/capacity", "80\n");
    put(sys, "class/power_supply/BAT0/serial_number", "SN12345\n");
    put(sys, "class/power_supply/BAT0/model_name", "Example Pack\n");
    put(sys, "class/platform-profile/platform-profile-0/profile", "balanced\n");
    put(sys, "class/powercap/intel-rapl/enabled", "1\n");
    put(sys, "class/powercap/intel-rapl:0/name", "package-0\n");
    put(sys, "class/powercap/intel-rapl:0/constraint_0_power_limit_uw", "45000000\n");
    put(sys, "class/powercap/intel-rapl:0/energy_uj", "1\n");
    put(sys, "class/thermal/thermal_zone0/type", "acpitz\n");
    put(sys, "class/thermal/thermal_zone0/temp", "27800\n");
    put(sys, "devices/system/cpu/cpu0/cpufreq/scaling_governor", "powersave\n");
    put(sys, "class/backlight/intel_backlight/brightness", "50\n");
    let reader = FsReader::default();
    let out = power_context(&reader, sys, "system/power.txt");
    let text = text_of(&out[0].data);
    assert!(text.contains("AC:\n  type: Mains\n  online: 1\n"), "{text}");
    assert!(text.contains("BAT0:\n  capacity: 80\n"));
    assert!(text.contains("profile: balanced"));
    assert!(text.contains("intel-rapl:0: package-0\n  constraint_0_power_limit_uw: 45000000\n"));
    assert!(!text.contains("intel-rapl: "), "{text}");
    assert!(text.contains("thermal_zone0: acpitz temp=27800\n"));
    assert!(text.contains("scaling_governor: powersave\n"));
    assert!(text.contains("intel_backlight:\n  brightness: 50\n"));
    // Nothing identifying is read or written.
    assert!(
        !text.contains("SN12345") && !text.contains("Example Pack") && !text.contains("energy"),
        "{text}"
    );
    let asked = reader.asked.lock().unwrap();
    assert!(
        asked.iter().all(|p| !p.contains("serial") && !p.contains("model_name") && !p.contains("energy_uj")),
        "{asked:?}"
    );
}

#[test]
fn an_empty_host_says_none_for_each_section() {
    let dir = PrivateTempDir::create("power").unwrap();
    let out = power_context(&FsReader::default(), dir.path(), "system/power.txt");
    assert_eq!(text_of(&out[0].data).matches("(none)").count(), 6);
}
