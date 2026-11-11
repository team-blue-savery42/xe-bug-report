// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/state.rs`.

use std::io::Write;

use super::*;
use crate::bundle::source::Status;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put, text_of};

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

const CONFIG: &str = "# Automatically generated\nCONFIG_DRM_XE=m\nCONFIG_DRM_XE_FORCE_PROBE=\"*\"\n\
# CONFIG_DRM_XE_DEBUG is not set\nCONFIG_NET=y\nCONFIG_HZ=1000\nCONFIG_HZ_1000=y\nCONFIG_PCI_IOV=y\n\
CONFIG_LOCALVERSION=\"-custom\"\nCONFIG_SOUND=m\n";

#[test]
fn taint_flags_are_spelled_out() {
    assert_eq!(describe_taint(0), "none");
    assert_eq!(describe_taint(4), "S (CPU out of specification)");
    assert_eq!(describe_taint(512 | 4096), "W (kernel warning issued), O (out-of-tree module loaded)");
    // Every flag has a distinct bit and letter.
    let mut bits: Vec<u32> = TAINT_FLAGS.iter().map(|f| f.0).collect();
    bits.dedup();
    assert_eq!(bits.len(), TAINT_FLAGS.len());
}

#[test]
fn the_state_report_decodes_the_taint_value() {
    let dir = PrivateTempDir::create("state").unwrap();
    put(dir.path(), "version", "Linux version 7.2.0 (builder@example.com)\n");
    put(dir.path(), "tainted", "512\n");
    put(dir.path(), "refcnt", "4\n");
    let probes = vec![
        Probe {
            label: "kernel.tainted".to_owned(),
            path: dir.path().join("tainted").to_string_lossy().into_owned(),
        },
        Probe {
            label: "xe module refcnt".to_owned(),
            path: dir.path().join("refcnt").to_string_lossy().into_owned(),
        },
        Probe {
            label: "xe module taint".to_owned(),
            path: dir.path().join("gone").to_string_lossy().into_owned(),
        },
    ];
    let out = state_report(&FsReader::default(), "system/state.txt", &probes, &dir.path().join("version"));
    let text = text_of(&out[0].data);
    assert_eq!(
        text,
        "kernel version: Linux version 7.2.0 (builder@example.com)\n\
         kernel.tainted: 512\n\
         kernel.tainted flags: W (kernel warning issued)\n\
         xe module refcnt: 4\n\
         xe module taint: (absent)\n"
    );
}

#[test]
fn the_state_probes_cover_suspend_counters_and_the_driver() {
    let probes = state_probes();
    for label in
        ["kernel.tainted", "xe module srcversion", "devcoredump disabled", "suspend_stats last_failed_dev"]
    {
        assert!(probes.iter().any(|p| p.label == label), "{label}");
    }
    // Only plain world-readable attributes: nothing under debugfs or a write-only control.
    assert!(probes.iter().all(|p| p.path.starts_with("/proc/") || p.path.starts_with("/sys/")));
    assert!(probes.iter().all(|p| !p.path.contains("/debug/")));
}

#[test]
fn the_configuration_is_filtered_to_the_symbols_that_matter() {
    let kept = filter_config(CONFIG);
    assert_eq!(
        kept,
        "CONFIG_DRM_XE=m\nCONFIG_DRM_XE_FORCE_PROBE=\"*\"\n# CONFIG_DRM_XE_DEBUG is not set\n\
         CONFIG_HZ=1000\nCONFIG_HZ_1000=y\nCONFIG_PCI_IOV=y\nCONFIG_LOCALVERSION=\"-custom\"\n"
    );
    assert_eq!(config_symbol("# CONFIG_X is not set"), Some("X"));
    assert_eq!(config_symbol("CONFIG_X=y"), Some("X"));
    assert_eq!(config_symbol("# a comment"), None);
}

#[test]
fn the_configuration_comes_from_proc_or_the_boot_directory() {
    let dir = PrivateTempDir::create("config").unwrap();
    let boot = dir.path().join("boot");
    put(dir.path(), "config.gz", gzip(CONFIG));
    let out = kernel_config(
        &FsReader::default(),
        "kernel/config.txt",
        &dir.path().join("config.gz"),
        &boot,
        "7.2.0",
    );
    assert_eq!(out[0].status, Status::Collected);
    let text = text_of(&out[0].data);
    assert!(text.starts_with("# from "), "{text}");
    assert!(text.contains("7 of 10 lines\nCONFIG_DRM_XE=m\n"), "{text}");

    // Without /proc/config.gz the file of the running release is used.
    put(dir.path(), "boot/config-7.2.0", CONFIG);
    let out =
        kernel_config(&FsReader::default(), "kernel/config.txt", &dir.path().join("none.gz"), &boot, "7.2.0");
    assert_eq!(out[0].status, Status::Collected);
    assert!(out[0].via.ends_with("config-7.2.0"), "{}", out[0].via);

    // A garbled /proc/config.gz also falls back.
    put(dir.path(), "bad.gz", "not gzip");
    let out =
        kernel_config(&FsReader::default(), "kernel/config.txt", &dir.path().join("bad.gz"), &boot, "7.2.0");
    assert_eq!(out[0].status, Status::Collected);

    // Neither: a skipped source that says what it looked for and does not claim a privilege.
    let out =
        kernel_config(&FsReader::default(), "kernel/config.txt", &dir.path().join("none.gz"), &boot, "9.9");
    assert_eq!(out[0].status, Status::Skipped);
    assert!(
        out[0].reason.contains("config-9.9") && !out[0].reason.starts_with("needs "),
        "{}",
        out[0].reason
    );
}

#[test]
fn a_decompression_bomb_is_cut_at_the_cap() {
    let big = "CONFIG_DRM_XE=m\n".repeat(100_000);
    let out = gunzip_capped(&gzip(&big), Bytes::kib(1)).unwrap();
    assert_eq!(out.len(), 1024);
    assert!(gunzip_capped(b"plain text", Bytes::kib(1)).is_none());
    assert!(gunzip_capped(b"", Bytes::kib(1)).is_none());
}

#[test]
fn module_lines_are_kept_by_whole_word() {
    for line in [
        "options xe force_probe=e20b",
        "blacklist xe",
        "options i915 enable_guc=3",
        "softdep xe pre: vfio-pci",
        "options xe.force_probe=1",
        "install drm /bin/true",
    ] {
        assert!(mentions_gpu_module(line), "{line}");
    }
    for line in ["blacklist nouveau", "options snd_hda_intel index=0", "alias xen_pci x", "# xe"] {
        assert!(!mentions_gpu_module(line) || line.starts_with('#'), "{line}");
    }
    assert!(!mentions_gpu_module("options next foo=1"));
}

#[test]
fn the_module_configuration_reads_filtered_files_and_configfs() {
    let dir = PrivateTempDir::create("modules").unwrap();
    let modprobe = dir.path().join("modprobe.d");
    put(&modprobe, "gpu.conf", "# comment mentioning xe\noptions xe force_probe=*\noptions snd index=1\n");
    put(&modprobe, "other.conf", "blacklist pcspkr\n");
    put(&modprobe, "readme.txt", "options xe ignored=1\n");
    let configfs = dir.path().join("configfs");
    put(&configfs, "0000:03:00.0/survivability_mode", "0\n");
    put(&configfs, "0000:03:00.0/sriov/max_vfs", "7\n");
    put(dir.path(), "fwpath", "");
    let out = module_configuration(
        &FsReader::default(),
        "kernel/modprobe-config.txt",
        &[modprobe.as_path(), Path::new("/nonexistent-modprobe-dir")],
        &configfs,
        &dir.path().join("fwpath"),
    );
    let text = text_of(&out[0].data);
    let line = format!("{}/gpu.conf: options xe force_probe=*\n", modprobe.display());
    assert!(text.contains(&line), "{text}");
    assert!(!text.contains("snd index") && !text.contains("ignored") && !text.contains("pcspkr"), "{text}");
    assert!(text.contains("# 2 configuration files read"), "{text}");
    assert!(text.contains("firmware_class path: (empty)\n"));
    assert!(
        text.contains("configfs xe/0000:03:00.0:\n  survivability_mode: 0\n  sriov/max_vfs: 7\n"),
        "{text}"
    );

    let none = module_configuration(
        &FsReader::default(),
        "x",
        &[],
        &dir.path().join("nope"),
        &dir.path().join("none"),
    );
    assert!(text_of(&none[0].data).contains("configfs xe: (empty or not mounted)\n"));
}

#[test]
fn memory_context_reports_the_locked_memory_limit() {
    let out = memory_context(&FsReader::default(), "system/memory.txt");
    let text = text_of(&out[0].data);
    assert!(text.contains("vm.max_map_count: "), "{text}");
    assert!(text.contains("limits: "), "{text}");
}

#[test]
fn identical_cpus_collapse_into_one_block_and_hybrid_ones_do_not() {
    let block = |n: u32, model: &str, mhz: &str| {
        format!(
            "processor\t: {n}\nmodel name\t: {model}\ncpu MHz\t\t: {mhz}\ncore id\t\t: {n}\nflags\t\t: fpu sse\n"
        )
    };
    let mut text = String::new();
    for n in 0..4 {
        text.push_str(&block(n, "Example P-core", &format!("{}00.0", 30 + n)));
        text.push('\n');
    }
    text.push_str(&block(4, "Example E-core", "2000.0"));
    text.push('\n');
    let summary = summarize_cpuinfo(&text);
    assert!(summary.starts_with("logical CPUs: 5\n"), "{summary}");
    assert!(summary.contains("# 4 logical CPUs like this: processor 0-3\n"), "{summary}");
    assert!(summary.contains("# 1 logical CPUs like this: processor 4\n"), "{summary}");
    assert_eq!(summary.matches("Example P-core").count(), 1);
    assert_eq!(summary.matches("flags").count(), 2);
    assert_eq!(summarize_cpuinfo(""), "logical CPUs: 0\n");
}

#[test]
fn processor_numbers_are_written_as_ranges() {
    let cpus: Vec<String> = ["0", "1", "2", "5", "7", "8"].iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(cpu_list(&cpus), "0-2,5,7-8");
}

#[test]
fn a_core_pattern_outside_the_system_directories_is_not_copied() {
    let dir = PrivateTempDir::create("state").unwrap();
    put(dir.path(), "version", "Linux version 7.2.0\n");
    let probe = |name: &str| Probe {
        label: "kernel.core_pattern".to_owned(),
        path: dir.path().join(name).to_string_lossy().into_owned(),
    };
    for (contents, expected) in [
        ("core\n", "kernel.core_pattern: core\n"),
        ("|/usr/share/apport/apport -p%p\n", "kernel.core_pattern: |/usr/share/apport/apport -p%p\n"),
        ("/var/crash/core.%e.%p\n", "kernel.core_pattern: <path>\n"),
        ("/srv/acme/cores/%e\n", "kernel.core_pattern: <path>\n"),
        (
            "|/usr/lib/systemd/systemd-coredump %P %u\n",
            "kernel.core_pattern: |/usr/lib/systemd/systemd-coredump %P %u\n",
        ),
    ] {
        put(dir.path(), "pattern", contents);
        let out = state_report(&FsReader::default(), "x", &[probe("pattern")], &dir.path().join("version"));
        assert!(text_of(&out[0].data).ends_with(expected), "{contents}: {}", text_of(&out[0].data));
    }
}
