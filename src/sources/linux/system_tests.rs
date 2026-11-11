// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/system.rs`.

use super::*;
use crate::bundle::source::{Keep, Status};
use crate::procio::PrivateTempDir;
use std::collections::BTreeMap;

/// A reader backed by a map of path to contents; every other path is Missing, and the paths
/// asked for are recorded.
struct MapReader {
    files: BTreeMap<&'static str, ReadResult>,
    asked: std::sync::Mutex<Vec<String>>,
}

impl MapReader {
    fn new(files: &[(&'static str, ReadResult)]) -> Self {
        Self { files: files.iter().cloned().collect(), asked: std::sync::Mutex::new(Vec::new()) }
    }
}

impl Reader for MapReader {
    fn read(&self, path: &Path, _max: Bytes, _keep: Keep) -> ReadResult {
        let key = path.to_string_lossy().into_owned();
        self.asked.lock().unwrap().push(key.clone());
        self.files
            .get(key.as_str())
            .cloned()
            .unwrap_or(ReadResult { outcome: ReadOutcome::Missing, ..Default::default() })
    }
}

fn read_of(data: &str) -> ReadResult {
    ReadResult { outcome: ReadOutcome::Read, data: data.as_bytes().to_vec(), ..Default::default() }
}

fn denied() -> ReadResult {
    ReadResult { outcome: ReadOutcome::Denied, ..Default::default() }
}

const STATUS: &str = "Name:\tx\nUid:\t1003\t1003\t1003\t1003\nGid:\t1003\t1003\t1003\t1003\nGroups:\t4 24 993\nCapEff:\t0000000000000000\n";

#[test]
fn capability_bits() {
    let caps = |hex: &str| capabilities_from_status(&format!("CapEff:\t{hex}\n")).unwrap();
    let none = caps("0000000000000000");
    assert!(!none.sys_admin() && !none.syslog() && !none.perfmon());
    let all = caps("000001ffffffffff");
    assert!(all.sys_admin() && all.syslog() && all.perfmon());
    assert!(caps("0000000000200000").sys_admin()); // bit 21
    assert!(!caps("0000000000200000").syslog());
    assert!(caps("0000000400000000").syslog()); // bit 34
    assert!(caps("0000004000000000").perfmon()); // bit 38
    assert!(capabilities_from_status("Name:\tx\n").is_none());
    assert!(capabilities_from_status("CapEff:\tnothex\n").is_none());
}

#[test]
fn privilege_follows_root_or_sys_admin() {
    let admin = Some(Capabilities { effective: 1 << CAP_SYS_ADMIN });
    let plain = Some(Capabilities { effective: 0 });
    assert_eq!(privilege_of(0, plain), Privilege::Privileged);
    assert_eq!(privilege_of(1000, admin), Privilege::Privileged);
    assert_eq!(privilege_of(1000, plain), Privilege::Unprivileged);
    assert_eq!(privilege_of(1000, None), Privilege::Unprivileged);
}

#[test]
fn device_numbers_follow_glibc() {
    let dev = (226u64 << 8) | 128;
    assert_eq!((dev_major(dev), dev_minor(dev)), (226, 128));
    assert_eq!((dev_major(0), dev_minor(0)), (0, 0));
    // 12-bit major in the low word, large minor spread over two fields.
    let dev = (0x123u64 << 8) | 0xab | (0x4567u64 << 20);
    assert_eq!(dev_major(dev), 0x123);
    assert_eq!(dev_minor(dev), 0xab | 0x4567 << 8);
}

#[test]
fn id_text_names_the_accounts_and_capabilities() {
    let accounts = Accounts {
        users: HashMap::from([(1003, "jdoe".to_owned())]),
        groups: HashMap::from([(4, "adm".to_owned()), (993, "render".to_owned())]),
    };
    let text = id_text(Some(STATUS), &accounts);
    assert!(
        text.starts_with("uid: 1003 (jdoe)\neuid: 1003 (jdoe)\ngid: 1003 (1003)\negid: 1003 (1003)\n"),
        "{text}"
    );
    assert!(text.contains("groups: 4(adm) 24(24) 993(render) 1003(1003)\n"), "{text}");
    assert!(text.contains("CapEff: 0000000000000000\n"));
    assert!(text.contains("capabilities: none of CAP_SYS_ADMIN, CAP_SYSLOG, CAP_PERFMON\n"));
    let root = id_text(Some("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n"), &accounts);
    assert!(root.contains("capabilities: CAP_SYS_ADMIN CAP_SYSLOG CAP_PERFMON\n"));
    let unreadable = id_text(None, &accounts);
    assert!(unreadable.contains("CapEff: (unavailable)\n"));
    assert!(unreadable.contains("uid: (unavailable)\n"));
}

#[test]
fn builtins_read_only_through_the_reader() {
    let reader = MapReader::new(&[
        ("/proc/sys/kernel/dmesg_restrict", read_of("1\n")),
        ("/sys/class/dmi/id/sys_vendor", read_of("Acme\n")),
        ("/proc/self/status", read_of("Name:\tx\nCapEff:\t0000000000000000\n")),
        ("/sys/kernel/security/lockdown", denied()),
    ]);

    let out = probe_builtin(&reader, "system/security.txt", &security_probes());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rel_path, "system/security.txt");
    assert_eq!(out[0].status, Status::Collected);
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    assert!(text.contains("kernel.dmesg_restrict: 1\n"));
    assert!(text.contains("/sys/fs/selinux/enforce: (absent)\n"));
    assert!(text.contains("/sys/kernel/security/lockdown: (denied)\n"));
    assert_eq!(reader.asked.lock().unwrap().len(), 8);

    let dmi = probe_builtin(&reader, "system/dmi.txt", &dmi_probes());
    let text = String::from_utf8_lossy(&dmi[0].data).into_owned();
    assert!(text.contains("sys_vendor: Acme\n"));
    assert!(text.contains("bios_release: (absent)\n"));
    assert!(!text.contains("serial") && !text.contains("uuid"));

    let id = id_builtin(&reader, "system/id.txt");
    let text = String::from_utf8_lossy(&id[0].data).into_owned();
    assert!(text.contains("CapEff: 0000000000000000\n"));
    assert!(text.starts_with("uid: "));

    let uname = uname_builtin(&reader, "system/uname.txt");
    let text = String::from_utf8_lossy(&uname[0].data).into_owned();
    assert!(text.starts_with("sysname: Linux\nnodename: \n"), "{text}");
    assert!(text.contains("\nmachine: "));
    // Every path any builtin asked for is one of the files the builtin is meant to read.
    let asked = reader.asked.lock().unwrap().clone();
    assert!(
        asked.iter().all(|p| p.starts_with("/proc/") || p.starts_with("/sys/") || p.starts_with("/etc/"))
    );
    let container = container_builtin(&reader, "system/container.txt");
    assert!(String::from_utf8_lossy(&container[0].data).contains("/proc/1/cgroup: (absent)\n"));
}

#[test]
fn the_os_release_fallback_reports_why_it_has_nothing() {
    let present = MapReader::new(&[("/usr/lib/os-release", read_of("NAME=x\n"))]);
    let out = os_release_fallback_builtin(&present, "system/os-release");
    assert_eq!((out[0].status, out[0].via.as_str()), (Status::Collected, "/usr/lib/os-release"));
    let out = os_release_fallback_builtin(&MapReader::new(&[("/usr/lib/os-release", denied())]), "r");
    assert_eq!((out[0].status, out[0].reason.as_str()), (Status::Skipped, "needs root"));
    let out = os_release_fallback_builtin(&MapReader::new(&[]), "r");
    assert_eq!(out[0].reason, "not present");
}

#[test]
fn firmware_listing_is_sorted_and_bounded() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("bmg")).unwrap();
    fs::write(root.join("bmg/guc_70.bin"), [0u8; 10]).unwrap();
    fs::write(root.join("bmg/huc.bin"), [0u8; 3]).unwrap();
    fs::write(root.join("a.bin"), []).unwrap();
    std::os::unix::fs::symlink("bmg/huc.bin", root.join("alias.bin")).unwrap();
    std::os::unix::fs::symlink("nowhere", root.join("dangling.bin")).unwrap();
    assert_eq!(list_firmware(root, 100), ["a.bin 0", "alias.bin 3", "bmg/guc_70.bin 10", "bmg/huc.bin 3"]);
    assert_eq!(list_firmware(root, 2).len(), 2);
    assert!(list_firmware(&root.join("absent"), 10).is_empty());
}

#[test]
fn links_name_the_last_component_or_absent() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    std::os::unix::fs::symlink("../../../bus/pci/drivers/xe", root.join("driver")).unwrap();
    std::os::unix::fs::symlink("../../../kernel/iommu_groups/12", root.join("iommu_group")).unwrap();
    let out = links_builtin("devices/x/links.txt", &root.to_string_lossy());
    assert_eq!(
        String::from_utf8_lossy(&out[0].data),
        "driver: xe\niommu_group: 12\nphysfn: (absent)\nfirmware_node: (absent)\n"
    );
}

#[test]
fn the_environment_builtin_filters_by_name() {
    let out = env_builtin("system/env.txt");
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    for line in text.lines().filter(|l| !l.starts_with("# ")) {
        let key = line.split('=').next().unwrap();
        assert!(
            key == "LANG"
                || key == "LC_ALL"
                || key == "LD_PRELOAD"
                || key == "LD_LIBRARY_PATH"
                || key == "container"
                || key.contains('_'),
            "{key}"
        );
    }
    assert!(!text.contains("HOME=") && !text.contains("\nPATH="));
    // The tools are located instead of the whole PATH being copied.
    assert!(text.contains("# xpu-smi: "), "{text}");
    assert!(text.contains("# lspci: "));
}

#[test]
fn gpu_mounts_keep_only_the_mounts_a_gpu_stack_needs_and_not_host_directories() {
    let mountinfo = "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n\
        40 22 0:6 /dri /dev/dri rw - devtmpfs devtmpfs rw\n\
        41 22 0:7 / /sys/kernel/debug rw - debugfs debugfs rw\n\
        42 22 8:2 /firmware /lib/firmware ro - ext4 /dev/sda2 rw\n\
        43 22 8:2 /home/alice/secret-project /home/dev/work rw - ext4 /dev/sda2 rw\n\
        44 22 0:30 / /sys rw - sysfs sysfs rw\n\
        45 22 0:31 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/abc\n\
        46 22 0:32 / /sys/fs/cgroup ro - cgroup2 cgroup rw\n\
        47 22 8:2 /srv/data/acme /data rw - ext4 /dev/sda2 rw\n\
        48 22 0:33 / /var/lib/docker/overlay2/abc123/merged rw - overlay overlay rw\n";
    let mounts = gpu_mounts(mountinfo);
    assert_eq!(
        mounts,
        [
            "/dev/dri devtmpfs devtmpfs",
            "/sys/kernel/debug debugfs debugfs",
            "/lib/firmware ext4 /dev/sda2",
            "/sys sysfs sysfs",
            "/ overlay overlay",
            "/sys/fs/cgroup cgroup2 cgroup",
        ]
    );
    // No bind-mount root or host directory survives, and the overlay options (lower directories) are gone.
    let all = mounts.join("\n");
    assert!(
        !all.contains("alice")
            && !all.contains("acme")
            && !all.contains("docker")
            && !all.contains("/dri rw"),
        "{all}"
    );
    assert!(gpu_mounts("").is_empty());
    assert!(gpu_mounts("garbage without separator").is_empty());
    let many: String = (0..100).map(|i| format!("{i} 1 0:1 / /dev/dri/{i} rw - tmpfs x rw\n")).collect();
    assert_eq!(gpu_mounts(&many).len(), 40);
}

#[test]
fn the_container_report_covers_namespaces_mounts_and_wsl() {
    let reader = MapReader::new(&[
        ("/proc/sys/kernel/osrelease", read_of("6.6.0-microsoft-standard-WSL2\n")),
        (
            "/proc/self/uid_map",
            read_of("         0       1000          1\n         1     100000      65536\n"),
        ),
        ("/proc/self/mountinfo", read_of("40 22 0:6 /dri /dev/dri rw - devtmpfs devtmpfs rw\n")),
    ]);
    let out = container_builtin(&reader, "system/container.txt");
    let text = String::from_utf8_lossy(&out[0].data).into_owned();
    assert!(text.contains("kernel release names Microsoft (WSL): yes\n"), "{text}");
    assert!(
        text.contains("/proc/self/uid_map: 0       1000          1; 1     100000      65536\n"),
        "{text}"
    );
    assert!(text.contains("/proc/self/gid_map: (absent)\n"));
    assert!(text.contains("GPU-related mounts: \n  /dev/dri devtmpfs devtmpfs\n"), "{text}");
    assert!(text.contains("/dev/dxg: ") && text.contains("/usr/lib/wsl: "));
}

#[test]
fn live_privilege_facts_are_consistent() {
    // Not asserted against the host: only that the probes run and agree with each other.
    let caps = capabilities();
    assert_eq!(has_sys_admin(), caps.is_some_and(Capabilities::sys_admin));
    let _ = any_render_node_accessible();
    let _ = current_privilege();
}

#[test]
fn the_virtual_functions_of_a_physical_function_are_listed_in_numeric_order() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    let functions = root.join("functions");
    for (n, driver) in [(10u32, Some("vfio-pci")), (2, None), (1, Some("xe"))] {
        let target = functions.join(format!("0000:03:00.{n}"));
        fs::create_dir_all(&target).unwrap();
        if let Some(driver) = driver {
            std::os::unix::fs::symlink(format!("../../../bus/pci/drivers/{driver}"), target.join("driver"))
                .unwrap();
        }
        std::os::unix::fs::symlink(&target, root.join(format!("virtfn{n}"))).unwrap();
    }
    fs::write(root.join("virtfn_note"), "x").unwrap();
    assert_eq!(
        virtual_functions(root),
        "virtfn1: 0000:03:00.1, driver xe\nvirtfn2: 0000:03:00.2, driver none\nvirtfn10: 0000:03:00.10, driver vfio-pci\n"
    );
    assert_eq!(virtual_functions(&root.join("absent")), "");
    let links = links_builtin("devices/x/links.txt", &root.to_string_lossy());
    assert!(String::from_utf8_lossy(&links[0].data).contains("virtfn1: 0000:03:00.1, driver xe\n"));
}
