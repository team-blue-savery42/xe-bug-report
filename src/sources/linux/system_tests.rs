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
    for line in text.lines() {
        let key = line.split('=').next().unwrap();
        assert!(
            key == "PATH"
                || key == "LANG"
                || key == "LC_ALL"
                || key == "LD_PRELOAD"
                || key == "LD_LIBRARY_PATH"
                || key == "container"
                || key.contains('_'),
            "{key}"
        );
    }
    assert!(!text.contains("HOME="));
}

#[test]
fn live_privilege_facts_are_consistent() {
    // Not asserted against the host: only that the probes run and agree with each other.
    let caps = capabilities();
    assert_eq!(has_sys_admin(), caps.is_some_and(Capabilities::sys_admin));
    let _ = any_render_node_accessible();
    let _ = current_privilege();
}
