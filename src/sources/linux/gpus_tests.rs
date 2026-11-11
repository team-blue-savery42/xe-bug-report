// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/gpus.rs`.

use super::*;
use crate::procio::PrivateTempDir;

fn add_device(root: &Path, real: &Path, name: &str, vendor: &str, class: &str) {
    let dir = real.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("vendor"), vendor).unwrap();
    fs::write(dir.join("class"), class).unwrap();
    fs::create_dir_all(root).unwrap();
    std::os::unix::fs::symlink(&dir, root.join(name)).unwrap();
}

#[test]
fn sysfs_devices_are_filtered_canonicalised_and_sorted() {
    let scratch = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let base = fs::canonicalize(scratch.path()).unwrap();
    let root = base.join("bus/pci/devices");
    let real = base.join("devices/pci0000:00");
    add_device(&root, &real, "0000:84:00.0", "0x8086\n", "0x030000\n");
    add_device(&root, &real, "0000:03:00.0", "0x8086\n", "0x038000\n");
    add_device(&root, &real, "0000:00:02.0", "0x8086\n", "0x060400\n"); // a bridge
    add_device(&root, &real, "0000:01:00.0", "0x10de\n", "0x030000\n"); // another vendor
    add_device(&root, &real, "0000:05:00.0", "0x8086\n", "0x120000\n"); // an accelerator
    fs::create_dir_all(root.join("not-an-address")).unwrap();
    let devices = gpus_in(&root);
    let bdfs: Vec<String> = devices.iter().map(|d| d.bdf.to_string()).collect();
    assert_eq!(bdfs, ["0000:03:00.0", "0000:05:00.0", "0000:84:00.0"]);
    assert_eq!(devices[0].os_path, real.join("0000:03:00.0").to_string_lossy());
    assert!(gpus_in(&base.join("absent")).is_empty());
}

#[test]
fn live_gpus_are_well_formed() {
    let devices = gpus_from_os();
    for pair in devices.windows(2) {
        assert!(pair[0].bdf < pair[1].bdf);
    }
    for device in &devices {
        assert!(device.os_path.starts_with("/sys/devices/"), "{}", device.os_path);
        assert_eq!(PciAddress::parse(&device.bdf.to_string()), Some(device.bdf));
    }
    println!("gpus_from_os: {devices:?}");
}
