// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/pcie.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put, text_of};

const OS_PATH: &str = "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/0000:03:00.0";
/// The GPU behind a switch: downstream port 02:01.0 and upstream port 01:00.0 of the same switch.
const OS_PATH_SWITCH: &str = "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/0000:02:01.0/0000:03:00.0";

fn gpu() -> PciAddress {
    PciAddress::parse("0000:03:00.0").unwrap()
}

/// A sysfs-like tree: the GPU, the two ports of a switch and the root port.
fn tree() -> PrivateTempDir {
    let dir = PrivateTempDir::create("pcie").unwrap();
    let root = dir.path();
    for (dev, speed, width, max_speed, max_width) in [
        ("0000:03:00.0", "2.5 GT/s PCIe", "1", "2.5 GT/s PCIe", "1"),
        ("0000:02:01.0", "2.5 GT/s PCIe", "1", "16.0 GT/s PCIe", "8"),
        ("0000:01:00.0", "16.0 GT/s PCIe", "8", "16.0 GT/s PCIe", "8"),
        ("0000:00:01.0", "16.0 GT/s PCIe", "8", "32.0 GT/s PCIe", "16"),
    ] {
        put(root, &format!("{dev}/vendor"), "0x8086\n");
        put(root, &format!("{dev}/current_link_speed"), format!("{speed}\n"));
        put(root, &format!("{dev}/current_link_width"), format!("{width}\n"));
        put(root, &format!("{dev}/max_link_speed"), format!("{max_speed}\n"));
        put(root, &format!("{dev}/max_link_width"), format!("{max_width}\n"));
        put(root, &format!("{dev}/power_state"), "D0\n");
        put(root, &format!("{dev}/d3cold_allowed"), "1\n");
        put(root, &format!("{dev}/power/runtime_status"), "suspended\n");
    }
    put(root, "0000:01:00.0/aer_dev_correctable", "RxErr 0\nBadTLP 3\nBadDLLP 0\nTOTAL_ERR_COR 3\n");
    put(root, "0000:00:01.0/aer_rootport_total_err_cor", "0\n");
    put(root, "0000:00:01.0/link/l1_aspm", "1\n");
    put(root, "0000:03:00.0/power/runtime_usage", "0\n");
    dir
}

#[test]
fn the_power_snapshot_comes_first_and_lists_the_bridges() {
    let dir = tree();
    let reader = FsReader::default();
    let out = power_state_snapshot(&reader, dir.path(), &gpu(), OS_PATH, "devices/x/power.txt");
    assert_eq!(out.len(), 1);
    let text = text_of(&out[0].data);
    assert!(text.starts_with("# Read before any other attribute"), "{text}");
    assert!(text.contains("  power/runtime_status: suspended\n"));
    assert!(text.contains("  power/runtime_usage: 0\n"));
    assert!(text.contains("  power/runtime_enabled: (absent)\n"));
    assert!(text.contains("0000:01:00.0: power_state: D0, runtime_status: suspended\n"));
    assert!(text.contains("0000:00:01.0: power_state: D0, runtime_status: suspended\n"));
    // Only power attributes are read, none of the attributes that wake the device.
    let asked = reader.asked.lock().unwrap();
    assert!(asked.len() >= POWER_ATTRIBUTES.len());
    for path in asked.iter() {
        let leaf = path.rsplit("0000:").next().unwrap_or(path);
        assert!(
            ["power_state", "d3cold_allowed", "power/runtime", "power/control", "power/autosuspend"]
                .iter()
                .any(|name| leaf.contains(name)),
            "{path}"
        );
    }
}

#[test]
fn the_link_chain_compares_each_link_with_the_lower_of_its_two_ports() {
    let dir = tree();
    let out = link_chain(&FsReader::default(), dir.path(), &gpu(), OS_PATH_SWITCH, "pci/x/link-chain.txt");
    let text = text_of(&out[0].data);
    assert!(
        text.starts_with("0000:03:00.0 (GPU)\n  link: current 2.5 GT/s PCIe x1, max 2.5 GT/s PCIe x1\n"),
        "{text}"
    );
    assert!(text.contains("0000:02:01.0 (upstream bridge 1)\n"));
    assert!(text.contains("0000:01:00.0 (upstream bridge 2)\n"));
    assert!(text.contains("0000:00:01.0 (root port)\n"));
    // The switch's downstream port can do Gen4 x8 but the GPU at its other end cannot.
    assert!(
        text.contains(
            "link: current 2.5 GT/s PCIe x1, max 2.5 GT/s PCIe x1 (limited by the port at the other end)\n"
        ),
        "{text}"
    );
    // The root port is Gen5 x16 but the switch's upstream port at the other end of its link is Gen4 x8:
    // a trained 16 GT/s x8 is the best this link can do and is not marked.
    assert!(
        text.contains(
            "link: current 16.0 GT/s PCIe x8, max 16.0 GT/s PCIe x8 (limited by the port at the other end)\n"
        ),
        "{text}"
    );
    assert!(!text.contains("below the maximum"), "{text}");
    assert!(text.contains("  aer_dev_correctable: RxErr 0; BadTLP 3; BadDLLP 0; TOTAL_ERR_COR 3\n"));
    assert!(text.contains("  aer_rootport_total_err_cor: 0\n"));
    assert!(text.contains("  link/l1_aspm: 1\n"));
    // An attribute the device lacks is left out, not reported as absent.
    assert!(!text.contains("(absent)"), "{text}");
    assert_eq!(text.matches("(GPU)").count(), 1);
}

#[test]
fn a_link_that_trained_below_what_both_ports_can_do_is_marked() {
    let dir = tree();
    put(dir.path(), "0000:01:00.0/current_link_speed", "8.0 GT/s PCIe\n");
    let out = link_chain(&FsReader::default(), dir.path(), &gpu(), OS_PATH_SWITCH, "x");
    let text = text_of(&out[0].data);
    assert!(
        text.contains("link: current 8.0 GT/s PCIe x8, max 16.0 GT/s PCIe x8 (below the maximum)\n"),
        "{text}"
    );
}

#[test]
fn a_chain_of_odd_length_says_the_partner_is_unknown() {
    let dir = tree();
    let out = link_chain(&FsReader::default(), dir.path(), &gpu(), OS_PATH, "x");
    let text = text_of(&out[0].data);
    assert!(
        text.contains(
            "link: current 16.0 GT/s PCIe x8, max 32.0 GT/s PCIe x16 (partner unknown) (below the maximum)\n"
        ),
        "{text}"
    );
}

#[test]
fn link_summaries_compare_speed_and_width() {
    let gen3 = "8.0 GT/s PCIe";
    assert_eq!(
        link_summary(gen3, "16", gen3, "16", Some((gen3, "16"))).unwrap(),
        "current 8.0 GT/s PCIe x16, max 8.0 GT/s PCIe x16"
    );
    assert!(
        link_summary(gen3, "8", gen3, "16", Some((gen3, "16"))).unwrap().ends_with("(below the maximum)")
    );
    assert!(
        link_summary("2.5 GT/s PCIe", "16", gen3, "16", Some((gen3, "16")))
            .unwrap()
            .ends_with("(below the maximum)")
    );
    // The partner's lower maximum is the limit.
    assert_eq!(
        link_summary(gen3, "4", "16.0 GT/s PCIe", "16", Some((gen3, "4"))).unwrap(),
        "current 8.0 GT/s PCIe x4, max 8.0 GT/s PCIe x4 (limited by the port at the other end)"
    );
    assert!(link_summary(gen3, "16", gen3, "16", None).unwrap().contains("(partner unknown)"));
    assert_eq!(link_summary("", "1", "2.5 GT/s PCIe", "1", None), None);
    assert_eq!(link_summary("Unknown speed", "1", "2.5 GT/s PCIe", "1", None), None);
    assert_eq!(parse_link_speed("16.0 GT/s PCIe"), Some(16.0));
}

#[test]
fn sizes_are_written_in_the_largest_exact_unit() {
    assert_eq!(format_size(16 << 30), "16 GiB");
    assert_eq!(format_size(256 << 20), "256 MiB");
    assert_eq!(format_size(3 << 10), "3 KiB");
    assert_eq!(format_size(1000), "1000 B");
    assert_eq!(format_size(0), "0 B");
    assert_eq!(resize_sizes(0x7f00), ["256 MiB", "512 MiB", "1 GiB", "2 GiB", "4 GiB", "8 GiB", "16 GiB"]);
    assert!(resize_sizes(0).is_empty());
}

#[test]
fn resource_lines_decode_to_bars() {
    let bar0 = decode_resource_line(0, "0x0000000081000000 0x0000000081ffffff 0x0000000000140204").unwrap();
    assert_eq!(bar0, "BAR0: 0x81000000-0x81ffffff, 16 MiB, mem, 64-bit");
    let bar2 = decode_resource_line(2, "0x0000004000000000 0x00000043ffffffff 0x000000000014220c").unwrap();
    assert_eq!(bar2, "BAR2: 0x4000000000-0x43ffffffff, 16 GiB, mem, 64-bit, prefetchable");
    let rom = decode_resource_line(6, "0x0000000082000000 0x00000000821fffff 0x0000000000046200").unwrap();
    assert!(rom.starts_with("ROM: ") && rom.contains("2 MiB"), "{rom}");
    assert_eq!(decode_resource_line(1, "0x0000000000000000 0x0000000000000000 0x0000000000000000"), None);
    assert_eq!(decode_resource_line(1, "garbage"), None);
    // A range that ends before it starts is not a BAR.
    assert_eq!(decode_resource_line(1, "0x0000000000100000 0x0000000000000001 0x0000000000000200"), None);
}

#[test]
fn the_bar_layout_lists_assigned_bars_and_resize_masks() {
    let dir = tree();
    put(
        dir.path(),
        "0000:03:00.0/resource",
        "0x0000000081000000 0x0000000081ffffff 0x0000000000140204\n\
         0x0000000000000000 0x0000000000000000 0x0000000000000000\n\
         0x0000004000000000 0x00000043ffffffff 0x000000000014220c\n",
    );
    put(dir.path(), "0000:03:00.0/resource2_resize", "0000000000007f00\n");
    let out = bar_layout(&FsReader::default(), dir.path(), &gpu(), "devices/x/bars.txt");
    let text = text_of(&out[0].data);
    assert!(text.contains("BAR0: 0x81000000-0x81ffffff, 16 MiB"));
    assert!(text.contains("BAR2: 0x4000000000-0x43ffffffff, 16 GiB"));
    assert!(
        text.contains(
            "BAR2 sizes the device accepts: 256 MiB, 512 MiB, 1 GiB, 2 GiB, 4 GiB, 8 GiB, 16 GiB\n"
        )
    );
    assert!(!text.contains("BAR1"));

    let none = bar_layout(&FsReader::default(), dir.path(), &PciAddress::parse("0000:09:00.0").unwrap(), "x");
    assert_eq!(text_of(&none[0].data), "resource: (unavailable)\n");
}

#[test]
fn the_iommu_state_names_the_group_type_and_members() {
    let dir = tree();
    let groups = PrivateTempDir::create("groups").unwrap();
    put(groups.path(), "18/type", "DMA-FQ\n");
    put(groups.path(), "18/devices/0000:03:00.0", "");
    put(groups.path(), "18/reserved_regions", "0x00000000fee00000 0x00000000feefffff msi\n");
    std::os::unix::fs::symlink(groups.path().join("18"), dir.path().join("0000:03:00.0/iommu_group"))
        .unwrap();
    let out = iommu_state(&FsReader::default(), dir.path(), groups.path(), &gpu(), "devices/x/iommu.txt");
    let text = text_of(&out[0].data);
    assert!(text.starts_with("group: 18\ntype: DMA-FQ\nmembers: 0000:03:00.0\n"), "{text}");
    assert!(text.contains("reserved_regions:\n  0x00000000fee00000 0x00000000feefffff msi\n"));
    assert!(text.contains("pcie_aspm policy: "));

    let without = iommu_state(
        &FsReader::default(),
        dir.path(),
        groups.path(),
        &PciAddress::parse("0000:01:00.0").unwrap(),
        "x",
    );
    assert!(text_of(&without[0].data).starts_with("group: (none: the device is not behind an IOMMU)\n"));
}
