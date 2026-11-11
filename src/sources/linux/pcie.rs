// SPDX-License-Identifier: MIT
//! The PCIe side of a GPU, from sysfs attributes anyone can read: the power state before any other
//! attribute is touched, the link and error counters of the GPU and every bridge above it, the BAR
//! layout and the IOMMU group.
//!
//! The GPU often sits behind an on-board switch, so the endpoint's own link files say little: the
//! upstream port holds the link that was actually trained. Every file is read through the
//! [`Reader`]; directory listings use `std::fs` on the collector's guarded thread.

use std::fmt::Write as _;
use std::path::Path;

use crate::bundle::source::{Produced, Reader};
use crate::pci::PciAddress;
use crate::units::Bytes;

use super::debugfs::collected;
use super::probes::{attribute_line, link_name, list_names, read_text, read_value};
use super::text::upstream_bridges;

/// The PCI device directory of sysfs.
pub const PCI_DEVICES_DIR: &str = "/sys/bus/pci/devices";
/// The IOMMU group directory of sysfs.
pub const IOMMU_GROUPS_DIR: &str = "/sys/kernel/iommu_groups";
/// The IOMMU units the kernel found.
pub const IOMMU_CLASS_DIR: &str = "/sys/class/iommu";
/// The ASPM policy of the kernel.
pub const ASPM_POLICY: &str = "/sys/module/pcie_aspm/parameters/policy";

/// The attributes that describe the runtime power state of a device, in the order they are read.
const POWER_ATTRIBUTES: &[&str] = &[
    "power_state",
    "d3cold_allowed",
    "power/runtime_status",
    "power/runtime_usage",
    "power/runtime_enabled",
    "power/runtime_active_kids",
    "power/control",
    "power/autosuspend_delay_ms",
    "power/runtime_active_time",
    "power/runtime_suspended_time",
];

/// The attributes of the GPU and of each bridge in the link chain.
const CHAIN_ATTRIBUTES: &[&str] = &[
    "vendor",
    "device",
    "class",
    "current_link_speed",
    "current_link_width",
    "max_link_speed",
    "max_link_width",
    "power_state",
    "d3cold_allowed",
    "power/runtime_status",
    "aer_dev_correctable",
    "aer_dev_nonfatal",
    "aer_dev_fatal",
    "aer_rootport_total_err_cor",
    "aer_rootport_total_err_nonfatal",
    "aer_rootport_total_err_fatal",
];

/// Most BAR lines decoded from a `resource` file: six BARs and the expansion ROM.
const BAR_LINES: usize = 7;
/// Size cap of a `resource` file.
const RESOURCE_MAX: Bytes = Bytes::kib(4);
/// Size cap of the reserved regions of an IOMMU group.
const RESERVED_MAX: Bytes = Bytes::kib(4);
/// Most members listed for an IOMMU group.
const GROUP_MEMBERS_MAX: usize = 32;

/// The state of a device's runtime power management, read before any other attribute of the
/// device: reading a frequency, an idle residency or a temperature can wake a suspended GPU, after
/// which `runtime_status` would say `active` whatever the state was before. The upstream bridges'
/// states follow, since a suspended bridge keeps the GPU below it unreachable.
pub fn power_state_snapshot(
    reader: &dyn Reader,
    devices_root: &Path,
    bdf: &PciAddress,
    os_path: &str,
    rel_path: &str,
) -> Vec<Produced> {
    let mut text = String::from(
        "# Read before any other attribute of the device, so a runtime-suspended GPU is reported as it was.\n",
    );
    let device = devices_root.join(bdf.to_string());
    let _ = writeln!(text, "{bdf}:");
    for attribute in POWER_ATTRIBUTES {
        let _ = writeln!(text, "  {}", attribute_line(reader, attribute, &device.join(attribute)));
    }
    for bridge in upstream_bridges(os_path) {
        let dir = devices_root.join(bridge.to_string());
        let _ = writeln!(
            text,
            "{bridge}: {}, {}",
            attribute_line(reader, "power_state", &dir.join("power_state")),
            attribute_line(reader, "runtime_status", &dir.join("power/runtime_status")),
        );
    }
    vec![collected(rel_path, text, "")]
}

/// The speed in GT/s at the start of a link speed attribute such as `16.0 GT/s PCIe`.
pub fn parse_link_speed(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// The maxima of the device at the other end of the link: its `max_link_speed` and `max_link_width`.
pub type Partner<'a> = Option<(&'a str, &'a str)>;

/// `current <speed> x<width>, max <speed> x<width>`, followed by `(below the maximum)` when the
/// link trained slower or narrower than it can; None when a value is missing.
///
/// A link is limited by both ends, so the maximum is the lower of the two ports'. `partner` holds
/// the other end's maxima; without it (a bridge in the chain with no known peer) the port's own
/// maxima are used and the line says the partner is unknown.
pub fn link_summary(
    current_speed: &str,
    current_width: &str,
    max_speed: &str,
    max_width: &str,
    partner: Partner<'_>,
) -> Option<String> {
    let cur_gt = parse_link_speed(current_speed)?;
    let (mut limit_speed, mut limit_gt) = (max_speed, parse_link_speed(max_speed)?);
    let cur_w: u32 = current_width.trim().parse().ok()?;
    let mut limit_w: u32 = max_width.trim().parse().ok()?;
    let mut limited = false;
    if let Some((partner_speed, partner_width)) = partner {
        if let Some(gt) = parse_link_speed(partner_speed)
            && gt < limit_gt
        {
            (limit_speed, limit_gt, limited) = (partner_speed, gt, true);
        }
        if let Some(w) = partner_width.trim().parse::<u32>().ok().filter(|w| *w < limit_w) {
            (limit_w, limited) = (w, true);
        }
    }
    let mut line = format!("current {current_speed} x{cur_w}, max {limit_speed} x{limit_w}");
    if limited {
        line.push_str(" (limited by the port at the other end)");
    } else if partner.is_none() {
        line.push_str(" (partner unknown)");
    }
    if cur_gt < limit_gt || cur_w < limit_w {
        line.push_str(" (below the maximum)");
    }
    Some(line)
}

/// One device of the link chain: the attributes that exist, then the ASPM files of its `link`
/// directory. `partner` is the device at the other end of its link.
fn chain_block(
    reader: &dyn Reader,
    devices_root: &Path,
    bdf: &PciAddress,
    role: &str,
    partner: Option<&PciAddress>,
) -> String {
    let dir = devices_root.join(bdf.to_string());
    let value = |name: &str| read_value(reader, &dir.join(name)).unwrap_or_default();
    let partner_max = partner.map(|p| {
        let dir = devices_root.join(p.to_string());
        let read = |name: &str| read_value(reader, &dir.join(name)).unwrap_or_default();
        (read("max_link_speed"), read("max_link_width"))
    });
    let mut text = format!("{bdf} ({role})\n");
    if let Some(summary) = link_summary(
        &value("current_link_speed"),
        &value("current_link_width"),
        &value("max_link_speed"),
        &value("max_link_width"),
        partner_max.as_ref().map(|(speed, width)| (speed.as_str(), width.as_str())),
    ) {
        let _ = writeln!(text, "  link: {summary}");
    }
    for attribute in CHAIN_ATTRIBUTES {
        let path = dir.join(attribute);
        // An attribute this device does not have is left out; a denied one is said so.
        if path.exists() {
            let _ = writeln!(text, "  {}", attribute_line(reader, attribute, &path));
        }
    }
    for name in list_names(&dir.join("link")) {
        let _ = writeln!(
            text,
            "  {}",
            attribute_line(reader, &format!("link/{name}"), &dir.join("link").join(&name))
        );
    }
    text
}

/// The link, error counters and power state of the GPU and of every bridge up to the root port.
///
/// In the chain `[GPU, b1, b2, ..., root port]` the links join the pairs `(GPU, b1)`, `(b2, b3)`,
/// ...: the two ports of one switch share no link. A device with no partner (an odd chain) is
/// compared with its own maxima only.
pub fn link_chain(
    reader: &dyn Reader,
    devices_root: &Path,
    bdf: &PciAddress,
    os_path: &str,
    rel_path: &str,
) -> Vec<Produced> {
    let mut chain = vec![*bdf];
    chain.extend(upstream_bridges(os_path));
    let last = chain.len() - 1;
    let mut text = String::new();
    for (index, device) in chain.iter().enumerate() {
        let role = match index {
            0 => "GPU".to_owned(),
            i if i == last => "root port".to_owned(),
            i => format!("upstream bridge {i}"),
        };
        let partner = chain.get(if index % 2 == 0 { index + 1 } else { index - 1 });
        text.push_str(&chain_block(reader, devices_root, device, &role, partner));
    }
    vec![collected(rel_path, text, "")]
}

/// A byte count as `16 GiB`, `256 MiB`, `64 KiB` or `100 B`: the largest unit that divides it.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (unit, size) in UNITS {
        if bytes >= size && bytes.is_multiple_of(size) {
            return format!("{} {unit}", bytes / size);
        }
    }
    format!("{bytes} B")
}

/// The BAR sizes a `resourceN_resize` bitmask offers: bit n is 2^(n+20) bytes, smallest first.
pub fn resize_sizes(mask: u64) -> Vec<String> {
    (0..44u32).filter(|bit| mask >> bit & 1 == 1).map(|bit| format_size(1u64 << (bit + 20))).collect()
}

/// One decoded line of a `resource` file: `start end flags`, three 0x-prefixed hex numbers.
pub fn decode_resource_line(index: usize, line: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    let parse = |field: Option<&str>| u64::from_str_radix(field?.trim_start_matches("0x"), 16).ok();
    let (start, end, flags) = (parse(fields.next())?, parse(fields.next())?, parse(fields.next())?);
    if start == 0 && end == 0 {
        return None;
    }
    let name = if index == 6 { "ROM".to_owned() } else { format!("BAR{index}") };
    let kind = if flags & 0x100 != 0 { "io" } else { "mem" };
    let size = end.checked_sub(start).and_then(|span| span.checked_add(1))?;
    let mut line = format!("{name}: {start:#x}-{end:#x}, {}, {kind}", format_size(size));
    if flags & 0x10_0000 != 0 {
        line.push_str(", 64-bit");
    }
    if flags & 0x2000 != 0 {
        line.push_str(", prefetchable");
    }
    Some(line)
}

/// The BARs the kernel assigned to the GPU and which sizes each resizable BAR can take. A BAR far
/// smaller than the VRAM means resizable BAR or above-4G decoding is off.
pub fn bar_layout(
    reader: &dyn Reader,
    devices_root: &Path,
    bdf: &PciAddress,
    rel_path: &str,
) -> Vec<Produced> {
    let dir = devices_root.join(bdf.to_string());
    let mut text = String::new();
    match read_text(reader, &dir.join("resource"), RESOURCE_MAX) {
        Some(resource) => {
            for (index, line) in resource.lines().take(BAR_LINES).enumerate() {
                if let Some(bar) = decode_resource_line(index, line) {
                    text.push_str(&bar);
                    text.push('\n');
                }
            }
        }
        None => text.push_str("resource: (unavailable)\n"),
    }
    for index in 0..6 {
        let path = dir.join(format!("resource{index}_resize"));
        if let Some(mask) = read_value(reader, &path)
            && let Ok(mask) = u64::from_str_radix(mask.trim_start_matches("0x"), 16)
        {
            let _ = writeln!(text, "BAR{index} sizes the device accepts: {}", resize_sizes(mask).join(", "));
        }
    }
    vec![collected(rel_path, text, "")]
}

/// The IOMMU group of the GPU: its translation type, the other devices in it, the reserved regions
/// and the IOMMU units; plus the PCIe ASPM policy of the kernel.
pub fn iommu_state(
    reader: &dyn Reader,
    devices_root: &Path,
    groups_root: &Path,
    bdf: &PciAddress,
    rel_path: &str,
) -> Vec<Produced> {
    let device = devices_root.join(bdf.to_string());
    let mut text = String::new();
    match link_name(&device.join("iommu_group")) {
        Some(group) => {
            let dir = groups_root.join(&group);
            let _ = writeln!(text, "group: {group}");
            let _ = writeln!(text, "{}", attribute_line(reader, "type", &dir.join("type")));
            let members = list_names(&dir.join("devices"));
            let shown: Vec<&str> = members.iter().take(GROUP_MEMBERS_MAX).map(String::as_str).collect();
            let more = members.len().saturating_sub(shown.len());
            let _ = write!(text, "members: {}", shown.join(" "));
            if more > 0 {
                let _ = write!(text, " and {more} more");
            }
            text.push('\n');
            match read_text(reader, &dir.join("reserved_regions"), RESERVED_MAX) {
                Some(regions) if !regions.trim().is_empty() => {
                    text.push_str("reserved_regions:\n");
                    for line in regions.lines() {
                        let _ = writeln!(text, "  {}", line.trim());
                    }
                }
                _ => text.push_str("reserved_regions: (none)\n"),
            }
        }
        None => text.push_str("group: (none: the device is not behind an IOMMU)\n"),
    }
    let units = list_names(Path::new(IOMMU_CLASS_DIR));
    let _ = writeln!(
        text,
        "iommu units: {}",
        if units.is_empty() { "(none)".to_owned() } else { units.join(" ") }
    );
    let _ = writeln!(text, "{}", attribute_line(reader, "pcie_aspm policy", Path::new(ASPM_POLICY)));
    vec![collected(rel_path, text, "")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "pcie_tests.rs"]
mod tests;
