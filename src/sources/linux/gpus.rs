// SPDX-License-Identifier: MIT
//! The Intel GPUs the kernel sees, from sysfs alone: no driver, Level Zero or `lspci` call.

use std::fs;
use std::path::Path;

use crate::bundle::source::GpuDevice;
use crate::pci::PciAddress;

use super::system::read_small;
use super::text::is_intel_gpu_class;

/// The PCI device directory of sysfs.
pub const PCI_DEVICES: &str = "/sys/bus/pci/devices";

/// The Intel display or accelerator devices below `root` (a `/sys/bus/pci/devices` directory), in
/// BDF order, with the canonical sysfs path of each as `os_path`.
pub fn gpus_in(root: &Path) -> Vec<GpuDevice> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut devices: Vec<GpuDevice> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let bdf = PciAddress::parse(&entry.file_name().to_string_lossy())?;
            let path = entry.path();
            if !is_intel_gpu_class(&read_small(path.join("vendor")), &read_small(path.join("class"))) {
                return None;
            }
            let canonical = fs::canonicalize(&path).ok()?;
            Some(GpuDevice { bdf, os_path: canonical.to_string_lossy().into_owned() })
        })
        .collect();
    devices.sort_by_key(|d| d.bdf);
    devices
}

/// The Intel GPUs the OS sees, without any driver call, in BDF order; empty when none.
pub fn gpus_from_os() -> Vec<GpuDevice> {
    gpus_in(Path::new(PCI_DEVICES))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "gpus_tests.rs"]
mod tests;
