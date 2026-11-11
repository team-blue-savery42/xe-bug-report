// SPDX-License-Identifier: MIT
//! Intel GPUs from one PowerShell query; the output parser is pure.

use std::time::Duration;

use crate::bundle::source::GpuDevice;
use crate::pci::PciAddress;
use crate::procio::run_child;
use crate::units::Bytes;

/// The vendor id fragment of an Intel hardware id.
const INTEL_VENDOR_ID: &str = "VEN_8086";
/// Instance ids of PCI-enumerated adapters start with this; only they have a bus and address.
const PCI_PREFIX: &str = "PCI\\";
/// The device number is the high word of `DEVPKEY_Device_Address`.
const ADDRESS_DEVICE_SHIFT: u32 = 16;
/// The function number is the low three bits of `DEVPKEY_Device_Address`.
const ADDRESS_FUNCTION_MASK: u32 = 0x7;
/// The highest PCI device number.
const MAX_DEVICE: u32 = 31;
/// How long the enumeration may take (PowerShell start-up is slow on a cold machine).
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// The most output read from the enumeration.
const ENUMERATION_MAX_OUTPUT: Bytes = Bytes::mib(1);

/// The PowerShell script that prints `instanceId|bus|address` for every present display device,
/// with the console forced to UTF-8. Only single quotes are used so that argument quoting of the
/// command line cannot damage it.
pub const ENUMERATION_SCRIPT: &str = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
Get-PnpDevice -Class Display -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { \
$id = $_.InstanceId; \
$bus = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_BusNumber' -ErrorAction SilentlyContinue).Data; \
$addr = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Address' -ErrorAction SilentlyContinue).Data; \
$id + '|' + $bus + '|' + $addr }";

/// The argv that runs a PowerShell script with the profile and prompts disabled.
pub fn powershell_argv(script: &str) -> Vec<String> {
    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// The Intel GPUs the OS sees, in BDF order; empty when PowerShell is missing, fails or times out.
pub fn gpus_from_os() -> Vec<GpuDevice> {
    let argv = powershell_argv(ENUMERATION_SCRIPT);
    let result = run_child(&argv, ENUMERATION_TIMEOUT, ENUMERATION_MAX_OUTPUT);
    parse_gpu_lines(&String::from_utf8_lossy(&result.output))
}

/// Parses a decimal (or `0x` hexadecimal) unsigned 32-bit number; None for anything else.
fn parse_number(text: &str) -> Option<u32> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u32::from_str_radix(hex, 16).ok();
    }
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parses one `instanceId|bus|address` line; None when it is not an Intel PCI display adapter
/// with a usable bus and address.
fn parse_line(line: &str) -> Option<GpuDevice> {
    let mut fields = line.rsplitn(3, '|');
    let address = fields.next()?;
    let bus = fields.next()?;
    let id = fields.next()?.trim();
    let upper = id.to_ascii_uppercase();
    if !upper.starts_with(PCI_PREFIX) || !upper.contains(INTEL_VENDOR_ID) {
        return None;
    }
    let bus = u8::try_from(parse_number(bus)?).ok()?;
    let address = parse_number(address)?;
    let device = address >> ADDRESS_DEVICE_SHIFT;
    if device > MAX_DEVICE {
        return None;
    }
    // Windows reports no PCI segment; the rest of the tool assumes segment 0 as well.
    let bdf = PciAddress {
        domain: 0,
        bus,
        device: u8::try_from(device).ok()?,
        function: u8::try_from(address & ADDRESS_FUNCTION_MASK).ok()?,
    };
    Some(GpuDevice { bdf, os_path: id.to_owned() })
}

/// Parses the output of [`ENUMERATION_SCRIPT`]: `instanceId|bus|address` lines.
///
/// Lines that are malformed, not Intel (`VEN_8086`), not PCI-enumerated, or whose bus (> 255) or
/// device (> 31) is out of range are ignored; a repeated instance id or address keeps its first
/// line. A byte order mark and CRLF line ends are tolerated. The result is in BDF order.
pub fn parse_gpu_lines(text: &str) -> Vec<GpuDevice> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut devices: Vec<GpuDevice> = Vec::new();
    for line in text.lines() {
        let Some(device) = parse_line(line.trim()) else { continue };
        let duplicate =
            devices.iter().any(|d| d.bdf == device.bdf || d.os_path.eq_ignore_ascii_case(&device.os_path));
        if !duplicate {
            devices.push(device);
        }
    }
    devices.sort_by_key(|d| d.bdf);
    devices
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "gpus_tests.rs"]
mod tests;
