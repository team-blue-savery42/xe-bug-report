// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/gpus.rs`.

use super::*;

fn bdf(bus: u8, device: u8, function: u8) -> PciAddress {
    PciAddress { domain: 0, bus, device, function }
}

const B580: &str = "PCI\\VEN_8086&DEV_E20B&SUBSYS_12121172&REV_00\\4&1A2B3C4D&0&0008";

#[test]
fn one_intel_gpu() {
    let text = format!("{B580}|3|0\n");
    let gpus = parse_gpu_lines(&text);
    assert_eq!(gpus, vec![GpuDevice { bdf: bdf(3, 0, 0), os_path: B580.to_owned() }]);
}

#[test]
fn device_is_high_word_and_function_low_three_bits() {
    // device 2, function 1 => 0x0002_0001
    let gpus = parse_gpu_lines(&format!("{B580}|0|{}\n", 0x0002_0001u32));
    assert_eq!(gpus[0].bdf, bdf(0, 2, 1));
    // bits 3..15 of the low word are ignored
    let gpus = parse_gpu_lines(&format!("{B580}|0|{}\n", 0x001f_00ffu32));
    assert_eq!(gpus[0].bdf, bdf(0, 31, 7));
}

#[test]
fn crlf_and_bom() {
    let text = format!("\u{feff}{B580}|3|0\r\n{B580}x|4|65536\r\n");
    let gpus = parse_gpu_lines(&text);
    assert_eq!(gpus.len(), 2);
    assert_eq!(gpus[0].bdf, bdf(3, 0, 0));
    assert_eq!(gpus[1].bdf, bdf(4, 1, 0));
    assert!(!gpus[0].os_path.contains('\r'));
}

#[test]
fn non_intel_and_non_pci_are_dropped() {
    let text = "PCI\\VEN_10DE&DEV_2204&SUBSYS_1&REV_A1\\4&1&0&0008|1|0\n\
                    ROOT\\BASICDISPLAY\\0000|0|0\n\
                    SWD\\VEN_8086\\0|0|0\n\
                    PCI\\VEN_1002&DEV_73BF\\5&2&0&0|2|0\n";
    assert!(parse_gpu_lines(text).is_empty());
}

#[test]
fn vendor_and_prefix_are_case_insensitive() {
    let gpus = parse_gpu_lines("pci\\ven_8086&dev_e20b\\4&1&0&0|3|0\n");
    assert_eq!(gpus.len(), 1);
    assert_eq!(gpus[0].os_path, "pci\\ven_8086&dev_e20b\\4&1&0&0");
}

#[test]
fn malformed_lines() {
    let text = "\n   \nnot a record\n|\n||\n|3|0\nPCI\\VEN_8086&DEV_1\\x\nPCI\\VEN_8086&DEV_1\\x|3\n\
                    PCI\\VEN_8086&DEV_1\\x|3|\nPCI\\VEN_8086&DEV_1\\x||0\n";
    assert!(parse_gpu_lines(text).is_empty());
}

#[test]
fn missing_fields_from_empty_property_values() {
    // Get-PnpDeviceProperty prints nothing when the property is absent.
    let id = "PCI\\VEN_8086&DEV_E20B\\1";
    assert!(parse_gpu_lines(&format!("{id}|3|\n")).is_empty());
    assert!(parse_gpu_lines(&format!("{id}||0\n")).is_empty());
    assert!(parse_gpu_lines(&format!("{id}||\n")).is_empty());
}

#[test]
fn non_numeric_values() {
    let id = "PCI\\VEN_8086&DEV_E20B\\1";
    for bad in
        ["x|0", "3|y", "-1|0", "3|-1", "3.5|0", "3|1.0", "0x|0", "0xzz|0", "3|0x", "+3|0", "3 4|0", "3|0 1"]
    {
        assert!(parse_gpu_lines(&format!("{id}|{bad}\n")).is_empty(), "{bad}");
    }
}

#[test]
fn hexadecimal_is_accepted() {
    let gpus = parse_gpu_lines("PCI\\VEN_8086&DEV_1\\1|0x3|0x00020001\n");
    assert_eq!(gpus[0].bdf, bdf(3, 2, 1));
}

#[test]
fn out_of_range_values() {
    let id = "PCI\\VEN_8086&DEV_E20B\\1";
    // bus 256 does not fit a PCI bus number; bus 255 does
    assert!(parse_gpu_lines(&format!("{id}|256|0\n")).is_empty());
    assert!(parse_gpu_lines(&format!("{id}|4294967296|0\n")).is_empty());
    assert_eq!(parse_gpu_lines(&format!("{id}|255|0\n"))[0].bdf, bdf(255, 0, 0));
    // device 32 is out of range; 31 is the last
    assert!(parse_gpu_lines(&format!("{id}|3|{}\n", 32u32 << 16)).is_empty());
    assert!(parse_gpu_lines(&format!("{id}|3|{}\n", 0xffff_ffffu32)).is_empty());
    assert!(parse_gpu_lines(&format!("{id}|3|4294967296\n")).is_empty());
    assert_eq!(parse_gpu_lines(&format!("{id}|3|{}\n", 31u32 << 16))[0].bdf, bdf(3, 31, 0));
}

#[test]
fn duplicates_keep_the_first() {
    let text = "PCI\\VEN_8086&DEV_E20B\\A|3|0\nPCI\\VEN_8086&DEV_E20B\\A|5|0\n\
                    PCI\\VEN_8086&DEV_E20B\\B|3|0\npci\\ven_8086&dev_e20b\\a|7|0\n";
    let gpus = parse_gpu_lines(text);
    assert_eq!(gpus.len(), 1);
    assert_eq!(gpus[0].bdf, bdf(3, 0, 0));
    assert_eq!(gpus[0].os_path, "PCI\\VEN_8086&DEV_E20B\\A");
}

#[test]
fn sorted_by_bdf() {
    let text = "PCI\\VEN_8086&DEV_1\\a|9|0\nPCI\\VEN_8086&DEV_1\\b|3|1\nPCI\\VEN_8086&DEV_1\\c|3|0\n";
    let order: Vec<_> = parse_gpu_lines(text).iter().map(|g| (g.bdf.bus, g.bdf.function)).collect();
    assert_eq!(order, [(3, 0), (3, 1), (9, 0)]);
}

#[test]
fn mixed_vendors_keep_only_intel() {
    let text = "PCI\\VEN_10DE&DEV_1\\a|1|0\nPCI\\VEN_8086&DEV_E20B\\b|3|0\n";
    let gpus = parse_gpu_lines(text);
    assert_eq!(gpus.len(), 1);
    assert_eq!(gpus[0].bdf, bdf(3, 0, 0));
}

#[test]
fn instance_id_with_a_bar_keeps_the_last_two_fields() {
    let gpus = parse_gpu_lines("PCI\\VEN_8086&DEV_1\\a|b|3|0\n");
    assert_eq!(gpus[0].os_path, "PCI\\VEN_8086&DEV_1\\a|b");
    assert_eq!(gpus[0].bdf, bdf(3, 0, 0));
}

#[test]
fn invalid_input_never_panics() {
    for text in ["", "\u{feff}", "|||||", "\r\r\r", "é|é|é", "PCI\\VEN_8086|99999999999999999999|1"] {
        assert!(parse_gpu_lines(text).is_empty());
    }
}

#[test]
fn script_has_no_double_quotes_and_forces_utf8() {
    assert!(!ENUMERATION_SCRIPT.contains('"'));
    assert!(ENUMERATION_SCRIPT.starts_with("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"));
    for key in
        ["Get-PnpDevice -Class Display -PresentOnly", "DEVPKEY_Device_BusNumber", "DEVPKEY_Device_Address"]
    {
        assert!(ENUMERATION_SCRIPT.contains(key), "{key}");
    }
    let argv = powershell_argv(ENUMERATION_SCRIPT);
    assert_eq!(&argv[..4], ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]);
    assert_eq!(argv[4], ENUMERATION_SCRIPT);
}
