// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/scripts.rs`. The scripts cannot run here, so these check
//! what can go wrong in transit: quoting, balance of brackets and the names they rely on.

use super::*;

const ALL: &[(&str, &str)] = &[
    ("KHRONOS_ICDS", KHRONOS_ICDS),
    ("UMD_VERSIONS", UMD_VERSIONS),
    ("GPU_COUNTERS", GPU_COUNTERS),
    ("INTEL_SOFTWARE", INTEL_SOFTWARE),
    ("MONITORS", MONITORS),
    ("ISOLATION", ISOLATION),
];

#[test]
fn scripts_survive_command_line_quoting() {
    for (name, script) in ALL {
        assert!(!script.contains('"'), "{name}");
        assert!(!script.ends_with('\\'), "{name}");
        assert!(!script.contains('\n') && !script.contains('\r'), "{name}");
        assert!(!script.trim().is_empty(), "{name}");
    }
}

#[test]
fn quotes_and_brackets_balance() {
    for (name, script) in ALL {
        assert_eq!(script.matches('\'').count() % 2, 0, "{name}: single quotes");
        assert_eq!(script.matches('{').count(), script.matches('}').count(), "{name}: braces");
        assert_eq!(script.matches('(').count(), script.matches(')').count(), "{name}: parentheses");
        assert_eq!(script.matches('[').count(), script.matches(']').count(), "{name}: brackets");
    }
}

#[test]
fn the_monitor_script_never_reads_a_serial_number() {
    let lowered = MONITORS.to_ascii_lowercase();
    assert!(!lowered.contains("serial"));
    for class in
        ["WmiMonitorID", "WmiMonitorBasicDisplayParams", "WmiMonitorConnectionParams", "Win32_DesktopMonitor"]
    {
        assert!(MONITORS.contains(class), "{class}");
    }
    assert!(MONITORS.contains("UserFriendlyName") && MONITORS.contains("ProductCodeID"));
}

#[test]
fn the_counter_script_names_the_gpu_counter_sets_and_hides_the_machine_name() {
    for counter in [
        r"'\GPU Engine(*)\Utilization Percentage'",
        r"'\GPU Adapter Memory(*)\Dedicated Usage'",
        r"'\GPU Adapter Memory(*)\Shared Usage'",
        r"'\GPU Process Memory(*)\Dedicated Usage'",
    ] {
        assert!(GPU_COUNTERS.contains(counter), "{counter}");
    }
    assert!(GPU_COUNTERS.contains(r"-replace '^\\\\[^\\]+', ''"));
    assert!(GPU_COUNTERS.contains("-SampleInterval 1 -MaxSamples 2"));
}

#[test]
fn the_registry_script_covers_both_views_and_the_current_user() {
    for key in [
        r"HKLM:\SOFTWARE\Khronos\OpenCL\Vendors",
        r"HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors",
        r"HKLM:\SOFTWARE\Khronos\Vulkan\Drivers",
        r"HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\Drivers",
        r"HKLM:\SOFTWARE\Khronos\Vulkan\ImplicitLayers",
        r"HKLM:\SOFTWARE\Khronos\Vulkan\ExplicitLayers",
        r"HKCU:\SOFTWARE\Khronos\Vulkan\Drivers",
    ] {
        assert!(KHRONOS_ICDS.contains(key), "{key}");
    }
}

#[test]
fn the_software_script_prints_names_and_versions_only() {
    assert!(INTEL_SOFTWARE.contains("$_.Name + ' ' + $_.Version"));
    assert!(INTEL_SOFTWARE.contains("$_.DisplayName + ' ' + $_.DisplayVersion"));
    assert!(!INTEL_SOFTWARE.contains("Publisher") && !INTEL_SOFTWARE.contains("InstallLocation"));
}

#[test]
fn the_isolation_script_asks_for_the_device_guard_namespace() {
    assert!(ISOLATION.contains(r"'root\Microsoft\Windows\DeviceGuard'"));
    assert!(ISOLATION.contains("VirtualizationBasedSecurityStatus"));
    assert!(ISOLATION.contains("HypervisorPresent"));
}

#[test]
fn the_monitor_script_handles_the_internal_and_other_connector_values() {
    // The values do not fit a 32-bit signed integer, so the script widens before it compares.
    assert!(MONITORS.contains("[int64]$_.VideoOutputTechnology"));
    assert!(MONITORS.contains("2147483648") && MONITORS.contains("4294967295"));
    assert!(!MONITORS.contains("[int]$_.VideoOutputTechnology"));
    for name in ["'internal'", "'other'", "14='SDTV dongle'", "1='S-video'"] {
        assert!(MONITORS.contains(name), "{name}");
    }
}

#[test]
fn the_isolation_script_says_so_when_the_class_returns_nothing() {
    assert!(ISOLATION.contains("Win32_DeviceGuard returned nothing (it needs an elevated prompt"));
    assert!(ISOLATION.contains("if ($dg)"));
}

#[test]
fn the_library_script_scans_the_intel_driver_store_folders() {
    assert!(UMD_VERSIONS.contains(r"System32\DriverStore\FileRepository"));
    assert!(UMD_VERSIONS.contains("-Filter 'iigd*'"));
    assert!(UMD_VERSIONS.contains("Select-Object -First 8"));
    assert!(UMD_VERSIONS.contains("igdrcl") || UMD_VERSIONS.contains("'igd*.dll'"));
}

#[test]
fn the_registry_script_skips_the_default_value_and_resolves_bare_library_names() {
    assert!(KHRONOS_ICDS.contains("if ($n -eq '') { continue }"));
    assert!(KHRONOS_ICDS.contains("Test-Path -LiteralPath $full"));
}
