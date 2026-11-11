// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/host.rs`.

use super::*;

#[test]
fn identity_has_host_fqdn_and_user() {
    let c = identity_from("WORKSTATION1", "LAB.EXAMPLE.COM", "jdoe");
    assert_eq!(c.hostnames, ["WORKSTATION1", "WORKSTATION1.LAB.EXAMPLE.COM"]);
    assert_eq!(c.user_names, ["jdoe"]);
}

#[test]
fn identity_without_domain_or_with_empty_values() {
    let c = identity_from("PC", "", "me");
    assert_eq!(c.hostnames, ["PC"]);
    let c = identity_from("", "corp.example", "");
    assert!(c.hostnames.is_empty());
    assert!(c.user_names.is_empty());
    let c = identity_from("  ", " . ", "  ");
    assert_eq!(c, Context::default());
}

#[test]
fn service_accounts_are_not_users() {
    for name in ["SYSTEM", "system", "Local Service", "LOCAL SERVICE", "network service", "NETWORK SERVICE"] {
        assert!(is_service_account(name), "{name}");
        assert!(identity_from("PC", "", name).user_names.is_empty(), "{name}");
    }
    assert!(!is_service_account("SYSTEM1"));
    assert_eq!(identity_from("PC", "", "systemd").user_names, ["systemd"]);
}

#[test]
fn hostname_and_user_are_not_duplicated() {
    let c = identity_from("PC", "PC", "PC");
    assert_eq!(c.hostnames, ["PC", "PC.PC"]);
    assert_eq!(c.user_names, ["PC"]);
}

const TCPIP: &str = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\n    \
Hostname    REG_SZ    a-very-long-workstation-name\r\n    NV Hostname    REG_SZ    a-very-long-workstation-name\r\n    \
Domain    REG_SZ    lab.example.com\r\n    NV Domain    REG_SZ    lab.example.com\r\n    \
DhcpIPAddress    REG_SZ    192.0.2.3\r\n";

#[test]
fn tcpip_names_with_domain() {
    let mut c = identity_from("A-VERY-LONG-WORK", "", "me");
    add_tcpip_names(&mut c, TCPIP);
    assert_eq!(
        c.hostnames,
        ["A-VERY-LONG-WORK", "a-very-long-workstation-name", "a-very-long-workstation-name.lab.example.com"]
    );
    assert_eq!(c.user_names, ["me"]);
}

#[test]
fn tcpip_names_with_empty_domain_and_different_nv_name() {
    let mut c = Context::default();
    add_tcpip_names(
        &mut c,
        "    Hostname    REG_SZ    pc1\r\n    Domain    REG_SZ    \r\n    NV Hostname    REG_SZ    pc2\r\n    NV Domain    REG_SZ    .lan.\r\n",
    );
    assert_eq!(c.hostnames, ["pc1", "pc2", "pc2.lan"]);
}

#[test]
fn tcpip_names_from_garbage() {
    let mut c = Context::default();
    add_tcpip_names(&mut c, "");
    add_tcpip_names(
        &mut c,
        "ERROR: The system was unable to find the specified registry key\n\u{0}\u{fffd}REG_SZ\n    REG_SZ\n",
    );
    assert_eq!(c, Context::default());
}

fn os(s: &str) -> OsString {
    OsString::from(s)
}

#[test]
fn environment_filter_and_sort() {
    let vars = vec![
        (os("Path"), os("C:\\Windows")),
        (os("ZE_AFFINITY_MASK"), os("0")),
        (os("USERNAME"), os("secret")),
        (os("=C:"), os("C:\\dir")),
        (os(""), os("x")),
        (os("sycl_cache_persistent"), os("1")),
        (os("INTEL_DEBUG"), os("a=b")),
        (os("FOO_UR_X"), os("no")),
        (os("LANG"), os("")),
    ];
    assert_eq!(
        environment_text(vars),
        "INTEL_DEBUG=a=b\nLANG=\nPath=C:\\Windows\nZE_AFFINITY_MASK=0\nsycl_cache_persistent=1\n"
    );
}

#[test]
fn wanted_names() {
    for n in [
        "NEOReadDebugKeys",
        "neoreaddebugkeys",
        "PATH",
        "Path",
        "MESA_LOADER_DRIVER_OVERRIDE",
        "ANV_DEBUG",
        "VK_DRIVER_FILES",
        "VK_LOADER_DEBUG",
        "DRI_PRIME",
        "LIBGL_ALWAYS_SOFTWARE",
        "EGL_PLATFORM",
        "GALLIUM_DRIVER",
        "MFX_IMPL",
        "ONEVPL_SEARCH_PATH",
        "OPENCL_VENDOR_PATH",
        "lc_all",
        "CONTAINER",
        "PROCESSOR_ARCHITECTURE",
        "NEO_X",
        "XPU_SMI_FOO",
        "xpum_a",
        "UR_ADAPTERS",
    ] {
        assert!(wanted_environment_name(n), "{n}");
    }
    for n in ["PROCESSOR_IDENTIFIER", "PATHEXT", "USER", "URL", "TEMP", "LANGUAGE", "NEO", ""] {
        assert!(!wanted_environment_name(n), "{n}");
    }
}

fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(n, v)| (os(n), os(v))).collect()
}

#[test]
fn debug_keys_by_plain_name_are_recorded_only_while_the_switch_is_on() {
    let pairs = [
        ("NEOReadDebugKeys", "1"),
        ("PrintDebugMessages", "1"),
        ("EnableDirectSubmission", "0"),
        ("ForceCsrFlushing", "1"),
        ("USERNAME", "jdoe"),
        ("USERPROFILE", "C:\\Users\\jdoe"),
        ("GITHUB_TOKEN", "t"),
        ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE"),
        ("AZURE_STORAGE_CONNECTION_STRING", "AccountKey=abc"),
        ("DATABASE_URL", "postgres://u:p@db.example.com/x"),
        ("HTTPS_PROXY", "http://proxy.example.com:8080"),
        ("USERDNSDOMAIN", "CORP.EXAMPLE.COM"),
        ("CLIENTNAME", "LAPTOP-7"),
        ("SENTRY_DSN", "https://abc@example.com/1"),
        ("=C:", "C:\\dir"),
    ];
    assert_eq!(
        environment_text(vars(&pairs)),
        "EnableDirectSubmission=0\nForceCsrFlushing=1\nNEOReadDebugKeys=1\nPrintDebugMessages=1\n"
    );
    let off: Vec<(&str, &str)> =
        pairs.iter().map(|&(n, v)| if n == "NEOReadDebugKeys" { (n, "0") } else { (n, v) }).collect();
    assert_eq!(environment_text(vars(&off)), "NEOReadDebugKeys=0\n");
    let unset: Vec<(&str, &str)> = pairs.iter().copied().filter(|(n, _)| *n != "NEOReadDebugKeys").collect();
    assert_eq!(environment_text(vars(&unset)), "");
}

#[test]
fn the_debug_key_list_is_clean_and_matches_prefixed_names() {
    assert!(DEBUG_KEY_NAMES.lines().count() > 100);
    assert!(
        DEBUG_KEY_NAMES.lines().all(|l| !l.is_empty() && l == l.trim() && !l.contains(char::is_whitespace))
    );
    assert!(DEBUG_KEY_NAMES.lines().any(|l| l == "PrintDebugMessages"));
    for name in [
        "PrintDebugMessages",
        "printdebugmessages",
        "NEO_PrintDebugMessages",
        "neo_ocl_PrintDebugMessages",
        "NEO_L0_PrintDebugMessages",
    ] {
        assert!(is_debug_key_name(name), "{name}");
    }
    for name in [
        "",
        "NEO_",
        "NEO_OCL_",
        "AWS_ACCESS_KEY_ID",
        "DATABASE_URL",
        "HTTPS_PROXY",
        "CLIENTNAME",
        "PrintDebugMessagesX",
    ] {
        assert!(!is_debug_key_name(name), "{name}");
    }
}

#[test]
fn debug_key_values_are_cut() {
    let long = "x".repeat(2000);
    let text = environment_text(vars(&[("NEOReadDebugKeys", "1"), ("AUBDumpCaptureDirPath", &long)]));
    let line = text.lines().find(|l| l.starts_with("AUBDumpCaptureDirPath=")).unwrap();
    assert_eq!(line.len(), "AUBDumpCaptureDirPath=".len() + 512);
}

#[test]
fn the_debug_key_switch_is_found_in_any_letter_case_and_empty_means_off() {
    let on = environment_text(vars(&[("neoreaddebugkeys", "1"), ("DumpKernels", "1")]));
    assert_eq!(on, "DumpKernels=1\nneoreaddebugkeys=1\n");
    let empty = environment_text(vars(&[("NEOReadDebugKeys", " "), ("DumpKernels", "1")]));
    assert_eq!(empty, "NEOReadDebugKeys= \n");
}

#[test]
fn environment_with_nothing_wanted_is_empty() {
    assert_eq!(environment_text(Vec::new()), "");
}

#[test]
fn directories_have_fallbacks() {
    assert_eq!(windows_dir_from(Some(os("D:\\WIN")), Some(os("C:\\Windows"))), PathBuf::from("D:\\WIN"));
    assert_eq!(windows_dir_from(Some(os("")), Some(os("E:\\W"))), PathBuf::from("E:\\W"));
    assert_eq!(windows_dir_from(None, None), PathBuf::from("C:\\Windows"));
    let w = PathBuf::from("D:\\WIN");
    assert_eq!(program_data_from(Some(os("F:\\PD")), &w), PathBuf::from("F:\\PD"));
    assert_eq!(program_data_from(None, &w), PathBuf::from("D:\\ProgramData"));
    assert_eq!(program_data_from(Some(os("")), &w), PathBuf::from("D:\\ProgramData"));
    assert_eq!(
        program_data_from(None, &PathBuf::from("\\\\server\\share\\Windows")),
        PathBuf::from("C:\\ProgramData")
    );
}

#[test]
fn local_app_data_has_a_fallback() {
    assert_eq!(
        local_app_data_from(Some(os("D:\\L")), Some(os("C:\\Users\\me"))),
        Some(PathBuf::from("D:\\L"))
    );
    assert_eq!(
        local_app_data_from(Some(os("")), Some(os("C:\\Users\\me"))),
        Some(PathBuf::from("C:\\Users\\me").join("AppData").join("Local"))
    );
    assert_eq!(
        local_app_data_from(None, Some(os("C:\\Users\\me"))),
        Some(PathBuf::from("C:\\Users\\me").join("AppData").join("Local"))
    );
    assert_eq!(local_app_data_from(None, None), None);
    assert_eq!(local_app_data_from(Some(os("")), Some(os(""))), None);
}

const REG: &str = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    \
SystemRoot    REG_SZ    C:\\WINDOWS\r\n    ProductName    REG_SZ    Windows 10 Pro\r\n    \
DisplayVersion    REG_SZ    24H2\r\n    CurrentBuildNumber    REG_SZ    26100\r\n    \
UBR    REG_DWORD    0x92a\r\n    Weird Name    REG_SZ    two words here\r\n    Empty    REG_SZ    \r\n    \
Blob    REG_BINARY    0102\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\r\n";

#[test]
fn reg_output_parses() {
    let v = parse_reg_values(REG);
    assert_eq!(v["ProductName"], "Windows 10 Pro");
    assert_eq!(v["UBR"], "0x92a");
    assert_eq!(v["Weird Name"], "two words here");
    assert_eq!(v["Empty"], "");
    assert_eq!(v["Blob"], "0102");
    assert!(!v.keys().any(|k| k.starts_with("HKEY")));
}

#[test]
fn windows_10_product_name_is_corrected_on_new_builds() {
    let v = parse_reg_values(REG);
    assert_eq!(describe_os(&v, "ARCH1"), "Windows 11 Pro 24H2, build 26100.2346, arch1");
}

#[test]
fn windows_10_stays_below_build_22000() {
    let mut v = parse_reg_values(REG);
    v.insert("CurrentBuildNumber".to_owned(), "19045".to_owned());
    v.insert("UBR".to_owned(), "5011".to_owned());
    assert_eq!(describe_os(&v, "ARCH2"), "Windows 10 Pro 24H2, build 19045.5011, arch2");
}

#[test]
fn description_without_registry() {
    assert_eq!(describe_os(&HashMap::new(), ""), "Windows, unknown architecture");
    assert_eq!(describe_os(&HashMap::new(), " Arch3 "), "Windows, arch3");
}

#[test]
fn description_without_ubr_or_version() {
    let mut v = HashMap::new();
    v.insert("ProductName".to_owned(), "Windows Server 2022 Standard".to_owned());
    v.insert("CurrentBuild".to_owned(), "20348".to_owned());
    assert_eq!(describe_os(&v, "arch1"), "Windows Server 2022 Standard, build 20348, arch1");
}

#[test]
fn garbage_registry_values_do_not_panic() {
    let mut v = HashMap::new();
    v.insert("CurrentBuildNumber".to_owned(), "abc".to_owned());
    v.insert("UBR".to_owned(), "0xzz".to_owned());
    assert_eq!(describe_os(&v, "   "), "Windows, unknown architecture");
    assert!(parse_reg_values("    REG_SZ    x\n    \n REG_\n").is_empty());
}

#[test]
fn architectures() {
    assert_eq!(architecture_name("ARCH1"), "arch1");
    assert_eq!(architecture_name(" Arch2 "), "arch2");
    assert_eq!(architecture_name(""), "unknown architecture");
}
