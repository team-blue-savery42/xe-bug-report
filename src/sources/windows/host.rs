// SPDX-License-Identifier: MIT
//! Host facts: this machine's and user's names, the OS description, the environment report and
//! the Windows directories. Everything that parses or formats is a pure function.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use crate::bundle::source::Produced;
use crate::procio::{ChildOutcome, run_child};
use crate::redact::Context;
use crate::units::Bytes;

/// Same classes of variable as the Linux table, minus the loader variables: the compute and
/// media runtimes, the shader compiler, and the Mesa, Vulkan, OpenGL and OpenCL loaders.
const ENV_PREFIXES: &[&str] = &[
    "NEO_",
    "ZE_",
    "ZET_",
    "ZES_",
    "ZEL_",
    "ZEX_",
    "ONEAPI_",
    "SYCL_",
    "UR_",
    "IGC_",
    "OCL_",
    "XPU_SMI_",
    "XPUM_",
    "LIBVA_",
    "INTEL_",
    "MESA_",
    "ANV_",
    "HASVK_",
    "VK_",
    "LIBGL_",
    "EGL_",
    "GALLIUM_",
    "DRI_PRIME",
    "MFX_",
    "VPL_",
    "ONEVPL_",
    "OPENCL_",
    "CL_",
];
/// Variables recorded by exact name (compared in upper case). `NEOReadDebugKeys` does not start
/// with `NEO_`; it switches the compute runtime's debug keys on. `PATH` decides which loader
/// libraries (`OpenCL.dll`, `vulkan-1.dll`, `ze_loader.dll`) a process finds first.
const ENV_EXACT: &[&str] =
    &["NEOREADDEBUGKEYS", "PATH", "LANG", "LC_ALL", "CONTAINER", "PROCESSOR_ARCHITECTURE"];

/// The variable that makes the compute runtime read its debug keys.
const DEBUG_KEYS_SWITCH: &str = "NEOREADDEBUGKEYS";
/// The compute runtime's debug key names, one per line: a snapshot of the runtime's key list.
/// Keys are read from variables with their plain names (`PrintDebugMessages`,
/// `EnableDirectSubmission`, ...), or with a `NEO_OCL_`, `NEO_L0_` or `NEO_` prefix. Keys added
/// by a newer runtime are not recorded.
const DEBUG_KEY_NAMES: &str = include_str!("debug_keys.txt");
/// The prefixes the compute runtime accepts before a debug key name, longest first.
const DEBUG_KEY_PREFIXES: &[&str] = &["NEO_OCL_", "NEO_L0_", "NEO_"];
/// Debug key values are cut at this many characters.
const MAX_DEBUG_VALUE_CHARS: usize = 512;

/// Account names of the built-in service accounts; they occur in ordinary log text and would be
/// rewritten everywhere, so they are never treated as a user name.
const SERVICE_ACCOUNTS: &[&str] = &["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"];

/// The first Windows build that is Windows 11.
const WINDOWS_11_FIRST_BUILD: u32 = 22000;
/// The registry key that describes the installed Windows.
const CURRENT_VERSION_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
/// The registry query is quick; this only bounds a wedged system.
const REG_TIMEOUT: Duration = Duration::from_secs(10);

// ---- identity -------------------------------------------------------------------------------------

/// Whether `name` is a built-in service account (any letter case).
pub fn is_service_account(name: &str) -> bool {
    SERVICE_ACCOUNTS.iter().any(|s| name.eq_ignore_ascii_case(s))
}

/// Builds the redaction context from the three environment values. Empty values are ignored, the
/// fully qualified name is `computer.dns_domain`, and service accounts are not user names.
pub fn identity_from(computer: &str, dns_domain: &str, user: &str) -> Context {
    let mut context = Context::default();
    let computer = computer.trim();
    let dns_domain = dns_domain.trim().trim_matches('.');
    add_unique(&mut context.hostnames, computer);
    if !computer.is_empty() && !dns_domain.is_empty() {
        add_unique(&mut context.hostnames, &format!("{computer}.{dns_domain}"));
    }
    if !is_service_account(user.trim()) {
        add_unique(&mut context.user_names, user);
    }
    context
}

fn env_lossy(name: &str) -> String {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()).unwrap_or_default()
}

/// This machine's names (COMPUTERNAME, USERDNSDOMAIN) and user (USERNAME) from the environment.
/// There is no name-service lookup, so this never blocks.
pub fn local_identity_without_lookups() -> Context {
    identity_from(&env_lossy("COMPUTERNAME"), &env_lossy("USERDNSDOMAIN"), &env_lossy("USERNAME"))
}

/// The registry key that holds the host name and DNS domain.
const TCPIP_PARAMETERS_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";

/// Adds a name unless it is empty or already present.
fn add_unique(names: &mut Vec<String>, name: &str) {
    let name = name.trim();
    if !name.is_empty() && !names.iter().any(|n| n == name) {
        names.push(name.to_owned());
    }
}

/// Adds the host names recorded in `reg query` output of the Tcpip parameters key: `Hostname`,
/// `NV Hostname`, and each with its domain (`Domain`, `NV Domain`) when that is non-empty.
pub fn add_tcpip_names(context: &mut Context, reg_output: &str) {
    let values = parse_reg_values(reg_output);
    let get = |name: &str| values.get(name).map_or("", |v| v.trim().trim_matches('.'));
    for (host, domain) in [("Hostname", "Domain"), ("NV Hostname", "NV Domain")] {
        let (host, domain) = (get(host), get(domain));
        add_unique(&mut context.hostnames, host);
        if !host.is_empty() && !domain.is_empty() {
            add_unique(&mut context.hostnames, &format!("{host}.{domain}"));
        }
    }
}

/// This machine's names: the environment ones plus the registry host name and domain (which can
/// differ from `COMPUTERNAME` for a name longer than 15 characters). No DNS query is made.
pub fn local_identity() -> Context {
    let mut context = local_identity_without_lookups();
    let argv = ["reg", "query", TCPIP_PARAMETERS_KEY].map(str::to_owned);
    let result = run_child(&argv, REG_TIMEOUT, Bytes::kib(64));
    if result.outcome == ChildOutcome::Exited(0) {
        add_tcpip_names(&mut context, &String::from_utf8_lossy(&result.output));
    }
    context
}

// ---- environment report ---------------------------------------------------------------------------

/// Whether an environment variable is on the list of GPU runtime settings worth recording.
pub fn wanted_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ENV_EXACT.contains(&upper.as_str()) || ENV_PREFIXES.iter().any(|p| upper.starts_with(p))
}

/// Whether `name` is a compute runtime debug key, bare or with a `NEO_OCL_`, `NEO_L0_` or `NEO_`
/// prefix (any letter case).
pub fn is_debug_key_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let bare = DEBUG_KEY_PREFIXES.iter().find_map(|prefix| upper.strip_prefix(prefix)).unwrap_or(&upper);
    !bare.is_empty() && DEBUG_KEY_NAMES.lines().any(|key| key.eq_ignore_ascii_case(bare))
}

/// Whether a variable is recorded while the debug-key switch is on: the switch itself and the
/// debug keys. Nothing else is, so unrelated variables with secrets or names never appear.
fn wanted_while_debug_keys_on(name: &str) -> bool {
    name.eq_ignore_ascii_case(DEBUG_KEYS_SWITCH) || is_debug_key_name(name)
}

/// Whether the debug-key switch is set to something other than empty or `0`.
fn debug_keys_switch_on(vars: &[(String, OsString)]) -> bool {
    vars.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(DEBUG_KEYS_SWITCH) && {
            let value = value.to_string_lossy();
            let value = value.trim();
            !value.is_empty() && value != "0"
        }
    })
}

/// Sorted `NAME=value` lines, one per wanted variable. Entries without a name, such as the
/// per-drive `=C:` working directories, are not variables. While `NEOReadDebugKeys` is set to
/// something other than `0`, the compute runtime's debug keys are wanted too, each value cut at
/// 512 characters.
pub fn environment_text<I>(vars: I) -> String
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let vars: Vec<(String, OsString)> = vars
        .into_iter()
        .map(|(name, value)| (name.to_string_lossy().into_owned(), value))
        .filter(|(name, _)| !name.is_empty() && !name.starts_with('='))
        .collect();
    let debug_keys = debug_keys_switch_on(&vars);
    let mut lines: Vec<String> = vars
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_string_lossy();
            if wanted_environment_name(name) {
                Some(format!("{name}={value}"))
            } else if debug_keys && wanted_while_debug_keys_on(name) {
                Some(format!("{name}={}", value.chars().take(MAX_DEBUG_VALUE_CHARS).collect::<String>()))
            } else {
                None
            }
        })
        .collect();
    lines.sort();
    let mut text = String::new();
    for line in lines {
        text.push_str(&line);
        text.push('\n');
    }
    text
}

/// The environment variables that change GPU runtime behaviour, as `system/env.txt`.
pub fn produce_environment() -> Vec<Produced> {
    vec![Produced {
        rel_path: "system/env.txt".to_owned(),
        data: environment_text(std::env::vars_os()).into_bytes(),
        ..Produced::default()
    }]
}

// ---- directories ----------------------------------------------------------------------------------

/// The Windows directory: `%SystemRoot%`, then `%windir%`, then `C:\Windows`.
pub fn windows_dir_from(system_root: Option<OsString>, windir: Option<OsString>) -> PathBuf {
    [system_root, windir]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from)
}

/// The ProgramData directory: `%ProgramData%`, else `ProgramData` on the drive of `windows_dir`.
pub fn program_data_from(program_data: Option<OsString>, windows_dir: &std::path::Path) -> PathBuf {
    if let Some(dir) = program_data.filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    let text = windows_dir.to_string_lossy();
    let mut chars = text.chars();
    let drive = match (chars.next(), chars.next()) {
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic() => format!("{letter}:"),
        _ => "C:".to_owned(),
    };
    PathBuf::from(format!("{drive}\\ProgramData"))
}

/// The per-user local application data directory: `%LOCALAPPDATA%`, else `AppData\Local` below
/// `%USERPROFILE%`; None when neither is set.
pub fn local_app_data_from(
    local_app_data: Option<OsString>,
    user_profile: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(dir) = local_app_data.filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    user_profile.filter(|v| !v.is_empty()).map(|p| PathBuf::from(p).join("AppData").join("Local"))
}

/// The local application data directory of the invoking user.
pub fn local_app_data_dir() -> Option<PathBuf> {
    local_app_data_from(std::env::var_os("LOCALAPPDATA"), std::env::var_os("USERPROFILE"))
}

/// The Windows directory of this machine.
pub fn windows_dir() -> PathBuf {
    windows_dir_from(std::env::var_os("SystemRoot"), std::env::var_os("windir"))
}

/// The ProgramData directory of this machine.
pub fn program_data_dir(windows_dir: &std::path::Path) -> PathBuf {
    program_data_from(std::env::var_os("ProgramData"), windows_dir)
}

// ---- OS description -------------------------------------------------------------------------------

/// Parses `reg query` output into value name -> data. Lines look like
/// `    Name    REG_SZ    Data`; key lines and anything else are ignored.
pub fn parse_reg_values(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if !line.starts_with(char::is_whitespace) {
            continue;
        }
        for (index, _) in line.match_indices("REG_") {
            let before = &line[..index];
            if !before.ends_with(char::is_whitespace) {
                continue;
            }
            let name = before.trim();
            let rest = &line[index..];
            let type_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if name.is_empty() {
                break;
            }
            values.insert(name.to_owned(), rest[type_end..].trim().to_owned());
            break;
        }
    }
    values
}

/// A registry DWORD as printed by `reg query`: `0x2b2`, or decimal.
fn parse_dword(text: &str) -> Option<u32> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The machine architecture as the OS reports it (`PROCESSOR_ARCHITEW6432` /
/// `PROCESSOR_ARCHITECTURE`), lower-cased; "unknown architecture" when it is empty.
pub fn architecture_name(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() { "unknown architecture".to_owned() } else { value.to_ascii_lowercase() }
}

/// "Windows 11 Pro 24H2, build 26100.2314, x64" from the CurrentVersion registry values.
pub fn describe_os(values: &HashMap<String, String>, architecture: &str) -> String {
    let build = values
        .get("CurrentBuildNumber")
        .or_else(|| values.get("CurrentBuild"))
        .and_then(|b| b.trim().parse::<u32>().ok());
    let mut product = values.get("ProductName").cloned().unwrap_or_default();
    // ProductName still says Windows 10 on Windows 11.
    if build.is_some_and(|b| b >= WINDOWS_11_FIRST_BUILD)
        && let Some(rest) = product.strip_prefix("Windows 10")
    {
        product = format!("Windows 11{rest}");
    }
    let mut text = if product.is_empty() { "Windows".to_owned() } else { product };
    if let Some(version) = values.get("DisplayVersion").filter(|v| !v.is_empty()) {
        text.push(' ');
        text.push_str(version);
    }
    if let Some(build) = build {
        let _ = write!(text, ", build {build}");
        if let Some(revision) = values.get("UBR").and_then(|r| parse_dword(r)) {
            let _ = write!(text, ".{revision}");
        }
    }
    text.push_str(", ");
    text.push_str(&architecture_name(architecture));
    text
}

/// One line naming the OS, e.g. "Windows 11 Pro 24H2, build 26100.2314, <architecture>".
pub fn os_description() -> String {
    let argv = ["reg", "query", CURRENT_VERSION_KEY].map(str::to_owned);
    let result = run_child(&argv, REG_TIMEOUT, Bytes::kib(256));
    let values = match result.outcome {
        ChildOutcome::Exited(0) => parse_reg_values(&String::from_utf8_lossy(&result.output)),
        _ => HashMap::new(),
    };
    let architecture = std::env::var_os("PROCESSOR_ARCHITEW6432")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("PROCESSOR_ARCHITECTURE"))
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    describe_os(&values, &architecture)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "host_tests.rs"]
mod tests;
