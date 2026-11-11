// SPDX-License-Identifier: MIT
//! The Windows source table and host facts.

pub mod events;
pub mod gpus;
pub mod host;
pub mod listings;

use std::path::Path;
use std::time::Duration;

use crate::bundle::source::{Gate, GpuDevice, Profile, Source, SourceOptions};
use crate::bundle::summary::Privilege;
use crate::redact::Context;
use crate::units::Bytes;

const TIMEOUT_30S: Duration = Duration::from_secs(30);
const TIMEOUT_60S: Duration = Duration::from_secs(60);
const TIMEOUT_120S: Duration = Duration::from_secs(120);

/// A source that runs a program with the given time limit.
fn command(rel_path: &str, argv: &[&str], profile: Profile, timeout: Duration, why: &'static str) -> Source {
    Source::command(rel_path, argv, profile, why).timeout(timeout)
}

/// A source that runs a PowerShell script with UTF-8 console output.
fn powershell(
    rel_path: &str,
    script: &str,
    profile: Profile,
    timeout: Duration,
    why: &'static str,
) -> Source {
    let argv = gpus::powershell_argv(&format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}"));
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    command(rel_path, &refs, profile, timeout, why)
}

/// The Windows platform rows, in reference order, before profile filtering. Time-windowed event
/// queries use `options.since` (72 hours by default).
pub fn table(options: &SourceOptions) -> Vec<Source> {
    let windows_dir = host::windows_dir();
    let program_data = host::program_data_dir(&windows_dir);
    table_for(options, &windows_dir, &program_data)
}

/// [`table`] with the Windows and ProgramData directories given.
// One push per row keeps the table readable and in reference order.
#[allow(clippy::vec_init_then_push)]
fn table_for(options: &SourceOptions, windows_dir: &Path, program_data: &Path) -> Vec<Source> {
    let window_ms = events::window_ms(options.since);
    let mut sources = Vec::new();

    // system/
    sources.push(powershell(
        "system/os.txt",
        "Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime",
        Profile::Minimal,
        TIMEOUT_30S,
        "operating system name, version, build and boot time",
    ));
    sources.push(command(
        "system/systeminfo.txt",
        &["systeminfo"],
        Profile::Default,
        TIMEOUT_60S,
        "systeminfo: hardware, firmware and hotfix summary",
    ));
    sources.push(Source::builtin(
        "system/env.txt",
        Box::new(|_reader| host::produce_environment()),
        Profile::Minimal,
        "environment variables that change GPU runtime behaviour",
    ));
    sources.push(command(
        "system/id.txt",
        &["whoami", "/user", "/groups", "/priv", "/fo", "list"],
        Profile::Minimal,
        crate::bundle::source::DEFAULT_TIMEOUT,
        "invoking user, groups and privileges",
    ));
    sources.push(powershell(
        "system/wmi-video.txt",
        "Get-CimInstance Win32_VideoController | Format-List *",
        Profile::Minimal,
        TIMEOUT_30S,
        "display adapters as the WMI video controller class",
    ));
    sources.push(powershell(
        "system/wmi-display-drivers.txt",
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'DISPLAY' } | Format-List \
DeviceName,DriverVersion,DriverDate,InfName,DeviceID,Manufacturer,IsSigned,Signer",
        Profile::Minimal,
        TIMEOUT_60S,
        "installed display driver packages and their signatures",
    ));

    // devices/
    sources.push(command(
        "devices/pnputil-devices.txt",
        &["pnputil", "/enum-devices", "/class", "Display", "/drivers"],
        Profile::Minimal,
        TIMEOUT_30S,
        "display devices, their problem status and driver candidates",
    ));
    sources.push(command(
        "devices/pnputil-drivers.txt",
        &["pnputil", "/enum-drivers", "/class", "Display"],
        Profile::Default,
        TIMEOUT_30S,
        "display drivers in the driver store",
    ));
    sources.push(
        command(
            "devices/display-class-registry.txt",
            &[
                "reg",
                "query",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}",
                "/s",
            ],
            Profile::Default,
            TIMEOUT_30S,
            "display device class registry key",
        )
        .cap(Bytes::mib(8)),
    );

    // kernel/
    sources.push(command(
        "kernel/graphicsdrivers-registry.txt",
        &["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", "/s"],
        Profile::Minimal,
        crate::bundle::source::DEFAULT_TIMEOUT,
        "graphics kernel settings (TDR, scheduler)",
    ));
    sources.push(command(
        "kernel/system-events.txt",
        &[
            "wevtutil",
            "qe",
            "System",
            &events::system_events_query(window_ms),
            "/f:text",
            "/rd:true",
            "/c:5000",
        ],
        Profile::Minimal,
        TIMEOUT_60S,
        "display, power and hardware-error events from the System log",
    ));
    sources.push(command(
        "kernel/application-events.txt",
        &[
            "wevtutil",
            "qe",
            "Application",
            &events::application_events_query(window_ms),
            "/f:text",
            "/rd:true",
            "/c:2000",
        ],
        Profile::Default,
        TIMEOUT_60S,
        "application crash and error-reporting events",
    ));
    sources.push(
        command(
            "kernel/",
            &["wevtutil", "epl", "System", "{outdir}\\System.evtx", &events::time_window_query(window_ms)],
            Profile::Full,
            TIMEOUT_120S,
            "the System event log as a binary .evtx export",
        )
        .binary()
        .identifying()
        .cap(Bytes::mib(64)),
    );
    sources.push(
        Source::file(
            "kernel/setupapi.dev.log",
            windows_dir.join("INF").join("setupapi.dev.log"),
            Profile::Default,
            "device and driver installation log",
        )
        .cap(Bytes::mib(4))
        .tail(),
    );

    // dumps/
    let roots = listings::roots(windows_dir, program_data);
    sources.push(
        Source::builtin(
            listings::REL_PATH,
            Box::new(move |_reader| vec![listings::list_roots(&roots)]),
            Profile::Default,
            "crash dump and GPU hang report files, listed but not copied",
        )
        .gate(Gate::Elevated),
    );

    // packages/ and tools/
    sources.push(command(
        "packages/driverquery.csv",
        &["driverquery", "/v", "/fo", "csv"],
        Profile::Default,
        TIMEOUT_30S,
        "all loaded drivers with versions and dates",
    ));
    sources.push(command(
        "tools/dxdiag/",
        &["dxdiag", "/whql:off", "/t", "{outdir}\\dxdiag.txt"],
        Profile::Full,
        TIMEOUT_120S,
        "DirectX diagnostic report",
    ));
    sources
}

/// The Intel GPUs the OS sees, without any driver call, in BDF order.
pub fn gpus_from_os() -> Vec<GpuDevice> {
    gpus::gpus_from_os()
}

/// This machine's names and user, including the registry host name and domain; no DNS query.
pub fn local_identity() -> Context {
    host::local_identity()
}

/// This machine's names without any lookup; never blocks.
pub fn local_identity_without_lookups() -> Context {
    host::local_identity_without_lookups()
}

/// One line naming the OS, e.g. "Windows 11 Pro 24H2, build 26100.2314, x64".
pub fn os_description() -> String {
    host::os_description()
}

/// The privilege of this process: Privileged when the token is elevated.
pub fn current_privilege() -> Privilege {
    #[cfg(windows)]
    {
        if crate::sys::windows::is_elevated() {
            return Privilege::Privileged;
        }
    }
    Privilege::Unprivileged
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
