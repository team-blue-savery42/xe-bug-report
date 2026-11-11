// SPDX-License-Identifier: MIT
//! Command-line parsing (clap builder API) and `--since` parsing.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Arg, ArgAction, Command, value_parser};

use crate::build_info;
use crate::bundle::source::{GpuDevice, Profile};
use crate::error::Error;
use crate::pci::PciAddress;

/// Default `--samples`.
pub const DEFAULT_SAMPLES: u32 = 5;
/// Largest `--samples`.
pub const MAX_SAMPLES: u32 = 3600;
/// Default `--timeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Largest `--timeout` in seconds (one year); keeps `Instant + timeout` from overflowing.
pub const MAX_TIMEOUT_SECS: u64 = 365 * 24 * 3600;
/// Largest `--since` window in minutes (365 days).
pub const MAX_SINCE_MINUTES: u64 = 365 * 24 * 60;
/// What a caller prints after a plain-text usage error.
pub const USAGE_HINT: &str = "Run with --help for more information.";

/// The parsed arguments of a collection or `--list` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// `--output`; None for the default name.
    pub output: Option<PathBuf>,
    /// `--device`; empty for every GPU.
    pub devices: Vec<PciAddress>,
    /// `--minimal`, `--full` or the default.
    pub profile: Profile,
    /// `--samples` (0 with `--minimal`).
    pub samples: u32,
    pub since: Option<Duration>,
    pub no_redact: bool,
    pub list: bool,
    pub json: bool,
    pub xpu_smi: Option<PathBuf>,
    /// `--timeout`; None when 0 disables the deadline.
    pub timeout: Option<Duration>,
    pub verbose: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            output: None,
            devices: Vec::new(),
            profile: Profile::Default,
            samples: DEFAULT_SAMPLES,
            since: None,
            no_redact: false,
            list: false,
            json: false,
            xpu_smi: None,
            timeout: Some(DEFAULT_TIMEOUT),
            verbose: false,
        }
    }
}

/// Why parsing ended without [`Args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliExit {
    /// `--help`: print the text to stdout, exit 0.
    Help(String),
    /// `--version`: print the text to stdout, exit 0.
    Version(String),
    /// A usage error: print to stderr (or as JSON when `json`), exit 1. The message is one
    /// paragraph without the "error: " prefix; plain-text callers follow it with [`USAGE_HINT`].
    Usage {
        message: String,
        /// `--json` was among the arguments.
        json: bool,
    },
}

/// The clap command; the single place that declares the options.
fn command() -> Command {
    Command::new("xe-bug-report")
        .about("Collect GPU diagnostics into a redacted zip bundle")
        .override_usage(
            "xe-bug-report [--output <file>] [--device <bdf,...>] [--minimal | --full] [--samples <n>]\n       \
             [--since <duration>] [--no-redact] [--list] [--json] [--xpu-smi <path>] [--timeout <seconds>]\n       \
             [--verbose]\n       \
             xe-bug-report --version | -v\n       \
             xe-bug-report --help | -h",
        )
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("file")
                .value_parser(value_parser!(OsString))
                .help("The zip file to write (default: xe-bug-report-<UTC time>.zip in the current directory)"),
        )
        .arg(
            Arg::new("device")
                .long("device")
                .value_name("bdf,...")
                .action(ArgAction::Append)
                .help("PCI addresses (dddd:bb:dd.f) of the GPUs to include, comma-separated"),
        )
        .arg(
            Arg::new("minimal")
                .long("minimal")
                .action(ArgAction::SetTrue)
                .conflicts_with("full")
                .help("Collect only the essentials, no samples"),
        )
        .arg(
            Arg::new("full")
                .long("full")
                .action(ArgAction::SetTrue)
                .conflicts_with("minimal")
                .help("Also collect large and slow sources"),
        )
        .arg(
            Arg::new("samples")
                .long("samples")
                .value_name("n")
                .allow_negative_numbers(true)
                .value_parser(value_parser!(u32).range(0..=i64::from(MAX_SAMPLES)))
                .help("Metric samples per GPU, 1 s apart (default: 5, 0 disables, at most 3600)"),
        )
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("duration")
                .help("Time window of the kernel and event logs: <n>m, <n>h, <n>d or hours (1 minute to 365 days)"),
        )
        .arg(
            Arg::new("no-redact")
                .long("no-redact")
                .action(ArgAction::SetTrue)
                .help("Keep host names, user names, serial numbers and addresses"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .action(ArgAction::SetTrue)
                .help("List the sources that would be collected and exit"),
        )
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Print the result as JSON"))
        .arg(
            Arg::new("xpu-smi")
                .long("xpu-smi")
                .value_name("path")
                .value_parser(value_parser!(OsString))
                .help("The xpu-smi executable (default: xpu-smi on PATH, then next to xe-bug-report)"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("seconds")
                .allow_negative_numbers(true)
                .value_parser(value_parser!(u64).range(0..=MAX_TIMEOUT_SECS))
                .help("Seconds for the whole run (default: 600, 0 disables the deadline)"),
        )
        .arg(Arg::new("verbose").long("verbose").action(ArgAction::SetTrue).help("Log progress to stderr and list every source that was not collected completely"))
        .arg(
            Arg::new("version")
                .long("version")
                .short('v')
                .action(ArgAction::SetTrue)
                .help("Print the version and exit"),
        )
}

/// Whether `--json` is among the raw arguments (argv[0] and anything after `--` excluded), so an
/// error found before parsing completes can still be reported as JSON.
fn wants_json(argv: &[OsString]) -> bool {
    argv.iter().skip(1).take_while(|arg| arg.as_os_str() != "--").any(|arg| arg.as_os_str() == "--json")
}

/// The first paragraph of a clap error, without the "error: " prefix.
fn error_message(error: &clap::Error) -> String {
    let text = error.to_string();
    let first = text.split("\n\n").next().unwrap_or_default().trim();
    first.strip_prefix("error: ").unwrap_or(first).trim().to_owned()
}

/// Splits one `--device` value at commas, trimming blanks around each address. Empty items are
/// kept (and later rejected) so "a,,b" is an error rather than silently accepted.
fn split_device_list(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').map(str::trim)
}

/// Parses every `--device` value into addresses, dropping repeats and keeping the typed order.
fn parse_devices<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Vec<PciAddress>, String> {
    let mut devices = Vec::new();
    for value in values {
        for item in split_device_list(value) {
            let address = PciAddress::parse(item)
                .ok_or_else(|| format!("Invalid PCI address '{item}' for --device; expected dddd:bb:dd.f"))?;
            if !devices.contains(&address) {
                devices.push(address);
            }
        }
    }
    Ok(devices)
}

/// Keeps the GPUs of `available` that `requested` names, in OS order; all of them when nothing is
/// requested.
///
/// Fails with [`Error::UnknownDevice`] naming the first requested address no GPU has.
pub fn select_devices(requested: &[PciAddress], available: Vec<GpuDevice>) -> Result<Vec<GpuDevice>, Error> {
    if let Some(missing) = requested.iter().find(|wanted| !available.iter().any(|gpu| gpu.bdf == **wanted)) {
        return Err(Error::UnknownDevice(missing.to_string()));
    }
    if requested.is_empty() {
        return Ok(available);
    }
    Ok(available.into_iter().filter(|gpu| requested.contains(&gpu.bdf)).collect())
}

/// Parses the process arguments (including argv[0]).
pub fn parse_args<I, T>(argv: I) -> Result<Args, CliExit>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
    let json = wants_json(&argv);
    let usage = |message: String| CliExit::Usage { message, json };

    let matches = match command().try_get_matches_from(argv) {
        Ok(matches) => matches,
        Err(error) if error.kind() == ErrorKind::DisplayHelp => return Err(CliExit::Help(error.to_string())),
        Err(error) => return Err(usage(error_message(&error))),
    };

    if matches.get_flag("version") {
        return Err(CliExit::Version(version_text()));
    }

    let output = matches.get_one::<OsString>("output").map(PathBuf::from);
    if output.as_ref().is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(usage("The output file name can't be empty".to_owned()));
    }
    let xpu_smi = matches.get_one::<OsString>("xpu-smi").map(PathBuf::from);
    if xpu_smi.as_ref().is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(usage("The --xpu-smi path can't be empty".to_owned()));
    }

    let devices =
        parse_devices(matches.get_many::<String>("device").into_iter().flatten().map(String::as_str))
            .map_err(usage)?;

    let since = match matches.get_one::<String>("since") {
        None => None,
        Some(text) => Some(parse_since(text).ok_or_else(|| {
            usage(format!(
                "Invalid value '{text}' for --since; use <n>m, <n>h or <n>d, or a bare number of hours, from 1 \
                 minute to 365 days"
            ))
        })?),
    };

    let minimal = matches.get_flag("minimal");
    let profile = if minimal {
        Profile::Minimal
    } else if matches.get_flag("full") {
        Profile::Full
    } else {
        Profile::Default
    };
    let samples =
        if minimal { 0 } else { matches.get_one::<u32>("samples").copied().unwrap_or(DEFAULT_SAMPLES) };
    let timeout = match matches.get_one::<u64>("timeout") {
        None => Some(DEFAULT_TIMEOUT),
        Some(0) => None,
        Some(&seconds) => Some(Duration::from_secs(seconds)),
    };

    Ok(Args {
        output,
        devices,
        profile,
        samples,
        since,
        no_redact: matches.get_flag("no-redact"),
        list: matches.get_flag("list"),
        json: matches.get_flag("json"),
        xpu_smi,
        timeout,
        verbose: matches.get_flag("verbose"),
    })
}

/// The `--version` text: "xe-bug-report <version> (<describe>, <commit>, built <time>)".
pub fn version_text() -> String {
    format_version(build_info::VERSION, build_info::DESCRIBE, build_info::COMMIT, &build_info::built_human())
}

/// Builds the version text; the parenthesised part lists only the non-empty items.
fn format_version(version: &str, describe: &str, commit: &str, built: &str) -> String {
    let built = if built.is_empty() { String::new() } else { format!("built {built}") };
    let details: Vec<&str> =
        [describe, commit, built.as_str()].into_iter().filter(|part| !part.is_empty()).collect();
    if details.is_empty() {
        format!("xe-bug-report {version}")
    } else {
        format!("xe-bug-report {version} ({})", details.join(", "))
    }
}

/// Parses `--since`: "<n>m", "<n>h", "<n>d" or a bare "<n>" (hours); from 1 minute to 365 days.
/// None for any other form, a sign, blanks, trailing text or out of range.
pub fn parse_since(text: &str) -> Option<Duration> {
    let (digits, unit_minutes) = match text.as_bytes().last()? {
        b'm' => (&text[..text.len() - 1], 1),
        b'h' => (&text[..text.len() - 1], 60),
        b'd' => (&text[..text.len() - 1], 24 * 60),
        last if last.is_ascii_digit() => (text, 60),
        _ => return None,
    };
    // Digits only: `str::parse` would also accept a leading '+'.
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let count: u64 = digits.parse().ok()?;
    if count < 1 || count > MAX_SINCE_MINUTES / unit_minutes {
        return None;
    }
    Some(Duration::from_secs(count * unit_minutes * 60))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "cli_tests.rs"]
mod tests;
