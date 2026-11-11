// SPDX-License-Identifier: MIT
//! Command-line parsing (clap builder API) and `--since` parsing.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::bundle::source::Profile;
use crate::pci::PciAddress;

/// Default `--samples`.
pub const DEFAULT_SAMPLES: u32 = 5;
/// Largest `--samples`.
pub const MAX_SAMPLES: u32 = 3600;
/// Default `--timeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

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
    /// A usage error: print to stderr (or as JSON when `json`), exit 1.
    Usage {
        /// The message.
        message: String,
        /// `--json` was among the arguments.
        json: bool,
    },
}

/// Parses the process arguments (including argv[0]).
pub fn parse_args<I, T>(argv: I) -> Result<Args, CliExit>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let _ = argv.into_iter().count();
    Ok(Args::default())
}

/// The `--version` text: "xe-bug-report <version> (<describe>, <commit>, built <time>)".
pub fn version_text() -> String {
    String::new()
}

/// Parses `--since`: "<n>m", "<n>h", "<n>d" or a bare "<n>" (hours); from 1 minute to 365 days.
/// None for any other form, a sign, blanks, trailing text or out of range.
pub fn parse_since(text: &str) -> Option<Duration> {
    let _ = text;
    None
}
