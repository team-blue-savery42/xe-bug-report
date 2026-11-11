// SPDX-License-Identifier: MIT
//! The diagnostic sources described as data, so the collector, the manifest and `--list` share
//! one table.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pci::PciAddress;
use crate::units::Bytes;

/// How much to collect; a source is included when the selected profile is at least its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Profile {
    /// The smallest useful bundle.
    Minimal,
    /// The normal bundle.
    #[default]
    Default,
    /// Everything, including large or slow sources.
    Full,
}

impl Profile {
    /// The manifest and `--list` spelling: "minimal", "default", "full".
    pub const fn name(self) -> &'static str {
        match self {
            Profile::Minimal => "minimal",
            Profile::Default => "default",
            Profile::Full => "full",
        }
    }
}

/// What a denied source needs; explains the denial to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Gate {
    /// No gate.
    #[default]
    None,
    /// The kernel log: journal group, CAP_SYSLOG or dmesg_restrict=0.
    KernelLog,
    /// Opening a GPU render node.
    DeviceAccess,
    /// Owner-only files: debugfs, devcoredump, most module parameters.
    Root,
    /// CAP_SYS_ADMIN: PCI configuration space past its first 64 bytes.
    SysAdmin,
    /// Windows: an elevated prompt.
    Elevated,
}

impl Gate {
    /// How to obtain the gate, phrased to follow "needs "; empty for `None`.
    pub const fn describe(self) -> &'static str {
        match self {
            Gate::None => "",
            Gate::KernelLog => {
                "root, CAP_SYSLOG, membership of the 'adm' or 'systemd-journal' group, or sysctl kernel.dmesg_restrict=0"
            }
            Gate::DeviceAccess => "membership of the 'render' group, or root",
            Gate::Root => "root",
            Gate::SysAdmin => "root or CAP_SYS_ADMIN",
            Gate::Elevated => "an elevated (Administrator) prompt",
        }
    }

    /// The manifest spelling; empty for `None`.
    pub const fn name(self) -> &'static str {
        match self {
            Gate::None => "",
            Gate::KernelLog => "kernel_log",
            Gate::DeviceAccess => "device_access",
            Gate::Root => "root",
            Gate::SysAdmin => "sys_admin",
            Gate::Elevated => "elevated",
        }
    }

    /// Every gate in enum order (notices are emitted in this order).
    pub const ALL: [Gate; 6] =
        [Gate::None, Gate::KernelLog, Gate::DeviceAccess, Gate::Root, Gate::SysAdmin, Gate::Elevated];
}

/// Whether a source is redacted as text or written as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Content {
    /// Redacted before it is written.
    #[default]
    Text,
    /// Written as-is.
    Binary,
}

/// Which end of an over-long file to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Keep {
    /// The first `max_bytes`.
    #[default]
    Head,
    /// The last `max_bytes`.
    Tail,
}

/// What happened to a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    /// Fully collected.
    #[default]
    Collected,
    /// Partly collected: size cap, or part of it denied.
    Truncated,
    /// Not collected: denied, absent, not installed, unsupported or excluded by redaction.
    Skipped,
    /// Hit its own time limit.
    TimedOut,
    /// Ran and produced no usable result.
    Failed,
}

impl Status {
    /// The manifest spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Status::Collected => "collected",
            Status::Truncated => "truncated",
            Status::Skipped => "skipped",
            Status::TimedOut => "timed_out",
            Status::Failed => "failed",
        }
    }
}

/// How a file read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadOutcome {
    /// `data` holds the contents (possibly truncated).
    Read,
    /// Permission denied (EACCES, EPERM, ERROR_ACCESS_DENIED).
    Denied,
    /// No such file.
    Missing,
    /// Any other error; `error` says which.
    #[default]
    Failed,
}

/// The result of a bounded file read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadResult {
    pub outcome: ReadOutcome,
    pub data: Vec<u8>,
    /// The file was larger than the cap.
    pub truncated: bool,
    /// OS error text when `outcome != Read`.
    pub error: String,
}

/// Bounded, hang-safe file reads handed to builtins. Implemented by the collector over `Guard`.
pub trait Reader: Sync {
    /// Reads at most `max` bytes of `path`, keeping the head or tail.
    fn read(&self, path: &Path, max: Bytes, keep: Keep) -> ReadResult;
}

/// One output of a builtin source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Produced {
    /// Entry name in the bundle.
    pub rel_path: String,
    pub status: Status,
    /// Its contents (redacted later unless the source is binary).
    pub data: Vec<u8>,
    /// Why it is not collected, if so.
    pub reason: String,
    /// The command or file it came from.
    pub via: String,
}

/// Data computed in code from bounded reads.
pub type Builtin = Box<dyn Fn(&dyn Reader) -> Vec<Produced> + Send + Sync>;

/// How a source obtains its data.
pub enum Spec {
    File {
        path: PathBuf,
    },
    /// Regular files under `root` matching `patterns` ('*' within one segment); symlinks never followed.
    Tree {
        root: PathBuf,
        /// Relative path patterns.
        patterns: Vec<String>,
    },
    /// argv[0] looked up on PATH; "{outdir}" in an argument is replaced by a private temp dir
    /// whose files are collected under rel_path.
    Command {
        argv: Vec<String>,
    },
    /// Arguments to the xpu-smi executable; "{outdir}" as for Command.
    XpuSmi {
        /// Arguments after the program.
        args: Vec<String>,
    },
    Builtin(Builtin),
}

impl std::fmt::Debug for Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Spec::File { path } => f.debug_struct("File").field("path", path).finish(),
            Spec::Tree { root, patterns } => {
                f.debug_struct("Tree").field("root", root).field("patterns", patterns).finish()
            }
            Spec::Command { argv } => f.debug_struct("Command").field("argv", argv).finish(),
            Spec::XpuSmi { args } => f.debug_struct("XpuSmi").field("args", args).finish(),
            Spec::Builtin(_) => f.write_str("Builtin"),
        }
    }
}

/// Default per-source time limit.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default per-source size cap.
pub const DEFAULT_CAP: Bytes = Bytes::mib(16);

/// One diagnostic source: where it goes in the bundle, how it is obtained and what it needs.
#[derive(Debug)]
pub struct Source {
    /// File in the bundle, or a directory ending in '/' for Tree and {outdir} sources.
    pub rel_path: String,
    /// How the data is obtained.
    pub spec: Spec,
    /// What a denial means.
    pub gate: Gate,
    /// Included when the selected profile is at least this.
    pub profile: Profile,
    /// Time limit; default 10 s.
    pub timeout: Duration,
    /// Size cap; default 16 MiB.
    pub max_bytes: Bytes,
    /// Which end to keep; default Head.
    pub keep: Keep,
    /// Text (redacted) or binary; default Text.
    pub content: Content,
    /// Binary that may hold personal data: skipped while redacting.
    pub identifying: bool,
    /// Guard group; default "host", devices "device:<bdf>".
    pub group: String,
    /// Non-empty: keep only lines containing one (case-insensitive).
    pub keep_lines: Vec<String>,
    /// Output containing it -> Truncated with gate.
    pub denied_marker: Option<String>,
    /// Output containing it -> Skipped "not supported by this xpu-smi".
    pub unsupported_marker: Option<String>,
    /// false -> Skipped with gate.
    pub available: Option<fn() -> bool>,
    /// One line for `--list`.
    pub why: &'static str,
}

impl Source {
    fn new(rel_path: &str, spec: Spec, profile: Profile, why: &'static str) -> Self {
        Self {
            rel_path: rel_path.to_owned(),
            spec,
            gate: Gate::None,
            profile,
            timeout: DEFAULT_TIMEOUT,
            max_bytes: DEFAULT_CAP,
            keep: Keep::Head,
            content: Content::Text,
            identifying: false,
            group: "host".to_owned(),
            keep_lines: Vec::new(),
            denied_marker: None,
            unsupported_marker: None,
            available: None,
            why,
        }
    }

    /// A single file.
    pub fn file(rel_path: &str, path: impl Into<PathBuf>, profile: Profile, why: &'static str) -> Self {
        Self::new(rel_path, Spec::File { path: path.into() }, profile, why)
    }

    /// Regular files under `root` matching `patterns`.
    pub fn tree(
        rel_path: &str,
        root: impl Into<PathBuf>,
        patterns: &[&str],
        profile: Profile,
        why: &'static str,
    ) -> Self {
        let patterns = patterns.iter().map(|p| (*p).to_owned()).collect();
        Self::new(rel_path, Spec::Tree { root: root.into(), patterns }, profile, why)
    }

    /// A command; argv[0] is looked up on PATH.
    pub fn command(rel_path: &str, argv: &[&str], profile: Profile, why: &'static str) -> Self {
        let argv = argv.iter().map(|a| (*a).to_owned()).collect();
        Self::new(rel_path, Spec::Command { argv }, profile, why)
    }

    /// Arguments to xpu-smi.
    pub fn xpu_smi(rel_path: &str, args: &[String], profile: Profile, why: &'static str) -> Self {
        Self::new(rel_path, Spec::XpuSmi { args: args.to_vec() }, profile, why)
    }

    /// Computed in code.
    pub fn builtin(rel_path: &str, f: Builtin, profile: Profile, why: &'static str) -> Self {
        Self::new(rel_path, Spec::Builtin(f), profile, why)
    }

    /// Sets the gate.
    pub fn gate(mut self, g: Gate) -> Self {
        self.gate = g;
        self
    }
    /// Sets the time limit.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
    /// Sets the size cap.
    pub fn cap(mut self, max: Bytes) -> Self {
        self.max_bytes = max;
        self
    }
    /// Keeps the tail instead of the head.
    pub fn tail(mut self) -> Self {
        self.keep = Keep::Tail;
        self
    }
    /// Marks the content binary (not redacted).
    pub fn binary(mut self) -> Self {
        self.content = Content::Binary;
        self
    }
    /// Marks it identifying: skipped while redacting.
    pub fn identifying(mut self) -> Self {
        self.identifying = true;
        self
    }
    /// Sets the guard group.
    pub fn group(mut self, g: &str) -> Self {
        self.group = g.to_owned();
        self
    }
    /// Keeps only lines containing one of `needles` (case-insensitive).
    pub fn keep_lines(mut self, needles: &[&str]) -> Self {
        self.keep_lines = needles.iter().map(|n| (*n).to_owned()).collect();
        self
    }
    /// Output containing `m` is Truncated with the gate.
    pub fn denied_marker(mut self, m: &str) -> Self {
        self.denied_marker = Some(m.to_owned());
        self
    }
    /// Output containing `m` is Skipped "not supported by this xpu-smi".
    pub fn unsupported_marker(mut self, m: &str) -> Self {
        self.unsupported_marker = Some(m.to_owned());
        self
    }
    /// `f()` false -> Skipped with the gate.
    pub fn available(mut self, f: fn() -> bool) -> Self {
        self.available = Some(f);
        self
    }
}

/// An Intel GPU the OS sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDevice {
    pub bdf: PciAddress,
    /// Linux: canonical sysfs directory; Windows: device instance id.
    pub os_path: String,
}

/// What the sources depend on.
#[derive(Debug, Clone, Default)]
pub struct SourceOptions {
    pub profile: Profile,
    /// Devices, already filtered by `--device`.
    pub devices: Vec<GpuDevice>,
    /// `xpu-smi dump` samples per device, 1 s apart; 0 disables.
    pub samples: u32,
    /// Log window; None for the per-OS default.
    pub since: Option<Duration>,
    /// The xpu-smi executable; None when not found.
    pub xpu_smi: Option<PathBuf>,
}
