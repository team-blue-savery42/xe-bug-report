// SPDX-License-Identifier: MIT
//! The optional configuration file: where the diagnostic tools are when they are not on PATH.
//!
//! It is read when it exists at `$XDG_CONFIG_HOME/xe-bug-report/config` (`~/.config/...` when
//! `XDG_CONFIG_HOME` is unset), or `%APPDATA%\xe-bug-report\config` on Windows ([`default_path`]):
//!
//! ```text
//! [tools]
//! xpu-smi = /opt/intel/xpu-smi/bin/xpu-smi
//! # Relative: below the directory of this file.
//! iclg = crashlog/iclg
//!
//! [search]
//! # Searched for every tool without its own line, before PATH.
//! dir = /opt/intel/oneapi/bin
//! ```
//!
//! Lines are `key = value`, `[section]` headers, blank, or comments starting with `#` or `;`. A
//! value is the rest of the line, trimmed, with one pair of surrounding quotes removed; there is
//! no escaping and no comment after a value, so paths may hold `#`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bundle::source::{Keep, ReadOutcome};
use crate::guard::Guard;
use crate::procio::{ToolLocations, read_file_bounded};
use crate::units::Bytes;

/// Largest configuration file read.
const MAX_SIZE: Bytes = Bytes::kib(64);
/// How long reading the file may take (the home directory may sit on a hung network mount).
const READ_LIMIT: Duration = Duration::from_secs(5);

/// A loaded configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The file it came from.
    pub path: PathBuf,
    /// The tool locations it gives.
    pub locations: ToolLocations,
    /// Lines that were understood but ignored (unknown sections), for the log.
    pub warnings: Vec<String>,
}

/// Reads the configuration file when it exists. None when there is none (or no home directory).
///
/// Fails with a message naming the file when it exists but cannot be read, is not safe to trust
/// or does not parse.
pub fn load() -> Result<Option<Config>, String> {
    match default_path(|name| std::env::var_os(name)) {
        Some(path) if path.is_file() => load_from(&path).map(Some),
        _ => Ok(None),
    }
}

/// Reads and parses the configuration file at `path`.
pub fn load_from(path: &Path) -> Result<Config, String> {
    check_trust(path)?;
    let text = read(path)?;
    let base = path.parent().unwrap_or(path);
    let (locations, warnings) =
        parse(&text, base).map_err(|message| format!("{}: {message}", path.display()))?;
    Ok(Config { path: path.to_path_buf(), locations, warnings })
}

/// Where the configuration file is: `$XDG_CONFIG_HOME/xe-bug-report/config`, else
/// `$HOME/.config/xe-bug-report/config`; `%APPDATA%\xe-bug-report\config` on Windows. None
/// without an absolute base directory. `env` reads an environment variable.
pub fn default_path(env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let var = |name: &str| env(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    let dir = if cfg!(windows) {
        var("APPDATA")
    } else {
        var("XDG_CONFIG_HOME")
            .filter(|dir| dir.is_absolute())
            .or_else(|| var("HOME").map(|home| home.join(".config")))
    };
    // A relative directory would be the current directory by another name.
    Some(dir.filter(|dir| dir.is_absolute())?.join("xe-bug-report").join("config"))
}

/// Parses the text of a configuration file; relative paths are taken from `base`. Returns the
/// locations and warnings for ignored lines, or the first error with its line number.
pub fn parse(text: &str, base: &Path) -> Result<(ToolLocations, Vec<String>), String> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Tools,
        Search,
        Unknown,
    }
    let mut section = Section::None;
    let mut locations = ToolLocations::default();
    let mut warnings = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let name = header
                .strip_suffix(']')
                .ok_or_else(|| format!("line {number}: a section header ends with ']'"))?
                .trim();
            section = match name {
                "tools" => Section::Tools,
                "search" => Section::Search,
                other => {
                    warnings.push(format!("line {number}: unknown section [{other}] is ignored"));
                    Section::Unknown
                }
            };
            continue;
        }
        let (key, value) =
            line.split_once('=').ok_or_else(|| format!("line {number}: expected 'name = value'"))?;
        let key = key.trim();
        let value = unquote(value.trim());
        if key.is_empty() {
            return Err(format!("line {number}: the name before '=' is empty"));
        }
        if value.is_empty() {
            return Err(format!("line {number}: '{key}' has no value"));
        }
        match section {
            Section::None => {
                return Err(format!("line {number}: '{key}' is outside a section; put it under [tools]"));
            }
            Section::Unknown => {}
            Section::Tools => {
                if key.contains(['/', '\\']) || key.chars().any(char::is_whitespace) {
                    return Err(format!("line {number}: '{key}' is not a tool name (a bare command name)"));
                }
                if locations.tools.iter().any(|(name, _)| name == key) {
                    return Err(format!("line {number}: '{key}' is set twice"));
                }
                locations.tools.push((key.to_owned(), base.join(value)));
            }
            Section::Search => {
                if key != "dir" {
                    return Err(format!("line {number}: [search] takes 'dir = <directory>', not '{key}'"));
                }
                locations.dirs.push(base.join(value));
            }
        }
    }
    Ok((locations, warnings))
}

/// `text` without one pair of matching surrounding quotes.
fn unquote(text: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = text.strip_prefix(quote).and_then(|rest| rest.strip_suffix(quote)) {
            return inner;
        }
    }
    text
}

/// The file's text, read with a time limit (the file may be on a hung mount).
fn read(path: &Path) -> Result<String, String> {
    let owned = path.to_path_buf();
    // One byte over the cap tells a file of exactly the cap from a larger one.
    let cap = Bytes(MAX_SIZE.get() + 1);
    let result = Guard::new(READ_LIMIT)
        .bounded("config", move || read_file_bounded(&owned, cap, Keep::Head))
        .ok_or_else(|| format!("{}: reading it did not finish in time", path.display()))?;
    match result.outcome {
        ReadOutcome::Read => {}
        ReadOutcome::Missing => return Err(format!("{}: no such file", path.display())),
        ReadOutcome::Denied => return Err(format!("{}: permission denied", path.display())),
        ReadOutcome::Failed => return Err(format!("{}: {}", path.display(), result.error)),
    }
    if result.truncated || result.data.len() as u64 > MAX_SIZE.get() {
        return Err(format!("{}: larger than {}", path.display(), MAX_SIZE.human()));
    }
    String::from_utf8(result.data).map_err(|_| format!("{}: not UTF-8 text", path.display()))
}

/// Refuses a file that users other than its owner may change, or that is owned by someone other
/// than the user running the tool, root, or (when running as root through sudo) the user who ran
/// sudo: the file decides which programs run, with this process's rights (as ssh does with its
/// configuration).
#[cfg(unix)]
fn check_trust(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        // Reported by the read with the OS's own words.
        return Ok(());
    };
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|uid| uid.parse().ok());
    trust_problem(meta.mode(), meta.uid(), crate::sys::unix::euid(), sudo_uid)
        .map_or(Ok(()), |problem| Err(format!("{}: {problem}", path.display())))
}

/// Why a file with `mode` and `owner` is not trusted by user `euid`, started by sudo for
/// `sudo_uid`; None when it is. `sudo_uid` counts only for root: only root can set it then.
#[cfg(unix)]
fn trust_problem(mode: u32, owner: u32, euid: u32, sudo_uid: Option<u32>) -> Option<&'static str> {
    if mode & 0o022 != 0 {
        return Some("other users may write to it, so it is not used (chmod go-w)");
    }
    let sudo_owner = euid == 0 && sudo_uid == Some(owner);
    if owner != euid && owner != 0 && !sudo_owner {
        return Some("it belongs to another user, so it is not used");
    }
    None
}

/// See the Unix version; Windows ACLs are not inspected.
#[cfg(not(unix))]
fn check_trust(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "config_tests.rs"]
mod tests;
