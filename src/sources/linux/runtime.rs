// SPDX-License-Identifier: MIT
//! The exact versions of the user-space GPU stack: `ocloc --version` and, for every GPU runtime
//! library the dynamic loader finds, the file its name finally resolves to.
//!
//! The package lists say what the package manager installed; this says what a process would load.
//! The two differ when a runtime was built from source, copied into `/usr/local` or `/opt`, or left
//! behind by an older package. The real file name carries the library version
//! (`libze_loader.so.1.32.0`); IGC records no version of its own in `libigc.so`, so its release
//! comes from the package lists.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bundle::source::Produced;
use crate::procio::{ChildOutcome, ChildResult, run_child};
use crate::units::Bytes;

use super::debugfs::collected;

/// File name prefixes of the GPU compute runtime libraries: the compiler (IGC and its front end),
/// the Level Zero driver, loader and validation layer, the memory manager and the OpenCL loader.
pub const RUNTIME_LIBRARIES: &[&str] = &[
    "libigc.so",
    "libigdfcl.so",
    "libiga64.so",
    "libopencl-clang",
    "libze_intel_gpu.so",
    "libze_loader.so",
    "libze_validation_layer.so",
    "libigdgmm.so",
    "libOpenCL.so",
];

/// Wall-clock limit of each child (`ocloc --version`, `ldconfig -p`).
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
/// Time the source gets: both children plus the time to start and stop them.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `ocloc --version` output kept.
const OCLOC_MAX: Bytes = Bytes::kib(16);
/// Largest `ldconfig -p` output read.
const LDCONFIG_MAX: Bytes = Bytes::mib(4);

/// Whether a library file name is one of [`RUNTIME_LIBRARIES`].
pub fn is_runtime_library(name: &str) -> bool {
    RUNTIME_LIBRARIES.iter().any(|prefix| name.starts_with(prefix))
}

/// One line of `ldconfig -p`: `\tlibze_loader.so.1 (libc6,x86-64) => /usr/lib/libze_loader.so.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// The library name the loader is asked for.
    pub name: String,
    /// The tags in parentheses (`libc6,x86-64`); empty when there are none.
    pub tags: String,
    /// The path the cache maps the name to.
    pub path: String,
}

/// The entries of an `ldconfig -p` listing; the header line and anything without ` => ` are
/// skipped.
pub fn parse_ldconfig(text: &str) -> Vec<CacheEntry> {
    text.lines()
        .filter_map(|line| {
            let (left, path) = line.split_once(" => ")?;
            let left = left.trim();
            let (name, tags) = match left.split_once(" (") {
                Some((name, rest)) => (name.trim(), rest.trim_end_matches(')').trim()),
                None => (left, ""),
            };
            let path = path.trim();
            (!name.is_empty() && !path.is_empty()).then(|| CacheEntry {
                name: name.to_owned(),
                tags: tags.to_owned(),
                path: path.to_owned(),
            })
        })
        .collect()
}

/// The `ocloc --version` part of the report: the output, or why there is none.
pub fn format_ocloc(result: &ChildResult) -> String {
    let output = String::from_utf8_lossy(&result.output);
    let output = output.trim();
    let mut text = match &result.outcome {
        ChildOutcome::NotFound => return "ocloc --version: ocloc not installed\n".to_owned(),
        ChildOutcome::SpawnFailed(error) => return format!("ocloc --version: could not start: {error}\n"),
        ChildOutcome::TimedOut => {
            format!("ocloc --version: did not finish within {} s\n", CHILD_TIMEOUT.as_secs())
        }
        ChildOutcome::Exited(0) => "ocloc --version:\n".to_owned(),
        ChildOutcome::Exited(code) => format!("ocloc --version: exit code {code}\n"),
    };
    for line in output.lines() {
        let _ = writeln!(text, "  {line}");
    }
    text
}

/// The library part of the report: one line per GPU runtime entry of the loader cache, with the
/// file `resolve` says the path ends at (`Err` holds why it could not be resolved).
pub fn format_libraries(
    ldconfig: &ChildResult,
    resolve: impl Fn(&Path) -> Result<PathBuf, String>,
) -> String {
    let mut text = String::from("\nGPU runtime libraries in the loader cache (ldconfig -p):\n");
    match &ldconfig.outcome {
        ChildOutcome::Exited(0) => {}
        ChildOutcome::NotFound => {
            text.push_str("  ldconfig not installed\n");
            return text;
        }
        ChildOutcome::SpawnFailed(error) => {
            let _ = writeln!(text, "  could not start ldconfig: {error}");
            return text;
        }
        ChildOutcome::TimedOut => {
            let _ = writeln!(text, "  ldconfig did not finish within {} s", CHILD_TIMEOUT.as_secs());
            return text;
        }
        ChildOutcome::Exited(code) => {
            let _ = writeln!(text, "  ldconfig -p: exit code {code}");
            return text;
        }
    }
    let entries: Vec<CacheEntry> = parse_ldconfig(&String::from_utf8_lossy(&ldconfig.output))
        .into_iter()
        .filter(|entry| is_runtime_library(&entry.name))
        .collect();
    if entries.is_empty() {
        text.push_str("  none\n");
    }
    for entry in entries {
        let target = match resolve(Path::new(&entry.path)) {
            Ok(real) if real == Path::new(&entry.path) => "(not a link)".to_owned(),
            Ok(real) => real.to_string_lossy().into_owned(),
            Err(error) => format!("(unresolved: {error})"),
        };
        let tags = if entry.tags.is_empty() { String::new() } else { format!(" ({})", entry.tags) };
        let _ = writeln!(text, "  {}{tags} => {} -> {target}", entry.name, entry.path);
    }
    if ldconfig.truncated {
        text.push_str("  (the cache listing was cut at its size cap)\n");
    }
    text
}

/// Runs `ocloc --version` and `ldconfig_argv` (the `ldconfig -p` of `system/ldconfig.txt`) and
/// writes both parts.
pub fn gpu_runtime(rel_path: &str, ldconfig_argv: &[String]) -> Vec<Produced> {
    let ocloc = run_child(&["ocloc".to_owned(), "--version".to_owned()], CHILD_TIMEOUT, OCLOC_MAX);
    let ldconfig = run_child(ldconfig_argv, CHILD_TIMEOUT, LDCONFIG_MAX);
    let mut text = format_ocloc(&ocloc);
    text.push_str(&format_libraries(&ldconfig, |path| {
        std::fs::canonicalize(path).map_err(|error| error.to_string())
    }));
    vec![collected(rel_path, text, format!("ocloc --version; {}", ldconfig_argv.join(" ")))]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "runtime_tests.rs"]
mod tests;
