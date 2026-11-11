// SPDX-License-Identifier: MIT
//! The user-mode graphics stack as configuration files describe it: which package repositories the
//! driver came from, which OpenCL, Vulkan and EGL drivers and layers the loaders will find, the
//! driver configuration overrides, and the shader and compiler caches.
//!
//! A repository line can carry credentials in its URL; such a line is withheld, never copied. The
//! other files hold library paths and driver names only. File contents are read through the
//! [`Reader`]; directory listings use `std::fs` on the collector's guarded thread.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::bundle::source::{Produced, Reader};
use crate::timefmt::utc_iso8601;
use crate::units::Bytes;

use super::debugfs::collected;
use super::probes::{list_names, read_text};
use super::text::trim;

/// Size cap of one repository or configuration file.
const FILE_MAX: Bytes = Bytes::kib(64);
/// Size cap of one driver or layer manifest.
const MANIFEST_MAX: Bytes = Bytes::kib(8);
/// Most files shown per directory.
const FILES_MAX: usize = 40;
/// Most entries named for a cache directory.
const CACHE_NAMES_MAX: usize = 10;
/// Longest manifest line kept, in bytes.
const MANIFEST_LINE_MAX: usize = 2000;

/// The note that replaces a repository line whose URL has credentials.
pub const WITHHELD: &str = "(line withheld: the URL has credentials)";

/// Words (lower case) in the part of a URL after the host that mean a secret travels in it.
const URL_SECRET_WORDS: &[&str] = &["token", "secret", "passw", "apikey", "auth="];
/// A path segment of at least this many letters and digits is taken for an access token
/// (package hosts that put the token in the path use 32 to 64 characters).
const TOKEN_SEGMENT_MIN: usize = 24;

/// Whether the part of a URL after the host looks like it carries a secret: a query string or
/// fragment, a word such as `token`, or a long run of letters and digits.
fn tail_has_secret(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    tail.contains(['?', '#'])
        || URL_SECRET_WORDS.iter().any(|w| lower.contains(w))
        || tail.split('/').any(|segment| {
            segment.len() >= TOKEN_SEGMENT_MIN
                && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Whether any URL in `text` carries a credential: a user name or password (`scheme://user[:pass]@host`),
/// or something after the host that looks like a token (see [`tail_has_secret`]).
pub fn has_credentials(text: &str) -> bool {
    text.match_indices("://").any(|(at, _)| {
        let rest = &text[at + 3..];
        let url = rest.split([' ', '\t', ']', ',', '"', '\'']).next().unwrap_or("");
        let authority = url.split(['/', '?', '#']).next().unwrap_or("");
        authority.contains('@') || tail_has_secret(&url[authority.len()..])
    })
}

/// A repository line as it may be shown: unchanged, or [`WITHHELD`] when its URL has credentials.
fn safe_line(line: &str) -> String {
    if has_credentials(line) { WITHHELD.to_owned() } else { line.to_owned() }
}

/// The relevant lines of an apt one-line-style file: the `deb` and `deb-src` lines.
pub fn apt_list_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(trim)
        .filter(|l| l.starts_with("deb ") || l.starts_with("deb-src ") || l.starts_with("deb\t"))
        .map(safe_line)
        .collect()
}

/// The keys of a deb822 source stanza worth keeping.
const DEB822_KEYS: &[&str] =
    &["Types", "URIs", "Suites", "Components", "Architectures", "Enabled", "Signed-By"];

/// The relevant lines of a deb822 `.sources` file. Continuation lines are dropped, so an inline
/// key block after `Signed-By:` is not copied; a `Signed-By` that is an inline key is reported as such.
pub fn deb822_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        if line.trim().is_empty() {
            if out.last().is_some_and(|l: &String| !l.is_empty()) {
                out.push(String::new());
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !DEB822_KEYS.contains(&key) {
            continue;
        }
        let value = trim(value);
        out.push(if key == "Signed-By" && (value.is_empty() || value.starts_with("-----BEGIN")) {
            "Signed-By: (inline key)".to_owned()
        } else {
            safe_line(&format!("{key}: {value}"))
        });
    }
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// The keys of an rpm `.repo` section worth keeping.
const REPO_KEYS: &[&str] =
    &["name", "baseurl", "mirrorlist", "metalink", "enabled", "gpgcheck", "repo_gpgcheck"];

/// The relevant lines of a yum or zypper `.repo` file: section names and the keys of [`REPO_KEYS`].
pub fn repo_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines().map(trim) {
        if line.starts_with('[') && line.ends_with(']') {
            out.push(line.to_owned());
        } else if let Some((key, value)) = line.split_once('=')
            && REPO_KEYS.contains(&trim(key))
        {
            out.push(safe_line(&format!("{}={}", trim(key), trim(value))));
        }
    }
    out
}

/// One repository file under a neutral name (`repo-3`: the file name can name a company), or
/// nothing when it has no relevant line.
fn repository_file(
    reader: &dyn Reader,
    path: &Path,
    lines: fn(&str) -> Vec<String>,
    index: &mut usize,
) -> String {
    let Some(content) = read_text(reader, path, FILE_MAX) else {
        return String::new();
    };
    let lines = lines(&content);
    if lines.is_empty() {
        return String::new();
    }
    *index += 1;
    format!("== repo-{} ==\n{}\n\n", *index, lines.join("\n"))
}

/// The package repositories the system installs from: apt (one-line and deb822 styles), yum and
/// zypper. Only the lines that name a repository are kept; any line with credentials in its URL is
/// withheld. Which repository a driver came from is what the report asks for, not how it is signed.
/// Files are numbered `repo-1`, `repo-2`, ... in the order read, not named.
pub fn repositories(reader: &dyn Reader, root: &Path, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    let mut index = 0;
    text.push_str(&repository_file(reader, &root.join("etc/apt/sources.list"), apt_list_lines, &mut index));
    for (dir, suffix, lines) in [
        ("etc/apt/sources.list.d", ".list", apt_list_lines as fn(&str) -> Vec<String>),
        ("etc/apt/sources.list.d", ".sources", deb822_lines),
        ("etc/yum.repos.d", ".repo", repo_lines),
        ("etc/zypp/repos.d", ".repo", repo_lines),
    ] {
        for name in list_names(&root.join(dir)).into_iter().filter(|n| n.ends_with(suffix)).take(FILES_MAX) {
            text.push_str(&repository_file(reader, &root.join(dir).join(name), lines, &mut index));
        }
    }
    if text.is_empty() {
        text.push_str("(no apt, yum or zypper repository files found)\n");
    }
    vec![collected(rel_path, text, "")]
}

/// A manifest on one line: whitespace collapsed, cut at [`MANIFEST_LINE_MAX`] bytes.
fn compact(content: &str) -> String {
    let mut line = content.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.len() > MANIFEST_LINE_MAX {
        let mut cut = MANIFEST_LINE_MAX;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
        line.push_str(" ...");
    }
    line
}

/// The OpenCL, Vulkan and EGL driver and layer manifests the loaders search, one line each, and the
/// loader configuration entries that mention Intel.
pub fn driver_manifests(reader: &dyn Reader, root: &Path, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    for (dir, suffix) in [
        ("etc/OpenCL/vendors", ".icd"),
        ("usr/share/vulkan/icd.d", ".json"),
        ("etc/vulkan/icd.d", ".json"),
        ("usr/local/share/vulkan/icd.d", ".json"),
        ("usr/share/vulkan/implicit_layer.d", ".json"),
        ("etc/vulkan/implicit_layer.d", ".json"),
        ("usr/share/vulkan/explicit_layer.d", ".json"),
        ("etc/vulkan/explicit_layer.d", ".json"),
        ("usr/share/glvnd/egl_vendor.d", ".json"),
        ("etc/glvnd/egl_vendor.d", ".json"),
    ] {
        let names: Vec<String> =
            list_names(&root.join(dir)).into_iter().filter(|n| n.ends_with(suffix)).collect();
        if names.is_empty() {
            continue;
        }
        let _ = writeln!(text, "[/{dir}]");
        for name in names.iter().take(FILES_MAX) {
            let content = read_text(reader, &root.join(dir).join(name), MANIFEST_MAX)
                .unwrap_or_else(|| "(unreadable)".to_owned());
            let _ = writeln!(text, "{name}: {}", compact(&content));
        }
        if names.len() > FILES_MAX {
            let _ = writeln!(text, "... {} more", names.len() - FILES_MAX);
        }
    }
    let conf_dir = root.join("etc/ld.so.conf.d");
    let mut conf = String::new();
    for name in list_names(&conf_dir).into_iter().filter(|n| n.ends_with(".conf")).take(FILES_MAX) {
        let Some(content) = read_text(reader, &conf_dir.join(&name), FILE_MAX) else {
            continue;
        };
        for line in content
            .lines()
            .map(trim)
            .filter(|l| !l.starts_with('#') && l.to_ascii_lowercase().contains("intel"))
        {
            let _ = writeln!(conf, "{name}: {line}");
        }
    }
    if !conf.is_empty() {
        text.push_str("[/etc/ld.so.conf.d entries that mention intel]\n");
        text.push_str(&conf);
    }
    if text.is_empty() {
        text.push_str("(no OpenCL, Vulkan or EGL manifests found)\n");
    }
    vec![collected(rel_path, text, "")]
}

/// The places configuration overrides and caches live, taken from the environment of the run.
#[derive(Debug, Clone, Default)]
pub struct UserDirs {
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// The current directory, where the compute runtime looks for `igdrcl.config`.
    pub cwd: Option<PathBuf>,
    /// `$XDG_CACHE_HOME`.
    pub xdg_cache: Option<PathBuf>,
    /// `$NEO_CACHE_DIR`.
    pub neo_cache: Option<PathBuf>,
    /// `$MESA_SHADER_CACHE_DIR`.
    pub mesa_cache: Option<PathBuf>,
}

impl UserDirs {
    /// The directories named by the environment and the current directory.
    pub fn from_environment() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        Self {
            home: var("HOME"),
            cwd: std::env::current_dir().ok(),
            xdg_cache: var("XDG_CACHE_HOME"),
            neo_cache: var("NEO_CACHE_DIR"),
            mesa_cache: var("MESA_SHADER_CACHE_DIR"),
        }
    }
}

/// `path` with the home directory written as `~`, so the report never carries the user name.
fn tilde(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// A cache directory in one block: whether it exists, how many entries it holds, when it was last
/// modified and the first few names with their sizes. Contents are never read.
fn cache_block(path: &Path, home: Option<&Path>) -> String {
    let shown = tilde(path, home);
    let Ok(meta) = fs::metadata(path) else {
        return format!("{shown}: (absent)\n");
    };
    let names = list_names(path);
    let modified = meta.modified().map_or_else(|_| "unknown".to_owned(), |t: SystemTime| utc_iso8601(t));
    let mut text = format!("{shown}: {} entries, modified {modified}\n", names.len());
    for name in names.iter().take(CACHE_NAMES_MAX) {
        let size = match fs::symlink_metadata(path.join(name)) {
            Ok(meta) if meta.is_dir() => "(directory)".to_owned(),
            Ok(meta) => format!("{} bytes", meta.len()),
            Err(_) => "?".to_owned(),
        };
        let _ = writeln!(text, "  {name} {size}");
    }
    text
}

/// Driver configuration overrides and cache state: `/etc/drirc` and `~/.drirc`, the stock driconf
/// files by name and size, `igdrcl.config` of the current directory, and the compiler and shader
/// caches. Stale caches and forgotten overrides cause bugs that vanish when cleared.
pub fn user_mode_config(reader: &dyn Reader, root: &Path, dirs: &UserDirs, rel_path: &str) -> Vec<Produced> {
    let home = dirs.home.as_deref();
    let mut text = String::new();
    // Only regular files are read: a FIFO would block the read and a link could point at a private
    // file (a key) that then ends up in the bundle.
    let mut file = |label: String, path: PathBuf| match fs::symlink_metadata(&path) {
        Err(_) => _ = writeln!(text, "== {label} == (absent)\n"),
        Ok(meta) if !meta.file_type().is_file() => {
            let _ = writeln!(text, "== {label} == (not a regular file)\n");
        }
        Ok(_) => match read_text(reader, &path, FILE_MAX) {
            Some(content) => _ = writeln!(text, "== {label} ==\n{}\n", content.trim_end()),
            None => _ = writeln!(text, "== {label} == (unreadable)\n"),
        },
    };
    file("/etc/drirc".to_owned(), root.join("etc/drirc"));
    if let Some(home) = home {
        file("~/.drirc".to_owned(), home.join(".drirc"));
    }
    if let Some(cwd) = &dirs.cwd {
        file("igdrcl.config in the current directory".to_owned(), cwd.join("igdrcl.config"));
    }
    text.push_str("== stock driconf files ==\n");
    let stock = root.join("usr/share/drirc.d");
    let confs: Vec<String> = list_names(&stock).into_iter().filter(|n| n.ends_with(".conf")).collect();
    if confs.is_empty() {
        text.push_str("(none)\n");
    }
    for name in confs.iter().take(FILES_MAX) {
        let size = fs::metadata(stock.join(name)).map_or_else(|_| "?".to_owned(), |m| m.len().to_string());
        let _ = writeln!(text, "{name} {size}");
    }
    text.push_str("\n== caches ==\n");
    let mut caches: Vec<PathBuf> = Vec::new();
    if let Some(home) = home {
        caches.push(home.join(".cache/neo_compiler_cache"));
        caches.push(home.join(".cache/mesa_shader_cache"));
    }
    if let Some(xdg) = &dirs.xdg_cache {
        caches.push(xdg.join("neo_compiler_cache"));
        caches.push(xdg.join("mesa_shader_cache"));
    }
    caches.extend(dirs.neo_cache.clone());
    caches.extend(dirs.mesa_cache.clone());
    let mut seen: Vec<PathBuf> = Vec::new();
    for cache in caches {
        if seen.contains(&cache) {
            continue;
        }
        text.push_str(&cache_block(&cache, home));
        seen.push(cache);
    }
    if seen.is_empty() {
        text.push_str("(no cache location known: HOME is not set)\n");
    }
    vec![collected(rel_path, text, "")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "usermode_tests.rs"]
mod tests;
