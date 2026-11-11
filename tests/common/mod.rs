// SPDX-License-Identifier: MIT
//! Shared helpers for the integration tests: an independent zip central-directory reader, a temp
//! directory, and a runner for the built binary.
//!
//! The zip reader deliberately shares no code with `src/archive`: it starts at the end-of-central-
//! directory record, the way `unzip` does, so a writer bug cannot hide behind a matching reader bug.
//! The helpers are used by two test crates that each use a different subset, hence `dead_code`.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The built binary.
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xe-bug-report"))
}

/// A fresh private temporary directory, removed when dropped.
pub fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("xe-bug-report-test-").tempdir().expect("create a temp dir")
}

/// What one run of the binary produced.
#[derive(Debug)]
pub struct Run {
    /// The exit code (-1 when the process was killed by a signal).
    pub code: i32,
    /// Standard output, decoded lossily.
    pub stdout: String,
    /// Standard error, decoded lossily.
    pub stderr: String,
}

/// Builds and runs one invocation of the binary.
#[derive(Debug, Default)]
pub struct Invocation {
    args: Vec<OsString>,
    env: Vec<(OsString, Option<OsString>)>,
}

impl Invocation {
    /// An invocation with no arguments.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Sets an environment variable for the child.
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env.push((key.as_ref().to_os_string(), Some(value.as_ref().to_os_string())));
        self
    }

    /// Removes an environment variable from the child's environment.
    pub fn env_remove(mut self, key: impl AsRef<OsStr>) -> Self {
        self.env.push((key.as_ref().to_os_string(), None));
        self
    }

    /// Runs the binary to completion with stdin closed.
    pub fn run(self) -> Run {
        let mut command = Command::new(binary());
        command.args(&self.args).stdin(Stdio::null());
        for (key, value) in &self.env {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        let output = command.output().expect("run the xe-bug-report binary");
        Run {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// Runs the binary with `args`.
pub fn run<I, S>(args: I) -> Run
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Invocation::new().args(args).run()
}

/// Whether `program` is found on the current PATH.
pub fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        let plain = dir.join(program);
        plain.is_file() || dir.join(format!("{program}.exe")).is_file()
    })
}

// ---- zip central-directory reader ----

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_MIN_LEN: usize = 22;
const MAX_COMMENT: usize = 65_535;

/// One central-directory entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw name bytes.
    pub name_bytes: Vec<u8>,
    /// The name, decoded lossily.
    pub name: String,
    /// Compression method: 0 stored, 8 deflate.
    pub method: u16,
    /// General purpose flags.
    pub flags: u16,
    /// DOS time field.
    pub dos_time: u16,
    /// DOS date field.
    pub dos_date: u16,
    /// CRC-32 of the uncompressed data, as recorded.
    pub crc: u32,
    /// Compressed size, as recorded.
    pub compressed_size: u32,
    /// Uncompressed size, as recorded.
    pub size: u32,
    /// Offset of the local header.
    pub local_offset: u32,
}

/// A parsed zip archive held in memory.
#[derive(Debug)]
pub struct Zip {
    bytes: Vec<u8>,
    /// The entries in central-directory order.
    pub entries: Vec<Entry>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    let s = b.get(at..at + 2).ok_or_else(|| format!("truncated at {at}"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    let s = b.get(at..at + 4).ok_or_else(|| format!("truncated at {at}"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl Zip {
    /// Reads and parses the archive at `path`; the error says what is wrong with it.
    pub fn open(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(bytes)
    }

    /// Parses `bytes`: end record, central directory, and each entry's local header.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < EOCD_MIN_LEN {
            return Err("too short for a zip archive".into());
        }
        // The end record is the last 22 bytes plus a comment of up to 65535 bytes.
        let lowest = bytes.len().saturating_sub(EOCD_MIN_LEN + MAX_COMMENT);
        let eocd = (lowest..=bytes.len() - EOCD_MIN_LEN)
            .rev()
            .find(|&at| u32_at(&bytes, at) == Ok(EOCD_SIGNATURE))
            .ok_or("no end-of-central-directory record")?;
        let disk = u16_at(&bytes, eocd + 4)?;
        let cd_disk = u16_at(&bytes, eocd + 6)?;
        let on_disk = u16_at(&bytes, eocd + 8)?;
        let total = u16_at(&bytes, eocd + 10)?;
        let cd_size = u32_at(&bytes, eocd + 12)? as usize;
        let cd_offset = u32_at(&bytes, eocd + 16)? as usize;
        let comment_len = u16_at(&bytes, eocd + 20)? as usize;
        if disk != 0 || cd_disk != 0 || on_disk != total {
            return Err("multi-disk archives are not supported".into());
        }
        if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
            return Err("zip64 markers in the end record".into());
        }
        if eocd + EOCD_MIN_LEN + comment_len != bytes.len() {
            return Err("bytes after the end record's comment".into());
        }
        if cd_offset.checked_add(cd_size) != Some(eocd) {
            return Err(format!(
                "central directory [{cd_offset}+{cd_size}] does not end at the end record {eocd}"
            ));
        }

        let mut entries = Vec::with_capacity(usize::from(total));
        let mut at = cd_offset;
        for index in 0..total {
            if u32_at(&bytes, at)? != CENTRAL_SIGNATURE {
                return Err(format!("entry {index}: bad central header signature at {at}"));
            }
            let name_len = usize::from(u16_at(&bytes, at + 28)?);
            let extra_len = usize::from(u16_at(&bytes, at + 30)?);
            let comment_len = usize::from(u16_at(&bytes, at + 32)?);
            let name_bytes = bytes
                .get(at + 46..at + 46 + name_len)
                .ok_or_else(|| format!("entry {index}: name runs past the file"))?
                .to_vec();
            let entry = Entry {
                name: String::from_utf8_lossy(&name_bytes).into_owned(),
                name_bytes,
                flags: u16_at(&bytes, at + 8)?,
                method: u16_at(&bytes, at + 10)?,
                dos_time: u16_at(&bytes, at + 12)?,
                dos_date: u16_at(&bytes, at + 14)?,
                crc: u32_at(&bytes, at + 16)?,
                compressed_size: u32_at(&bytes, at + 20)?,
                size: u32_at(&bytes, at + 24)?,
                local_offset: u32_at(&bytes, at + 42)?,
            };
            if entry.compressed_size == 0xFFFF_FFFF || entry.size == 0xFFFF_FFFF {
                return Err(format!("entry {}: zip64 sizes are not supported", entry.name));
            }
            at += 46 + name_len + extra_len + comment_len;
            entries.push(entry);
        }
        if at != eocd {
            return Err(format!("central directory ends at {at}, the end record is at {eocd}"));
        }
        let zip = Self { bytes, entries };
        for entry in &zip.entries {
            zip.data_range(entry)?;
        }
        Ok(zip)
    }

    /// The entry names, in order.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// The entry called `name`.
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// The byte range of an entry's stored data, after checking its local header against the
    /// central record.
    fn data_range(&self, entry: &Entry) -> Result<std::ops::Range<usize>, String> {
        let at = entry.local_offset as usize;
        if u32_at(&self.bytes, at)? != LOCAL_SIGNATURE {
            return Err(format!("{}: bad local header signature", entry.name));
        }
        if u16_at(&self.bytes, at + 8)? != entry.method {
            return Err(format!("{}: local and central methods differ", entry.name));
        }
        let name_len = usize::from(u16_at(&self.bytes, at + 26)?);
        let extra_len = usize::from(u16_at(&self.bytes, at + 28)?);
        let local_name =
            self.bytes.get(at + 30..at + 30 + name_len).ok_or("local name runs past the file")?;
        if local_name != entry.name_bytes.as_slice() {
            return Err(format!("{}: local header names a different entry", entry.name));
        }
        let start = at + 30 + name_len + extra_len;
        let end = start + entry.compressed_size as usize;
        if end > self.bytes.len() {
            return Err(format!("{}: data runs past the file", entry.name));
        }
        Ok(start..end)
    }

    /// The uncompressed contents of `entry`, with the size and the CRC-32 checked against the
    /// central directory.
    pub fn read(&self, entry: &Entry) -> Result<Vec<u8>, String> {
        let raw = &self.bytes[self.data_range(entry)?];
        let data = match entry.method {
            0 => raw.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(entry.size as usize);
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("{}: inflate failed: {e}", entry.name))?;
                out
            }
            other => return Err(format!("{}: unsupported method {other}", entry.name)),
        };
        if data.len() != entry.size as usize {
            return Err(format!("{}: size {} but the directory says {}", entry.name, data.len(), entry.size));
        }
        let crc = crc32fast::hash(&data);
        if crc != entry.crc {
            return Err(format!("{}: crc {crc:08x} but the directory says {:08x}", entry.name, entry.crc));
        }
        Ok(data)
    }

    /// The contents of the entry called `name`.
    pub fn read_named(&self, name: &str) -> Result<Vec<u8>, String> {
        let entry = self.find(name).ok_or_else(|| format!("no entry {name}"))?;
        self.read(entry)
    }

    /// Reads every entry, which checks every size and CRC.
    pub fn read_all(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.entries.iter().map(|e| Ok((e.name.clone(), self.read(e)?))).collect()
    }

    /// The manifest, parsed.
    pub fn manifest(&self) -> Result<serde_json::Value, String> {
        let data = self.read_named("manifest.json")?;
        serde_json::from_slice(&data).map_err(|e| format!("manifest.json is not valid JSON: {e}"))
    }
}

/// Checks an entry name against the bundle layout rule: UTF-8, `/` separators,
/// no leading `/`, no empty, `.` or `..` segment, no `\`, no byte below 0x20.
pub fn check_entry_name(raw: &[u8]) -> Result<(), String> {
    let name = std::str::from_utf8(raw).map_err(|_| format!("{raw:?}: not UTF-8"))?;
    if name.is_empty() {
        return Err("empty name".into());
    }
    if let Some(byte) = raw.iter().find(|&&b| b < 0x20) {
        return Err(format!("{name:?}: control byte {byte:#04x}"));
    }
    if name.contains('\\') {
        return Err(format!("{name:?}: backslash"));
    }
    if name.starts_with('/') {
        return Err(format!("{name:?}: leading slash"));
    }
    if name.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..") {
        return Err(format!("{name:?}: empty, . or .. segment"));
    }
    Ok(())
}

/// Every problem found in an archive written by the tool: names, duplicates, methods, the
/// manifest being last, and every entry inflating with a matching size and CRC. Empty when fine.
pub fn check_archive(zip: &Zip) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in &zip.entries {
        if let Err(e) = check_entry_name(&entry.name_bytes) {
            problems.push(e);
        }
        if !seen.insert(entry.name.clone()) {
            problems.push(format!("{}: duplicate entry", entry.name));
        }
        if !matches!(entry.method, 0 | 8) {
            problems.push(format!("{}: method {}", entry.name, entry.method));
        }
        if let Err(e) = zip.read(entry) {
            problems.push(e);
        }
    }
    match zip.entries.last() {
        Some(last) if last.name == "manifest.json" => {}
        Some(last) => problems.push(format!("the last entry is {}, not manifest.json", last.name)),
        None => problems.push("no entries".into()),
    }
    if zip.entries.iter().filter(|e| e.name == "manifest.json").count() != 1 {
        problems.push("manifest.json must appear exactly once".into());
    }
    problems
}

/// The tool's golden manifest key list (`tests/golden/manifest-keys.txt`): per scope, the keys in
/// emission order and whether each is optional.
pub fn golden_manifest_keys() -> Vec<(String, Vec<(String, bool)>)> {
    let text = include_str!("../golden/manifest-keys.txt");
    let mut scopes: Vec<(String, Vec<(String, bool)>)> = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let (Some(scope), Some(key)) = (parts.next(), parts.next()) else { continue };
        let (key, optional) = match key.strip_suffix('?') {
            Some(k) => (k, true),
            None => (key, false),
        };
        match scopes.iter_mut().find(|(s, _)| s == scope) {
            Some((_, keys)) => keys.push((key.to_owned(), optional)),
            None => scopes.push((scope.to_owned(), vec![(key.to_owned(), optional)])),
        }
    }
    scopes
}

/// Checks one object's keys against a golden scope: no unknown key, every required key present,
/// and the keys present in the golden order.
pub fn check_keys(object: &serde_json::Map<String, serde_json::Value>, scope: &str) -> Result<(), String> {
    let golden = golden_manifest_keys();
    let (_, keys) = golden.iter().find(|(s, _)| s == scope).ok_or(format!("no golden scope {scope}"))?;
    let mut last = None;
    for key in object.keys() {
        let position =
            keys.iter().position(|(k, _)| k == key).ok_or(format!("{scope}: unexpected key {key:?}"))?;
        if last.is_some_and(|l| position <= l) {
            return Err(format!("{scope}: key {key:?} is out of order"));
        }
        last = Some(position);
    }
    for (key, optional) in keys {
        if !optional && !object.contains_key(key) {
            return Err(format!("{scope}: required key {key:?} is missing"));
        }
    }
    Ok(())
}

/// Checks a whole manifest against the golden key list, the status and gate vocabularies and the
/// value types.
pub fn check_manifest(manifest: &serde_json::Value) -> Result<(), String> {
    let top = manifest.as_object().ok_or("the manifest is not an object")?;
    check_keys(top, "top")?;
    if top["schema"] != 1 {
        return Err(format!("schema is {}", top["schema"]));
    }
    check_keys(top["tool"].as_object().ok_or("tool is not an object")?, "tool")?;
    if let Some(xpu_smi) = top.get("xpu_smi") {
        check_keys(xpu_smi.as_object().ok_or("xpu_smi is not an object")?, "xpu_smi")?;
    }
    if !matches!(top["compression"].as_str(), Some("stored" | "deflate")) {
        return Err(format!("compression is {}", top["compression"]));
    }
    if !matches!(top["profile"].as_str(), Some("minimal" | "default" | "full")) {
        return Err(format!("profile is {}", top["profile"]));
    }
    if !top["redaction"].is_array() || top.get("devices").is_some_and(|d| !d.is_array()) {
        return Err("redaction and devices must be arrays".into());
    }
    let sources = top["sources"].as_array().ok_or("sources is not an array")?;
    let mut paths = BTreeSet::new();
    for source in sources {
        let object = source.as_object().ok_or("a source is not an object")?;
        check_keys(object, "source")?;
        let path = object["path"].as_str().ok_or("source path is not a string")?;
        if !paths.insert(path.to_owned()) {
            return Err(format!("{path}: listed twice"));
        }
        if !matches!(
            object["status"].as_str(),
            Some("collected" | "truncated" | "skipped" | "timed_out" | "failed")
        ) {
            return Err(format!("{path}: status {}", object["status"]));
        }
        if let Some(gate) = object.get("gate")
            && !matches!(
                gate.as_str(),
                Some("kernel_log" | "device_access" | "root" | "sys_admin" | "elevated")
            )
        {
            return Err(format!("{path}: gate {gate}"));
        }
        if !object["ms"].is_u64() {
            return Err(format!("{path}: ms is not an unsigned integer"));
        }
        for key in ["bytes", "files", "denied", "exit"] {
            if let Some(value) = object.get(key)
                && !(value.is_u64() || (key == "exit" && value.is_i64()))
            {
                return Err(format!("{path}: {key} is not an integer"));
            }
        }
    }
    Ok(())
}

/// Whether `haystack` holds `needle` as a whole token, ignoring ASCII case, with the redactor's
/// notion of a token (letters, digits, `_` and `-` continue a name).
pub fn contains_name(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes().to_ascii_lowercase();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let token = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let lowered = haystack.to_ascii_lowercase();
    lowered.windows(needle.len()).enumerate().any(|(at, window)| {
        window == needle.as_slice()
            && (at == 0 || !token(lowered[at - 1]))
            && lowered.get(at + needle.len()).is_none_or(|&b| !token(b))
    })
}

// ---- the `--list` table ----

/// One row of the `--list` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    /// `minimal`, `default` or `full`.
    pub profile: String,
    /// A gate name, or `-`.
    pub needs: String,
    /// The path column.
    pub path: String,
    /// The reason column.
    pub why: String,
}

/// Parses a table laid out like `--list` prints it (header `PROFILE  NEEDS  PATH  WHY`, columns
/// padded), by the column offsets of its own header. The header row is not returned.
pub fn parse_table(text: &str) -> Result<Vec<ListRow>, String> {
    let mut lines = text.lines();
    let header = lines.next().ok_or("empty table")?;
    let column = |name: &str| header.find(name).ok_or(format!("no {name} column in {header:?}"));
    let (needs_at, path_at, why_at) = (column("NEEDS")?, column("PATH")?, column("WHY")?);
    if !header.starts_with("PROFILE") {
        return Err(format!("unexpected header {header:?}"));
    }
    let mut rows = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        if line.len() < why_at || !line.is_ascii() {
            return Err(format!("short or non-ASCII row {line:?}"));
        }
        rows.push(ListRow {
            profile: line[..needs_at].trim().to_owned(),
            needs: line[needs_at..path_at].trim().to_owned(),
            path: line[path_at..why_at].trim().to_owned(),
            why: line[why_at..].trim().to_owned(),
        });
    }
    Ok(rows)
}

/// A path with each PCI directory name (`dddd-bb-dd.f`) replaced by `<dev>`, so a row of this
/// host's table compares with the golden row that names it generically.
pub fn generic_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let is_bdf_at = |at: usize| {
        let Some(rest) = bytes.get(at..at + 12) else { return false };
        rest[..4].iter().all(u8::is_ascii_hexdigit)
            && rest[4] == b'-'
            && rest[5..7].iter().all(u8::is_ascii_hexdigit)
            && rest[7] == b'-'
            && rest[8..10].iter().all(u8::is_ascii_hexdigit)
            && rest[10] == b'.'
            && (b'0'..=b'7').contains(&rest[11])
            && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric())
    };
    let mut out = String::new();
    let mut at = 0;
    while at < path.len() {
        if is_bdf_at(at) {
            out.push_str("<dev>");
            at += 12;
        } else {
            let ch = path[at..].chars().next().unwrap_or('?');
            out.push(ch);
            at += ch.len_utf8();
        }
    }
    out
}
