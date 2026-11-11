// SPDX-License-Identifier: MIT
//! Pure text helpers of the Linux sources: parsing and formatting that never touches the machine,
//! so every function here is unit tested with literals.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use crate::bundle::source::{ReadOutcome, ReadResult};
use crate::pci::PciAddress;
use crate::sources::debug_keys::is_debug_key;

/// Environment variable prefixes recorded in `system/env.txt`: the runtime, compiler, media,
/// graphics-loader and driver debug variables. Generic prefixes (`CL_`, `MDA_`, `INTEL_`) are not
/// here: they match licence, account and cache settings that have nothing to do with the GPU.
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
    "MESA_",
    "ANV_",
    "HASVK_",
    "VK_",
    "DRI_PRIME",
    "DRIRC_",
    "LIBGL_",
    "EGL_",
    "GALLIUM_",
    "GBM_",
    "__GLX_",
    "MFX_",
    "VPL_",
    "ONEVPL_",
    "OPENCL_",
];
/// Environment variables recorded by exact name. `NEOReadDebugKeys` does not start with `NEO_`.
/// The `INTEL_` names are the ones the Mesa Intel drivers read.
const ENV_EXACT: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LANG",
    "LC_ALL",
    "container",
    "NEOReadDebugKeys",
    "vblank_mode",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "INTEL_DEBUG",
    "INTEL_MEASURE",
    "INTEL_NO_HW",
    "INTEL_PRECISE_TRIG",
    "INTEL_BLACKHOLE_DEFAULT",
    "INTEL_COMPUTE_CLASS",
];
/// Words (lower case) in a variable name that mean it holds a credential, an account, a licence or
/// a network location. A variable whose name has one is never recorded, whatever its prefix.
const ENV_SECRET_WORDS: &[&str] = &[
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
    "auth",
    "cookie",
    "apikey",
    "privatekey",
    "accesskey",
    "key",
    "license",
    "licence",
    "user",
    "login",
    "proxy",
    "url",
    "host",
    "server",
];
/// The directories a path-valued variable may point into and still be recorded as written. Others
/// are likely to name a user, a project or a company, and are replaced by `<path>`.
const ENV_PATH_ROOTS: &[&str] = &["/usr", "/opt/intel", "/etc", "/lib", "/run", "/home/", "~"];
/// Name endings (upper case) of variables that hold file system paths.
const ENV_PATH_SUFFIXES: &[&str] =
    &["DIR", "DIRECTORY", "PATH", "FILE", "FILES", "FILENAME", "FILENAMES", "PRELOAD"];
/// Recorded values are cut at this many characters.
const ENV_VALUE_MAX_CHARS: usize = 512;

/// Whether a variable holds file system paths, by its name.
fn is_path_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ENV_PATH_SUFFIXES.iter().any(|suffix| upper.ends_with(suffix))
}

/// A path-valued variable's value as it may be recorded: unchanged when every entry starts in one
/// of the [`ENV_PATH_ROOTS`] (entries are separated by `:` or blanks), else `<path>`.
pub fn safe_path_value(value: &str) -> String {
    let ok = value
        .split([':', ' '])
        .filter(|entry| !entry.is_empty())
        .all(|entry| ENV_PATH_ROOTS.iter().any(|root| entry.starts_with(root)));
    if ok { value.to_owned() } else { "<path>".to_owned() }
}

/// Whether a variable name is one the report may record: not a credential, account, licence or
/// network location by its name.
fn name_is_harmless(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !ENV_SECRET_WORDS.iter().any(|w| lower.contains(w))
}

/// The most lines `journalctl` is asked for.
pub const JOURNAL_MAX_LINES: u32 = 200_000;

/// Removes leading and trailing blanks (space, tab, CR, LF).
pub fn trim(text: &str) -> &str {
    text.trim_matches([' ', '\t', '\r', '\n'])
}

/// Parses all of `text` as an unsigned number in `radix`; no sign, prefix or blanks.
pub fn parse_unsigned(text: &str, radix: u32) -> Option<u64> {
    if text.is_empty() || !text.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(text, radix).ok()
}

/// Parses a sysfs hexadecimal attribute such as `0x8086\n`.
pub fn parse_hex_attribute(text: &str) -> Option<u64> {
    let text = trim(text);
    let text = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    parse_unsigned(text, 16)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes the `\xNN` escapes the kernel uses for unprintable bytes in `/dev/kmsg` messages;
/// invalid escapes are kept as written.
fn decode_kmsg_escapes(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len());
    let mut i = 0;
    while i < message.len() {
        if message[i] == b'\\'
            && i + 3 < message.len()
            && message[i + 1] == b'x'
            && let (Some(hi), Some(lo)) = (hex_digit(message[i + 2]), hex_digit(message[i + 3]))
        {
            out.push(hi * 16 + lo);
            i += 4;
            continue;
        }
        out.push(message[i]);
        i += 1;
    }
    out
}

/// The parts of a `/dev/kmsg` record the log needs.
struct KmsgRecord<'a> {
    usec: u64,
    message: &'a [u8],
}

/// Splits a record `pri,seq,usec,flags[,...];message` followed by optional continuation lines.
fn parse_kmsg_record(record: &[u8]) -> Option<KmsgRecord<'_>> {
    let line_end = record.iter().position(|&b| b == b'\n').unwrap_or(record.len());
    let line = &record[..line_end];
    let semicolon = line.iter().position(|&b| b == b';')?;
    let prefix = &line[..semicolon];
    let mut fields = prefix.split(|&b| b == b',');
    let _priority = fields.next()?;
    let _sequence = fields.next()?;
    let usec = std::str::from_utf8(fields.next()?).ok()?;
    let usec = parse_unsigned(usec, 10)?;
    Some(KmsgRecord { usec, message: &line[semicolon + 1..] })
}

/// Formats one `/dev/kmsg` record as `[%5u.%06u] message`, without a trailing newline. Continuation
/// lines (key=value metadata) are dropped and `\xNN` escapes decoded. None when malformed.
pub fn format_kmsg_record(record: &[u8]) -> Option<String> {
    let parsed = parse_kmsg_record(record)?;
    let message = decode_kmsg_escapes(parsed.message);
    Some(format!(
        "[{:5}.{:06}] {}",
        parsed.usec / 1_000_000,
        parsed.usec % 1_000_000,
        String::from_utf8_lossy(&message)
    ))
}

/// The time since boot a `/dev/kmsg` record is stamped with; None when malformed.
pub fn kmsg_timestamp(record: &[u8]) -> Option<Duration> {
    parse_kmsg_record(record).map(|r| Duration::from_micros(r.usec))
}

/// The `journalctl` arguments that print the kernel log.
///
/// Without a window the log is that of one boot (`-k -b N`), limited to the last
/// [`JOURNAL_MAX_LINES`] lines. With a window it is the last `since` from any boot: `-k` implies
/// `-b`, so the kernel messages are selected with the match `_TRANSPORT=kernel` instead.
/// `previous_boot` is ignored when `since` is set. A window passes no `-n`: with `-n`, journalctl
/// walks back through the whole journal (17 s for `--since=-5min` on a month-old journal, 0.05 s
/// without it); the output cap of the caller bounds a long window instead.
pub fn journal_argv(since: Option<Duration>, previous_boot: bool) -> Vec<String> {
    let mut argv = vec!["journalctl".to_owned()];
    if let Some(since) = since {
        argv.push("_TRANSPORT=kernel".to_owned());
        argv.push(format!("--since=-{}min", window_minutes(since)));
    } else {
        argv.extend(["-k", "-b", if previous_boot { "-1" } else { "0" }].map(str::to_owned));
        argv.extend(["-n".to_owned(), JOURNAL_MAX_LINES.to_string()]);
    }
    argv.extend(["--no-pager", "-q", "-o", "short-monotonic"].map(str::to_owned));
    argv
}

/// A window in whole minutes, at least one.
pub fn window_minutes(window: Duration) -> u64 {
    window.as_secs().div_ceil(60).max(1)
}

/// A window in words: the largest whole unit, e.g. "1 day", "36 hours" or "90 minutes".
pub fn describe_window(window: Duration) -> String {
    let count = window_minutes(window);
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if count.is_multiple_of(24 * 60) {
        plural(count / (24 * 60), "day")
    } else if count.is_multiple_of(60) {
        plural(count / 60, "hour")
    } else {
        plural(count, "minute")
    }
}

/// The PRETTY_NAME value of an os-release file, unquoted; the last non-empty one wins.
pub fn parse_pretty_name(os_release: &str) -> Option<String> {
    const KEY: &str = "PRETTY_NAME=";
    let mut found = None;
    for line in os_release.split('\n') {
        let Some(value) = trim(line).strip_prefix(KEY) else {
            continue;
        };
        let bytes = value.as_bytes();
        let value = if bytes.len() >= 2
            && (bytes[0] == b'"' || bytes[0] == b'\'')
            && bytes[bytes.len() - 1] == bytes[0]
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if !value.is_empty() {
            found = Some(value.to_owned());
        }
    }
    found
}

/// `<pretty name>, <sysname> <release> <machine>`; the pretty name defaults to the sysname.
pub fn format_os_description(pretty_name: &str, sysname: &str, release: &str, machine: &str) -> String {
    let name = if pretty_name.is_empty() { sysname } else { pretty_name };
    format!("{name}, {sysname} {release} {machine}")
}

/// Whether sysfs `vendor` and `class` contents describe an Intel display or accelerator device.
pub fn is_intel_gpu_class(vendor: &str, pci_class: &str) -> bool {
    const INTEL: u64 = 0x8086;
    let (Some(vendor), Some(class)) = (parse_hex_attribute(vendor), parse_hex_attribute(pci_class)) else {
        return false;
    };
    let base = (class >> 16) & 0xff;
    vendor == INTEL && class <= 0xff_ffff && (base == 0x03 || base == 0x12)
}

/// The PCI bridges between the root complex and a device, nearest first: every address path
/// component before the last one.
pub fn upstream_bridges(os_path: &str) -> Vec<PciAddress> {
    let mut bdfs: Vec<PciAddress> = os_path.split('/').filter_map(PciAddress::parse).collect();
    bdfs.pop();
    bdfs.reverse();
    bdfs
}

/// The environment variables worth recording, as sorted `KEY=value` lines. When `NEOReadDebugKeys`
/// is set to something other than empty or 0, the variables named like compute runtime debug keys
/// (see [`crate::sources::debug_keys`]) are recorded too. Names that look like credentials,
/// accounts, licences or network locations are dropped even when a prefix matches, path values
/// outside the system directories are replaced by `<path>`, and each value is cut at 512 characters.
pub fn filter_environment(environment: &[String]) -> String {
    let debug_keys = environment.iter().any(|entry| {
        entry
            .split_once('=')
            .is_some_and(|(key, value)| key == "NEOReadDebugKeys" && !value.is_empty() && value != "0")
    });
    let kept: BTreeSet<String> = environment
        .iter()
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            let wanted = ENV_EXACT.contains(&key)
                || (ENV_PREFIXES.iter().any(|p| key.starts_with(p)) && name_is_harmless(key))
                || (debug_keys && is_debug_key(key));
            if !wanted {
                return None;
            }
            let value: String = value.chars().take(ENV_VALUE_MAX_CHARS).collect();
            let value = if is_path_variable(key) { safe_path_value(&value) } else { value };
            Some(format!("{key}={value}"))
        })
        .collect();
    kept.into_iter().fold(String::new(), |mut text, entry| {
        text.push_str(&entry);
        text.push('\n');
        text
    })
}

/// `name: value` for a small attribute file; the value is `(absent)`, `(denied)` or `(error: ...)`
/// when it could not be read, and `(empty)` when it is blank.
pub fn format_probe_line(name: &str, result: &ReadResult) -> String {
    let value = match result.outcome {
        ReadOutcome::Read => {
            let text = String::from_utf8_lossy(&result.data);
            let value = trim(&text);
            if value.is_empty() { "(empty)".to_owned() } else { value.to_owned() }
        }
        ReadOutcome::Denied => "(denied)".to_owned(),
        ReadOutcome::Missing => "(absent)".to_owned(),
        ReadOutcome::Failed => format!("(error: {})", result.error),
    };
    format!("{name}: {value}")
}

/// The last path component of a symlink target, ignoring trailing slashes.
pub fn link_target_name(target: &str) -> String {
    let mut target = target;
    while target.len() > 1 && target.ends_with('/') {
        target = &target[..target.len() - 1];
    }
    match target.rfind('/') {
        Some(slash) => target[slash + 1..].to_owned(),
        None => target.to_owned(),
    }
}

/// The value of a `Name:\tvalue` line of `/proc/self/status`, trimmed.
pub fn status_field(status: &str, name: &str) -> Option<String> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?.strip_prefix(':')?;
        Some(trim(rest).to_owned())
    })
}

/// One line of the `/dev/dri` listing: `<path> <mode octal> <user>:<group> <major>:<minor>[ -> <target>]`.
pub fn format_dev_line(
    path: &str,
    mode: u32,
    user: &str,
    group: &str,
    device: Option<(u32, u32)>,
    target: &str,
) -> String {
    let mut line = format!("{path} {mode:o} {user}:{group}");
    if let Some((major, minor)) = device {
        let _ = write!(line, " {major}:{minor}");
    }
    if !target.is_empty() {
        line.push_str(" -> ");
        line.push_str(target);
    }
    line
}

/// Host and domain name spellings to redact, without any resolver lookup: the host name, its part
/// before the first '.', then the other two; trimmed, with no empty, `(none)` or repeated entry.
pub fn host_name_variants(host_name: &str, proc_hostname: &str, proc_domainname: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        let name = trim(name);
        if !name.is_empty() && name != "(none)" && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    };
    let host_name = trim(host_name);
    add(host_name);
    add(host_name.split('.').next().unwrap_or(""));
    add(proc_hostname);
    add(proc_domainname);
    names
}

/// The DNS domains named by resolv.conf `search` and `domain` lines, in file order, without
/// duplicates or a trailing '.'. The fully qualified host name usually comes only from DNS, which
/// can block; resolv.conf is a local file that names the same domains.
pub fn resolver_domains(resolv_conf: &str) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for line in resolv_conf.split('\n') {
        let line = trim(line);
        let Some(key_end) = line.find([' ', '\t']) else {
            continue;
        };
        let key = &line[..key_end];
        if key != "search" && key != "domain" {
            continue;
        }
        for word in line[key_end..].split([' ', '\t']) {
            let domain = word.trim_end_matches('.');
            if !domain.is_empty() && !domains.iter().any(|d| d == domain) {
                domains.push(domain.to_owned());
            }
        }
    }
    domains
}

/// Domains that name a public service, not this site: a package repository or a code host that
/// every machine of the kind may talk to. They stay readable when they are a machine's domain.
const PUBLIC_DOMAINS: &[&str] = &[
    "ubuntu.com",
    "debian.org",
    "launchpad.net",
    "launchpadcontent.net",
    "fedoraproject.org",
    "opensuse.org",
    "github.com",
    "docker.com",
    "example.com",
    "example.net",
    "example.org",
];
/// Top-level and generic second-level domains: too general to be a site's own domain.
const PUBLIC_SUFFIXES: &[&str] = &[
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "io",
    "co.uk",
    "ac.uk",
    "gov.uk",
    "org.uk",
    "com.au",
    "co.jp",
    "co.in",
    "com.cn",
    "localdomain",
    "local",
    "lan",
    "home",
    "internal",
    "invalid",
    "test",
];

/// The private domain names of this machine: the domain part of its fully qualified host name and
/// every resolver `search` or `domain` entry. A name is dropped when it has no dot (a single label
/// is too general), is a public suffix, or is one of the [`PUBLIC_DOMAINS`] (or below one), so that
/// `example.com` and the public package repositories stay readable. Lower case, without duplicates.
pub fn private_domains(host_name: &str, resolver: &[String]) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some((_, domain)) = trim(host_name).split_once('.') {
        candidates.push(domain.to_owned());
    }
    candidates.extend(resolver.iter().cloned());
    let mut out: Vec<String> = Vec::new();
    for candidate in candidates {
        let name = trim(&candidate).trim_matches('.').to_ascii_lowercase();
        let public = |list: &[&str]| list.iter().any(|d| name == *d || name.ends_with(&format!(".{d}")));
        if !name.contains('.') || PUBLIC_SUFFIXES.contains(&name.as_str()) || public(PUBLIC_DOMAINS) {
            continue;
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// A machine id as `/etc/machine-id` writes it: 32 hexadecimal digits. None for anything else.
pub fn parse_machine_id(text: &str) -> Option<String> {
    let id = trim(text);
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

/// The user names the redactor should treat as personal.
///
/// Never returns `root`, `nobody` or a purely numeric name (a uid without a passwd entry, common in
/// containers): they occur in ordinary log text and would be rewritten everywhere. The effective
/// user is skipped when it is uid 0; under sudo SUDO_USER names the real person.
pub fn redactable_user_names(
    effective_uid: u32,
    effective_name: Option<&str>,
    other_names: &[Option<&str>],
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut add = |candidate: Option<&str>| {
        let Some(candidate) = candidate else {
            return;
        };
        let name = trim(candidate);
        let numeric = name.bytes().all(|b| b.is_ascii_digit());
        if !name.is_empty()
            && !numeric
            && name != "root"
            && name != "nobody"
            && !names.iter().any(|n| n == name)
        {
            names.push(name.to_owned());
        }
    };
    if effective_uid != 0 {
        add(effective_name);
    }
    for name in other_names {
        add(*name);
    }
    names
}

/// Adds `<short name>.<domain>` for each resolver domain to a list of host name spellings; the
/// first spelling names the host. Unchanged when `host_names` is empty.
pub fn with_resolver_domains(mut host_names: Vec<String>, domains: &[String]) -> Vec<String> {
    let Some(first) = host_names.first() else {
        return host_names;
    };
    let short = first.split('.').next().unwrap_or("").to_owned();
    for domain in domains {
        let qualified = format!("{short}.{domain}");
        if !host_names.contains(&qualified) {
            host_names.push(qualified);
        }
    }
    host_names
}

/// What `journalctl`'s output means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalVerdict {
    /// Log lines.
    Ok,
    /// It ran and the selection holds no messages: empty or `-- No entries --`.
    NoEntries,
    /// The requested boot is not in the journal.
    NoPersistentJournal,
    /// An error, or a result that says nothing because the caller may not read the journal.
    Unusable,
}

/// The longest output that can still be a `journalctl` diagnostic rather than a log.
const DIAGNOSTIC_MAX: usize = 1024;

/// Interprets a finished `journalctl` kernel log run.
pub fn classify_journal(exit_code: i32, output: &str) -> JournalVerdict {
    const ABSENT: [&str; 5] = [
        "No journal files were found",
        "not available",
        "No such boot",
        "No journal boot entry found",
        "no persistent journal",
    ];
    // journalctl's own diagnostics are one or two short lines. A real log can contain the same
    // words ("GuC firmware: version not available"), so the markers count only in short output
    // that holds no log line (`-o short-monotonic` lines start with a bracketed timestamp).
    let diagnostic = output.len() <= DIAGNOSTIC_MAX && !output.lines().any(|l| l.starts_with('['));
    if diagnostic && ABSENT.iter().any(|marker| output.contains(marker)) {
        return JournalVerdict::NoPersistentJournal;
    }
    // journalctl prints this hint instead of failing when the caller may not read the system
    // journal, so an empty result with it says nothing about the window.
    if diagnostic && output.contains("not seeing messages from") {
        return JournalVerdict::Unusable;
    }
    let body = trim(output);
    if exit_code != 0 {
        return JournalVerdict::Unusable;
    }
    if body.is_empty() || body == "-- No entries --" {
        return JournalVerdict::NoEntries;
    }
    JournalVerdict::Ok
}

/// Splits a text at runs of blanks.
pub fn split_words(text: &str) -> Vec<String> {
    text.split(' ').filter(|w| !w.is_empty()).map(str::to_owned).collect()
}

/// Parses the `Name:` / `Groups:` style numeric list of `/proc/self/status` into numbers.
pub fn parse_id_list(value: &str) -> Vec<u32> {
    value.split_whitespace().filter_map(|w| w.parse().ok()).collect()
}

/// The `CapEff` bit mask of a `/proc/self/status` text.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    parse_unsigned(&status_field(status, "CapEff")?, 16)
}

/// `name:x:uid:gid:...` lines of `/etc/passwd` or `/etc/group` as `(id, name)`; `id_field` is the
/// zero-based field that holds the number (2 for both files).
pub fn parse_account_names(text: &str, id_field: usize) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let id = fields.nth(id_field - 1)?.parse().ok()?;
            (!name.is_empty()).then(|| (id, name.to_owned()))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "text_tests.rs"]
mod tests;
