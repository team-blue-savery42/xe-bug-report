// SPDX-License-Identifier: MIT
//! Pure text helpers of the Linux sources: parsing and formatting that never touches the machine,
//! so every function here is unit tested with literals.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use crate::bundle::source::{ReadOutcome, ReadResult};
use crate::pci::PciAddress;

/// Environment variable prefixes recorded in `system/env.txt`.
const ENV_PREFIXES: &[&str] = &[
    "NEO_", "ZE_", "ZET_", "ZES_", "ZEL_", "ZEX_", "ONEAPI_", "SYCL_", "UR_", "IGC_", "OCL_", "XPU_SMI_",
    "XPUM_", "LIBVA_", "INTEL_",
];
/// Environment variables recorded by exact name.
const ENV_EXACT: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "LANG", "LC_ALL", "container"];

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

/// The environment variables worth recording, as sorted `KEY=value` lines.
pub fn filter_environment(environment: &[String]) -> String {
    let kept: BTreeSet<&String> = environment
        .iter()
        .filter(|entry| {
            let Some((key, _)) = entry.split_once('=') else {
                return false;
            };
            ENV_PREFIXES.iter().any(|p| key.starts_with(p)) || ENV_EXACT.contains(&key)
        })
        .collect();
    kept.into_iter().fold(String::new(), |mut text, entry| {
        text.push_str(entry);
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
