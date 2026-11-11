// SPDX-License-Identifier: MIT
//! The text redaction scanners and the registry that runs them.
//!
//! A new rule is one scanner function (`fn(&[u8], &Context) -> Option<Vec<u8>>`) plus one entry in
//! [`ALL_RULES`]; the manifest name is the entry's `name`.

use std::borrow::Cow;

use super::bytes::{
    Rewriter, TOKEN_HOST, TOKEN_IPV4, TOKEN_IPV6, TOKEN_MAC, TOKEN_SERIAL, TOKEN_USER, TOKEN_UUID,
    equals_ignore_case, is_blank, is_token_char, is_word_char, percent_separator_ends_at, skip_blanks,
};
use super::context::{Context, Rules};
use super::names::NameSet;

/// One class of identifier: its manifest name, its switch in [`Rules`] and its scanner.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Name in the manifest's list of active rules.
    pub name: &'static str,
    /// Position in the manifest list (`serials`, `hostname`, `users`, `addresses`).
    pub manifest_order: u8,
    /// Whether `rules` selects this class.
    pub enabled: fn(&Rules) -> bool,
    /// Scans `text`; the redacted copy, or `None` when nothing changed.
    pub apply: fn(&[u8], &Context) -> Option<Vec<u8>>,
}

/// Every rule, in the order the scanners run. Later scanners never re-scan our own tokens as
/// data: none of the tokens matches a pattern of a later rule.
pub const ALL_RULES: &[Rule] = &[
    Rule { name: "serials", manifest_order: 0, enabled: |r| r.serials, apply: |t, _| redact_serials(t) },
    Rule { name: "users", manifest_order: 2, enabled: |r| r.users, apply: redact_users },
    Rule { name: "hostname", manifest_order: 1, enabled: |r| r.hostname, apply: redact_hostnames },
    Rule {
        name: "addresses",
        manifest_order: 3,
        enabled: |r| r.addresses,
        apply: |t, _| redact_addresses(t),
    },
];

/// Replaces the identifiers `rules` selects in `text` (need not be valid UTF-8) with fixed tokens
/// such as `<host>`.
pub fn redact_text(text: &[u8], rules: &Rules, context: &Context) -> Vec<u8> {
    let mut current: Cow<'_, [u8]> = Cow::Borrowed(text);
    for rule in ALL_RULES {
        if !(rule.enabled)(rules) {
            continue;
        }
        if let Some(next) = (rule.apply)(&current, context) {
            current = Cow::Owned(next);
        }
    }
    current.into_owned()
}

/// [`redact_text`] for a `&str`; the result is valid UTF-8 because tokens are ASCII.
pub fn redact_str(text: &str, rules: &Rules, context: &Context) -> String {
    String::from_utf8_lossy(&redact_text(text.as_bytes(), rules, context)).into_owned()
}

/// The names of the active rules, for the manifest: "serials", "hostname", "users", "addresses"
/// for each active rule, in that order.
pub fn rule_names(rules: &Rules) -> Vec<&'static str> {
    let mut active: Vec<&Rule> = ALL_RULES.iter().filter(|rule| (rule.enabled)(rules)).collect();
    active.sort_by_key(|rule| rule.manifest_order);
    active.into_iter().map(|rule| rule.name).collect()
}

// ---------------------------------------------------------------------------------------------
// hostnames and users by name
// ---------------------------------------------------------------------------------------------

/// Names every machine has: they identify no one, and as whole words they occur in kernel command
/// lines (`root=UUID=...`), lspci (`Root Port`) and ownership listings (`root root`). Lowercase.
const GENERIC_USER_NAMES: &[&str] =
    &["root", "nobody", "daemon", "system", "administrator", "local service", "network service"];
/// Host names that identify no machine. Lowercase.
const GENERIC_HOST_NAMES: &[&str] = &["localhost", "localhost.localdomain"];

fn redact_hostnames(text: &[u8], context: &Context) -> Option<Vec<u8>> {
    let hosts = NameSet::new(&context.hostnames, GENERIC_HOST_NAMES);
    if hosts.is_empty() {
        return None;
    }
    hosts.replace_all(text, TOKEN_HOST)
}

/// Home-directory components and `USER=` values, then the context's user names.
fn redact_users(text: &[u8], context: &Context) -> Option<Vec<u8>> {
    let mut current: Cow<'_, [u8]> = Cow::Borrowed(text);
    if let Some(next) = redact_user_paths(&current) {
        current = Cow::Owned(next);
    }
    let users = NameSet::new(&context.user_names, GENERIC_USER_NAMES);
    if !users.is_empty()
        && let Some(next) = users.replace_all(&current, TOKEN_USER)
    {
        current = Cow::Owned(next);
    }
    match current {
        Cow::Borrowed(_) => None,
        Cow::Owned(done) => Some(done),
    }
}

// ---------------------------------------------------------------------------------------------
// users in paths and variables
// ---------------------------------------------------------------------------------------------

/// Whether `c` ends a path segment or user name.
const fn is_segment_stop(c: u8) -> bool {
    matches!(
        c,
        b'/' | b'\\'
            | b'"'
            | b'\''
            | b'`'
            | b':'
            | b','
            | b';'
            | b'<'
            | b'>'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'|'
            | b'*'
            | b'?'
            | 0x7f
    ) || c <= 0x20
}

/// Length of the user name at `pos`; a trailing `.` is sentence punctuation, not name. A
/// percent-encoded separator (`%2F`, `%5C`, `%20`) ends the name like its plain form.
fn segment_length(text: &[u8], pos: usize) -> usize {
    let mut end = pos;
    while end < text.len() && !is_segment_stop(text[end]) {
        if text[end] == b'%' && percent_separator_ends_at(text, end + 3) {
            break;
        }
        end += 1;
    }
    while end > pos && text[end - 1] == b'.' {
        end -= 1;
    }
    end - pos
}

/// Length of a path separator at `pos`: the literal byte, or its percent-encoding (`encoded` is
/// the two hex digits, matched in either case).
fn separator_len(text: &[u8], pos: usize, literal: u8, encoded: &[u8; 2]) -> Option<usize> {
    match text.get(pos) {
        Some(&c) if c == literal => Some(1),
        Some(b'%') if text.get(pos + 1..pos + 3).is_some_and(|code| code.eq_ignore_ascii_case(encoded)) => {
            Some(3)
        }
        _ => None,
    }
}

/// The user name's start after `/home/`, `/Users/` or `C:\Users\` (also with doubled
/// backslashes). Both separators may be percent-encoded: `%2Fhome%2F`, `%5CUsers%5C`.
fn home_prefix_end(text: &[u8], i: usize) -> Option<usize> {
    if let Some(slash) = separator_len(text, i, b'/', b"2f") {
        let word = i + slash;
        for name in [&b"home"[..], b"users"] {
            if equals_ignore_case(text, word, name)
                && let Some(next) = separator_len(text, word + name.len(), b'/', b"2f")
            {
                return Some(word + name.len() + next);
            }
        }
    } else if let Some(slash) = separator_len(text, i, b'\\', b"5c") {
        let word = i + slash;
        if equals_ignore_case(text, word, b"users")
            && let Some(next) = separator_len(text, word + 5, b'\\', b"5c")
        {
            let mut pos = word + 5 + next;
            // Backslashes doubled by JSON-style escaping.
            if let Some(more) = separator_len(text, pos, b'\\', b"5c") {
                pos += more;
            }
            return Some(pos);
        }
    }
    None
}

/// The value's start after `USERNAME=`, `USER=` or `LOGNAME=` at a word start.
fn user_variable_prefix_end(text: &[u8], i: usize) -> Option<usize> {
    if i > 0 && is_token_char(text[i - 1]) {
        return None;
    }
    [&b"USERNAME="[..], b"USER=", b"LOGNAME="]
        .into_iter()
        .find(|name| text[i..].starts_with(name))
        .map(|name| i + name.len())
}

/// Replaces user names in home paths and user variables in one linear sweep.
fn redact_user_paths(text: &[u8]) -> Option<Vec<u8>> {
    let mut rewriter = Rewriter::new(text);
    let mut i = 0;
    while i < text.len() {
        let start = match text[i] {
            b'/' | b'\\' | b'%' => home_prefix_end(text, i),
            b'U' | b'L' => user_variable_prefix_end(text, i),
            _ => None,
        };
        let Some(start) = start else {
            i += 1;
            continue;
        };
        let len = segment_length(text, start);
        if len == 0 {
            i = start;
            continue;
        }
        rewriter.replace(start, start + len, TOKEN_USER);
        i = start + len;
    }
    rewriter.finish()
}

// ---------------------------------------------------------------------------------------------
// serials and UUIDs
// ---------------------------------------------------------------------------------------------

const UUID_LENGTH: usize = 36;
const DEVICE_SERIAL_GROUPS: usize = 8;

/// A range of the text to replace and the token that replaces it.
struct Replacement {
    begin: usize,
    end: usize,
    token: &'static [u8],
}

/// Whether a standalone 8-4-4-4-12 UUID starts at `i`.
fn is_uuid_at(text: &[u8], i: usize) -> bool {
    if text.len() - i < UUID_LENGTH || text[i + 8] != b'-' {
        return false;
    }
    if i > 0 && is_word_char(text[i - 1]) {
        return false;
    }
    let end = i + UUID_LENGTH;
    if end < text.len() && is_word_char(text[end]) {
        return false;
    }
    (0..UUID_LENGTH).all(|k| {
        let dash = matches!(k, 8 | 13 | 18 | 23);
        if dash { text[i + k] == b'-' } else { text[i + k].is_ascii_hexdigit() }
    })
}

/// Whether `c` ends the value after `key=`: whitespace and the punctuation that closes a list or
/// quotation.
const fn ends_assigned_value(c: u8) -> bool {
    matches!(c, b',' | b';' | b'"' | b'\'' | b')' | b']' | b'}') || c <= 0x20
}

/// Whether `c` ends an unquoted value after a quoted key.
const fn ends_json_value(c: u8) -> bool {
    matches!(c, b',' | b'}' | b']')
}

/// Finds the value of a `key: value`, `key=value`, `"key": value` or `'key': value` assignment.
///
/// After `=` the value is one token, so `root=UUID=x ro quiet` keeps the options. After `:` a
/// quoted value ends at its closing quote on the same line; an unquoted one runs to the end of
/// the line, or to a double quote (the end of an enclosing JSON or log string) and, when the key
/// itself was quoted, to a `,`, `}` or `]`. Everything else is over-redacted on purpose: a serial
/// must not leave a tail behind. An escaped quote inside a quoted value ends it early.
///
/// `pos` is right after the key word; one closing quote of the key, then blanks, are skipped.
/// `None` when no `:` or `=` follows the key, or the value is empty.
fn value_after_delimiter(text: &[u8], mut pos: usize) -> Option<Replacement> {
    let quoted_key = pos < text.len() && (text[pos] == b'"' || text[pos] == b'\'');
    if quoted_key {
        pos += 1;
    }
    pos = skip_blanks(text, pos);
    if pos >= text.len() || (text[pos] != b':' && text[pos] != b'=') {
        return None;
    }
    let assignment = text[pos] == b'=';
    let mut begin = skip_blanks(text, pos + 1);
    let mut quote = None;
    if begin < text.len() && (text[begin] == b'"' || text[begin] == b'\'') {
        quote = Some(text[begin]);
        begin += 1;
    }
    // Each scan below ends at the value it consumes, so a long line with many keys stays linear.
    let mut end = begin;
    if assignment {
        while end < text.len() && !ends_assigned_value(text[end]) {
            end += 1;
        }
    } else if let Some(quote) = quote {
        end = text[begin..]
            .iter()
            .position(|&c| c == quote || c == b'\r' || c == b'\n')
            .map_or(text.len(), |offset| begin + offset);
    } else {
        while end < text.len()
            && text[end] != b'\r'
            && text[end] != b'\n'
            && text[end] != b'"'
            && !(quoted_key && ends_json_value(text[end]))
        {
            end += 1;
        }
        while end > begin && is_blank(text[end - 1]) {
            end -= 1;
        }
    }
    if begin >= end {
        return None;
    }
    let is_uuid = end - begin == UUID_LENGTH && is_uuid_at(text, begin);
    Some(Replacement { begin, end, token: if is_uuid { TOKEN_UUID } else { TOKEN_SERIAL } })
}

/// Skips `number`, `_number` or ` number` after the word `serial`.
fn after_number_word(text: &[u8], mut pos: usize) -> Option<usize> {
    if pos < text.len() && (text[pos] == b'_' || text[pos] == b' ') {
        pos += 1;
    }
    equals_ignore_case(text, pos, b"number").then_some(pos + 6)
}

/// Skips one optional plural `s` or `S` after a key word.
fn skip_plural(text: &[u8], pos: usize) -> usize {
    if pos < text.len() && matches!(text[pos], b's' | b'S') { pos + 1 } else { pos }
}

/// Finds `xx-xx-xx-xx-xx-xx-xx-xx` (or with `:`) after at least one blank, as lspci prints a
/// device serial. `None` when no eight-group value follows, or it is part of a longer run.
fn device_serial_after(text: &[u8], pos: usize) -> Option<Replacement> {
    let begin = skip_blanks(text, pos);
    if begin == pos || begin >= text.len() {
        return None;
    }
    let length = DEVICE_SERIAL_GROUPS * 3 - 1;
    if text.len() - begin < length {
        return None;
    }
    let sep = text[begin + 2];
    if sep != b'-' && sep != b':' {
        return None;
    }
    for k in 0..DEVICE_SERIAL_GROUPS {
        let at = begin + k * 3;
        if !text[at].is_ascii_hexdigit() || !text[at + 1].is_ascii_hexdigit() {
            return None;
        }
        if k + 1 < DEVICE_SERIAL_GROUPS && text[at + 2] != sep {
            return None;
        }
    }
    let end = begin + length;
    if end < text.len()
        && (is_word_char(text[end])
            || (text[end] == sep && end + 1 < text.len() && text[end + 1].is_ascii_hexdigit()))
    {
        return None;
    }
    Some(Replacement { begin, end, token: TOKEN_SERIAL })
}

/// Finds the value to hide for a serial or UUID key starting at `i`, an `s`, `S`, `u` or `U`.
fn serial_key_value(text: &[u8], i: usize) -> Option<Replacement> {
    // The key must start a word: "board_serial" and "ProductSerial" qualify, "unserial" does not.
    if i > 0
        && text[i - 1].is_ascii_alphanumeric()
        && !(text[i].is_ascii_uppercase() && text[i - 1].is_ascii_lowercase())
    {
        return None;
    }
    if equals_ignore_case(text, i, b"uuid") {
        return value_after_delimiter(text, skip_plural(text, i + 4));
    }
    if !equals_ignore_case(text, i, b"serial") {
        return None;
    }
    let after_serial = skip_plural(text, i + 6);
    if let Some(number) = after_number_word(text, i + 6).map(|n| skip_plural(text, n)) {
        if let Some(value) = value_after_delimiter(text, number) {
            return Some(value);
        }
        if let Some(device) = device_serial_after(text, number) {
            return Some(device);
        }
    }
    value_after_delimiter(text, after_serial)
}

/// Replaces serial numbers, labelled UUIDs and bare UUIDs in one linear sweep.
fn redact_serials(text: &[u8]) -> Option<Vec<u8>> {
    let mut rewriter = Rewriter::new(text);
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if matches!(c, b's' | b'S' | b'u' | b'U') {
            if let Some(value) = serial_key_value(text, i) {
                rewriter.replace(value.begin, value.end, value.token);
                i = value.end;
                continue;
            }
        } else if c.is_ascii_hexdigit() && i + 8 < text.len() && text[i + 8] == b'-' && is_uuid_at(text, i) {
            rewriter.replace(i, i + UUID_LENGTH, TOKEN_UUID);
            i += UUID_LENGTH;
            continue;
        }
        i += 1;
    }
    rewriter.finish()
}

// ---------------------------------------------------------------------------------------------
// addresses
// ---------------------------------------------------------------------------------------------

/// Longest textual IPv6 address with an embedded IPv4 tail is 45 characters.
const MAX_IPV6_LENGTH: usize = 45;
const MAC_LENGTH: usize = 17;
const IPV4_OCTETS: usize = 4;
const MAX_OCTET_DIGITS: usize = 3;
const MAX_OCTET_VALUE: u32 = 255;

/// Parses `a.b.c.d` with octets of at most three digits and at most 255; the end of the address.
fn parse_ipv4(text: &[u8], mut pos: usize) -> Option<usize> {
    for octet in 0..IPV4_OCTETS {
        let mut digits = 0;
        let mut value: u32 = 0;
        while pos < text.len() && text[pos].is_ascii_digit() && digits <= MAX_OCTET_DIGITS {
            value = value * 10 + u32::from(text[pos] - b'0');
            digits += 1;
            pos += 1;
        }
        if digits == 0 || digits > MAX_OCTET_DIGITS || value > MAX_OCTET_VALUE {
            return None;
        }
        if octet + 1 < IPV4_OCTETS {
            if pos >= text.len() || text[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

/// Length of a non-loopback IPv4 address at `i` (a digit) that is not part of a longer dotted
/// number; 0 when none starts here.
fn ipv4_length(text: &[u8], i: usize) -> usize {
    if i > 0 && (text[i - 1] == b'.' || text[i - 1] == b'-') {
        return 0;
    }
    let Some(end) = parse_ipv4(text, i) else {
        return 0;
    };
    if end < text.len() {
        let next = text[end];
        if is_word_char(next) || next == b'-' {
            return 0;
        }
        // Part of a longer dotted sequence, e.g. a four-part build number with a fifth part.
        if next == b'.' && end + 1 < text.len() && text[end + 1].is_ascii_digit() {
            return 0;
        }
    }
    let found = &text[i..end];
    if found == b"127.0.0.1" || found == b"0.0.0.0" {
        return 0;
    }
    found.len()
}

/// Length of a six-group MAC address at `i` (a hex digit) that is not part of a longer group run
/// (EUI-64, WWN, device serial); 0 when none starts here.
fn mac_length(text: &[u8], i: usize) -> usize {
    if text.len() - i < MAC_LENGTH {
        return 0;
    }
    let sep = text[i + 2];
    if sep != b':' && sep != b'-' {
        return 0;
    }
    for k in 0..6 {
        let at = i + k * 3;
        if !text[at].is_ascii_hexdigit() || !text[at + 1].is_ascii_hexdigit() {
            return 0;
        }
        if k < 5 && text[at + 2] != sep {
            return 0;
        }
    }
    // A longer run of groups is something else (EUI-64, WWN, device serial).
    if i >= 3
        && text[i - 1] == sep
        && text[i - 2].is_ascii_hexdigit()
        && text[i - 3].is_ascii_hexdigit()
        && (i == 3 || !is_word_char(text[i - 4]))
    {
        return 0;
    }
    let end = i + MAC_LENGTH;
    if end < text.len() {
        if is_word_char(text[end]) {
            return 0;
        }
        if text[end] == sep
            && end + 2 < text.len()
            && text[end + 1].is_ascii_hexdigit()
            && text[end + 2].is_ascii_hexdigit()
            && (end + 3 >= text.len() || !is_word_char(text[end + 3]))
        {
            return 0;
        }
    }
    MAC_LENGTH
}

/// Checks the shape of an IPv6 candidate: groups of at most four hex digits, at most one `::`,
/// eight groups or fewer with `::`, at least two colons and one digit. `dotted_tail` says the last
/// group is an already validated IPv4 tail, which counts as two groups.
fn valid_ipv6(candidate: &[u8], dotted_tail: bool) -> bool {
    if candidate.iter().filter(|&&c| c == b':').count() < 2 || !candidate.iter().any(u8::is_ascii_digit) {
        return false;
    }
    let mut groups = 0;
    let mut compressed = false;
    let mut pos = 0;
    if candidate.first() == Some(&b':') {
        if !candidate.starts_with(b"::") {
            return false;
        }
        compressed = true;
        pos = 2;
    }
    while pos < candidate.len() {
        let colon = candidate[pos..].iter().position(|&c| c == b':').map(|offset| pos + offset);
        let last = colon.is_none();
        let end = colon.unwrap_or(candidate.len());
        let group = &candidate[pos..end];
        if group.is_empty() {
            return false;
        }
        if last && dotted_tail {
            groups += 2;
        } else {
            if group.len() > 4 || !group.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            groups += 1;
        }
        pos = end;
        if last {
            break;
        }
        if pos + 1 < candidate.len() && candidate[pos + 1] == b':' {
            if compressed {
                return false;
            }
            compressed = true;
            pos += 2;
        } else {
            pos += 1;
            if pos == candidate.len() {
                return false;
            }
        }
    }
    if compressed { groups <= 7 } else { groups == 8 }
}

/// Whether `candidate` followed by `next` is the unified-hierarchy marker of a cgroup line:
/// `0::/init.scope` is hierarchy id 0, an empty controller list and a path, not the address `0::`.
fn is_cgroup_marker(candidate: &[u8], next: Option<&u8>) -> bool {
    let Some(id) = candidate.strip_suffix(b"::") else {
        return false;
    };
    next == Some(&b'/') && (1..=2).contains(&id.len()) && id.iter().all(u8::is_ascii_digit)
}

/// Length of an IPv6 address at `i` (a hex digit or `:`), including an embedded IPv4 tail; a
/// trailing `:` or sentence `.` is not included. 0 when none starts here.
fn ipv6_length(text: &[u8], i: usize) -> usize {
    // "ab:cd" before us means we are inside a longer group sequence that already failed.
    if i >= 2 && text[i - 1] == b':' && (text[i - 2].is_ascii_hexdigit() || text[i - 2] == b':') {
        return 0;
    }
    let limit = text.len().min(i + MAX_IPV6_LENGTH + 1);
    let mut end = i;
    while end < limit && (text[end].is_ascii_hexdigit() || text[end] == b':') {
        end += 1;
    }
    let mut dotted_tail = false;
    // A '.' is an IPv4 tail only when a digit follows; otherwise it ends the sentence
    // ("connected to fe80::1.").
    if end + 1 < text.len() && text[end] == b'.' && text[end + 1].is_ascii_digit() {
        let Some(last_colon) = text[i..end].iter().rposition(|&c| c == b':') else {
            return 0;
        };
        let Some(v4_end) = parse_ipv4(text, i + last_colon + 1) else {
            return 0;
        };
        end = v4_end;
        dotted_tail = true;
    }
    if end - i > MAX_IPV6_LENGTH {
        return 0;
    }
    if end < text.len() && is_word_char(text[end]) {
        return 0;
    }
    if !dotted_tail && end - i >= 2 && text[end - 1] == b':' && text[end - 2] != b':' {
        end -= 1;
    }
    if !valid_ipv6(&text[i..end], dotted_tail) || is_cgroup_marker(&text[i..end], text.get(end)) {
        return 0;
    }
    end - i
}

/// Replaces MAC, IPv4 and IPv6 addresses in one linear sweep.
fn redact_addresses(text: &[u8]) -> Option<Vec<u8>> {
    let mut rewriter = Rewriter::new(text);
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        let can_start = (c.is_ascii_hexdigit() || c == b':') && (i == 0 || !is_word_char(text[i - 1]));
        if !can_start {
            i += 1;
            continue;
        }
        let mut token = TOKEN_MAC;
        let mut len = if c.is_ascii_hexdigit() { mac_length(text, i) } else { 0 };
        if len == 0 && c.is_ascii_digit() {
            token = TOKEN_IPV4;
            len = ipv4_length(text, i);
        }
        if len == 0 {
            token = TOKEN_IPV6;
            len = ipv6_length(text, i);
        }
        if len == 0 {
            i += 1;
            continue;
        }
        rewriter.replace(i, i + len, token);
        i += len;
    }
    rewriter.finish()
}
