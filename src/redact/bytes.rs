// SPDX-License-Identifier: MIT
//! Byte-level helpers shared by the scanners: the tokens, ASCII character classes and the
//! [`Rewriter`] that keeps every pass one linear sweep.

/// Replacement for this machine's names.
pub(crate) const TOKEN_HOST: &[u8] = b"<host>";
/// Replacement for user names.
pub(crate) const TOKEN_USER: &[u8] = b"<user>";
/// Replacement for IPv4 addresses.
pub(crate) const TOKEN_IPV4: &[u8] = b"<ipv4>";
/// Replacement for IPv6 addresses.
pub(crate) const TOKEN_IPV6: &[u8] = b"<ipv6>";
/// Replacement for MAC addresses.
pub(crate) const TOKEN_MAC: &[u8] = b"<mac>";
/// Replacement for serial numbers.
pub(crate) const TOKEN_SERIAL: &[u8] = b"<serial>";
/// Replacement for UUIDs.
pub(crate) const TOKEN_UUID: &[u8] = b"<uuid>";

/// Whether `lower_name` is the word inside one of the tokens, such as `host` in `<host>`.
pub(crate) fn is_token_word(lower_name: &[u8]) -> bool {
    [TOKEN_HOST, TOKEN_USER, TOKEN_IPV4, TOKEN_IPV6, TOKEN_MAC, TOKEN_SERIAL, TOKEN_UUID]
        .iter()
        .any(|token| token.get(1..token.len() - 1) == Some(lower_name))
}

/// Whether `c` continues a name: a hostname or user name is delimited by anything else.
pub(crate) const fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// Whether `c` is part of an identifier-like word (letters, digits, `_`).
pub(crate) const fn is_word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Space or tab.
pub(crate) const fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Compares `text` at `pos` with an already lowercase literal, ignoring ASCII case.
pub(crate) fn equals_ignore_case(text: &[u8], pos: usize, lower_literal: &[u8]) -> bool {
    match text.get(pos..pos.saturating_add(lower_literal.len())) {
        Some(window) => window.eq_ignore_ascii_case(lower_literal),
        None => false,
    }
}

/// Whether a percent-encoded separator (`%2F`, `%5C`, `%20`, any hex case) ends right before
/// `end`. Syslog and URLs write paths this way (`%2Fhome%2Fuser%2Fx`), so such an escape ends a
/// name the way `/` does and the name after it starts a token.
pub(crate) fn percent_separator_ends_at(text: &[u8], end: usize) -> bool {
    end >= 3
        && end <= text.len()
        && text[end - 3] == b'%'
        && [&b"2f"[..], b"5c", b"20"].iter().any(|code| text[end - 2..end].eq_ignore_ascii_case(code))
}

/// First position at or after `pos` that is not a space or tab.
pub(crate) fn skip_blanks(text: &[u8], mut pos: usize) -> usize {
    while pos < text.len() && is_blank(text[pos]) {
        pos += 1;
    }
    pos
}

/// Copies the unchanged stretches between replacements, so each pass is one linear sweep.
///
/// Replacements must be given in ascending, non-overlapping order.
pub(crate) struct Rewriter<'a> {
    input: &'a [u8],
    output: Vec<u8>,
    copied: usize,
    changed: bool,
}

impl<'a> Rewriter<'a> {
    /// Starts a rewrite of `input`.
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, output: Vec::new(), copied: 0, changed: false }
    }

    /// Replaces `begin..end` of the input with `token`.
    pub(crate) fn replace(&mut self, begin: usize, end: usize, token: &[u8]) {
        if !self.changed {
            self.changed = true;
            self.output.reserve(self.input.len() + self.input.len() / 8);
        }
        self.output.extend_from_slice(&self.input[self.copied..begin]);
        self.output.extend_from_slice(token);
        self.copied = end;
    }

    /// The rewritten text, or `None` when nothing was replaced.
    pub(crate) fn finish(mut self) -> Option<Vec<u8>> {
        if !self.changed {
            return None;
        }
        self.output.extend_from_slice(&self.input[self.copied..]);
        Some(self.output)
    }
}
