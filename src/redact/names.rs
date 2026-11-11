// SPDX-License-Identifier: MIT
//! Whole-token, case-insensitive matching of this machine's host and user names.

use super::bytes::{Rewriter, equals_ignore_case, is_token_char, is_token_word, percent_separator_ends_at};

/// A one-letter name would rewrite every such token in the text.
const MIN_NAME_LENGTH: usize = 2;

/// Whole-token, case-insensitive matcher for a set of names, longest first.
pub(crate) struct NameSet {
    names: Vec<Vec<u8>>,
    first_char: [bool; 256],
}

impl NameSet {
    /// Builds the set from `source`. Names shorter than two bytes and names in `ignored`
    /// (lowercase generic names that identify no one) are dropped; duplicates are merged.
    pub(crate) fn new(source: &[String], ignored: &[&str]) -> Self {
        let mut names: Vec<Vec<u8>> = Vec::new();
        for name in source {
            if name.len() < MIN_NAME_LENGTH {
                continue;
            }
            let lowered = name.as_bytes().to_ascii_lowercase();
            if ignored.iter().any(|generic| generic.as_bytes() == lowered.as_slice()) {
                continue;
            }
            names.push(lowered);
        }
        names.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        names.dedup();
        let mut first_char = [false; 256];
        for name in &names {
            if let Some(&first) = name.first() {
                first_char[usize::from(first)] = true;
                first_char[usize::from(first.to_ascii_uppercase())] = true;
            }
        }
        Self { names, first_char }
    }

    /// Whether the set has nothing to match.
    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Replaces every whole-token occurrence of a name with `token`; `None` when there is none.
    pub(crate) fn replace_all(&self, text: &[u8], token: &[u8]) -> Option<Vec<u8>> {
        let mut rewriter = Rewriter::new(text);
        let mut i = 0;
        while i < text.len() {
            if !self.first_char[usize::from(text[i])]
                || (i > 0 && is_token_char(text[i - 1]) && !percent_separator_ends_at(text, i))
            {
                i += 1;
                continue;
            }
            let len = self.match_at(text, i);
            if len == 0 {
                i += 1;
                continue;
            }
            rewriter.replace(i, i + len, token);
            i += len;
        }
        rewriter.finish()
    }

    /// Length of the longest name that matches at `i` as a whole token, 0 for none.
    ///
    /// Our own tokens (`<host>`) are not matched; any other name in angle brackets is real data.
    fn match_at(&self, text: &[u8], i: usize) -> usize {
        for name in &self.names {
            if !equals_ignore_case(text, i, name) {
                continue;
            }
            let end = i + name.len();
            if end < text.len() && is_token_char(text[end]) {
                continue;
            }
            // A host called "host" inside "<host>" is our own token. Any other name in angle
            // brackets is real data: systemd logs "Hostname set to <name>".
            if i > 0 && text[i - 1] == b'<' && end < text.len() && text[end] == b'>' && is_token_word(name) {
                continue;
            }
            return name.len();
        }
        0
    }
}
