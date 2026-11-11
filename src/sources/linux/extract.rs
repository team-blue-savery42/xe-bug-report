// SPDX-License-Identifier: MIT
//! A short file to read first, derived from the kernel log that was already collected: the
//! firmware lines and the first and last errors with a little context.
//!
//! A noisy boot can push the first error out of a tail-limited log, and the log itself is megabytes
//! of USB, network and storage lines. The extract keeps the lines a GPU triage starts from. It is
//! one linear pass over the log with fixed limits, so its cost and size do not depend on how noisy
//! the log is.

/// Most firmware and load-status lines kept.
pub const FIRMWARE_LINES_MAX: usize = 200;
/// Most error matches kept from the start of the log.
pub const FIRST_MATCHES: usize = 200;
/// Most error matches kept from the end of the log.
pub const LAST_MATCHES: usize = 200;
/// Lines shown after each error match.
pub const CONTEXT_AFTER: usize = 2;
/// Longest line shown, in characters.
pub const LINE_MAX_CHARS: usize = 400;
/// Largest extract, in bytes.
pub const EXTRACT_MAX_BYTES: usize = 256 * 1024;

/// Substrings (lower case) that mark a line about GPU firmware, its load status or its features.
const FIRMWARE_MARKERS: &[&str] = &[
    "using guc firmware",
    "using huc firmware",
    "dmc firmware",
    "gsc",
    "late bind",
    "late_bind",
    "latebind",
    "pxp",
];
/// Words (lower case) that, together with "firmware", mark a load problem.
const FIRMWARE_PROBLEM_WORDS: &[&str] = &["load", "fail", "error", "not found", "missing"];
/// Substrings (lower case) that mark an error or a warning.
const ERROR_MARKERS: &[&str] = &[
    "sigid=",
    "*error*",
    "warning:",
    "oops:",
    "call trace",
    "hung task",
    "wedged",
    "gt reset",
    "machine check",
    "timeout",
    "timed out",
];
/// Words (lower case) that mark an error only as a whole word: `bug:` would match `debug:`.
const ERROR_BOUNDED: &[&str] = &["bug:"];
/// Subsystems that log routinely at boot: a line about one counts only when it also names a problem.
const NOISY_SUBSYSTEMS: &[&str] = &["dmar", "iommu", "mei", "pmt", "aer"];
/// Words (lower case) that name a problem.
const TROUBLE_WORDS: &[&str] =
    &["fail", "error", "timeout", "timed out", "unable", "cannot", "denied", "reset", "wedged"];
/// Substrings that mark an error only in exactly this case (short upper-case tokens).
const ERROR_TOKENS_EXACT: &[&str] = &["TDR", "RIP:"];

/// Whether `word` occurs in `line` bounded by anything but letters and digits.
fn contains_word(line: &str, word: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices(word).any(|(at, _)| {
        let before = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let after = bytes.get(at + word.len()).is_none_or(|b| !b.is_ascii_alphanumeric());
        before && after
    })
}

/// Whether a log line is about GPU firmware or its load status.
pub fn is_firmware_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    FIRMWARE_MARKERS.iter().any(|m| lower.contains(m))
        || (lower.contains("firmware") && FIRMWARE_PROBLEM_WORDS.iter().any(|w| lower.contains(w)))
}

/// Whether a log line reports an error, a warning, a hang or a reset. The IOMMU, management engine
/// and telemetry drivers log a dozen routine lines per boot, so theirs count only with a problem word.
pub fn is_error_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ERROR_MARKERS.iter().any(|m| lower.contains(m))
        || ERROR_TOKENS_EXACT.iter().any(|t| line.contains(t))
        || ERROR_BOUNDED.iter().any(|w| contains_word(&lower, w))
        || (NOISY_SUBSYSTEMS.iter().any(|w| contains_word(&lower, w))
            // `fault` as a word: the routine "Default domain type" does not count.
            && (contains_word(&lower, "fault") || TROUBLE_WORDS.iter().any(|w| lower.contains(w))))
}

/// A line cut to [`LINE_MAX_CHARS`] characters.
fn shorten(line: &str) -> String {
    match line.char_indices().nth(LINE_MAX_CHARS) {
        Some((at, _)) => format!("{} ...", &line[..at]),
        None => line.to_owned(),
    }
}

/// The index ranges (start inclusive, end exclusive) to show: each selected match with its context,
/// overlapping or touching ranges merged.
fn context_ranges(matches: &[usize], total: usize) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &at in matches {
        let range = (at, (at + 1 + CONTEXT_AFTER).min(total));
        match ranges.last_mut() {
            Some(last) if range.0 <= last.1 => last.1 = last.1.max(range.1),
            _ => ranges.push(range),
        }
    }
    ranges
}

/// Appends `line` and its newline unless that would pass the size limit; false when it did not fit.
fn push_line(out: &mut String, line: &str) -> bool {
    if out.len() + line.len() + 1 > EXTRACT_MAX_BYTES {
        return false;
    }
    out.push_str(line);
    out.push('\n');
    true
}

/// The extract of `log`, the text of a kernel log with one message per line. `origin` names the
/// log in the header and `log_cut` says that the log itself was cut short by a size limit.
pub fn extract_kernel_log(log: &str, origin: &str, log_cut: bool) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let mut out = String::new();
    push_line(
        &mut out,
        &format!(
            "# extract of {origin}: {} lines in the log{}",
            lines.len(),
            if log_cut { " (the log was cut at its size limit)" } else { "" }
        ),
    );

    let firmware: Vec<usize> = (0..lines.len()).filter(|&i| is_firmware_line(lines[i])).collect();
    push_line(
        &mut out,
        &format!(
            "\n# firmware and load status: {} lines{}",
            firmware.len(),
            if firmware.len() > FIRMWARE_LINES_MAX {
                format!(", the first {FIRMWARE_LINES_MAX} shown")
            } else {
                String::new()
            }
        ),
    );
    for &at in firmware.iter().take(FIRMWARE_LINES_MAX) {
        push_line(&mut out, &shorten(lines[at]));
    }

    let errors: Vec<usize> = (0..lines.len()).filter(|&i| is_error_line(lines[i])).collect();
    let shown = if errors.len() > FIRST_MATCHES + LAST_MATCHES {
        let mut picked = errors[..FIRST_MATCHES].to_vec();
        picked.extend_from_slice(&errors[errors.len() - LAST_MATCHES..]);
        picked
    } else {
        errors.clone()
    };
    let omitted = errors.len() - shown.len();
    push_line(
        &mut out,
        &format!(
            "\n# errors, warnings, hangs and resets: {} matching lines{}",
            errors.len(),
            if omitted > 0 {
                format!(", the first {FIRST_MATCHES} and the last {LAST_MATCHES} shown")
            } else {
                String::new()
            }
        ),
    );
    // One pass over all shown matches, so context shared by neighbours is printed once. The note about
    // the omitted matches goes where the first group ends.
    let first_group = shown.len().min(FIRST_MATCHES);
    let first_group_last = first_group.checked_sub(1).map(|i| shown[i]);
    let mut noted = omitted == 0;
    let mut previous_end = None;
    for (start, end) in context_ranges(&shown, lines.len()) {
        let after_gap = first_group_last.is_some_and(|last| start > last);
        if !noted && after_gap {
            if !push_line(&mut out, &format!("# ... {omitted} matching lines omitted ...")) {
                return out;
            }
            noted = true;
        } else if previous_end.is_some_and(|p| p != start) && !push_line(&mut out, "--") {
            return out;
        }
        for line in &lines[start..end] {
            if !push_line(&mut out, &shorten(line)) {
                push_line(&mut out, "# extract size limit reached");
                return out;
            }
        }
        previous_end = Some(end);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "extract_tests.rs"]
mod tests;
