// SPDX-License-Identifier: MIT
//! A minimal `log` backend writing to stderr behind `--verbose`.

use std::io::Write;

use log::{LevelFilter, Log, Metadata, Record};

/// Writes "xe-bug-report: <level>: <message>" lines to stderr.
struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            // A closed stderr must not abort the collection, so the result is ignored.
            let _ = writeln!(
                std::io::stderr().lock(),
                "xe-bug-report: {}: {}",
                record.level().as_str().to_ascii_lowercase(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

/// Installs the stderr logger; `verbose` selects `Debug`, otherwise only `Warn` and above.
/// Calling it twice is harmless: the logger is installed once and the level is updated.
pub fn init(verbose: bool) {
    // An Err means a logger is already installed (an earlier call, or a test harness); keep it.
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(if verbose { LevelFilter::Debug } else { LevelFilter::Warn });
}

#[cfg(test)]
#[path = "diag_tests.rs"]
mod tests;
