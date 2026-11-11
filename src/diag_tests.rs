// SPDX-License-Identifier: MIT
//! Unit tests for `src/diag.rs`.

use super::*;

/// One test: the max level is process-global, so separate tests would race.
#[test]
fn init_sets_the_level_and_is_repeatable() {
    let warn = Metadata::builder().level(log::Level::Warn).build();
    let debug = Metadata::builder().level(log::Level::Debug).build();

    init(false);
    assert_eq!(log::max_level(), LevelFilter::Warn);
    assert!(LOGGER.enabled(&warn));
    assert!(!LOGGER.enabled(&debug));

    init(true);
    init(true);
    assert_eq!(log::max_level(), LevelFilter::Debug);
    assert!(LOGGER.enabled(&debug));

    init(false);
    assert_eq!(log::max_level(), LevelFilter::Warn);
}
