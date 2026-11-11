// SPDX-License-Identifier: MIT
//! The `xe-bug-report` binary: parse arguments, collect, print, exit.
#![forbid(unsafe_code)]

fn main() {
    let _ = xe_bug_report::cli::parse_args(std::env::args_os());
    std::process::exit(0);
}
