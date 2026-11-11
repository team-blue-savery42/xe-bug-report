// SPDX-License-Identifier: MIT
//! Records git describe, commit and build time for `--version` and the manifest.

use std::process::Command;

fn git(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn main() {
    let describe = git(&["describe", "--tags", "--always", "--dirty"]);
    let commit = git(&["rev-parse", "--short=12", "HEAD"]);
    // SOURCE_DATE_EPOCH keeps reproducible builds reproducible; otherwise the current time.
    let built =
        std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=XE_BUG_REPORT_DESCRIBE={describe}");
    println!("cargo:rustc-env=XE_BUG_REPORT_COMMIT={commit}");
    println!("cargo:rustc-env=XE_BUG_REPORT_BUILT_EPOCH={built}");
    // A crates.io or release-tarball build has no .git; watching missing paths would rerun every build.
    if std::path::Path::new(".git").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
        println!("cargo:rerun-if-changed=.git/index");
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
