// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/debugfs.rs`.

use super::*;
use crate::procio::PrivateTempDir;

/// Reads real files with std, for tests on temporary directories.
struct FsReader;
impl Reader for FsReader {
    fn read(&self, path: &Path, max: Bytes, _keep: Keep) -> ReadResult {
        match fs::read(path) {
            Ok(mut data) => {
                let truncated = data.len() as u64 > max.get();
                data.truncate(max.get() as usize);
                ReadResult { outcome: ReadOutcome::Read, data, truncated, error: String::new() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ReadResult { outcome: ReadOutcome::Missing, ..Default::default() }
            }
            Err(e) => ReadResult { outcome: ReadOutcome::Failed, error: e.to_string(), ..Default::default() },
        }
    }
}

fn touch(root: &Path, rel: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "x").unwrap();
}

#[test]
fn glob_matching_is_segment_local_star_only() {
    assert!(glob_match("gt*", "gt0"));
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*", ""));
    assert!(glob_match("*_freq", "min_freq"));
    assert!(glob_match("a*b*c", "aXXbYYc"));
    assert!(!glob_match("a*b*c", "aXXbYY"));
    assert!(!glob_match("gt*", "tile0"));
    assert!(glob_match("exact", "exact"));
    assert!(!glob_match("exact", "exactly"));
    assert!(!glob_match("a?", "ab"));
    assert!(glob_match("**", "x"));
    assert!(!glob_match("", "x"));
    assert!(glob_match("", ""));
}

#[test]
fn debugfs_allowlist_never_reaches_the_denylist() {
    let patterns = debugfs_patterns();
    for pattern in &patterns {
        for part in pattern.split('/') {
            assert!(!is_denied_debugfs_name(part), "{pattern}");
        }
        for bad in ["forcewake", "wedged", "force", "fail_", "reset", "inject", "dmesg", "lfd"] {
            assert!(!pattern.contains(bad), "{pattern}");
        }
        assert!(!pattern.contains(".."), "{pattern}");
    }
    // The GuC log is the last file read, in both layouts.
    assert_eq!(&patterns[patterns.len() - 2..], ["gt*/uc/guc_log", "tile*/gt*/uc/guc_log"]);
    // Each GT file is looked for in both layouts.
    for name in
        ["gt*/hw_engines", "tile*/gt*/hw_engines", "gt*/uc/gsc_info", "tile*/gt*/uc/guc_pc", "tile*/vram_mm"]
    {
        assert!(patterns.iter().any(|p| p == name), "{name}");
    }
    // Names the driver does not have are no longer asked for.
    assert!(!patterns.iter().any(|p| p == "clients" || p.ends_with("/pat")));
    assert!(patterns.iter().any(|p| p == "gt*/pat_sw_config"));
    for denied in [
        "forcewake_all",
        "wedged_mode",
        "force_reset",
        "fail_gt",
        "gt_reset",
        "reset",
        "inject_fault",
        "ras_inject",
        "i915_dp_force_link_rate",
        "i915_dp_force_link_retrain",
        "guc_log_dmesg",
        "guc_log_lfd",
    ] {
        assert!(is_denied_debugfs_name(denied), "{denied}");
    }
    for allowed in
        ["info", "name", "hw_engines", "guc_log", "gt0", "register-save-restore", "i915_display_info"]
    {
        assert!(!is_denied_debugfs_name(allowed), "{allowed}");
    }
}

#[test]
fn pattern_expansion_returns_only_allowed_regular_files() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    touch(root, "name");
    touch(root, "gt0/uc/guc_info");
    touch(root, "gt0/hw_engines");
    touch(root, "gt0/force_reset");
    touch(root, "gt1/hw_engines");
    std::os::unix::fs::symlink("gt0/hw_engines", root.join("info")).unwrap();
    // A symlinked directory is not entered either.
    std::os::unix::fs::symlink("gt0", root.join("gt9")).unwrap();

    let mut files = Vec::new();
    expand_pattern(root, Path::new(""), "gt*/hw_engines", &mut files);
    assert_eq!(files, [PathBuf::from("gt0/hw_engines"), PathBuf::from("gt1/hw_engines")]);

    files.clear();
    expand_pattern(root, Path::new(""), "info", &mut files);
    assert!(files.is_empty(), "a symlink is never returned");
    expand_pattern(root, Path::new(""), "gt*/force_reset", &mut files);
    assert!(files.is_empty(), "denied at the last component");
    expand_pattern(root, Path::new(""), "name", &mut files);
    assert_eq!(files, [PathBuf::from("name")]);

    assert_eq!(expand_component(&root.join("gt0"), "*"), ["hw_engines", "uc"]);
    assert!(expand_component(root, "wedged_mode").is_empty());
}

#[test]
fn debugfs_builtin_reads_only_allowlisted_files() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    let bdf = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };
    let dev = root.join("0000:03:00.0");
    touch(&dev, "name");
    touch(&dev, "gt0/hw_engines");
    touch(&dev, "gt0/uc/guc_log");
    touch(&dev, "gt0/force_reset");
    touch(&dev, "wedged_mode");
    touch(&dev, "not-on-the-list");
    let rel = "devices/0000-03-00.0/debugfs/";
    touch(&dev, "gt0/uc/guc_log_dmesg");
    touch(&dev, "tile0/gt0/hw_engines");
    touch(&dev, "tile0/vram_mm");
    touch(&dev, "i915_dp_force_link_rate");
    touch(&dev, "i915_psr_status");
    let names: Vec<String> =
        debugfs_builtin(&FsReader, root, rel, &bdf).into_iter().map(|p| p.rel_path).collect();
    // Device files first, then the tile files, then the GT files of both layouts, the GuC log last.
    assert_eq!(
        names,
        [
            format!("{rel}name"),
            format!("{rel}i915_psr_status"),
            format!("{rel}tile0/vram_mm"),
            format!("{rel}gt0/hw_engines"),
            format!("{rel}tile0/gt0/hw_engines"),
            format!("{rel}gt0/uc/guc_log"),
        ]
    );
}

#[test]
fn a_debugfs_directory_without_any_listed_file_is_skipped_with_a_reason() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let bdf = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };
    touch(&dir.path().join("0000:03:00.0"), "not-on-the-list");
    let out = debugfs_builtin(&FsReader, dir.path(), "d/", &bdf);
    assert_eq!((out.len(), out[0].status), (1, Status::Skipped));
    assert!(out[0].reason.contains("none of the listed debugfs files"), "{}", out[0].reason);
}

#[test]
fn debugfs_lookup_falls_back_to_the_name_file() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = dir.path();
    let bdf = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };
    fs::create_dir_all(root.join("0")).unwrap();
    fs::write(root.join("0/name"), "xe dev=0000:84:00.0 unique=x\n").unwrap();
    fs::create_dir_all(root.join("1")).unwrap();
    fs::write(root.join("1/name"), "xe dev=0000:03:00.0 unique=y\n").unwrap();
    assert!(
        matches!(find_debugfs_dir(&FsReader, root, &bdf), DebugfsLookup::Found(p) if p == root.join("1"))
    );
    let other = PciAddress { domain: 0, bus: 9, device: 0, function: 0 };
    assert!(matches!(find_debugfs_dir(&FsReader, root, &other), DebugfsLookup::NotFound));
    let missing = root.join("absent");
    assert!(matches!(find_debugfs_dir(&FsReader, &missing, &bdf), DebugfsLookup::Error(_)));
    let out = debugfs_builtin(&FsReader, &missing, "d/", &bdf);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rel_path, "d/");
    assert_eq!(out[0].status, Status::Skipped);
    assert_eq!(out[0].reason, "debugfs is not mounted");
}

#[test]
fn coredumps_are_taken_for_the_failing_device_only() {
    let dir = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let class = root.join("class");
    for (name, device) in [("devcd2", "0000:03:00.0"), ("devcd1", "0000:03:00.0"), ("devcd3", "0000:84:00.0")]
    {
        let dev = root.join("devices").join(device);
        fs::create_dir_all(&dev).unwrap();
        fs::create_dir_all(class.join(name)).unwrap();
        fs::write(class.join(name).join("data"), format!("dump of {name}")).unwrap();
        std::os::unix::fs::symlink(&dev, class.join(name).join("failing_device")).unwrap();
    }
    fs::create_dir_all(class.join("other")).unwrap();
    let bdf = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };
    let out = devcoredump_builtin(&FsReader, &class, "dumps/0000-03-00.0/", &bdf);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].rel_path, "dumps/0000-03-00.0/devcoredump-0.txt");
    assert_eq!(out[0].data, b"dump of devcd1");
    assert_eq!(out[1].rel_path, "dumps/0000-03-00.0/devcoredump-1.txt");
    assert!(devcoredump_builtin(&FsReader, &root.join("absent"), "d/", &bdf).is_empty());
}

#[test]
fn reads_become_artifacts() {
    let ok =
        ReadResult { outcome: ReadOutcome::Read, data: b"x".to_vec(), truncated: true, error: String::new() };
    let p = from_read("a".into(), ok).unwrap();
    assert_eq!(p.status, Status::Truncated);
    assert_eq!(p.reason, "larger than the size cap");
    let denied =
        from_read("a".into(), ReadResult { outcome: ReadOutcome::Denied, ..Default::default() }).unwrap();
    assert_eq!((denied.status, denied.reason.as_str()), (Status::Skipped, "needs root"));
    assert!(
        from_read("a".into(), ReadResult { outcome: ReadOutcome::Missing, ..Default::default() }).is_none()
    );
    let failed = from_read(
        "a".into(),
        ReadResult { outcome: ReadOutcome::Failed, error: "I/O error".into(), ..Default::default() },
    )
    .unwrap();
    assert_eq!((failed.status, failed.reason.as_str()), (Status::Failed, "I/O error"));
}
