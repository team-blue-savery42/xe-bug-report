// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/drm_clients.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put};

const FDINFO: &str = "pos:\t0\nflags:\t02100002\nmnt_id:\t23\nino:\t512\n\
drm-driver:\txe\ndrm-client-id:\t7\ndrm-pdev:\t0000:03:00.0\ndrm-total-vram0:\t1024 KiB\n\
drm-resident-vram0:\t512 KiB\ndrm-total-cycles-rcs:\t1000\n";

/// A fake process: its `fd` directory links and `fdinfo` files.
fn process(root: &Path, pid: u32, comm: &str, fds: &[(u32, &str, &str)]) {
    put(root, &format!("{pid}/comm"), format!("{comm}\n"));
    fs::create_dir_all(root.join(format!("{pid}/fd"))).unwrap();
    for &(fd, target, info) in fds {
        std::os::unix::fs::symlink(target, root.join(format!("{pid}/fd/{fd}"))).unwrap();
        put(root, &format!("{pid}/fdinfo/{fd}"), info);
    }
}

#[test]
fn only_gpu_nodes_count() {
    for target in
        ["/dev/dri/card0", "/dev/dri/renderD128", "/dev/accel/accel0", "/dev/dri/renderD128 (deleted)"]
    {
        assert!(is_drm_node(target), "{target}");
    }
    for target in ["/dev/null", "/dev/dri", "socket:[123]", "/home/u/dev/dri/card0", "/dev/dri/by-path/x"] {
        assert!(!is_drm_node(target), "{target}");
    }
}

#[test]
fn only_drm_lines_are_kept_and_they_are_bounded() {
    let lines = drm_lines(FDINFO);
    assert_eq!(lines.len(), 6);
    assert!(lines.iter().all(|l| l.starts_with("drm-")));
    assert!(!lines.iter().any(|l| l.contains("mnt_id") || l.contains("flags")));
    let long = format!("drm-client-name:\t{}\n", "é".repeat(500));
    assert!(drm_lines(&long)[0].len() <= LINE_MAX);
    let many: String = (0..200).map(|i| format!("drm-x{i}: 1\n")).collect();
    assert_eq!(drm_lines(&many).len(), LINES_MAX);
    assert_eq!(value_of(&lines, "drm-client-id"), Some("7"));
    assert_eq!(value_of(&lines, "drm-nothing"), None);
}

#[test]
fn clients_are_listed_with_their_statistics_and_duplicates_collapse() {
    let dir = PrivateTempDir::create("proc").unwrap();
    let root = dir.path();
    process(
        root,
        42,
        "compositor",
        &[(5, "/dev/dri/card0", FDINFO), (6, "/dev/dri/card0", FDINFO), (3, "/dev/null", "")],
    );
    process(root, 7, "render-app", &[(9, "/dev/dri/renderD128", "drm-driver:\txe\ndrm-client-id:\t99\n")]);
    process(root, 8, "idle", &[(0, "/dev/null", "")]);
    put(root, "self_note", "not a pid");
    let reader = FsReader::default();
    let result = scan(&reader, root, Duration::from_secs(5));
    assert_eq!((result.processes, result.count, result.denied), (3, 2, 0));
    // Ascending by pid; the duplicated descriptor of pid 42 is one client.
    assert!(
        result.clients.starts_with("pid 7 (render-app) fd 9 /dev/dri/renderD128\n  drm-driver: xe\n"),
        "{}",
        result.clients
    );
    assert!(
        result
            .clients
            .contains("pid 42 (compositor) fd 5 /dev/dri/card0\n  drm-driver: xe\n  drm-client-id: 7\n")
    );
    assert!(result.clients.contains("  drm-total-vram0: 1024 KiB\n"));
    assert_eq!(result.clients.matches("pid 42").count(), 1);
    // Every file read went through the reader and none of them is a command line or environment.
    let asked = reader.asked.lock().unwrap();
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|p| p.contains("/fdinfo/") || p.ends_with("/comm")), "{asked:?}");

    let produced = report(&result, "system/drm-clients.txt");
    assert_eq!(produced.status, Status::Collected);
    let text = String::from_utf8_lossy(&produced.data).into_owned();
    assert!(text.starts_with("# 3 processes looked at, 2 DRM clients found\n"), "{text}");
}

#[test]
fn a_node_without_statistics_is_still_a_client() {
    let dir = PrivateTempDir::create("proc").unwrap();
    process(dir.path(), 5, "old", &[(4, "/dev/dri/card0", "pos:\t0\n")]);
    let result = scan(&FsReader::default(), dir.path(), Duration::from_secs(5));
    assert_eq!(result.count, 1);
    assert!(result.clients.contains("(no drm-* statistics"));
}

#[test]
fn processes_that_cannot_be_listed_make_the_report_partial() {
    let dir = PrivateTempDir::create("proc").unwrap();
    process(dir.path(), 5, "mine", &[(4, "/dev/dri/card0", FDINFO)]);
    let result = Scan { denied: 3, processes: 1, count: 1, ..Scan::default() };
    let produced = report(&result, "x");
    assert_eq!((produced.status, produced.reason.as_str()), (Status::Truncated, "needs root"));
    assert!(String::from_utf8_lossy(&produced.data).contains("3 other processes could not be listed"));
    let none = report(&Scan::default(), "x");
    assert_eq!(none.status, Status::Collected);
    assert!(String::from_utf8_lossy(&none.data).contains("(no process holds a DRM device node open)"));
}

#[test]
fn the_scan_stops_at_its_budget_and_at_the_client_limit() {
    let dir = PrivateTempDir::create("proc").unwrap();
    process(dir.path(), 5, "a", &[(4, "/dev/dri/card0", FDINFO)]);
    let result = scan(&FsReader::default(), dir.path(), Duration::ZERO);
    assert_eq!(result.count, 0);
    assert_eq!(result.stopped, Some("the scan stopped at its time budget"));
    let produced = report(&result, "x");
    assert_eq!(produced.status, Status::Truncated);

    let many = PrivateTempDir::create("proc").unwrap();
    for pid in 1..=(CLIENTS_MAX as u32 + 10) {
        process(many.path(), pid, "c", &[(4, "/dev/dri/card0", "drm-driver:\txe\n")]);
    }
    let result = scan(&FsReader::default(), many.path(), Duration::from_secs(30));
    assert_eq!(result.count, CLIENTS_MAX);
    assert_eq!(result.stopped, Some("the client limit was reached"));
}

#[test]
fn a_missing_proc_is_an_empty_scan() {
    let result = scan(&FsReader::default(), Path::new("/nonexistent-proc-root"), Duration::from_secs(1));
    assert_eq!((result.processes, result.count, result.denied), (0, 0, 0));
}
