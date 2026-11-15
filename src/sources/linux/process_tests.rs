// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/process.rs`.

use super::*;
use crate::bundle::source::Keep;
use crate::sources::linux::testkit::{FsReader, put, text_of as data_text};

const MAPS: &str = "\
55d0c0a00000-55d0c0a01000 r--p 00000000 103:02 1311 /usr/bin/app
7f1000000000-7f1000100000 r-xp 00000000 103:02 2001 /usr/lib/libze_loader.so.1.32.0
7f1000100000-7f1000200000 r--p 00100000 103:02 2001 /usr/lib/libze_loader.so.1.32.0
7f1000200000-7f1000300000 r-xp 00000000 103:02 2002 /usr/lib/libze_intel_gpu.so.1.17.39758 (deleted)
7f1000300000-7f1000400000 r-xp 00000000 103:02 2003 /usr/lib/libigc.so.2.41.0+0
7f1000400000-7f1000500000 r-xp 00000000 103:02 2004 /usr/lib/libz.so.1.3.1
7f1000500000-7f1000600000 r-xp 00000000 103:02 2005 /opt/my libs/libigdrcl.so
7f1000600000-7f1000700000 rw-p 00000000 00:00 0
7f1000700000-7f1000800000 rw-p 00000000 00:00 0 [heap]
7f1000800000-7f1000900000 r-xp 00000000 103:02 2006 /usr/lib/libvulkan_intel.so
7f1000900000-7f1000a00000 rw-s 00000000 00:01 7 /dev/dri/renderD128
";

#[test]
fn mapped_gpu_libraries_are_listed_once_in_order() {
    assert_eq!(
        mapped_libraries(MAPS),
        [
            "/usr/lib/libze_loader.so.1.32.0",
            "/usr/lib/libze_intel_gpu.so.1.17.39758 (deleted)",
            "/usr/lib/libigc.so.2.41.0+0",
            "/opt/my libs/libigdrcl.so",
            "/usr/lib/libvulkan_intel.so",
        ]
    );
    assert!(mapped_libraries("").is_empty());
    assert!(mapped_libraries("garbage\n1 2 3\n").is_empty());
}

#[test]
fn gpu_library_names() {
    for path in ["/usr/lib/libOpenCL.so.1.0.0", "/x/libmesa_dri.so", "/x/libigdgmm.so.12 (deleted)"] {
        assert!(is_gpu_library(path), "{path}");
    }
    for path in ["/usr/lib/libz.so", "/usr/lib/libigccmcompiler.so", "[vdso]"] {
        assert!(!is_gpu_library(path), "{path}");
    }
}

#[test]
fn thread_state_and_wait_channel() {
    assert_eq!(stat_state("1234 (app) S 1 2 3"), Some('S'));
    // The command name may hold blanks and parentheses.
    assert_eq!(stat_state("1234 (a (b) c) D 1 2 3"), Some('D'));
    assert_eq!(stat_state("garbage"), None);
    assert_eq!(stat_state("1 (x)"), None);
    assert_eq!(wchan_label("0"), "-");
    assert_eq!(wchan_label(""), "-");
    assert_eq!(wchan_label("dma_fence_default_wait\n"), "dma_fence_default_wait");
}

/// A fake `/proc/<pid>` with two threads.
fn fake_process(root: &Path) {
    put(root, "status", "Name:\tapp\nState:\tS (sleeping)\nPid:\t42\nThreads:\t2\n");
    put(root, "comm", "app\n");
    put(root, "cmdline", "app\0--token=secret\0");
    put(
        root,
        "environ",
        "PATH=/usr/bin\0ZE_AFFINITY_MASK=0\0NEO_CACHE_DIR=/srv/acme/cache\0API_TOKEN=x\0\0HOME=/h\0",
    );
    put(root, "maps", MAPS);
    put(root, "task/42/stat", "42 (app) S 1 42 42");
    put(root, "task/42/wchan", "0");
    put(root, "task/43/stat", "43 (ze worker) D 1 42 42");
    put(root, "task/43/wchan", "dma_fence_default_wait");
}

#[test]
fn a_readable_process_gives_three_files() {
    let dir = tempfile::tempdir().unwrap();
    fake_process(dir.path());
    let reader = FsReader::default();
    let produced = process_report(&reader, dir.path(), "processes/42/");
    let names: Vec<&str> = produced.iter().map(|p| p.rel_path.as_str()).collect();
    assert_eq!(
        names,
        ["processes/42/status.txt", "processes/42/environment.txt", "processes/42/libraries.txt"]
    );
    assert!(produced.iter().all(|p| p.status == Status::Collected), "{produced:?}");

    let status = data_text(&produced[0].data);
    assert_eq!(
        status,
        "comm: app\nState: S (sleeping)\nThreads: 2\n\nthreads (tid, state, wchan):\n42 S -\n43 D dma_fence_default_wait\n"
    );
    let environment = data_text(&produced[1].data);
    assert_eq!(environment, "NEO_CACHE_DIR=<path>\nZE_AFFINITY_MASK=0\n");
    let libraries = data_text(&produced[2].data);
    assert!(libraries.starts_with("/usr/lib/libze_loader.so.1.32.0\n"), "{libraries}");
    // The command line is never read.
    let asked = reader.asked.lock().unwrap();
    assert!(!asked.iter().any(|p| p.ends_with("cmdline")), "{asked:?}");
    // The status is read before anything that takes the memory map lock.
    let at = |name: &str| asked.iter().position(|p| p.ends_with(name)).unwrap();
    assert!(at("status") < at("environ") && at("environ") < at("maps"));
}

#[test]
fn a_process_without_gpu_libraries_or_variables_says_so() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "status", "State:\tR (running)\nThreads:\t1\n");
    put(dir.path(), "environ", "PATH=/usr/bin\0");
    put(dir.path(), "maps", "7f00-7f01 r-xp 00000000 103:02 9 /usr/lib/libc.so.6\n");
    let produced = process_report(&FsReader::default(), dir.path(), "processes/7/");
    assert_eq!(data_text(&produced[0].data).lines().next(), Some("comm: "));
    assert!(data_text(&produced[0].data).contains("(the thread list could not be read)"));
    assert_eq!(data_text(&produced[1].data), "(no GPU runtime variables set)\n");
    assert_eq!(data_text(&produced[2].data), "(no GPU runtime library is mapped)\n");
}

/// Denies `environ`, `maps` and `wchan`, as the kernel does for another user's process.
struct OtherUser(FsReader);

impl Reader for OtherUser {
    fn read(&self, path: &Path, max: Bytes, keep: Keep) -> ReadResult {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if matches!(name, "environ" | "maps" | "wchan") {
            return ReadResult {
                outcome: ReadOutcome::Denied,
                error: "Permission denied".into(),
                ..Default::default()
            };
        }
        self.0.read(path, max, keep)
    }
}

#[test]
fn another_users_process_records_why_per_file() {
    let dir = tempfile::tempdir().unwrap();
    fake_process(dir.path());
    let produced = process_report(&OtherUser(FsReader::default()), dir.path(), "processes/42/");
    assert_eq!(produced[0].status, Status::Collected);
    let status = data_text(&produced[0].data);
    assert!(status.contains("43 D ?\n"), "{status}");
    assert!(
        status.contains("(wait channels denied; needs root (or the user that owns the process))"),
        "{status}"
    );
    for denied in &produced[1..] {
        assert_eq!(denied.status, Status::Skipped);
        assert_eq!(denied.reason, "needs root (or the user that owns the process)");
        assert!(denied.data.is_empty());
    }
}

#[test]
fn an_exited_process_is_skipped_not_failed() {
    let dir = tempfile::tempdir().unwrap();
    let produced = process_report(&FsReader::default(), &dir.path().join("gone"), "processes/9/");
    assert_eq!(produced.len(), 3);
    for item in produced {
        assert_eq!(item.status, Status::Skipped, "{item:?}");
        assert_eq!(item.reason, "the process has exited");
    }
}

#[test]
fn the_thread_list_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "status", "State:\tS\nThreads:\t300\n");
    for tid in 1..=(MAX_THREADS as u32 + 3) {
        std::fs::create_dir_all(dir.path().join("task").join(tid.to_string())).unwrap();
    }
    let produced = process_report(&FsReader::default(), dir.path(), "processes/1/");
    let status = data_text(&produced[0].data);
    assert_eq!(status.lines().filter(|l| l.ends_with(" ? ?")).count(), MAX_THREADS);
    assert!(status.contains("(3 more threads not listed)"), "{status}");
}
