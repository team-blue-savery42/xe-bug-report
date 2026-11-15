// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/attach.rs`.

use std::fs;

use super::*;
use crate::bundle::source::{Content, ReadResult, Spec};
use crate::procio::read_file_bounded;

/// Reads real files with the bounded reader the collector uses, without a guard.
struct Direct;

impl Reader for Direct {
    fn read(&self, path: &Path, max: Bytes, keep: Keep) -> ReadResult {
        read_file_bounded(path, max, keep)
    }
}

fn put(root: &Path, rel: &str, data: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

fn summary(produced: &[Produced]) -> Vec<(String, Status, String)> {
    produced.iter().map(|p| (p.rel_path.clone(), p.status, p.reason.clone())).collect()
}

#[test]
fn directories_are_numbered_and_named_after_the_path() {
    assert_eq!(attachment_dir(0, Path::new("/tmp/kernel.spv")), "attachments/1-kernel.spv/");
    assert_eq!(attachment_dir(2, Path::new("dumps/igc dump/")), "attachments/3-igc_dump/");
    assert_eq!(attachment_dir(0, Path::new("/")), "attachments/1-attachment/");
    assert_eq!(attachment_dir(0, Path::new("..")), "attachments/1-attachment/");
}

#[test]
fn every_attachment_is_a_minimal_detecting_source_of_its_own() {
    let sources = attachment_sources(&[PathBuf::from("/a/x.spv"), PathBuf::from("/b/dump")]);
    let paths: Vec<&str> = sources.iter().map(|s| s.rel_path.as_str()).collect();
    assert_eq!(paths, ["attachments/1-x.spv/", "attachments/2-dump/"]);
    for (at, source) in sources.iter().enumerate() {
        assert_eq!(source.profile, Profile::Minimal);
        assert_eq!(source.content, Content::Detect);
        assert_eq!(source.max_bytes, FILE_MAX);
        assert_eq!(source.group, format!("attachment:{}", at + 1));
        assert!(matches!(source.spec, Spec::Builtin(_)));
    }
    assert!(attachment_sources(&[]).is_empty());
}

#[test]
fn a_single_file_is_attached_under_its_name() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "kernel.spv", b"\x03\x02\x23\x07binary");
    let produced =
        attachment(&Direct, &dir.path().join("kernel.spv"), "attachments/1-kernel.spv/", &Budget::default());
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0].rel_path, "attachments/1-kernel.spv/kernel.spv");
    assert_eq!(produced[0].status, Status::Collected);
    assert_eq!(produced[0].data, b"\x03\x02\x23\x07binary");
    assert!(produced[0].via.ends_with("kernel.spv"));
}

#[cfg(unix)]
#[test]
fn a_directory_is_walked_in_name_order_without_following_links() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dump");
    put(&root, "b.txt", b"text\n");
    put(&root, "a/deep/c.ll", b"; llvm\n");
    put(&root, "odd name!.bin", b"\0\x01");
    put(dir.path(), "outside.txt", b"never read\n");
    std::os::unix::fs::symlink(dir.path().join("outside.txt"), root.join("link.txt")).unwrap();
    std::os::unix::fs::symlink(dir.path(), root.join("up")).unwrap();
    let produced = attachment(&Direct, &root, "attachments/1-dump/", &Budget::default());
    assert_eq!(
        summary(&produced),
        [
            ("attachments/1-dump/b.txt".to_owned(), Status::Collected, String::new()),
            (
                "attachments/1-dump/link.txt".to_owned(),
                Status::Skipped,
                "symbolic link, not followed".to_owned()
            ),
            ("attachments/1-dump/odd_name_.bin".to_owned(), Status::Collected, String::new()),
            ("attachments/1-dump/up".to_owned(), Status::Skipped, "symbolic link, not followed".to_owned()),
            ("attachments/1-dump/a/deep/c.ll".to_owned(), Status::Collected, String::new()),
        ]
    );
    assert!(!produced.iter().any(|p| p.data == b"never read\n"));
}

#[cfg(unix)]
#[test]
fn fifos_are_never_opened() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("d");
    fs::create_dir(&root).unwrap();
    let fifo = root.join("pipe");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !status.is_ok_and(|s| s.success()) {
        eprintln!("mkfifo is not available; skipping");
        return;
    }
    // Opening the FIFO for reading would block this test forever.
    let produced = attachment(&Direct, &root, "attachments/1-d/", &Budget::default());
    assert_eq!(
        summary(&produced),
        [("attachments/1-d/pipe".to_owned(), Status::Skipped, "not a regular file".to_owned())]
    );
}

#[test]
fn an_empty_or_vanished_attachment_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let empty = attachment(&Direct, dir.path(), "attachments/1-x/", &Budget::default());
    assert_eq!(
        summary(&empty),
        [("attachments/1-x/".to_owned(), Status::Skipped, "empty directory".to_owned())]
    );
    let gone = attachment(&Direct, &dir.path().join("gone"), "attachments/2-gone/", &Budget::default());
    assert_eq!(gone[0].status, Status::Skipped);
    assert_eq!(gone[0].rel_path, "attachments/2-gone/");
}

#[test]
fn the_file_size_and_total_limits_hold_across_attachments() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.bin");
    fs::File::create(&big).unwrap().set_len(FILE_MAX.get() + 1).unwrap();
    let budget = Budget::default();
    let produced = attachment(&Direct, &big, "attachments/1-big.bin/", &budget);
    assert_eq!(produced[0].status, Status::Skipped);
    assert_eq!(produced[0].reason, "larger than 16 MiB");

    // Four files of 16 MiB fill the total; the fifth, in another attachment, does not fit.
    for n in 0..4 {
        let path = dir.path().join(format!("f{n}"));
        fs::File::create(&path).unwrap().set_len(FILE_MAX.get()).unwrap();
        let produced = attachment(&Direct, &path, &format!("attachments/{}-f/", n + 2), &budget);
        assert_eq!(produced[0].status, Status::Collected, "{:?}", produced[0].reason);
    }
    put(dir.path(), "small.txt", b"x\n");
    let produced = attachment(&Direct, &dir.path().join("small.txt"), "attachments/6-small.txt/", &budget);
    assert_eq!((produced[0].status, produced[0].reason.as_str()), (Status::Skipped, TOTAL_REASON));
}

#[test]
fn files_past_the_count_limit_are_summed_up_in_one_entry() {
    let dir = tempfile::tempdir().unwrap();
    for n in 0..(MAX_FILES + 5) {
        put(dir.path(), &format!("f{n:04}"), b"x\n");
    }
    let produced = attachment(&Direct, dir.path(), "attachments/1-d/", &Budget::default());
    assert_eq!(produced.len(), MAX_FILES + 1);
    assert!(produced[..MAX_FILES].iter().all(|p| p.status == Status::Collected));
    let last = produced.last().unwrap();
    assert_eq!(last.rel_path, "attachments/1-d/");
    assert_eq!(last.reason, "5 more files not attached: the limit of 256 attached files is reached");
}

#[test]
fn text_is_told_from_binary_by_content() {
    assert_eq!(Content::Detect.of(b"plain text\n"), Content::Text);
    assert_eq!(Content::Detect.of("caf\u{e9}".as_bytes()), Content::Text);
    assert_eq!(Content::Detect.of(b""), Content::Text);
    // Cut in the middle of a multi-byte character at a size cap: still text.
    assert_eq!(Content::Detect.of(&"caf\u{e9}".as_bytes()[..4]), Content::Text);
    assert_eq!(Content::Detect.of(b"\x03\x02\x23\x07\0\0"), Content::Binary);
    assert_eq!(Content::Detect.of(b"text with a NUL\0"), Content::Binary);
    assert_eq!(Content::Detect.of(b"\xff\xfe latin-1"), Content::Binary);
    assert_eq!(Content::Text.of(b"\0"), Content::Text);
    assert_eq!(Content::Binary.of(b"text"), Content::Binary);
}
