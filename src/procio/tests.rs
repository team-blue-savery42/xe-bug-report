// SPDX-License-Identifier: MIT
//! Unit tests for `src/procio/mod.rs`.

use super::*;
use std::io::Cursor;

fn read(data: &[u8], cap: usize, keep: Keep) -> ReadResult {
    read_stream(Cursor::new(data.to_vec()), cap, keep, false, ReadResult::default())
}

#[test]
fn read_stream_head_and_tail() {
    let r = read(b"0123456789", 100, Keep::Head);
    assert_eq!((r.outcome, r.data.as_slice(), r.truncated), (ReadOutcome::Read, &b"0123456789"[..], false));
    let r = read(b"0123456789", 10, Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(b"0123456789", 4, Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123"[..], true));
    let r = read(b"0123456789", 0, Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b""[..], true));
    let r = read(b"", 0, Keep::Head);
    assert_eq!((r.data.as_slice(), r.truncated), (&b""[..], false));

    let r = read(b"0123456789", 100, Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(b"0123456789", 10, Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"0123456789"[..], false));
    let r = read(b"0123456789", 4, Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b"6789"[..], true));
    let r = read(b"0123456789", 0, Keep::Tail);
    assert_eq!((r.data.as_slice(), r.truncated), (&b""[..], true));
}

#[test]
fn read_stream_rolls_the_tail_across_chunks() {
    let content: Vec<u8> = (0..300_000usize).map(|i| b'a' + (i % 251 % 26) as u8).collect();
    let r = read(&content, 1000, Keep::Tail);
    assert!(r.truncated);
    assert_eq!(r.data, content[content.len() - 1000..]);
    let r = read(&content, 100_000, Keep::Head);
    assert!(r.truncated);
    assert_eq!(r.data, content[..100_000]);
    let r = read(&content, 1 << 20, Keep::Head);
    assert!(!r.truncated);
    assert_eq!(r.data, content);
    let r = read(&content, 100_000, Keep::Tail);
    assert_eq!(r.data, content[content.len() - 100_000..]);
}

#[test]
fn read_stream_reports_a_read_error_as_failed() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("device on fire"))
        }
    }
    let r = read_stream(Broken, 10, Keep::Head, false, ReadResult::default());
    assert_eq!(r.outcome, ReadOutcome::Failed);
    assert!(r.error.contains("device on fire"));
}

#[test]
fn read_stream_retries_interrupted_reads() {
    struct Flaky(u8);
    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            match self.0 {
                1 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                2 => {
                    buf[0] = b'x';
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }
    let r = read_stream(Flaky(0), 10, Keep::Tail, false, ReadResult::default());
    assert_eq!((r.outcome, r.data.as_slice()), (ReadOutcome::Read, &b"x"[..]));
}

#[test]
fn capture_keeps_the_cap_and_flags_truncation() {
    let capture = Capture::start(Cursor::new(vec![7u8; 200_000]), 1000).unwrap();
    assert!(capture.wait_eof(Instant::now() + Duration::from_secs(5)));
    let (data, truncated) = capture.finish();
    assert_eq!(data.len(), 1000);
    assert!(truncated);
}

#[test]
fn capture_does_not_flag_an_exact_fit() {
    let capture = Capture::start(Cursor::new(b"abcd".to_vec()), 4).unwrap();
    assert!(capture.wait_eof(Instant::now() + Duration::from_secs(5)));
    assert_eq!(capture.finish(), (b"abcd".to_vec(), false));
}

#[test]
fn capture_can_be_abandoned_while_the_reader_is_blocked() {
    struct Blocked(std::sync::mpsc::Receiver<()>);
    impl Read for Blocked {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let capture = Capture::start(Blocked(rx), 10).unwrap();
    let start = Instant::now();
    assert!(!capture.wait_eof(Instant::now() + Duration::from_millis(80)));
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(capture.finish(), (Vec::new(), false));
    drop(tx); // lets the detached thread end
}

#[test]
fn deadline_after_never_overflows() {
    let now = Instant::now();
    assert!(deadline_after(now, Duration::MAX) > now + Duration::from_secs(3600));
    assert_eq!(deadline_after(now, Duration::ZERO), now);
}

#[test]
fn capacity_is_clamped() {
    assert_eq!(capacity(Bytes(0)), 0);
    assert_eq!(capacity(Bytes(4096)), 4096);
    assert!(capacity(Bytes(u64::MAX)) <= usize::MAX / 2);
}

#[test]
fn utf8_check_allows_a_cut_tail_only() {
    assert!(is_utf8_allowing_cut_tail("héllo".as_bytes()));
    assert!(is_utf8_allowing_cut_tail(&"é".as_bytes()[..1]));
    assert!(is_utf8_allowing_cut_tail(&"€".as_bytes()[..2]));
    assert!(!is_utf8_allowing_cut_tail(b"caf\x82 ok"));
    assert!(!is_utf8_allowing_cut_tail(b"\xFF"));
}

#[test]
fn pathext_candidates_follow_pathext_order() {
    let ext = parse_pathext(".COM;.EXE;;.BAT; .CMD ");
    assert_eq!(ext, [".COM", ".EXE", ".BAT", ".CMD"]);
    let c = pathext_candidates(Path::new("dir"), "tool", &ext);
    assert_eq!(
        c,
        [
            Path::new("dir").join("tool.COM"),
            Path::new("dir").join("tool.EXE"),
            Path::new("dir").join("tool.BAT"),
            Path::new("dir").join("tool.CMD")
        ]
    );
    // A name that already carries a PATHEXT extension is tried as given first, case-insensitively.
    let c = pathext_candidates(Path::new("dir"), "Tool.exe", &ext);
    assert_eq!(c[0], Path::new("dir").join("Tool.exe"));
    assert_eq!(c.len(), 5);
    assert!(pathext_candidates(Path::new("dir"), "tool", &[]).is_empty());
}

#[test]
fn private_temp_dir_is_private_and_removed_on_drop() {
    let path;
    {
        let dir = PrivateTempDir::create("xe-procio-test-").unwrap();
        path = dir.path().to_path_buf();
        assert!(path.is_dir());
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("xe-procio-test-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o700);
        }
        std::fs::create_dir_all(path.join("sub/deeper")).unwrap();
        std::fs::write(path.join("sub/file"), b"data").unwrap();
    }
    assert!(!path.exists());
}

#[test]
fn private_temp_dir_rejects_a_prefix_with_a_path_separator() {
    for bad in ["../x", "a/b", "a\\b", "nul\0byte", "/abs"] {
        let err = PrivateTempDir::create(bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
    }
    assert!(PrivateTempDir::create("fine-prefix-").is_ok());
}

#[test]
fn random_suffixes_are_16_hex_digits_and_differ() {
    let a = random_suffix();
    let b = random_suffix();
    assert_eq!(a.len(), 16);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

/// Yields the scripted results one `read` at a time, like a record device.
struct Scripted(std::collections::VecDeque<io::Result<Vec<u8>>>);

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(Err(e)) => Err(e),
            Some(Ok(rec)) => {
                assert!(buf.len() >= rec.len(), "buffer smaller than the record: {}", buf.len());
                buf[..rec.len()].copy_from_slice(&rec);
                Ok(rec.len())
            }
        }
    }
}

fn scripted(items: Vec<io::Result<Vec<u8>>>) -> Scripted {
    Scripted(items.into())
}

#[test]
fn records_mode_treats_would_block_as_the_end_and_skips_overwritten_records() {
    let items = || {
        vec![
            Ok(b"rec1\n".to_vec()),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            Ok(b"rec2\n".to_vec()),
            Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Ok(b"never\n".to_vec()),
        ]
    };
    let r = read_stream(scripted(items()), 100, Keep::Head, true, ReadResult::default());
    assert_eq!((r.outcome, r.data.as_slice(), r.truncated), (ReadOutcome::Read, &b"rec1\nrec2\n"[..], false));
    // Without records mode the same stream is an error.
    let r = read_stream(scripted(items()), 100, Keep::Head, false, ReadResult::default());
    assert_eq!(r.outcome, ReadOutcome::Failed);
}

#[test]
fn records_mode_never_shrinks_the_buffer_and_clips_afterwards() {
    let rec = vec![b'x'; 100];
    let r = read_stream(scripted(vec![Ok(rec.clone())]), 10, Keep::Head, true, ReadResult::default());
    assert_eq!((r.data.len(), r.truncated), (10, true));
    let mut two = rec.clone();
    two.extend_from_slice(b"END");
    let r = read_stream(scripted(vec![Ok(two)]), 5, Keep::Tail, true, ReadResult::default());
    assert_eq!((r.data.as_slice(), r.truncated), (&b"xxEND"[..], true));
}

#[test]
fn private_temp_dirs_are_distinct() {
    let a = PrivateTempDir::create("xe-procio-dup-").unwrap();
    let b = PrivateTempDir::create("xe-procio-dup-").unwrap();
    assert_ne!(a.path(), b.path());
}

#[test]
fn self_executable_path_is_the_running_binary() {
    let me = self_executable_path().unwrap();
    assert!(me.is_absolute());
    assert!(me.is_file());
}

#[cfg(unix)]
#[test]
fn reap_within_gives_up_on_a_child_that_does_not_exit() {
    let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let start = Instant::now();
    let reaped = reap_within(&mut child, Duration::from_millis(200));
    let took = start.elapsed();
    assert!(!reaped);
    assert!(took >= Duration::from_millis(200), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");

    // Once killed, the helper collects it; afterwards there is nothing left to collect, which
    // counts as done.
    child.kill().unwrap();
    assert!(reap_within(&mut child, Duration::from_secs(10)));
    assert!(reap_within(&mut child, Duration::from_millis(50)));
}

#[test]
fn empty_argv_is_a_spawn_failure() {
    let r = run_child(&[], Duration::from_secs(1), Bytes::kib(1));
    assert!(matches!(r.outcome, ChildOutcome::SpawnFailed(_)));
    let r = run_child(&[String::new()], Duration::from_secs(1), Bytes::kib(1));
    assert!(matches!(r.outcome, ChildOutcome::SpawnFailed(_)));
}

#[test]
fn a_missing_program_is_not_found() {
    let r = run_child(&["xe-no-such-program-anywhere".to_owned()], Duration::from_secs(5), Bytes::kib(1));
    assert_eq!(r.outcome, ChildOutcome::NotFound);
    assert!(r.output.is_empty());
}
