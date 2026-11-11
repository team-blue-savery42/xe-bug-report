// SPDX-License-Identifier: MIT
//! Unit tests for `src/archive/zip.rs`.

use super::*;
use std::io::Read;
use std::time::{Duration, UNIX_EPOCH};

// ---- an independent central-directory reader ----------------------------------------------

#[derive(Debug)]
struct Parsed {
    name: String,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc: u32,
    compressed_size: u32,
    size: u32,
    local_offset: u32,
    data: Vec<u8>,
}

fn get16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn get32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Parses an archive independently of the writer; None when any structural check fails: the end
/// record, every central header and its local header must agree and the central directory must
/// end exactly at the end record.
fn parse_zip(b: &[u8]) -> Option<Vec<Parsed>> {
    let eocd = b.len().checked_sub(22)?;
    if get32(b, eocd)? != END_RECORD_SIGNATURE || get16(b, eocd + 20)? != 0 {
        return None;
    }
    let count = get16(b, eocd + 10)?;
    let cd_size = get32(b, eocd + 12)? as usize;
    let cd_offset = get32(b, eocd + 16)? as usize;
    if get16(b, eocd + 8)? != count || cd_offset + cd_size != eocd {
        return None;
    }
    let mut pos = cd_offset;
    let mut out = Vec::new();
    for _ in 0..count {
        if get32(b, pos)? != CENTRAL_HEADER_SIGNATURE {
            return None;
        }
        let name_len = get16(b, pos + 28)? as usize;
        let name = String::from_utf8(b.get(pos + 46..pos + 46 + name_len)?.to_vec()).ok()?;
        let mut e = Parsed {
            name,
            flags: get16(b, pos + 8)?,
            method: get16(b, pos + 10)?,
            dos_time: get16(b, pos + 12)?,
            dos_date: get16(b, pos + 14)?,
            crc: get32(b, pos + 16)?,
            compressed_size: get32(b, pos + 20)?,
            size: get32(b, pos + 24)?,
            local_offset: get32(b, pos + 42)?,
            data: Vec::new(),
        };
        pos += 46 + name_len + get16(b, pos + 30)? as usize + get16(b, pos + 32)? as usize;

        let lo = e.local_offset as usize;
        if get32(b, lo)? != LOCAL_HEADER_SIGNATURE
            || get16(b, lo + 8)? != e.method
            || get32(b, lo + 14)? != e.crc
            || get32(b, lo + 18)? != e.compressed_size
            || get32(b, lo + 22)? != e.size
            || get16(b, lo + 26)? as usize != name_len
            || b.get(lo + 30..lo + 30 + name_len)? != e.name.as_bytes()
        {
            return None;
        }
        let start = lo + 30 + name_len + get16(b, lo + 28)? as usize;
        e.data = b.get(start..start + e.compressed_size as usize)?.to_vec();
        out.push(e);
    }
    (pos == eocd).then_some(out)
}

/// The uncompressed contents of `e`, verified against its CRC and size.
fn contents(e: &Parsed) -> Vec<u8> {
    let plain = match e.method {
        METHOD_STORED => e.data.clone(),
        METHOD_DEFLATED => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(&e.data[..]).read_to_end(&mut out).unwrap();
            out
        }
        other => panic!("unexpected method {other}"),
    };
    assert_eq!(plain.len(), e.size as usize, "{}", e.name);
    assert_eq!(crc32(&plain, 0), e.crc, "{}", e.name);
    plain
}

// ---- helpers ------------------------------------------------------------------------------

fn now() -> SystemTime {
    // 2026-11-10 14:28:03 UTC
    UNIX_EPOCH + Duration::from_secs(1_794_320_883)
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> =
        fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

fn binary_blob() -> Vec<u8> {
    (0..300u32).map(|i| ((i * 37 + 11) & 0xFF) as u8).collect()
}

fn compressible_text() -> String {
    "device 0000:03:00.0 reports nominal state\n".repeat(500)
}

/// Deterministic noise (xorshift) that deflate cannot shrink.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

// ---- crc32 --------------------------------------------------------------------------------

#[test]
fn crc32_known_vectors() {
    assert_eq!(crc32(b"123456789", 0), 0xCBF4_3926);
    assert_eq!(crc32(b"", 0), 0);
    let part = crc32(b"1234", 0);
    assert_eq!(crc32(b"56789", part), 0xCBF4_3926);
}

// ---- names --------------------------------------------------------------------------------

#[test]
fn name_validation() {
    let long = "a".repeat(65_536);
    let max = "a".repeat(65_535);
    for bad in [
        "",
        "/abs",
        "a/../b",
        "..",
        "../x",
        "a/..",
        "a\\b",
        "a//b",
        "a/",
        "a/./b",
        ".",
        "dir/\n/x",
        "nul\0byte",
        "tab\there",
        long.as_str(),
    ] {
        assert!(!valid_entry_name(bad), "{:?}", bad.chars().take(20).collect::<String>());
    }
    for good in
        ["a", "a/b/c.txt", "..a", "a..", "dir/.hidden", "caf\u{e9}.txt", "0000-03-00.0/x", max.as_str()]
    {
        assert!(valid_entry_name(good), "{:?}", good.chars().take(20).collect::<String>());
    }
}

#[test]
fn invalid_names_are_rejected_and_poison_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["", "/abs", "a/../b", "a\\b", "a/", "dir/\n/x"] {
        let out = dir.path().join("bad.zip");
        let mut w = ZipWriter::create(&out).unwrap();
        let err = w.add(name, b"x", now()).unwrap_err();
        assert!(matches!(err, Error::InvalidEntryName(ref n) if n == name), "{err}");
        assert!(w.add("fine", b"x", now()).is_err());
        assert!(w.finish().is_err());
        assert!(listing(dir.path()).is_empty());
    }
}

// ---- round trip ---------------------------------------------------------------------------

#[test]
fn archive_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("bundle.zip");
    let blob = binary_blob();
    let text = compressible_text();
    // 2021-03-04 05:06:08 UTC
    let mtime = UNIX_EPOCH + Duration::from_secs(1_614_834_368);

    let mut w = ZipWriter::create(&out).unwrap();
    assert_eq!(w.compression(), Compression::Stored);
    w.add("empty.txt", b"", mtime).unwrap();
    w.add("dir/small.txt", b"hello\n", mtime).unwrap();
    w.add("bin/blob.bin", &blob, mtime).unwrap();
    w.add("dir/sub/big.log", text.as_bytes(), now()).unwrap();
    assert_eq!(w.compression(), Compression::Deflate);
    let before = w.bytes_written();
    assert!(before > Bytes(0));
    let size = w.finish().unwrap();
    assert!(size > before);
    assert_eq!(listing(dir.path()), ["bundle.zip"]);

    let file = fs::read(&out).unwrap();
    assert_eq!(file.len() as u64, size.get());
    let zip = parse_zip(&file).unwrap();
    assert_eq!(zip.len(), 4);

    let empty = &zip[0];
    assert_eq!(empty.name, "empty.txt");
    assert_eq!((empty.size, empty.compressed_size, empty.crc, empty.method), (0, 0, 0, 0));
    assert_ne!(empty.flags & 0x0800, 0);
    assert_eq!(empty.local_offset, 0);
    assert_eq!(empty.dos_time, (5 << 11) | (6 << 5) | 4);
    assert_eq!(empty.dos_date, (41 << 9) | (3 << 5) | 4);

    let small = &zip[1];
    assert_eq!(small.name, "dir/small.txt");
    assert_eq!(small.local_offset as usize, 30 + empty.name.len());
    assert_eq!(small.method, METHOD_STORED);
    assert_eq!(contents(small), b"hello\n");

    let bin = &zip[2];
    assert_eq!(bin.local_offset as usize, small.local_offset as usize + 30 + small.name.len() + 6);
    assert_eq!(contents(bin), blob);

    let big = &zip[3];
    assert_eq!(big.name, "dir/sub/big.log");
    assert_eq!(big.method, METHOD_DEFLATED);
    assert!(big.compressed_size < big.size);
    assert_eq!(contents(big), text.as_bytes());
    assert_eq!(big.dos_date, (46 << 9) | (11 << 5) | 10);
    assert_eq!(big.dos_time, (14 << 11) | (28 << 5) | 1);
}

#[test]
fn incompressible_data_is_stored() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("s.zip");
    let data = noise(4096);
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("noise", &data, now()).unwrap();
    assert_eq!(w.compression(), Compression::Stored);
    w.finish().unwrap();
    let zip = parse_zip(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(zip[0].method, METHOD_STORED);
    assert_eq!(zip[0].data, data);
}

#[test]
fn a_larger_entry_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("l.zip");
    let mut data = Vec::new();
    for i in 0..200_000u32 {
        data.extend_from_slice(format!("line {i} of a long kernel log\n").as_bytes());
    }
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("big", &data, now()).unwrap();
    w.add("noise", &noise(300_000), now()).unwrap();
    w.finish().unwrap();
    let zip = parse_zip(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(contents(&zip[0]), data);
    assert_eq!(zip[0].method, METHOD_DEFLATED);
    assert_eq!(contents(&zip[1]), noise(300_000));
}

#[test]
fn an_archive_without_entries_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("none.zip");
    let w = ZipWriter::create(&out).unwrap();
    assert_eq!(w.finish().unwrap(), Bytes(22));
    let file = fs::read(&out).unwrap();
    assert_eq!(file.len(), 22);
    assert!(parse_zip(&file).unwrap().is_empty());
}

// ---- create / finish / drop ---------------------------------------------------------------

#[test]
fn create_refuses_an_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("exists.zip");
    fs::write(&out, "keep me").unwrap();
    let err = ZipWriter::create(&out).unwrap_err();
    assert!(matches!(err, Error::OutputExists(ref p) if *p == out), "{err}");
    assert_eq!(listing(dir.path()), ["exists.zip"]);
    assert_eq!(fs::read(&out).unwrap(), b"keep me");

    // A stale .partial blocks exclusive creation and is left alone.
    let other = dir.path().join("other.zip");
    fs::write(dir.path().join("other.zip.partial"), "stale").unwrap();
    let err = ZipWriter::create(&other).unwrap_err();
    assert!(matches!(err, Error::OutputUnwritable { .. }), "{err}");
    assert!(err.to_string().contains("interrupted run"), "{err}");
    assert_eq!(fs::read(dir.path().join("other.zip.partial")).unwrap(), b"stale");

    let err = ZipWriter::create(&dir.path().join("missing_dir").join("x.zip")).unwrap_err();
    assert!(matches!(err, Error::OutputUnwritable { .. }), "{err}");
}

#[test]
fn an_empty_output_path_is_refused_before_creating_anything() {
    for path in ["", "/", ".."] {
        let err = ZipWriter::create(Path::new(path)).unwrap_err();
        assert!(matches!(err, Error::OutputUnwritable { .. }), "{path:?}: {err}");
    }
    let err = ZipWriter::create(Path::new("")).unwrap_err();
    assert!(err.to_string().contains("empty output path"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_at_the_output_path_counts_as_existing() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("link.zip")).unwrap();
    let err = ZipWriter::create(&dir.path().join("link.zip")).unwrap_err();
    assert!(matches!(err, Error::OutputExists(_)), "{err}");
    assert_eq!(listing(dir.path()), ["link.zip"]);
}

#[cfg(unix)]
#[test]
fn an_unwritable_directory_is_output_unwritable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ro = dir.path().join("ro");
    fs::create_dir(&ro).unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
    let result = ZipWriter::create(&ro.join("x.zip"));
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
    // Root bypasses permissions; everyone else must get the error.
    if let Err(err) = result {
        assert!(matches!(err, Error::OutputUnwritable { .. }), "{err}");
    }
}

#[test]
fn dropping_without_finish_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("never.zip");
    {
        let mut w = ZipWriter::create(&out).unwrap();
        assert_eq!(listing(dir.path()), ["never.zip.partial"]);
        w.add("a.txt", b"data", now()).unwrap();
    }
    assert!(listing(dir.path()).is_empty());
}

#[test]
fn finish_leaves_exactly_the_final_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("done.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("a.txt", b"data", now()).unwrap();
    assert_eq!(listing(dir.path()), ["done.zip.partial"]);
    w.finish().unwrap();
    assert_eq!(listing(dir.path()), ["done.zip"]);
}

#[test]
fn finish_does_not_replace_a_file_that_appeared_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("race.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("a.txt", b"data", now()).unwrap();
    fs::write(&out, "intruder").unwrap();
    let err = w.finish().unwrap_err();
    assert!(matches!(err, Error::OutputExists(ref p) if *p == out), "{err}");
    assert_eq!(listing(dir.path()), ["race.zip"]);
    assert_eq!(fs::read(&out).unwrap(), b"intruder");
}

#[cfg(unix)]
#[test]
fn finish_does_not_follow_a_symlink_that_appeared_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("sym.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("a.txt", b"data", now()).unwrap();
    std::os::unix::fs::symlink(dir.path().join("target"), &out).unwrap();
    assert!(matches!(w.finish().unwrap_err(), Error::OutputExists(_)));
    assert!(!dir.path().join("target").exists());
    assert_eq!(listing(dir.path()), ["sym.zip"]);
}

#[test]
fn the_entry_count_stops_below_the_zip64_marker() {
    let dir = tempfile::tempdir().unwrap();
    let mut w = ZipWriter::create(&dir.path().join("many.zip")).unwrap();
    for _ in 0..ENTRIES_MAX {
        w.add("e", b"", now()).unwrap();
    }
    assert!(w.add("e", b"", now()).is_err());
    assert!(w.finish().is_err());
    assert!(listing(dir.path()).is_empty());
}

#[test]
fn the_maximum_entry_count_is_a_valid_archive() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("max.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    for i in 0..ENTRIES_MAX {
        w.add(&format!("e{i}"), b"", now()).unwrap();
    }
    w.finish().unwrap();
    assert_eq!(parse_zip(&fs::read(&out).unwrap()).unwrap().len(), ENTRIES_MAX);
    match std::process::Command::new("unzip").arg("-t").arg(&out).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "unzip -t failed: {text}{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => eprintln!("unzip not installed; skipped"),
        Err(err) => panic!("cannot run unzip: {err}"),
    }
}

#[test]
fn times_outside_the_dos_range_are_clamped() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("t.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("old", b"x", UNIX_EPOCH).unwrap();
    w.add("future", b"x", UNIX_EPOCH + Duration::from_secs(250 * 365 * 86_400)).unwrap();
    w.add("odd", b"x", UNIX_EPOCH + Duration::from_secs(1_614_834_369)).unwrap();
    w.finish().unwrap();
    let zip = parse_zip(&fs::read(&out).unwrap()).unwrap();
    assert_eq!((zip[0].dos_date, zip[0].dos_time), ((1 << 5) | 1, 0));
    assert_eq!(zip[1].dos_date, (127 << 9) | (12 << 5) | 31);
    assert_eq!(zip[1].dos_time, (23 << 11) | (59 << 5) | 29);
    assert_eq!(zip[2].dos_time, (5 << 11) | (6 << 5) | 4);
}

#[test]
fn non_ascii_names_set_the_utf8_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("u.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("dir/caf\u{e9}.log", b"x", now()).unwrap();
    w.finish().unwrap();
    let zip = parse_zip(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(zip[0].name, "dir/caf\u{e9}.log");
    assert_ne!(zip[0].flags & 0x0800, 0);
}

// ---- the descriptor is not inherited --------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn the_partial_file_is_close_on_exec() {
    const O_CLOEXEC: u32 = 0o2_000_000;
    let dir = tempfile::tempdir().unwrap();
    let w = ZipWriter::create(&dir.path().join("cloexec.zip")).unwrap();
    let mut found = false;
    for entry in fs::read_dir("/proc/self/fd").unwrap().flatten() {
        let Ok(target) = fs::read_link(entry.path()) else { continue };
        if target.file_name().and_then(|n| n.to_str()) != Some("cloexec.zip.partial")
            || target.parent() != Some(dir.path())
        {
            continue;
        }
        found = true;
        let info =
            fs::read_to_string(format!("/proc/self/fdinfo/{}", entry.file_name().to_string_lossy())).unwrap();
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .map(|v| u32::from_str_radix(v.trim(), 8).unwrap())
            .unwrap();
        assert_ne!(flags & O_CLOEXEC, 0, "{info}");
    }
    assert!(found);
    drop(w);
}

// ---- external validators accept the archive ----------------------------------

#[cfg(unix)]
#[test]
fn unzip_accepts_the_archive() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("check.zip");
    let mut w = ZipWriter::create(&out).unwrap();
    w.add("empty.txt", b"", now()).unwrap();
    w.add("dir/small.txt", b"hello\n", now()).unwrap();
    w.add("bin/blob.bin", &binary_blob(), now()).unwrap();
    w.add("rand/noise.bin", &noise(10_000), now()).unwrap();
    w.add("dir/caf\u{e9}.log", compressible_text().as_bytes(), now()).unwrap();
    w.finish().unwrap();
    // Our own reader accepts it as well.
    assert_eq!(parse_zip(&fs::read(&out).unwrap()).unwrap().len(), 5);

    let result = Command::new("unzip").arg("-t").arg(&out).output();
    match result {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "unzip -t failed: {text}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(text.contains("No errors detected"), "{text}");
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => eprintln!("unzip not installed; skipped"),
        Err(err) => panic!("cannot run unzip: {err}"),
    }
}

#[cfg(unix)]
#[test]
fn unzip_accepts_an_empty_archive() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("empty.zip");
    ZipWriter::create(&out).unwrap().finish().unwrap();
    if let Ok(output) = Command::new("unzip").arg("-l").arg(&out).output() {
        assert!(output.status.success() || output.status.code() == Some(1), "{:?}", output.status);
    }
}
