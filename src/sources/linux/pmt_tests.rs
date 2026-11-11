// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/pmt.rs`.

use super::*;
use crate::bundle::source::{Keep, ReadOutcome, ReadResult, Status};
use crate::procio::PrivateTempDir;

struct FsReader {
    deny_crashlog: bool,
    cap_seen: std::sync::Mutex<Vec<u64>>,
}

impl FsReader {
    fn new(deny_crashlog: bool) -> Self {
        Self { deny_crashlog, cap_seen: std::sync::Mutex::new(Vec::new()) }
    }
}

impl Reader for FsReader {
    fn read(&self, path: &Path, max: Bytes, _keep: Keep) -> ReadResult {
        if self.deny_crashlog && path.file_name().is_some_and(|n| n == "crashlog") {
            return ReadResult { outcome: ReadOutcome::Denied, ..Default::default() };
        }
        match fs::read(path) {
            Ok(data) => {
                self.cap_seen.lock().unwrap().push(max.get());
                ReadResult { outcome: ReadOutcome::Read, data, ..Default::default() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ReadResult { outcome: ReadOutcome::Missing, ..Default::default() }
            }
            Err(e) => ReadResult { outcome: ReadOutcome::Failed, error: e.to_string(), ..Default::default() },
        }
    }
}

fn add_region(class_dir: &Path, name: &str, owner: &Path, guid: &str) {
    fs::create_dir_all(owner).unwrap();
    let region = class_dir.join(name);
    fs::create_dir_all(&region).unwrap();
    for (file, value) in [
        ("guid", format!("{guid}\n")),
        ("size", "2048\n".into()),
        ("offset", "2736\n".into()),
        ("enable", "1\n".into()),
        ("error", "0\n".into()),
        ("trigger", "0\n".into()),
        ("consumed", "0\n".into()),
    ] {
        fs::write(region.join(file), value).unwrap();
    }
    fs::write(region.join("crashlog"), [1u8, 2, 0, 4]).unwrap();
    std::os::unix::fs::symlink(owner, region.join("device")).unwrap();
}

#[test]
fn region_names() {
    assert!(is_pmt_crashlog_name("crashlog1"));
    assert!(is_pmt_crashlog_name("crashlog10"));
    assert!(!is_pmt_crashlog_name("crashlog"));
    assert!(!is_pmt_crashlog_name("crashlog_x"));
    assert!(!is_pmt_crashlog_name("telem3"));
    assert!(!is_pmt_crashlog_name("crashlog+1"));
}

#[test]
fn crash_logs_are_taken_from_the_regions_below_the_device() {
    let scratch = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = fs::canonicalize(scratch.path()).unwrap();
    let class_dir = root.join("class");
    let device = root.join("devices").join("0000:03:00.0");
    add_region(&class_dir, "crashlog1", &device.join("intel_vsec.crashlog.2"), "0xe2f8200");
    add_region(&class_dir, "crashlog2", &device.join("intel_vsec.crashlog.2"), "0x4e2f8210");
    add_region(&class_dir, "crashlog10", &device.join("intel_vsec.crashlog.3"), "0x1");
    // Another device, a telemetry region, a look-alike name and a prefix that is not a parent directory.
    add_region(&class_dir, "crashlog3", &root.join("devices/0000:84:00.0/intel_vsec.crashlog.2"), "0x3");
    add_region(&class_dir, "telem3", &device.join("intel_vsec.telemetry.1"), "0x5");
    add_region(&class_dir, "crashlog_x", &device.join("intel_vsec.crashlog.2"), "0x6");
    add_region(&class_dir, "crashlog4", &root.join("devices/0000:03:00.01"), "0x7");

    let dir_rel = "dumps/0000-03-00.0/";
    let dev = device.to_string_lossy().into_owned();
    let reader = FsReader::new(false);
    let binary = pmt_crashlogs(&reader, &class_dir, dir_rel, &dev, PmtPart::Binary);
    assert_eq!(binary.len(), 3);
    assert_eq!(binary[0].rel_path, format!("{dir_rel}pmt-crashlog1.bin"));
    assert_eq!(binary[1].rel_path, format!("{dir_rel}pmt-crashlog10.bin"));
    assert_eq!(binary[2].rel_path, format!("{dir_rel}pmt-crashlog2.bin"));
    assert_eq!(binary[0].status, Status::Collected);
    assert_eq!(binary[0].data, [1, 2, 0, 4]);
    assert_eq!(binary[0].via, class_dir.join("crashlog1").to_string_lossy());
    assert!(reader.cap_seen.lock().unwrap().iter().all(|&c| c == 1024 * 1024));

    let info = pmt_crashlogs(&reader, &class_dir, dir_rel, &format!("{dev}/"), PmtPart::Info);
    assert_eq!(info.len(), 3);
    assert_eq!(info[0].rel_path, format!("{dir_rel}pmt-crashlog1.txt"));
    assert_eq!(
        String::from_utf8_lossy(&info[0].data),
        "guid: 0xe2f8200\nsize: 2048\noffset: 2736\nenable: 1\nerror: 0\ntrigger: 0\nconsumed: 0\n"
    );
    assert!(String::from_utf8_lossy(&info[2].data).starts_with("guid: 0x4e2f8210\n"));

    // The binary attribute is owner-only; the text attributes are not.
    let denied = FsReader::new(true);
    let out = pmt_crashlogs(&denied, &class_dir, dir_rel, &dev, PmtPart::Binary);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].status, Status::Skipped);
    assert_eq!(out[0].reason, "needs root");
    assert_eq!(pmt_crashlogs(&denied, &class_dir, dir_rel, &dev, PmtPart::Info).len(), 3);

    // A device with no region, and a missing class directory, produce nothing.
    let none = root.join("devices/none").to_string_lossy().into_owned();
    assert!(pmt_crashlogs(&reader, &class_dir, dir_rel, &none, PmtPart::Binary).is_empty());
    assert!(pmt_crashlogs(&reader, &root.join("absent"), dir_rel, &dev, PmtPart::Info).is_empty());
}

#[test]
fn a_missing_attribute_is_omitted() {
    let scratch = PrivateTempDir::create("xe-bug-report-test-").unwrap();
    let root = fs::canonicalize(scratch.path()).unwrap();
    let device = root.join("devices/0000:03:00.0");
    add_region(&root.join("class"), "crashlog1", &device.join("intel_vsec.crashlog.2"), "0x1");
    add_region(&root.join("class"), "crashlog2", &device.join("intel_vsec.crashlog.2"), "0x2");
    fs::remove_file(root.join("class/crashlog2/crashlog")).unwrap();
    let out = pmt_crashlogs(
        &FsReader::new(false),
        &root.join("class"),
        "dumps/x/",
        &device.to_string_lossy(),
        PmtPart::Binary,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rel_path, "dumps/x/pmt-crashlog1.bin");
}
