// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/wer.rs`.

use super::*;
use crate::bundle::source::{ReadResult, Status};

/// The shape of a GPU watchdog report; the machine, user and driver names are made up.
const REPORT: &str = "Version=1\r\nEventType=LiveKernelEvent\r\nEventTime=133800000000000000\r\n\
ReportType=4\r\nConsent=1\r\nUploadTime=133800000100000000\r\nReportIdentifier=0b0f6d4c-1111-2222-3333-444455556666\r\n\
IntegratorReportIdentifier=aaaaaaaa-1111-2222-3333-444455556666\r\nWow64Host=34404\r\nNsAppName=LiveKernelEvent\r\n\
Response.BucketId=0123456789abcdef0123456789abcdef\r\nResponse.BucketTable=5\r\nResponse.type=4\r\n\
Sig[0].Name=Problem Event Name\r\nSig[0].Value=LiveKernelEvent\r\nSig[1].Name=Code\r\nSig[1].Value=141\r\n\
Sig[2].Name=Parameter 1\r\nSig[2].Value=ffffc00123456789\r\nSig[3].Name=Parameter 2\r\nSig[3].Value=fffff80012345678\r\n\
DynamicSig[1].Name=OS Version\r\nDynamicSig[1].Value=10.0.26100.2.0.0.256.48\r\n\
DynamicSig[2].Name=Locale ID\r\nDynamicSig[2].Value=1033\r\n\
UI[2]=C:\\Users\\jdoe\\AppData\\Local\\Temp\\x.exe\r\nLoadedModule[0]=C:\\Windows\\system32\\ntdll.dll\r\n\
State[0].Key=Transport.DoneStage1\r\nState[0].Value=1\r\nFriendlyEventName=Hardware error\r\nConsentKey=LiveKernelEvent\r\n\
AppName=Windows\r\nAppPath=C:\\Windows\\System32\\wer.exe\r\nMachineName=WORKSTATION1\r\n";

fn utf16le(text: &str, with_bom: bool) -> Vec<u8> {
    let mut bytes = if with_bom { vec![0xff, 0xfe] } else { Vec::new() };
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// A reader over the real file system without the collector's guards.
struct FsReader;

impl Reader for FsReader {
    fn read(&self, path: &Path, max: Bytes, _keep: Keep) -> ReadResult {
        match fs::read(path) {
            Ok(mut data) => {
                data.truncate(usize::try_from(max.get()).unwrap_or(usize::MAX));
                ReadResult { outcome: ReadOutcome::Read, data, ..ReadResult::default() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ReadResult { outcome: ReadOutcome::Missing, ..ReadResult::default() }
            }
            Err(e) => {
                ReadResult { outcome: ReadOutcome::Failed, error: e.to_string(), ..ReadResult::default() }
            }
        }
    }
}

/// A reader that denies every file.
struct DenyingReader;

impl Reader for DenyingReader {
    fn read(&self, _path: &Path, _max: Bytes, _keep: Keep) -> ReadResult {
        ReadResult { outcome: ReadOutcome::Denied, ..ReadResult::default() }
    }
}

#[test]
fn utf16_with_a_byte_order_mark_decodes() {
    assert_eq!(decode_report(&utf16le(REPORT, true)), REPORT);
}

#[test]
fn utf16_without_a_byte_order_mark_decodes() {
    assert_eq!(decode_report(&utf16le("Version=1\r\n", false)), "Version=1\r\n");
}

#[test]
fn big_endian_utf16_decodes() {
    let mut bytes = vec![0xfe, 0xff];
    for unit in "Version=1".encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    assert_eq!(decode_report(&bytes), "Version=1");
}

#[test]
fn utf8_and_garbage_decode_without_failing() {
    assert_eq!(decode_report(b"\xef\xbb\xbfVersion=1"), "Version=1");
    assert_eq!(decode_report(b"Version=1"), "Version=1");
    assert_eq!(decode_report(b""), "");
    // An odd trailing byte and a lone surrogate are replaced, not fatal.
    let mut bytes = vec![0xff, 0xfe, 0x00, 0xd8, b'a'];
    assert_eq!(decode_report(&bytes), "\u{fffd}");
    bytes.truncate(2);
    assert_eq!(decode_report(&bytes), "");
}

#[test]
fn filetimes_become_dates() {
    // 133800000000000000 ticks is 2024-12-30 in UTC; 116444736000000000 is the Unix epoch.
    assert_eq!(filetime_to_utc("116444736000000000").as_deref(), Some("1970-01-01T00:00:00Z"));
    assert_eq!(filetime_to_utc(" 116444736010000000 ").as_deref(), Some("1970-01-01T00:00:01Z"));
    assert!(filetime_to_utc("133800000000000000").unwrap().starts_with("2024-"));
    assert_eq!(filetime_to_utc("0"), None);
    assert_eq!(filetime_to_utc("abc"), None);
    assert_eq!(filetime_to_utc(""), None);
    assert_eq!(filetime_to_utc("-5"), None);
    // Huge values must not panic where SystemTime is narrower than u64 seconds; they give None or a
    // clamped date.
    for huge in ["18446744073709551615", "9223372036854775808", "9223372036854775807"] {
        let _ = filetime_to_utc(huge);
    }
    assert_eq!(filetime_to_utc("18446744073709551616"), None);
}

#[test]
fn only_whitelisted_keys_survive() {
    let lines = summarize_report(REPORT);
    assert!(lines.contains(&"EventType=LiveKernelEvent".to_owned()));
    assert!(lines.contains(&"Sig[1].Name=Code".to_owned()));
    assert!(lines.contains(&"Sig[1].Value=141".to_owned()));
    assert!(lines.contains(&"Sig[2].Value=ffffc00123456789".to_owned()));
    assert!(lines.contains(&"DynamicSig[1].Value=10.0.26100.2.0.0.256.48".to_owned()));
    assert!(lines.contains(&"Response.BucketId=0123456789abcdef0123456789abcdef".to_owned()));
    assert!(lines.contains(&"FriendlyEventName=Hardware error".to_owned()));
    let joined = lines.join("\n");
    for dropped in [
        "UI[2]",
        "LoadedModule",
        "State[0]",
        "AppPath",
        "MachineName",
        "WORKSTATION1",
        "jdoe",
        "Wow64Host",
        "Consent=1",
    ] {
        assert!(!joined.contains(dropped), "{dropped} in {joined}");
    }
}

#[test]
fn times_carry_their_date() {
    let lines = summarize_report(REPORT);
    let event = lines.iter().find(|l| l.starts_with("EventTime=")).unwrap();
    assert!(event.starts_with("EventTime=133800000000000000 (2024-"), "{event}");
    assert!(event.ends_with("Z)"), "{event}");
    let upload = lines.iter().find(|l| l.starts_with("UploadTime=")).unwrap();
    assert!(upload.starts_with("UploadTime=133800000100000000 (2024-"), "{upload}");
    // A time that is not a number is kept as it is.
    assert_eq!(summarize_report("EventTime=soon\n"), ["EventTime=soon"]);
}

#[test]
fn signature_keys_need_a_numeric_index_and_a_known_field() {
    assert!(is_signature_key("Sig[12].Name", "Sig"));
    assert!(is_signature_key("DynamicSig[0].Value", "DynamicSig"));
    for key in [
        "Sig[].Name",
        "Sig[x].Name",
        "Sig[1].Other",
        "Sig[1]",
        "Sig1.Name",
        "DynamicSig[1].Name",
        "sig[1].Name",
    ] {
        assert!(!is_signature_key(key, "Sig"), "{key}");
    }
}

#[test]
fn long_values_are_cut_and_odd_lines_ignored() {
    let long = format!("Sig[0].Value={}\nno equals sign\n=x\n\n", "a".repeat(1000));
    let lines = summarize_report(&long);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].chars().count(), "Sig[0].Value=".len() + MAX_VALUE_CHARS);
    assert!(summarize_report("").is_empty());
    assert!(summarize_report("\u{feff}Version=1\n").contains(&"Version=1".to_owned()));
}

#[test]
fn kernel_folder_names() {
    assert!(is_kernel_report_folder("Kernel_141_0123456789abcdef_00000000_cab_1a2b3c4d"));
    assert!(is_kernel_report_folder("KERNEL_117_x"));
    assert!(!is_kernel_report_folder("Kernel_"));
    assert!(!is_kernel_report_folder("AppCrash_x"));
    assert!(!is_kernel_report_folder("Kernel"));
    assert!(!is_kernel_report_folder("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"));
}

fn folder(name: &str, modified: Option<SystemTime>) -> ReportFolder {
    ReportFolder { area: "ReportArchive", name: name.to_owned(), path: PathBuf::from(name), modified }
}

#[test]
fn a_report_block_has_header_files_and_keys() {
    let block = format_report(
        &folder("Kernel_141_abc", Some(UNIX_EPOCH + Duration::from_secs(86_400))),
        &[("Report.wer".to_owned(), 2310), ("WD-1.dmp".to_owned(), 1_048_576)],
        &ReportText::Text("Sig[1].Name=Code\nSig[1].Value=141\nUI[2]=secret\n".to_owned()),
    );
    assert_eq!(
        block,
        "== ReportArchive\\Kernel_141_abc (modified 1970-01-02T00:00:00Z) ==\n  files: Report.wer 2310, WD-1.dmp 1048576\n  \
Sig[1].Name=Code\n  Sig[1].Value=141\n\n"
    );
}

#[test]
fn report_block_notes_for_unreadable_reports() {
    let none = format_report(&folder("Kernel_1_a", None), &[], &ReportText::Missing);
    assert_eq!(
        none,
        "== ReportArchive\\Kernel_1_a (modified -) ==\n  files: none listed\n  Report.wer: not present\n\n"
    );
    let denied = format_report(&folder("Kernel_1_a", None), &[], &ReportText::Denied);
    assert!(denied.contains("access denied (needs an elevated (Administrator) prompt)"), "{denied}");
    let failed = format_report(&folder("Kernel_1_a", None), &[], &ReportText::Failed("boom".to_owned()));
    assert!(failed.contains("Report.wer: cannot be read: boom"), "{failed}");
    let empty =
        format_report(&folder("Kernel_1_a", None), &[], &ReportText::Text("nothing useful\n".to_owned()));
    assert!(empty.contains("Report.wer: no recognised keys"), "{empty}");
}

fn make_report(root: &Path, area: &str, name: &str, body: &str) -> PathBuf {
    let dir = root.join(area).join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("Report.wer"), utf16le(body, true)).unwrap();
    fs::write(dir.join("WD-20250324-1200.dmp"), b"MDMP").unwrap();
    dir
}

#[test]
fn reports_of_both_areas_are_summarised_and_other_folders_skipped() {
    let wer = tempfile::tempdir().unwrap();
    make_report(wer.path(), "ReportArchive", "Kernel_141_aaaa", REPORT);
    make_report(wer.path(), "ReportQueue", "Kernel_117_bbbb", "Sig[1].Name=Code\nSig[1].Value=117\n");
    make_report(wer.path(), "ReportArchive", "AppCrash_notepad.exe_1", "Sig[1].Value=other\n");
    fs::write(wer.path().join("ReportArchive").join("Kernel_file"), b"x").unwrap();
    let p = produce(wer.path(), &FsReader);
    assert_eq!(p.rel_path, "dumps/wer-kernel-reports.txt");
    assert_eq!(p.status, Status::Collected);
    assert!(p.reason.is_empty());
    let text = String::from_utf8(p.data).unwrap();
    assert!(text.contains("== ReportArchive\\Kernel_141_aaaa"), "{text}");
    assert!(text.contains("== ReportQueue\\Kernel_117_bbbb"), "{text}");
    assert!(text.contains("  files: Report.wer "), "{text}");
    assert!(text.contains("WD-20250324-1200.dmp 4"), "{text}");
    assert!(text.contains("  Sig[1].Value=141\n"), "{text}");
    assert!(text.contains("  Sig[1].Value=117\n"), "{text}");
    assert!(!text.contains("AppCrash") && !text.contains("Kernel_file"), "{text}");
    assert!(!text.contains("MDMP"), "{text}");
}

#[test]
fn a_clean_machine_gives_a_note() {
    let wer = tempfile::tempdir().unwrap();
    let p = produce(wer.path(), &FsReader);
    assert_eq!(p.status, Status::Collected);
    assert_eq!(String::from_utf8(p.data).unwrap(), "no kernel report folders\n");
    let absent = produce(&wer.path().join("absent"), &FsReader);
    assert_eq!(absent.status, Status::Collected);
}

#[test]
fn only_the_newest_reports_are_summarised() {
    let wer = tempfile::tempdir().unwrap();
    for i in 0..(MAX_REPORTS + 5) {
        make_report(wer.path(), "ReportArchive", &format!("Kernel_141_{i:03}"), "Sig[1].Value=141\n");
    }
    let p = produce(wer.path(), &FsReader);
    let text = String::from_utf8(p.data).unwrap();
    assert_eq!(text.matches("== ReportArchive").count(), MAX_REPORTS);
    assert!(text.ends_with("5 older report folders not shown\n"), "{text}");
}

#[test]
fn denied_reports_make_the_artifact_truncated_with_the_elevation_gate() {
    let wer = tempfile::tempdir().unwrap();
    make_report(wer.path(), "ReportArchive", "Kernel_141_aaaa", REPORT);
    let p = produce(wer.path(), &DenyingReader);
    assert_eq!(p.status, Status::Truncated);
    assert_eq!(p.reason, "needs an elevated (Administrator) prompt");
    let text = String::from_utf8(p.data).unwrap();
    assert!(text.contains("Report.wer: access denied"), "{text}");
    assert!(text.contains("Kernel_141_aaaa"), "{text}");
}
