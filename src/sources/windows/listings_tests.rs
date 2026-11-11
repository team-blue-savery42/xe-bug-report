// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/windows/listings.rs`.

use super::*;

fn text(p: &Produced) -> String {
    String::from_utf8_lossy(&p.data).into_owned()
}

#[test]
fn roots_are_the_four_crash_folders() {
    let r = roots(Path::new("C:\\Windows"), Path::new("C:\\ProgramData"));
    let names: Vec<_> =
        r.iter().map(|r| r.path.file_name().unwrap().to_string_lossy().into_owned()).collect();
    assert_eq!(names, ["Minidump", "LiveKernelReports", "ReportArchive", "ReportQueue"]);
    assert!(r[0].filter.is_empty() && r[1].filter.is_empty());
    assert_eq!(r[2].filter, WER_NAME_PARTS);
    assert_eq!(r[3].filter, WER_NAME_PARTS);
    assert!(r[2].path.starts_with("C:\\ProgramData"));
}

#[test]
fn missing_directory_is_not_present() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root { path: dir.path().join("absent"), filter: &[] };
    let p = list_roots(std::slice::from_ref(&root));
    assert_eq!(p.status, Status::Collected);
    assert_eq!(p.rel_path, "dumps/listings.txt");
    assert_eq!(text(&p), format!("== {} ==\n  (not present)\n\n", root.path.to_string_lossy()));
}

#[test]
fn lists_files_directories_and_depth() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("b.dmp"), b"12345").unwrap();
    fs::write(dir.path().join("a.dmp"), b"").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub").join("c.dmp"), b"xyz").unwrap();
    let p = list_roots(&[Root { path: dir.path().to_path_buf(), filter: &[] }]);
    let t = text(&p);
    let lines: Vec<&str> = t.lines().collect();
    assert_eq!(lines.len(), 6, "{t}");
    assert!(lines[1].ends_with("           0  a.dmp"), "{}", lines[1]);
    assert!(lines[2].ends_with("           5  b.dmp"), "{}", lines[2]);
    assert!(lines[3].ends_with("       <DIR>  sub\\"), "{}", lines[3]);
    assert!(lines[4].ends_with("           3  sub\\c.dmp"), "{}", lines[4]);
    assert_eq!(lines[5], "");
    assert_eq!(p.status, Status::Collected);
    assert!(p.reason.is_empty());
}

#[test]
fn filter_applies_to_top_level_names_only_case_insensitively() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("Kernel_141_IGDKMD_1")).unwrap();
    fs::write(dir.path().join("Kernel_141_IGDKMD_1").join("Report.wer"), b"abc").unwrap();
    fs::create_dir(dir.path().join("AppCrash_notepad")).unwrap();
    fs::write(dir.path().join("note.txt"), b"x").unwrap();
    fs::create_dir(dir.path().join("LiveKernelEvent_1")).unwrap();
    let p = list_roots(&[Root { path: dir.path().to_path_buf(), filter: WER_NAME_PARTS }]);
    let t = text(&p);
    assert!(t.contains("Kernel_141_IGDKMD_1\\\n"), "{t}");
    assert!(t.contains("Kernel_141_IGDKMD_1\\Report.wer\n"), "{t}");
    assert!(t.contains("LiveKernelEvent_1\\\n"), "{t}");
    assert!(!t.contains("AppCrash"), "{t}");
    assert!(!t.contains("note.txt"), "{t}");
}

#[test]
fn depth_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    for i in 0..(MAX_LISTING_DEPTH + 3) {
        path = path.join(format!("d{i}"));
    }
    fs::create_dir_all(&path).unwrap();
    let p = list_roots(&[Root { path: dir.path().to_path_buf(), filter: &[] }]);
    // Entries at depth 0 ..= MAX_LISTING_DEPTH are listed; the last directory is not entered.
    let listed = text(&p).lines().filter(|l| l.contains("<DIR>")).count();
    assert_eq!(listed, MAX_LISTING_DEPTH + 1);
}

#[cfg(unix)]
#[test]
fn symlinks_are_listed_not_entered() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("real")).unwrap();
    fs::write(dir.path().join("real").join("f"), b"1").unwrap();
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    let t = text(&list_roots(&[Root { path: dir.path().to_path_buf(), filter: &[] }]));
    assert!(t.lines().any(|l| l.ends_with("      <LINK>  link")), "{t}");
    assert!(!t.contains("link\\f"), "{t}");
    assert!(t.contains("real\\f"), "{t}");
}

#[cfg(unix)]
#[test]
fn denied_directory_truncates_with_the_elevated_gate() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // Root can list anything; the check only makes sense for an ordinary user.
    let readable = fs::read_dir(&locked).is_ok();
    let p = list_roots(&[Root { path: locked.clone(), filter: &[] }]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    if readable {
        return;
    }
    assert_eq!(p.status, Status::Truncated);
    assert_eq!(p.reason, "1 directory could not be listed; needs an elevated (Administrator) prompt");
    assert!(text(&p).contains("  .: access denied (needs an elevated (Administrator) prompt)\n"));
}

#[test]
fn entry_limit_truncates() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        fs::write(dir.path().join(format!("f{i}")), b"1").unwrap();
    }
    let p = list_roots_limited(REL_PATH, &[Root { path: dir.path().to_path_buf(), filter: &[] }], 3);
    assert_eq!(p.status, Status::Truncated);
    assert_eq!(p.reason, "listing stopped after 3 entries");
    let t = text(&p);
    assert_eq!(t.lines().filter(|l| l.contains("  f")).count(), 3, "{t}");
    assert!(
        t.ends_with(
            "listing stopped after 3 entries
"
        ),
        "{t}"
    );
}

#[test]
fn filtered_out_names_do_not_use_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        fs::write(dir.path().join(format!("a{i}")), b"1").unwrap();
    }
    fs::write(dir.path().join("xpu_1"), b"1").unwrap();
    fs::write(dir.path().join("igd_2"), b"1").unwrap();
    let p =
        list_roots_limited(REL_PATH, &[Root { path: dir.path().to_path_buf(), filter: WER_NAME_PARTS }], 3);
    assert_eq!(p.status, Status::Collected);
    let t = text(&p);
    assert!(t.contains("igd_2") && t.contains("xpu_1"), "{t}");
    assert!(!t.contains("  a0"), "{t}");
}

#[test]
fn denial_text() {
    assert_eq!(denial_note(), "access denied (needs an elevated (Administrator) prompt)");
}

#[test]
fn name_matching() {
    assert!(name_matches("anything", &[]));
    assert!(name_matches("Kernel_IGD_1", WER_NAME_PARTS));
    assert!(name_matches("ZE_loader", WER_NAME_PARTS));
    assert!(!name_matches("AppCrash", WER_NAME_PARTS));
}

#[test]
fn kernel_report_folders_match_without_a_module_name() {
    // A GPU watchdog report folder carries the bugcheck code and a hash, not the driver module.
    for name in [
        "Kernel_141_0123456789abcdef0123456789abcdef01234567_00000000_cab_1a2b3c4d",
        "kernel_117_89abcdef",
        "Kernel_1a8_ffff",
    ] {
        assert!(name_matches(name, WER_NAME_PARTS), "{name}");
    }
    assert!(name_matches("AppCrash_igc64.dll_1", WER_NAME_PARTS));
    assert!(!name_matches("AppCrash_notepad.exe_1", WER_NAME_PARTS));
    assert!(!name_matches("NonCritical_7_1", WER_NAME_PARTS));
}

#[test]
fn the_user_crash_dump_folder_is_listed_under_its_own_name() {
    let dir = tempfile::tempdir().unwrap();
    let dumps = dir.path().join("CrashDumps");
    fs::create_dir(&dumps).unwrap();
    fs::write(dumps.join("app.exe.1234.dmp"), b"12345").unwrap();
    let roots = user_dump_roots(dir.path());
    assert_eq!(roots.len(), 1);
    assert!(roots[0].filter.is_empty());
    let p = list_user_dumps(&roots);
    assert_eq!(p.rel_path, "dumps/user-crashdumps.txt");
    assert_eq!(p.status, Status::Collected);
    assert!(text(&p).contains("           5  app.exe.1234.dmp\n"), "{}", text(&p));
}

#[test]
fn an_unknown_local_app_data_directory_skips_the_user_listing() {
    let p = produce_user_dumps(None);
    assert_eq!(p.rel_path, "dumps/user-crashdumps.txt");
    assert_eq!(p.status, Status::Skipped);
    assert!(p.data.is_empty());
    assert!(!p.reason.is_empty());
}

#[test]
fn a_missing_user_crash_dump_folder_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = list_user_dumps(&user_dump_roots(dir.path()));
    assert_eq!(p.status, Status::Collected);
    assert!(text(&p).contains("(not present)"));
}
