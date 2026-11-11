// SPDX-License-Identifier: MIT
//! Unit tests for `src/bundle/writer.rs`.

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

use super::*;
use crate::bundle::source::Profile;
use crate::procio::find_in_path;

fn request(output: &Path) -> BundleRequest {
    BundleRequest {
        output: output.to_path_buf(),
        options: SourceOptions { profile: Profile::Default, ..SourceOptions::default() },
        rules: redact::Rules::none(),
        deadline: None,
    }
}

fn fake_sources(dir: &Path) -> Arc<[Source]> {
    fs::create_dir_all(dir.join("tree/sub")).unwrap();
    fs::write(dir.join("one.txt"), "hello\n").unwrap();
    fs::write(dir.join("tree/a"), "a").unwrap();
    fs::write(dir.join("tree/sub/b"), "b").unwrap();
    let sources = vec![
        Source::file("system/one.txt", dir.join("one.txt"), Profile::Minimal, "t"),
        Source::file("system/missing.txt", dir.join("missing"), Profile::Minimal, "t"),
        Source::tree("devices/d/sysfs/", dir.join("tree"), &["a", "sub/*"], Profile::Minimal, "t"),
        Source::command(
            "tools/out/",
            &["/bin/sh", "-c", "echo $0 > /dev/null; echo hi > \"$0/f\"; echo out", "{outdir}"],
            Profile::Minimal,
            "t",
        ),
        Source::builtin(
            "kernel/b.txt",
            Box::new(|_| {
                vec![crate::bundle::source::Produced {
                    rel_path: "kernel/b.txt".into(),
                    data: b"built".to_vec(),
                    ..Default::default()
                }]
            }),
            Profile::Minimal,
            "t",
        ),
        Source::xpu_smi("xpu-smi/version.txt", &["-v".to_owned()], Profile::Minimal, "t"),
    ];
    sources.into()
}

fn unzip(args: &[&str], zip: &Path) -> Option<String> {
    let unzip = find_in_path("unzip")?;
    let output = Command::new(unzip).args(args).arg(zip).output().ok()?;
    assert!(output.status.success(), "unzip {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn entry_text(zip: &Path, name: &str) -> Option<String> {
    let unzip = find_in_path("unzip")?;
    let out = Command::new(unzip).arg("-p").arg(zip).arg(name).output().ok()?;
    assert!(out.status.success());
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn manifest_of(zip: &Path) -> Option<Value> {
    Some(serde_json::from_str(&entry_text(zip, "manifest.json")?).unwrap())
}

#[test]
fn the_default_name_is_utc_and_sortable() {
    let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(default_bundle_name(when), "xe-bug-report-20231114T221320Z.zip");
    let name = default_bundle_name(SystemTime::now());
    assert!(name.starts_with("xe-bug-report-") && name.ends_with("Z.zip"), "{name}");
    assert_eq!(name.len(), "xe-bug-report-YYYYMMDDTHHMMSSZ.zip".len());
}

#[test]
fn the_partial_path_appends_to_the_whole_name() {
    assert_eq!(partial_path(Path::new("/tmp/a.zip")), Path::new("/tmp/a.zip.partial"));
    assert_eq!(partial_path(Path::new("b")), Path::new("b.partial"));
}

#[test]
fn a_bundle_lists_manifest_last_and_passes_unzip() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    let result = write_bundle_with(&request(&output), fake_sources(tmp.path())).unwrap();

    assert_eq!(result.artifacts.len(), 6);
    assert_eq!(result.archive_bytes.get(), fs::metadata(&output).unwrap().len());
    assert_eq!(result.compression, Compression::Deflate);
    assert!(!partial_path(&output).exists());
    let statuses: Vec<Status> = result.artifacts.iter().map(|a| a.status).collect();
    assert_eq!(
        statuses,
        [
            Status::Collected,
            Status::Skipped,
            Status::Collected,
            Status::Collected,
            Status::Collected,
            Status::Skipped
        ]
    );
    assert_eq!(result.artifacts[5].reason, "xpu-smi not found");

    let Some(test) = unzip(&["-t"], &output) else { return };
    assert!(test.contains("No errors detected"), "{test}");
    let list = unzip(&["-Z1"], &output).unwrap();
    let names: Vec<&str> = list.lines().collect();
    assert_eq!(
        names,
        [
            "system/one.txt",
            "devices/d/sysfs/a",
            "devices/d/sysfs/sub/b",
            "tools/out/stdout.txt",
            "tools/out/f",
            "kernel/b.txt",
            "manifest.json"
        ]
    );

    let manifest = manifest_of(&output).unwrap();
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["profile"], "default");
    assert_eq!(manifest["compression"], "deflate");
    assert_eq!(manifest["redaction"], serde_json::json!([]));
    assert!(manifest.get("identity").is_none());
    assert!(manifest.get("xpu_smi").is_none());
    let sources = manifest["sources"].as_array().unwrap();
    let paths: Vec<&str> = sources.iter().map(|s| s["path"].as_str().unwrap()).collect();
    assert_eq!(
        paths,
        [
            "system/one.txt",
            "system/missing.txt",
            "devices/d/sysfs/",
            "tools/out/",
            "kernel/b.txt",
            "xpu-smi/version.txt"
        ]
    );
    assert_eq!(sources[1]["reason"], "not present");
    assert_eq!(sources[2]["files"], 2);
    assert_eq!(sources[3]["files"], 2);
    assert_eq!(sources[5]["reason"], "xpu-smi not found");
}

#[test]
fn the_manifest_is_indented_by_two_and_ends_with_a_newline() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    write_bundle_with(&request(&output), fake_sources(tmp.path())).unwrap();
    let Some(text) = entry_text(&output, "manifest.json") else { return };
    assert!(text.starts_with("{\n  \"schema\": 1,\n"), "{text}");
    assert!(text.ends_with("}\n"), "{text}");
}

#[test]
fn xpu_smi_is_recorded_in_the_manifest_when_found() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    let mut request = request(&output);
    request.options.xpu_smi = Some(PathBuf::from("/bin/sh"));
    let sources: Arc<[Source]> = vec![Source::xpu_smi(
        "xpu-smi/version.txt",
        &["-c".to_owned(), "echo xpu-smi version 9".to_owned()],
        Profile::Minimal,
        "t",
    )]
    .into();
    let result = write_bundle_with(&request, sources).unwrap();
    assert_eq!(result.artifacts[0].status, Status::Collected);
    let Some(manifest) = manifest_of(&output) else { return };
    assert_eq!(manifest["xpu_smi"]["path"], "/bin/sh");
    assert!(manifest["xpu_smi"]["version"].is_string());
}

#[test]
fn redaction_is_applied_and_recorded() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    let identity = resolve_identity(IDENTITY_LIMIT).context;
    let Some(host) = identity.hostnames.first().cloned() else { return };
    fs::write(tmp.path().join("f.txt"), format!("on {host} up\n")).unwrap();
    let mut request = request(&output);
    request.rules = redact::Rules::default();
    let sources: Arc<[Source]> =
        vec![Source::file("system/f.txt", tmp.path().join("f.txt"), Profile::Minimal, "t")].into();
    write_bundle_with(&request, sources).unwrap();
    let Some(text) = entry_text(&output, "system/f.txt") else { return };
    assert!(!text.contains(&host), "{text}");
    assert!(text.contains("<host>"), "{text}");
    let manifest = manifest_of(&output).unwrap();
    assert_eq!(manifest["redaction"], serde_json::json!(["serials", "hostname", "users", "addresses"]));
}

#[test]
fn an_expired_deadline_still_finishes_the_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    let mut request = request(&output);
    request.deadline = Some(Instant::now());
    let result = write_bundle_with(&request, fake_sources(tmp.path())).unwrap();
    assert!(result.artifacts.iter().all(|a| a.status == Status::Skipped));
    assert!(result.artifacts.iter().all(|a| a.reason == "collector deadline reached"));
    let Some(test) = unzip(&["-t"], &output) else { return };
    assert!(test.contains("No errors detected"), "{test}");
    assert_eq!(unzip(&["-Z1"], &output).unwrap().trim(), "manifest.json");
}

#[test]
fn an_existing_output_is_refused_and_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("exists.zip");
    fs::write(&output, "x").unwrap();
    let error = write_bundle_with(&request(&output), fake_sources(tmp.path())).unwrap_err();
    assert!(matches!(error, Error::OutputExists(_)));
    assert_eq!(error.to_string(), format!("{} already exists", output.display()));
    assert_eq!(fs::read_to_string(&output).unwrap(), "x");
    assert!(!partial_path(&output).exists());
}

#[test]
fn an_unwritable_directory_is_reported_without_a_trace() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("no-such-dir/out.zip");
    let error = write_bundle_with(&request(&output), fake_sources(tmp.path())).unwrap_err();
    assert!(matches!(error, Error::OutputUnwritable { .. }), "{error}");
    assert!(error.to_string().starts_with("cannot create "), "{error}");
    assert!(!tmp.path().join("no-such-dir").exists());
}

#[test]
fn a_non_utf8_output_path_works() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join(OsStr::from_bytes(b"bad\xffname.zip"));
    let result = write_bundle_with(&request(&output), fake_sources(tmp.path())).unwrap();
    assert!(output.exists());
    let json = crate::bundle::summary::json_result(&result, &output);
    let text = json_text(&json, crate::bundle::summary::JSON_INDENT);
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert!(parsed["file"].as_str().unwrap().contains("bad"));
    if let Some(test) = unzip(&["-t"], &output) {
        assert!(test.contains("No errors detected"));
    }
}

#[test]
fn no_output_directory_survives_a_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("bundle.zip");
    let marker = tmp.path().join("dir");
    let script = format!("echo \"$0\" > {}; echo hi > \"$0/f\"", marker.display());
    let sources: Arc<[Source]> =
        vec![Source::command("tools/out/", &["/bin/sh", "-c", &script, "{outdir}"], Profile::Minimal, "t")]
            .into();
    let result = write_bundle_with(&request(&output), sources).unwrap();
    assert_eq!(result.artifacts[0].status, Status::Collected);
    let dir = PathBuf::from(fs::read_to_string(&marker).unwrap().trim());
    assert!(!dir.exists(), "{} survived", dir.display());
}

#[test]
fn the_backstop_fires_after_the_grace() {
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    let started = Instant::now();
    let handle = spawn_backstop(Instant::now(), Duration::from_millis(150), move || {
        flag.store(true, Ordering::SeqCst);
    })
    .unwrap()
    .unwrap();
    assert!(!fired.load(Ordering::SeqCst));
    handle.join().unwrap();
    assert!(fired.load(Ordering::SeqCst));
    assert!(started.elapsed() >= Duration::from_millis(150));
}

#[test]
fn the_backstop_waits_for_the_deadline_plus_the_grace() {
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    let deadline = Instant::now() + Duration::from_millis(200);
    let _handle = spawn_backstop(deadline, Duration::from_millis(200), move || {
        flag.store(true, Ordering::SeqCst);
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(250));
    assert!(!fired.load(Ordering::SeqCst), "fired before deadline + grace");
    std::thread::sleep(Duration::from_millis(400));
    assert!(fired.load(Ordering::SeqCst));
}

#[test]
fn a_backstop_beyond_the_clock_range_is_not_started() {
    let handle = spawn_backstop(Instant::now(), Duration::MAX, || panic!("must not fire")).unwrap();
    assert!(handle.is_none());
    assert_eq!(BACKSTOP_EXIT_CODE, 124);
    assert_eq!(BACKSTOP_GRACE, Duration::from_secs(60));
}

#[test]
fn leftovers_include_the_partial_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("x.zip");
    fs::write(partial_path(&output), "half").unwrap();
    // Not `remove_leftovers`: it removes the `{outdir}` of every test running in parallel.
    remove_partial(&output);
    assert!(!partial_path(&output).exists());
    remove_partial(&output);
}
