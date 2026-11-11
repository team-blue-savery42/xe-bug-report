// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/text.rs`.

use super::*;
use std::time::Duration;

fn read_of(data: &str) -> ReadResult {
    ReadResult { outcome: ReadOutcome::Read, data: data.as_bytes().to_vec(), ..Default::default() }
}

fn outcome_of(outcome: ReadOutcome, error: &str) -> ReadResult {
    ReadResult { outcome, error: error.to_owned(), ..Default::default() }
}

fn bdf(domain: u32, bus: u8, device: u8, function: u8) -> PciAddress {
    PciAddress { domain, bus, device, function }
}

const PATH_A: &str = "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/0000:02:01.0/0000:03:00.0";
const PATH_B: &str = "/sys/devices/pci0000:80/0000:80:01.0/0000:84:00.0";

#[test]
fn kmsg_records_are_formatted_like_dmesg() {
    let f = |s: &str| format_kmsg_record(s.as_bytes());
    assert_eq!(
        f("6,339,5140900,-;NetworkManager started\n").unwrap(),
        "[    5.140900] NetworkManager started"
    );
    assert_eq!(
        f("6,1,123456789,-,caller=T1;hello\n SUBSYSTEM=acpi\n DEVICE=+acpi:x\n").unwrap(),
        "[  123.456789] hello"
    );
    assert_eq!(f("4,2,0,-;at zero").unwrap(), "[    0.000000] at zero");
    assert_eq!(f("6,5,100000000000,c;big").unwrap(), "[100000.000000] big");
    assert_eq!(f("6,9,1000000,-;a\\x5cb\\x09tab\\xZZ\n").unwrap(), "[    1.000000] a\\b\ttab\\xZZ");
    assert_eq!(f("6,9,1000000,-;msg; with semicolon").unwrap(), "[    1.000000] msg; with semicolon");
    assert!(f("no separator").is_none());
    assert!(f("6,1;too few fields").is_none());
    assert!(f("6,1,abc,-;bad usec").is_none());
    assert!(f("6,1,+5,-;signed usec").is_none());
    assert!(f("").is_none());
    // Escapes forming UTF-8 decode to the character; a lone high byte becomes U+FFFD; no panic
    // on a record that is not UTF-8.
    assert_eq!(f("6,1,1,-;en\\xe2\\x80\\x93dash").unwrap(), "[    0.000001] en\u{2013}dash");
    assert!(format_kmsg_record(b"6,1,1,-;bad \xff bytes").unwrap().contains('\u{fffd}'));
    // An escape cut off at the end of the message stays as written.
    assert_eq!(f("6,1,1,-;end\\x4").unwrap(), "[    0.000001] end\\x4");
}

#[test]
fn kmsg_timestamps() {
    let t = |s: &str| kmsg_timestamp(s.as_bytes());
    assert_eq!(t("6,339,5140900,-;NetworkManager started\n"), Some(Duration::from_micros(5_140_900)));
    assert_eq!(
        t("6,1,123456789,-,caller=T1;hello\n SUBSYSTEM=acpi\n"),
        Some(Duration::from_micros(123_456_789))
    );
    assert_eq!(t("6,1,0,-;at zero"), Some(Duration::ZERO));
    assert_eq!(t("no separator"), None);
    assert_eq!(t("6,1,abc,-;bad usec"), None);
    assert_eq!(t("6,1,99999999999999999999,-;too big"), None);
}

#[test]
fn journal_arguments() {
    let count = JOURNAL_MAX_LINES.to_string();
    let tail = ["--no-pager", "-q", "-o", "short-monotonic"];
    let expect =
        |head: &[&str]| -> Vec<String> { head.iter().chain(tail.iter()).map(|s| (*s).to_owned()).collect() };
    assert_eq!(journal_argv(None, false), expect(&["journalctl", "-k", "-b", "0", "-n", &count]));
    assert_eq!(journal_argv(None, true), expect(&["journalctl", "-k", "-b", "-1", "-n", &count]));
    // A window uses the transport match, because -k implies -b; it ignores the flag.
    // It passes no -n, which makes journalctl scan the whole journal.
    let window = expect(&["journalctl", "_TRANSPORT=kernel", "--since=-30min"]);
    assert_eq!(journal_argv(Some(Duration::from_secs(30 * 60)), false), window);
    assert_eq!(journal_argv(Some(Duration::from_secs(30 * 60)), true), window);
    assert_eq!(journal_argv(Some(Duration::from_secs(2 * 3600)), false)[2], "--since=-120min");
    assert!(!window.iter().any(|a| a == "-k" || a == "-b" || a == "-n"));
    assert_eq!(journal_argv(Some(Duration::from_secs(5)), false)[2], "--since=-1min");
    assert_eq!(journal_argv(Some(Duration::from_secs(30 * 86_400)), false)[2], "--since=-43200min");
}

#[test]
fn windows_are_described_in_whole_units() {
    let m = |n: u64| describe_window(Duration::from_secs(n * 60));
    assert_eq!(m(1), "1 minute");
    assert_eq!(m(30), "30 minutes");
    assert_eq!(m(90), "90 minutes");
    assert_eq!(m(60), "1 hour");
    assert_eq!(m(120), "2 hours");
    assert_eq!(m(1440), "1 day");
    assert_eq!(m(30 * 1440), "30 days");
    assert_eq!(m(36 * 60), "36 hours");
}

#[test]
fn journal_output_is_classified() {
    use JournalVerdict::*;
    assert_eq!(classify_journal(0, "[    1.0] host kernel: hello\n"), Ok);
    assert_eq!(classify_journal(0, ""), NoEntries);
    assert_eq!(classify_journal(0, "-- No entries --\n"), NoEntries);
    assert_eq!(classify_journal(0, "  \n"), NoEntries);
    assert_eq!(
        classify_journal(
            0,
            "Hint: You are currently not seeing messages from other users and the system.\n-- No entries --\n"
        ),
        Unusable
    );
    assert_eq!(classify_journal(1, "-- No entries --\n"), Unusable);
    assert_eq!(classify_journal(1, "boom"), Unusable);
    assert_eq!(
        classify_journal(
            1,
            "Data from the specified boot (-1) is not available: No such boot ID in journal\n"
        ),
        NoPersistentJournal
    );
    assert_eq!(classify_journal(0, "No journal files were found.\n-- No entries --\n"), NoPersistentJournal);
    // systemd 255 spelling of a boot that is not in the journal.
    assert_eq!(
        classify_journal(1, "No journal boot entry found from the specified boot offset (-50).\n"),
        NoPersistentJournal
    );
}

#[test]
fn markers_inside_a_real_log_do_not_misclassify_it() {
    let log = "[    0.000000] Linux version 7.2\n\
                   [    1.2] xe 0000:03:00.0: [drm] GuC firmware: version not available\n\
                   [    2.0] done\n";
    assert_eq!(classify_journal(0, log), JournalVerdict::Ok);
    // The same words in a log longer than a diagnostic can be are still ignored.
    let long = format!("{}{log}", "[    0.1] filler line of kernel text\n".repeat(60));
    assert!(long.len() > DIAGNOSTIC_MAX);
    assert_eq!(classify_journal(0, &long), JournalVerdict::Ok);
    let hint = format!("{long}Hint: You are currently not seeing messages from other users\n");
    assert_eq!(classify_journal(0, &hint), JournalVerdict::Ok);
}

#[test]
fn os_release_pretty_name() {
    let p = |s: &str| parse_pretty_name(s);
    assert_eq!(
        p("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nID=ubuntu\n").unwrap(),
        "Ubuntu 24.04.3 LTS"
    );
    assert_eq!(p("PRETTY_NAME='Fedora Linux 42'\n").unwrap(), "Fedora Linux 42");
    assert_eq!(p("PRETTY_NAME=Plain\r\n").unwrap(), "Plain");
    assert_eq!(p("  PRETTY_NAME=\"Indented\"  \n").unwrap(), "Indented");
    assert!(p("NAME=\"Ubuntu\"\nID=ubuntu\n").is_none());
    assert!(p("PRETTY_NAME=\"\"\n").is_none());
    assert!(p("").is_none());
    assert!(p("XPRETTY_NAME=\"no\"\n").is_none());
    assert_eq!(
        format_os_description("Ubuntu 24.04.3 LTS", "Linux", "7.2.0", "x86_64"),
        "Ubuntu 24.04.3 LTS, Linux 7.2.0 x86_64"
    );
    assert_eq!(format_os_description("", "Linux", "6.1", "aarch64"), "Linux, Linux 6.1 aarch64");
}

#[test]
fn sysfs_vendor_and_class_select_intel_gpus() {
    assert!(is_intel_gpu_class("0x8086\n", "0x030000\n"));
    assert!(is_intel_gpu_class("0x8086", "0x038000"));
    assert!(is_intel_gpu_class("0x8086\n", "0x120000\n"));
    assert!(!is_intel_gpu_class("0x10de\n", "0x030000\n"));
    assert!(!is_intel_gpu_class("0x8086\n", "0x060400\n"));
    assert!(!is_intel_gpu_class("0x8086\n", "0x040300\n"));
    assert!(!is_intel_gpu_class("", "0x030000\n"));
    assert!(!is_intel_gpu_class("0x8086\n", ""));
    assert!(!is_intel_gpu_class("junk", "0x030000"));
    assert!(!is_intel_gpu_class("0x8086", "0xFF030000"));
    assert!(!is_intel_gpu_class("0x+886", "0x030000"));
}

#[test]
fn upstream_bridges_come_nearest_first() {
    assert_eq!(upstream_bridges(PATH_A), vec![bdf(0, 2, 1, 0), bdf(0, 1, 0, 0), bdf(0, 0, 1, 0)]);
    assert!(upstream_bridges("/sys/devices/pci0000:00/0000:00:02.0").is_empty());
    assert!(upstream_bridges("").is_empty());
    assert_eq!(upstream_bridges(PATH_B).len(), 1);
    // A domain above 0xffff (a device behind VMD) has more than four digits.
    let vmd = upstream_bridges("/sys/devices/pci0000:00/0000:00:0e.0/10000:e0:06.0/10000:e1:00.0");
    assert_eq!(vmd, vec![bdf(0x10000, 0xe0, 6, 0), bdf(0, 0, 0x0e, 0)]);
}

#[test]
fn environment_filter_keeps_gpu_runtime_variables_sorted() {
    let env: Vec<String> = [
        "HOME=/home/u",
        "ZE_AFFINITY_MASK=0",
        "PATH=/usr/bin",
        "NEO_CACHE_DIR=/tmp/x",
        "container=docker",
        "SECRET_TOKEN=abc",
        "LD_PRELOAD=/usr/lib/x.so",
        "ZE_NOEQUALS",
        "XPU_SMI_DEBUG=1",
        "INTEL_DEBUG=perf",
        "LANGUAGE=en",
        "LANG=C",
        "MESA_LOADER_DRIVER_OVERRIDE=iris",
        "ANV_DEBUG=startup",
        "VK_DRIVER_FILES=/usr/share/vulkan/icd.d/intel_icd.x86_64.json",
        "DRI_PRIME=1",
        "EGL_PLATFORM=surfaceless",
        "XDG_SESSION_TYPE=wayland",
        "vblank_mode=0",
        "CLASSPATH=/x",
        "PrintDebugMessages=1",
    ]
    .map(str::to_owned)
    .to_vec();
    assert_eq!(
        filter_environment(&env),
        "ANV_DEBUG=startup\nDRI_PRIME=1\nEGL_PLATFORM=surfaceless\nINTEL_DEBUG=perf\nLANG=C\nLD_PRELOAD=/usr/lib/x.so\n\
         MESA_LOADER_DRIVER_OVERRIDE=iris\nNEO_CACHE_DIR=<path>\nVK_DRIVER_FILES=/usr/share/vulkan/icd.d/intel_icd.x86_64.json\n\
         XDG_SESSION_TYPE=wayland\nXPU_SMI_DEBUG=1\nZE_AFFINITY_MASK=0\ncontainer=docker\nvblank_mode=0\n"
    );
    assert!(filter_environment(&[]).is_empty());
}

#[test]
fn generic_prefixes_and_secret_looking_names_are_not_recorded() {
    let env: Vec<String> = [
        "CL_API_TOKEN=abc123",
        "INTEL_LICENSE_FILE=28518@lic.corp.example",
        "MDA_CONFIG=1",
        "ZE_API_KEY=k",
        "SYCL_PROXY_URL=http://proxy.example.com:3128",
        "ONEAPI_SERVER=build1",
        "VK_LOGIN=me",
        "UR_USER_NAME=alice",
        "OCL_HOST_NAME=box",
    ]
    .map(str::to_owned)
    .to_vec();
    assert_eq!(filter_environment(&env), "");
}

#[test]
fn path_values_are_kept_only_inside_system_directories() {
    assert_eq!(
        safe_path_value("/usr/lib:/opt/intel/oneapi/lib:/etc/x"),
        "/usr/lib:/opt/intel/oneapi/lib:/etc/x"
    );
    assert_eq!(safe_path_value("/usr/lib:/data/alice/cache"), "<path>");
    assert_eq!(safe_path_value("/srv/projects/secretproj/cache"), "<path>");
    assert_eq!(safe_path_value("~/cache"), "~/cache");
    assert_eq!(safe_path_value("/home/someone/lib"), "/home/someone/lib");
    assert_eq!(safe_path_value(""), "");
    let env: Vec<String> = [
        "MESA_SHADER_CACHE_DIR=/data/alice/cache",
        "SYCL_CACHE_DIR=/srv/projects/secretproj/cache",
        "LD_LIBRARY_PATH=/opt/acme-corp/lib",
        "VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/a.json:/opt/acme/b.json",
        "MESA_SHADER_CACHE_MAX_SIZE=1G",
    ]
    .map(str::to_owned)
    .to_vec();
    assert_eq!(
        filter_environment(&env),
        "LD_LIBRARY_PATH=<path>\nMESA_SHADER_CACHE_DIR=<path>\nMESA_SHADER_CACHE_MAX_SIZE=1G\nSYCL_CACHE_DIR=<path>\nVK_ICD_FILENAMES=<path>\n"
    );
}

#[test]
fn debug_keys_are_recorded_only_when_the_runtime_reads_them() {
    let mut env: Vec<String> = [
        "PrintDebugMessages=1",
        "EnableDirectSubmission=0",
        "HOME=/home/u",
        "GithubPat=ghp_abc123",
        "OpenAIKey=sk-zzz",
        "AcmeCorpVpnUser=jsmith",
        "MyEmployerProxy=http://proxy.acme.example:3128",
        "NoDefaultCurrentDirectoryInExePath=1",
        "APITOKEN=y",
    ]
    .map(str::to_owned)
    .to_vec();
    assert!(filter_environment(&env).is_empty());
    // Set to 0 the runtime ignores the keys, so they are not recorded either.
    env.push("NEOReadDebugKeys=0".to_owned());
    assert_eq!(filter_environment(&env), "NEOReadDebugKeys=0\n");
    env.pop();
    env.push("NEOReadDebugKeys=1".to_owned());
    let text = filter_environment(&env);
    assert_eq!(text, "EnableDirectSubmission=0\nNEOReadDebugKeys=1\nPrintDebugMessages=1\n");
    // A long value is cut.
    env.push(format!("DumpKernels={}", "x".repeat(2000)));
    let text = filter_environment(&env);
    let line = text.lines().find(|l| l.starts_with("DumpKernels=")).unwrap();
    assert_eq!(line.len(), "DumpKernels=".len() + 512);
}

#[test]
fn probe_lines_name_every_outcome() {
    assert_eq!(format_probe_line("kernel.dmesg_restrict", &read_of("1\n")), "kernel.dmesg_restrict: 1");
    assert_eq!(
        format_probe_line("a", &read_of("none [integrity] confidentiality\n")),
        "a: none [integrity] confidentiality"
    );
    assert_eq!(format_probe_line("a", &read_of("")), "a: (empty)");
    assert_eq!(format_probe_line("a", &outcome_of(ReadOutcome::Missing, "")), "a: (absent)");
    assert_eq!(format_probe_line("a", &outcome_of(ReadOutcome::Denied, "")), "a: (denied)");
    assert_eq!(
        format_probe_line("a", &outcome_of(ReadOutcome::Failed, "I/O error")),
        "a: (error: I/O error)"
    );
}

#[test]
fn small_text_helpers() {
    assert_eq!(link_target_name("../../../bus/pci/drivers/xe"), "xe");
    assert_eq!(link_target_name("../../../kernel/iommu_groups/12/"), "12");
    assert_eq!(link_target_name("plain"), "plain");
    assert_eq!(link_target_name(""), "");
    assert_eq!(link_target_name("/"), "");

    let status = "Name:\txpu-smi\nCapEff:\t000001ffffffffff\nCapPrm:\t0\n";
    assert_eq!(status_field(status, "CapEff").unwrap(), "000001ffffffffff");
    assert_eq!(status_field(status, "Cap"), None);
    assert_eq!(status_field(status, "Missing"), None);
    assert_eq!(parse_cap_eff(status), Some(0x1ff_ffff_ffff));
    assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);

    assert_eq!(
        format_dev_line("/dev/dri/card0", 0o20660, "root", "video", Some((226, 0)), ""),
        "/dev/dri/card0 20660 root:video 226:0"
    );
    assert_eq!(
        format_dev_line("/dev/dri/by-path/x-card", 0o120777, "root", "root", Some((226, 0)), "../card0"),
        "/dev/dri/by-path/x-card 120777 root:root 226:0 -> ../card0"
    );
    assert_eq!(format_dev_line("/dev/dri/x", 0o100644, "u", "g", None, ""), "/dev/dri/x 100644 u:g");

    let names = |a: &str, b: &str, c: &str| host_name_variants(a, b, c);
    assert_eq!(names("gpu-box", "gpu-box\n", "example.com\n"), ["gpu-box", "example.com"]);
    assert_eq!(
        names("gpu-box.example.com", "gpu-box.example.com\n", "(none)\n"),
        ["gpu-box.example.com", "gpu-box"]
    );
    assert_eq!(names("a.b.c", "", ""), ["a.b.c", "a"]);
    assert_eq!(names("solo", "solo", "solo"), ["solo"]);
    assert_eq!(names("short", "renamed\n", "lab.local"), ["short", "renamed", "lab.local"]);
    assert!(names("", "", "").is_empty());
    assert!(names("", "(none)", "\n").is_empty());
}

#[test]
fn resolver_domains_read_search_and_domain_lines() {
    // The FQDN comes from resolv.conf, never from a DNS lookup.
    let d = |s: &str| resolver_domains(s);
    assert_eq!(
        d("# comment\nnameserver 127.0.0.53\nsearch lab.example.com example.com.\n"),
        ["lab.example.com", "example.com"]
    );
    assert_eq!(d("domain lab.local\nsearch lab.local other.example\n"), ["lab.local", "other.example"]);
    assert!(d("options edns0\nsearch\n").is_empty());
    assert!(d("").is_empty());
    assert!(d("searchdomain x.y\n").is_empty());
    assert_eq!(d("search\ta.example\tb.example\r\n"), ["a.example", "b.example"]);
}

#[test]
fn redactable_user_names_exclude_privileged_and_numeric_accounts() {
    // The effective user under sudo is root, which is never a name to redact.
    let n = |uid: u32, effective: Option<&str>, others: &[Option<&str>]| {
        redactable_user_names(uid, effective, others)
    };
    assert_eq!(n(1000, Some("alice"), &[None, None]), ["alice"]);
    // Root under sudo: the invoking person is named by SUDO_USER, never "root".
    assert_eq!(n(0, Some("root"), &[None, Some("jdoe"), Some("root")]), ["jdoe"]);
    assert!(n(0, Some("root"), &[None, None]).is_empty());
    assert!(n(0, None, &[]).is_empty());
    // A container uid without a passwd entry has no name; a numeric name is never one.
    assert!(n(1000, None, &[None, None]).is_empty());
    assert!(n(1000, Some("1000"), &[Some("1000")]).is_empty());
    assert_eq!(n(1000, Some("nobody"), &[Some("root"), Some("  bob \n"), Some("bob"), Some("")]), ["bob"]);
    // The effective name of uid 0 is skipped even when it is spelled differently.
    assert_eq!(n(0, Some("toor"), &[Some("alice")]), ["alice"]);
}

#[test]
fn resolver_domains_qualify_the_short_host_name() {
    let domains = vec!["lab.example".to_owned(), "example.com".to_owned()];
    assert_eq!(
        with_resolver_domains(vec!["gpu-box.lab.example".into(), "gpu-box".into()], &domains),
        ["gpu-box.lab.example", "gpu-box", "gpu-box.example.com"]
    );
    assert!(with_resolver_domains(Vec::new(), &domains).is_empty());
    assert_eq!(with_resolver_domains(vec!["solo".into()], &[]), ["solo"]);
}

#[test]
fn account_files_and_id_lists() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\njdoe:x:1003:1003::/home/jdoe:/bin/zsh\nbroken\n:x:5:5\nbad:x:nan:1\n";
    assert_eq!(parse_account_names(passwd, 2), [(0, "root".to_owned()), (1003, "jdoe".to_owned())]);
    assert_eq!(parse_id_list("4 24\t27 x 30"), [4, 24, 27, 30]);
    assert!(parse_id_list("").is_empty());
    assert_eq!(split_words("  a  b c "), ["a", "b", "c"]);
}
