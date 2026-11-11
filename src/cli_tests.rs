// SPDX-License-Identifier: MIT
//! Unit tests for `src/cli.rs`.

use super::*;

fn parse(args: &[&str]) -> Result<Args, CliExit> {
    parse_args(std::iter::once("xe-bug-report").chain(args.iter().copied()))
}

fn usage_message(args: &[&str]) -> (String, bool) {
    match parse(args) {
        Err(CliExit::Usage { message, json }) => (message, json),
        other => panic!("expected a usage error for {args:?}, got {other:?}"),
    }
}

fn minutes(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

fn hours(n: u64) -> Duration {
    minutes(n * 60)
}

fn days(n: u64) -> Duration {
    hours(n * 24)
}

fn gpu(bus: u8) -> GpuDevice {
    GpuDevice { bdf: PciAddress { domain: 0, bus, device: 0, function: 0 }, os_path: format!("/sys/{bus}") }
}

#[test]
fn since_accepts_minutes_hours_and_days() {
    assert_eq!(parse_since("30m"), Some(minutes(30)));
    assert_eq!(parse_since("1m"), Some(minutes(1)));
    assert_eq!(parse_since("2h"), Some(hours(2)));
    assert_eq!(parse_since("3d"), Some(days(3)));
    // A bare number counts hours.
    assert_eq!(parse_since("2"), Some(hours(2)));
    assert_eq!(parse_since("72"), Some(hours(72)));
    assert_eq!(parse_since("0030m"), Some(minutes(30)));
}

#[test]
fn since_range_ends() {
    assert_eq!(parse_since("365d"), Some(days(365)));
    assert_eq!(parse_since("8760"), Some(days(365)));
    assert_eq!(parse_since("8760h"), Some(days(365)));
    assert_eq!(parse_since("525600m"), Some(days(365)));
    for bad in ["366d", "400d", "8761", "525601m", "0", "0m", "0d", "0h"] {
        assert_eq!(parse_since(bad), None, "{bad}");
    }
}

#[test]
fn since_rejects_other_forms() {
    for bad in [
        "",
        "m",
        "d",
        "h",
        "5x",
        "5 m",
        " 5",
        "5 ",
        "-5",
        "+5",
        "+5m",
        "5mm",
        "1.5h",
        "h2",
        "5M",
        "5D",
        "abc",
        "99999999999999999999",
        "99999999999999999999d",
        "\u{e9}",
        "5\u{e9}",
        "\u{661}",
    ] {
        assert_eq!(parse_since(bad), None, "{bad:?}");
    }
}

#[test]
fn device_list_splitting() {
    assert_eq!(split_device_list("a,b").collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(split_device_list("a").collect::<Vec<_>>(), ["a"]);
    assert_eq!(split_device_list(" a , b ").collect::<Vec<_>>(), ["a", "b"]);
    // Empty items survive so that parsing can reject them.
    assert_eq!(split_device_list("a,,b").collect::<Vec<_>>(), ["a", "", "b"]);
    assert_eq!(split_device_list("").collect::<Vec<_>>(), [""]);
    assert_eq!(split_device_list("a,").collect::<Vec<_>>(), ["a", ""]);
}

#[test]
fn device_selection_filters_in_os_order() {
    let available = vec![gpu(3), gpu(9), gpu(0x18)];
    let all = select_devices(&[], available.clone()).unwrap();
    assert_eq!(all, available);
    let wanted = [gpu(0x18).bdf, gpu(3).bdf];
    let picked = select_devices(&wanted, available.clone()).unwrap();
    assert_eq!(picked, vec![gpu(3), gpu(0x18)]);
}

#[test]
fn device_selection_names_a_missing_address() {
    let error = select_devices(&[gpu(3).bdf, gpu(7).bdf], vec![gpu(3)]).unwrap_err();
    assert!(matches!(error, Error::UnknownDevice(ref text) if text == "0000:07:00.0"), "{error:?}");
    assert_eq!(error.to_string(), "No Intel GPU with PCI address 0000:07:00.0 was found on this system");
    assert!(select_devices(&[gpu(3).bdf], Vec::new()).is_err());
}

#[test]
fn defaults() {
    assert_eq!(parse(&[]).unwrap(), Args::default());
    let args = parse(&[]).unwrap();
    assert_eq!(args.samples, 5);
    assert_eq!(args.timeout, Some(Duration::from_secs(600)));
    assert_eq!(args.profile, Profile::Default);
}

#[test]
fn plain_options() {
    let args = parse(&[
        "--output",
        "out.zip",
        "--full",
        "--samples",
        "12",
        "--since",
        "2d",
        "--no-redact",
        "--list",
        "--json",
        "--xpu-smi",
        "/opt/xpu-smi",
        "--timeout",
        "30",
        "--verbose",
    ])
    .unwrap();
    assert_eq!(args.output, Some(PathBuf::from("out.zip")));
    assert_eq!(args.profile, Profile::Full);
    assert_eq!(args.samples, 12);
    assert_eq!(args.since, Some(days(2)));
    assert!(args.no_redact && args.list && args.json && args.verbose);
    assert_eq!(args.xpu_smi, Some(PathBuf::from("/opt/xpu-smi")));
    assert_eq!(args.timeout, Some(Duration::from_secs(30)));
    assert_eq!(parse(&["--output=a.zip"]).unwrap().output, Some(PathBuf::from("a.zip")));
}

#[test]
fn minimal_forces_no_samples() {
    let args = parse(&["--minimal"]).unwrap();
    assert_eq!(args.profile, Profile::Minimal);
    assert_eq!(args.samples, 0);
    assert_eq!(parse(&["--minimal", "--samples", "9"]).unwrap().samples, 0);
    assert_eq!(parse(&["--samples", "9"]).unwrap().samples, 9);
}

#[test]
fn minimal_and_full_conflict() {
    let (message, json) = usage_message(&["--minimal", "--full"]);
    assert!(message.contains("--minimal") && message.contains("--full"), "{message}");
    assert!(!json);
    let (_, json) = usage_message(&["--full", "--minimal", "--json"]);
    assert!(json);
}

#[test]
fn samples_range() {
    assert_eq!(parse(&["--samples", "0"]).unwrap().samples, 0);
    assert_eq!(parse(&["--samples", "3600"]).unwrap().samples, 3600);
    for bad in ["3601", "x", "", "1.5", "99999999999"] {
        let (message, _) = usage_message(&["--samples", bad]);
        assert!(message.contains("--samples"), "{bad}: {message}");
    }
    // A negative number is an invalid value, not an unknown option.
    for negative in [&["--samples", "-1"][..], &["--samples=-1"]] {
        let (message, _) = usage_message(negative);
        assert!(message.contains("-1") && message.contains("--samples"), "{message}");
    }
}

#[test]
fn timeout_zero_disables_the_deadline() {
    assert_eq!(parse(&["--timeout", "0"]).unwrap().timeout, None);
    assert_eq!(parse(&["--timeout", "1"]).unwrap().timeout, Some(Duration::from_secs(1)));
    assert_eq!(
        parse(&["--timeout", "31536000"]).unwrap().timeout,
        Some(Duration::from_secs(MAX_TIMEOUT_SECS))
    );
    for bad in ["31536001", "18446744073709551615", "-1", "ten"] {
        assert!(matches!(parse(&["--timeout", bad]), Err(CliExit::Usage { .. })), "{bad}");
    }
}

#[test]
fn since_option() {
    assert_eq!(parse(&["--since", "30m"]).unwrap().since, Some(minutes(30)));
    assert_eq!(parse(&["--since", "6"]).unwrap().since, Some(hours(6)));
    let (message, _) = usage_message(&["--since", "400d"]);
    assert_eq!(
        message,
        "Invalid value '400d' for --since; use <n>m, <n>h or <n>d, or a bare number of hours, from 1 minute \
             to 365 days"
    );
    let (_, json) = usage_message(&["--since", "5x", "--json"]);
    assert!(json);
}

#[test]
fn empty_paths_are_refused() {
    let (message, _) = usage_message(&["--output", ""]);
    assert_eq!(message, "The output file name can't be empty");
    let (message, _) = usage_message(&["--xpu-smi", ""]);
    assert_eq!(message, "The --xpu-smi path can't be empty");
}

#[cfg(unix)]
#[test]
fn non_utf8_output_is_kept() {
    use std::os::unix::ffi::OsStringExt;
    let name = OsString::from_vec(b"bad\xff.zip".to_vec());
    let args =
        parse_args([OsString::from("xe-bug-report"), OsString::from("--output"), name.clone()]).unwrap();
    assert_eq!(args.output, Some(PathBuf::from(name)));
}

#[test]
fn unknown_and_positional_arguments_are_usage_errors() {
    for bad in [&["--bogus"][..], &["extra"], &["-x"], &["--output"], &["-f", "a.zip"], &["-j"]] {
        let (message, _) = usage_message(bad);
        assert!(!message.is_empty() && !message.contains('\n'), "{bad:?}: {message}");
    }
    // Long options are not abbreviated.
    assert!(matches!(parse(&["--out", "a.zip"]), Err(CliExit::Usage { .. })));
}

#[test]
fn json_is_detected_in_raw_arguments() {
    let (message, json) = usage_message(&["--bogus", "--json"]);
    assert!(json, "{message}");
    assert!(message.contains("--bogus"), "{message}");
    let (_, json) = usage_message(&["--bogus"]);
    assert!(!json);
    // Not an option once it follows `--`.
    assert!(!wants_json(&[OsString::from("x"), OsString::from("--"), OsString::from("--json")]));
    // argv[0] is not an argument.
    assert!(!wants_json(&[OsString::from("--json")]));
}

#[test]
fn help_and_version_exit_early() {
    for flag in ["--help", "-h"] {
        let Err(CliExit::Help(text)) = parse(&[flag]) else { panic!("{flag}") };
        for expected in ["--output", "--device", "--minimal", "--full", "--samples", "--since", "--no-redact"]
        {
            assert!(text.contains(expected), "{flag}: help lacks {expected}");
        }
        for expected in ["--list", "--json", "--xpu-smi", "--timeout", "--verbose", "--version"] {
            assert!(text.contains(expected), "{flag}: help lacks {expected}");
        }
        assert!(!text.contains('\u{1b}'));
    }
    for flag in ["--version", "-v"] {
        assert_eq!(parse(&[flag]), Err(CliExit::Version(version_text())));
    }
}

#[test]
fn version_format() {
    assert_eq!(
        format_version("0.1.0", "v0.1.0-3-gabc", "abc1234", "2026-01-02 03:04:05 UTC"),
        "xe-bug-report 0.1.0 (v0.1.0-3-gabc, abc1234, built 2026-01-02 03:04:05 UTC)"
    );
    assert_eq!(format_version("0.1.0", "", "", ""), "xe-bug-report 0.1.0");
    assert_eq!(format_version("0.1.0", "", "abc1234", ""), "xe-bug-report 0.1.0 (abc1234)");
    assert!(version_text().starts_with(&format!("xe-bug-report {}", build_info::VERSION)));
}

#[test]
fn device_option_rejects_bad_addresses() {
    let (message, _) = usage_message(&["--device", "not-a-bdf"]);
    assert_eq!(message, "Invalid PCI address 'not-a-bdf' for --device; expected dddd:bb:dd.f");
    let (message, json) = usage_message(&["--device", "", "--json"]);
    assert_eq!(message, "Invalid PCI address '' for --device; expected dddd:bb:dd.f");
    assert!(json);
    assert!(matches!(parse(&["--device"]), Err(CliExit::Usage { .. })));
}

#[test]
fn device_option_accepts_comma_lists() {
    let a = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };
    let b = PciAddress { domain: 0, bus: 0x18, device: 0, function: 1 };
    assert_eq!(parse(&["--device", "0000:03:00.0"]).unwrap().devices, [a]);
    assert_eq!(parse(&["--device", "0000:03:00.0,0000:18:00.1"]).unwrap().devices, [a, b]);
    assert_eq!(parse(&["--device", "0000:03:00.0", "--device", "0000:18:00.1"]).unwrap().devices, [a, b]);
    assert_eq!(parse(&["--device", "0000:03:00.0,0000:03:00.0"]).unwrap().devices, [a]);
    assert_eq!(parse(&["--device=00000:03:00.0"]).unwrap().devices, [a]);
    let (message, _) = usage_message(&["--device", "0000:03:00.0,,0000:18:00.1"]);
    assert!(message.starts_with("Invalid PCI address ''"), "{message}");
    let (message, _) = usage_message(&["--device", "0000:03:00.0,zz"]);
    assert!(message.starts_with("Invalid PCI address 'zz'"), "{message}");
}
