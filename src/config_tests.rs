// SPDX-License-Identifier: MIT
//! Unit tests for `src/config.rs`.

use super::*;

fn base() -> PathBuf {
    if cfg!(windows) { PathBuf::from(r"C:\conf") } else { PathBuf::from("/conf") }
}

fn abs(path: &str) -> String {
    if cfg!(windows) { format!("C:{}", path.replace('/', "\\")) } else { path.to_owned() }
}

#[test]
fn tools_and_search_directories_are_read_in_order() {
    let text = format!(
        "# where the tools are\n\n[tools]\nxpu-smi = {}\niclg = crashlog/iclg\n; another comment\n\n\
         [search]\ndir = {}\ndir = more\n",
        abs("/opt/xpu-smi/bin/xpu-smi"),
        abs("/opt/intel/bin")
    );
    let (locations, warnings) = parse(&text, &base()).unwrap();
    assert!(warnings.is_empty());
    assert_eq!(
        locations.tools,
        vec![
            ("xpu-smi".to_owned(), PathBuf::from(abs("/opt/xpu-smi/bin/xpu-smi"))),
            ("iclg".to_owned(), base().join("crashlog/iclg")),
        ]
    );
    assert_eq!(locations.dirs, vec![PathBuf::from(abs("/opt/intel/bin")), base().join("more")]);
}

#[test]
fn values_keep_hashes_and_lose_one_pair_of_quotes() {
    let text = "[tools]\na = \"/x y/a\"\nb = '/b#1'\nc = \"/c'\n  d=/d  \n";
    let (locations, _) = parse(text, &base()).unwrap();
    let values: Vec<String> =
        locations.tools.iter().map(|(_, path)| path.to_string_lossy().into_owned()).collect();
    let expected =
        ["/x y/a", "/b#1", "\"/c'", "/d"].map(|value| base().join(value).to_string_lossy().into_owned());
    assert_eq!(values, expected);
}

#[test]
fn an_empty_file_or_one_with_only_comments_gives_nothing() {
    for text in ["", "\n\n", "# only\n; comments\n", "\u{feff}# with a byte order mark\n"] {
        assert_eq!(parse(text, &base()).unwrap(), (ToolLocations::default(), Vec::new()));
    }
}

#[test]
fn unknown_sections_are_skipped_with_a_warning() {
    let (locations, warnings) = parse("[later]\nanything = 1\n[tools]\na = /a\n", &base()).unwrap();
    assert_eq!(locations.tools.len(), 1);
    assert_eq!(warnings, vec!["line 1: unknown section [later] is ignored".to_owned()]);
}

#[test]
fn malformed_lines_are_errors_with_their_line_number() {
    let cases = [
        ("a = /a\n", "line 1: 'a' is outside a section; put it under [tools]"),
        ("[tools\n", "line 1: a section header ends with ']'"),
        ("[tools]\njust words\n", "line 2: expected 'name = value'"),
        ("[tools]\n = /a\n", "line 2: the name before '=' is empty"),
        ("[tools]\na =\n", "line 2: 'a' has no value"),
        ("[tools]\na = ''\n", "line 2: 'a' has no value"),
        ("[tools]\nbin/a = /a\n", "line 2: 'bin/a' is not a tool name (a bare command name)"),
        ("[tools]\nmy tool = /a\n", "line 2: 'my tool' is not a tool name (a bare command name)"),
        ("[tools]\na = /a\n\na = /b\n", "line 4: 'a' is set twice"),
        ("[search]\npath = /a\n", "line 2: [search] takes 'dir = <directory>', not 'path'"),
    ];
    for (text, expected) in cases {
        assert_eq!(parse(text, &base()).unwrap_err(), expected, "{text:?}");
    }
}

#[cfg(unix)]
#[test]
fn the_file_is_under_xdg_config_home_else_dot_config() {
    let env = |vars: &'static [(&'static str, &'static str)]| {
        move |name: &str| vars.iter().find(|(key, _)| *key == name).map(|(_, value)| OsString::from(value))
    };
    let both = env(&[("XDG_CONFIG_HOME", "/home/u/.cfg"), ("HOME", "/home/u")]);
    assert_eq!(default_path(both), Some(PathBuf::from("/home/u/.cfg/xe-bug-report/config")));
    let home_only = env(&[("HOME", "/home/u")]);
    assert_eq!(default_path(home_only), Some(PathBuf::from("/home/u/.config/xe-bug-report/config")));
    // An empty or relative XDG_CONFIG_HOME is ignored, as the XDG specification says.
    let relative_xdg = env(&[("XDG_CONFIG_HOME", "cfg"), ("HOME", "/home/u")]);
    assert_eq!(default_path(relative_xdg), Some(PathBuf::from("/home/u/.config/xe-bug-report/config")));
    // A relative or missing home is the current directory by another name, or nothing.
    assert_eq!(default_path(env(&[("HOME", "home")])), None);
    assert_eq!(default_path(env(&[])), None);
}

#[cfg(windows)]
#[test]
fn the_file_is_under_appdata() {
    let env = |name: &str| (name == "APPDATA").then(|| OsString::from(r"C:\Users\u\AppData\Roaming"));
    assert_eq!(default_path(env), Some(PathBuf::from(r"C:\Users\u\AppData\Roaming\xe-bug-report\config")));
    assert_eq!(default_path(|_| None), None);
}

#[cfg(unix)]
#[test]
fn files_others_may_change_are_not_trusted() {
    assert_eq!(trust_problem(0o644, 1000, 1000, None), None);
    assert_eq!(trust_problem(0o600, 0, 1000, None), None);
    assert!(trust_problem(0o664, 1000, 1000, None).is_some());
    assert!(trust_problem(0o646, 1000, 1000, None).is_some());
    assert!(trust_problem(0o644, 1001, 1000, None).is_some());
    assert!(trust_problem(0o644, 1000, 0, None).is_some());
    // Root through sudo trusts the file of the user who ran sudo, and only that one.
    assert_eq!(trust_problem(0o644, 1000, 0, Some(1000)), None);
    assert!(trust_problem(0o644, 1001, 0, Some(1000)).is_some());
    // SUDO_UID means nothing to a process that is not root: anyone can set it.
    assert!(trust_problem(0o644, 1001, 1000, Some(1001)).is_some());
}

#[cfg(unix)]
#[test]
fn load_from_reads_the_file_and_reports_problems_with_its_name() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, "[tools]\nxpu-smi = bin/xpu-smi\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let config = load_from(&path).unwrap();
    assert_eq!(config.path, path);
    assert_eq!(config.locations.tools, vec![("xpu-smi".to_owned(), dir.path().join("bin/xpu-smi"))]);

    let missing = dir.path().join("absent");
    assert_eq!(load_from(&missing).unwrap_err(), format!("{}: no such file", missing.display()));

    std::fs::write(&path, "[tools]\nbroken\n").unwrap();
    assert_eq!(load_from(&path).unwrap_err(), format!("{}: line 2: expected 'name = value'", path.display()));

    std::fs::write(&path, vec![b'#'; MAX_SIZE.get() as usize + 1]).unwrap();
    assert_eq!(load_from(&path).unwrap_err(), format!("{}: larger than 64.0 KiB", path.display()));

    std::fs::write(&path, "[tools]\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(load_from(&path).unwrap_err().contains("other users may write to it"));
}

#[cfg(unix)]
#[test]
fn locations_find_own_entries_then_directories_and_skip_what_is_not_executable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let make = |rel: &str, mode: u32| {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    };
    let own = make("own/xpu-smi", 0o755);
    let in_dir = make("extra/iclg", 0o755);
    let shadowed = make("extra/xpu-smi", 0o755);
    let not_executable = make("own/lspci", 0o644);
    let locations = ToolLocations {
        tools: vec![
            ("xpu-smi".to_owned(), own.clone()),
            ("lspci".to_owned(), not_executable.clone()),
            ("ghost".to_owned(), dir.path().join("nowhere/ghost")),
        ],
        dirs: vec![PathBuf::from("relative"), dir.path().join("extra")],
    };
    assert_eq!(locations.find("xpu-smi"), Some(own));
    assert_ne!(locations.find("xpu-smi"), Some(shadowed));
    assert_eq!(locations.find("iclg"), Some(in_dir));
    assert_eq!(locations.find("lspci"), None);
    assert_eq!(locations.find("ghost"), None);
    let unusable: Vec<&str> = locations.unusable().iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(unusable, ["lspci", "ghost"]);
}
