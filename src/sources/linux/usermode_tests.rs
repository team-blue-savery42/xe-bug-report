// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/usermode.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put, text_of};

#[test]
fn credentials_in_a_url_are_detected() {
    for text in [
        "deb https://user:secret@repo.example.com/ubuntu noble main",
        "deb https://token@repo.example.com/ubuntu noble main",
        "baseurl=http://u:p@192.0.2.7/repo",
        "deb [trusted=yes] ftp://anon@example.com/x main",
        "deb https://h.example.com/x?token=1 noble main",
        "baseurl=https://h.example.com/$basearch?auth=abc",
        "deb https://h.example.com/x#frag noble main",
        "deb https://dl.example.com/basic/0123456789abcdef0123456789abcdef/deb noble main",
        "deb https://h.example.com/private-token/x noble main",
        "baseurl=https://h.example.com/secret/x",
    ] {
        assert!(has_credentials(text), "{text}");
    }
    for text in [
        "deb https://repo.example.com/ubuntu noble main",
        "deb [signed-by=/usr/share/keyrings/x.gpg] https://repo.example.com/a@b noble main",
        "git@example.com:x/y.git",
        "deb https://artifacts.example.com/ubuntu-official-packages/ubuntu noble main",
        "deb [trusted=yes] http://h.example.com/x noble main",
        "baseurl=https://h.example.com/$releasever/$basearch/",
        "no url at all",
    ] {
        assert!(!has_credentials(text), "{text}");
    }
}

#[test]
fn apt_list_lines_keep_only_deb_lines_and_withhold_credentials() {
    let content = "# comment\n\ndeb https://repo.example.com/ubuntu noble main\n\
                   deb-src https://repo.example.com/ubuntu noble main\n\
                   deb https://user:pw@private.example.com/x noble main\nsomething else\n";
    assert_eq!(
        apt_list_lines(content),
        [
            "deb https://repo.example.com/ubuntu noble main".to_owned(),
            "deb-src https://repo.example.com/ubuntu noble main".to_owned(),
            WITHHELD.to_owned(),
        ]
    );
}

#[test]
fn deb822_stanzas_drop_inline_keys_and_continuations() {
    let content = "Types: deb\nURIs: https://repo.example.com/ubuntu/\nSuites: noble\nComponents: main\n\
                   Signed-By: -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n mQINBGTSU84BEADVSs1CRYCbfu4x\n -----END PGP PUBLIC KEY BLOCK-----\n\
                   \nTypes: deb\nURIs: https://u:p@private.example.com/\nSigned-By: /usr/share/keyrings/x.gpg\nX-Other: ignored\n\
                   \nTypes: deb\nURIs: https://c.example.com/\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n abc\n";
    let lines = deb822_lines(content);
    assert_eq!(
        lines,
        [
            "Types: deb",
            "URIs: https://repo.example.com/ubuntu/",
            "Suites: noble",
            "Components: main",
            "Signed-By: (inline key)",
            "",
            "Types: deb",
            WITHHELD,
            "Signed-By: /usr/share/keyrings/x.gpg",
            "",
            "Types: deb",
            "URIs: https://c.example.com/",
            "Signed-By: (inline key)",
        ]
    );
    assert!(!lines.join("\n").contains("mQINB"));
}

#[test]
fn repo_files_keep_sections_and_known_keys() {
    let content = "[example]\nname=Example repo\nbaseurl=https://repo.example.com/$releasever/\n\
                   password=hunter2\nusername=me\nenabled=1\nsslclientkey=/etc/pki/key.pem\n\
                   [private]\nbaseurl=https://a:b@private.example.com/\n";
    let lines = repo_lines(content);
    assert_eq!(
        lines,
        [
            "[example]",
            "name=Example repo",
            "baseurl=https://repo.example.com/$releasever/",
            "enabled=1",
            "[private]",
            WITHHELD,
        ]
    );
}

#[test]
fn the_repository_source_reads_every_style_and_never_a_credential() {
    let dir = PrivateTempDir::create("repos").unwrap();
    let root = dir.path();
    put(root, "etc/apt/sources.list", "deb https://main.example.com/ubuntu noble main\n");
    put(root, "etc/apt/sources.list.d/a.list", "deb https://x:y@private.example.com/ noble main\n");
    put(root, "etc/apt/sources.list.d/b.sources", "Types: deb\nURIs: https://b.example.com/\n");
    put(root, "etc/apt/sources.list.d/c.save", "deb https://ignored.example.com/ x\n");
    put(root, "etc/yum.repos.d/d.repo", "[d]\nbaseurl=https://d.example.com/\n");
    let out = repositories(&FsReader::default(), root, "packages/repositories.txt");
    let text = text_of(&out[0].data);
    assert!(text.contains("== repo-1 ==\ndeb https://main.example.com/ubuntu noble main"), "{text}");
    assert!(text.contains("== repo-3 ==\nTypes: deb"), "{text}");
    assert!(!text.contains("sources.list") && !text.contains("a.list") && !text.contains("d.repo"), "{text}");
    assert!(text.contains("URIs: https://b.example.com/"));
    assert!(text.contains("[d]\nbaseurl=https://d.example.com/"));
    assert!(!text.contains("private.example.com") && !text.contains("ignored.example.com"), "{text}");
    assert!(text.contains(WITHHELD));
    let none = repositories(&FsReader::default(), &root.join("nothing"), "x");
    assert!(text_of(&none[0].data).starts_with("(no apt, yum or zypper"));
}

#[test]
fn driver_manifests_are_listed_one_line_each() {
    let dir = PrivateTempDir::create("icd").unwrap();
    let root = dir.path();
    put(root, "etc/OpenCL/vendors/intel.icd", "/usr/lib/x86_64-linux-gnu/intel-opencl/libigdrcl.so\n");
    put(
        root,
        "usr/share/vulkan/icd.d/intel_icd.x86_64.json",
        "{\n    \"ICD\": {\n        \"api_version\": \"1.4.318\",\n        \"library_path\": \"libvulkan_intel.so\"\n    }\n}",
    );
    put(root, "usr/share/vulkan/icd.d/readme.txt", "ignored");
    put(root, "usr/share/glvnd/egl_vendor.d/50_mesa.json", "{ \"file_format_version\": \"1.0.0\" }");
    put(root, "etc/ld.so.conf.d/intel.conf", "# comment intel\n/opt/intel/lib\n");
    put(root, "etc/ld.so.conf.d/libc.conf", "/usr/local/lib\n");
    let out = driver_manifests(&FsReader::default(), root, "system/icd.txt");
    let text = text_of(&out[0].data);
    assert!(
        text.contains(
            "[/etc/OpenCL/vendors]\nintel.icd: /usr/lib/x86_64-linux-gnu/intel-opencl/libigdrcl.so\n"
        ),
        "{text}"
    );
    assert!(text.contains("intel_icd.x86_64.json: { \"ICD\": { \"api_version\": \"1.4.318\", \"library_path\": \"libvulkan_intel.so\" } }\n"), "{text}");
    assert!(text.contains("50_mesa.json: { \"file_format_version\": \"1.0.0\" }"));
    assert!(text.contains("intel.conf: /opt/intel/lib\n") && !text.contains("libc.conf"), "{text}");
    assert!(!text.contains("ignored"));
    let none = driver_manifests(&FsReader::default(), &root.join("nothing"), "x");
    assert!(text_of(&none[0].data).starts_with("(no OpenCL, Vulkan or EGL manifests found)"));
}

#[test]
fn a_long_manifest_is_cut_on_a_character_boundary() {
    let long = format!("{{ \"d\": \"{}\" }}", "é".repeat(2000));
    let line = compact(&long);
    assert!(line.ends_with(" ...") && line.len() <= MANIFEST_LINE_MAX + 4);
}

#[test]
fn configuration_overrides_and_caches_are_reported_with_the_home_as_a_tilde() {
    let dir = PrivateTempDir::create("umd").unwrap();
    let root = dir.path().join("root");
    let home = dir.path().join("home/someone");
    let cwd = dir.path().join("work");
    put(&root, "usr/share/drirc.d/00-mesa-defaults.conf", "<driconf/>");
    put(&home, ".drirc", "<driconf><device/></driconf>\n");
    put(&home, ".cache/mesa_shader_cache/index", "x");
    put(&home, ".cache/neo_compiler_cache/a.bin", "xx");
    put(&cwd, "igdrcl.config", "PrintDebugMessages = 1\n");
    let dirs = UserDirs {
        home: Some(home.clone()),
        cwd: Some(cwd),
        xdg_cache: None,
        neo_cache: Some(home.join(".cache/neo_compiler_cache")),
        mesa_cache: None,
    };
    let out = user_mode_config(&FsReader::default(), &root, &dirs, "system/umd-config.txt");
    let text = text_of(&out[0].data);
    assert!(text.contains("== /etc/drirc == (absent)"), "{text}");
    assert!(text.contains("== ~/.drirc ==\n<driconf><device/></driconf>\n"), "{text}");
    assert!(text.contains("== igdrcl.config in the current directory ==\nPrintDebugMessages = 1\n"));
    assert!(text.contains("00-mesa-defaults.conf 10\n"));
    assert!(text.contains("~/.cache/mesa_shader_cache: 1 entries, modified 20"), "{text}");
    assert!(text.contains("  a.bin 2 bytes\n"));
    // The same directory named twice is listed once.
    assert_eq!(text.matches("~/.cache/neo_compiler_cache:").count(), 1, "{text}");
    assert!(!text.contains("someone"), "the home directory name must not appear: {text}");
}

#[test]
fn without_a_home_no_cache_is_guessed() {
    let dir = PrivateTempDir::create("umd").unwrap();
    let out = user_mode_config(&FsReader::default(), dir.path(), &UserDirs::default(), "x");
    assert!(text_of(&out[0].data).contains("(no cache location known: HOME is not set)"));
}

#[test]
fn paths_outside_the_home_are_kept() {
    assert_eq!(tilde(Path::new("/var/cache/x"), Some(Path::new("/home/a"))), "/var/cache/x");
    assert_eq!(tilde(Path::new("/home/a"), Some(Path::new("/home/a"))), "~");
    assert_eq!(tilde(Path::new("/home/a/.cache"), Some(Path::new("/home/a"))), "~/.cache");
    assert_eq!(tilde(Path::new("/home/a/.cache"), None), "/home/a/.cache");
}

#[test]
fn only_regular_files_are_read_for_the_overrides() {
    let dir = PrivateTempDir::create("umd").unwrap();
    let root = dir.path().join("root");
    let home = dir.path().join("home/someone");
    let cwd = dir.path().join("work");
    put(&root, "usr/share/drirc.d/x.conf", "");
    // A link to a private file in the working directory, and a FIFO as the user's drirc.
    put(dir.path(), "private/id_key", "SECRET-KEY-MATERIAL\n");
    std::fs::create_dir_all(&cwd).unwrap();
    std::os::unix::fs::symlink(dir.path().join("private/id_key"), cwd.join("igdrcl.config")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let made =
        std::process::Command::new("mkfifo").arg(home.join(".drirc")).status().is_ok_and(|s| s.success());
    let dirs = UserDirs { home: Some(home), cwd: Some(cwd), ..UserDirs::default() };
    let out = user_mode_config(&FsReader::default(), &root, &dirs, "x");
    let text = text_of(&out[0].data);
    assert!(!text.contains("SECRET-KEY-MATERIAL"), "{text}");
    assert!(text.contains("== igdrcl.config in the current directory == (not a regular file)"), "{text}");
    if made {
        assert!(text.contains("== ~/.drirc == (not a regular file)"), "{text}");
    }
}
