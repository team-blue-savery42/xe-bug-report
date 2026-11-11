// SPDX-License-Identifier: MIT
//! Port of the reference's `redact_test.cpp`, plus regression and survivor tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

use super::*;

fn context() -> Context {
    Context {
        hostnames: vec!["TESTHOST42".into(), "testhost42.example.com".into()],
        user_names: vec!["kwan".into(), "ops".into()],
    }
}

fn redact(text: &str) -> String {
    redact_with(text, &Rules::default())
}

fn redact_with(text: &str, rules: &Rules) -> String {
    redact_str(text, rules, &context())
}

fn redact_ctx(text: &str, rules: &Rules, hostnames: &[&str], user_names: &[&str]) -> String {
    let context = Context {
        hostnames: hostnames.iter().map(|s| (*s).to_owned()).collect(),
        user_names: user_names.iter().map(|s| (*s).to_owned()).collect(),
    };
    redact_str(text, rules, &context)
}

const ONLY_SERIALS: Rules = Rules { serials: true, hostname: false, users: false, addresses: false };
const ONLY_HOST: Rules = Rules { serials: false, hostname: true, users: false, addresses: false };
const ONLY_USERS: Rules = Rules { serials: false, hostname: false, users: true, addresses: false };
const ONLY_ADDRESSES: Rules = Rules { serials: false, hostname: false, users: false, addresses: true };

/// Checks `(input, expected)` pairs under `rules`.
fn check_all(rules: &Rules, cases: &[(&str, &str)]) {
    for (input, expected) in cases {
        assert_eq!(redact_with(input, rules), *expected, "input: {input:?}");
    }
}

/// Checks that every input survives unchanged under `rules`.
fn check_same(rules: &Rules, inputs: &[&str]) {
    for input in inputs {
        assert_eq!(redact_with(input, rules), *input, "input: {input:?}");
    }
}

#[test]
fn rules_and_rule_names() {
    assert!(Rules::default().any());
    assert!(!Rules::none().any());
    assert!(ONLY_ADDRESSES.any());
    assert_eq!(rule_names(&Rules::default()), ["serials", "hostname", "users", "addresses"]);
    assert!(rule_names(&Rules::none()).is_empty());
    assert_eq!(Rules::default(), Rules::default());
    assert_ne!(Rules::default(), Rules::none());
    assert_eq!(
        rule_names(&Rules { serials: false, hostname: true, users: false, addresses: true }),
        ["hostname", "addresses"]
    );
    assert_eq!(
        rule_names(&Rules { serials: true, hostname: false, users: true, addresses: false }),
        ["serials", "users"]
    );
}

#[test]
fn registry_names_are_unique_and_match_rules() {
    let mut names: Vec<_> = ALL_RULES.iter().map(|r| r.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ALL_RULES.len());
    for rule in ALL_RULES {
        let mut only = Rules::none();
        match rule.name {
            "serials" => only.serials = true,
            "hostname" => only.hostname = true,
            "users" => only.users = true,
            "addresses" => only.addresses = true,
            other => panic!("unknown rule {other}"),
        }
        assert!((rule.enabled)(&only));
        assert_eq!(rule_names(&only), [rule.name]);
    }
}

#[test]
fn none_is_the_identity() {
    let text = "testhost42 kwan 192.0.2.3 aa:bb:cc:dd:ee:ff fe80::1 Serial Number: X \
                12345678-1234-1234-1234-123456789abc /home/kwan/x USER=kwan";
    assert_eq!(redact_with(text, &Rules::none()), text);
    assert!(redact_with("", &Rules::default()).is_empty());

    let j = json!({"hostname": "testhost42", "serial": "S1", "note": text});
    assert_eq!(redact_json(j.clone(), &Rules::none(), &context()), j);
}

#[test]
fn hostname() {
    check_all(
        &ONLY_HOST,
        &[
            ("host TESTHOST42 up", "host <host> up"),
            ("host testhost42 up", "host <host> up"),
            ("TESTHOST42", "<host>"),
            ("testhost42.example.com:22", "<host>:22"),
            ("[testhost42]", "[<host>]"),
            ("testhost42.other.org", "<host>.other.org"),
            ("a TESTHOST42 b testhost42", "a <host> b <host>"),
        ],
    );
    check_same(&ONLY_HOST, &["xTESTHOST42", "TESTHOST421", "TESTHOST42_x", "pre-TESTHOST42", "TESTHOST42-2"]);
    assert_eq!(redact_ctx("a b ab", &ONLY_HOST, &["a", ""], &[]), "a b ab");
    assert_eq!(redact_ctx("host", &ONLY_HOST, &["host"], &[]), "<host>");
    assert_eq!(redact_ctx("<host> host", &ONLY_HOST, &["host"], &[]), "<host> <host>");
    assert_eq!(redact_with("TESTHOST42", &ONLY_USERS), "TESTHOST42");
    assert_eq!(redact_ctx("TESTHOST42", &ONLY_HOST, &[], &[]), "TESTHOST42");
}

#[test]
fn users() {
    check_all(
        &ONLY_USERS,
        &[
            ("login kwan ok", "login <user> ok"),
            ("Kwan", "<user>"),
            ("ops, kwan", "<user>, <user>"),
            ("/home/jdoe/.cache/x", "/home/<user>/.cache/x"),
            ("cd /home/kwan", "cd /home/<user>"),
            ("see /home/jdoe.", "see /home/<user>."),
            ("/Users/Jane Doe/x", "/Users/<user> Doe/x"),
            ("C:\\Users\\jdoe\\AppData\\Local", "C:\\Users\\<user>\\AppData\\Local"),
            ("c:\\users\\JDoe\\x", "c:\\users\\<user>\\x"),
            ("\"C:\\\\Users\\\\jdoe\\\\x\"", "\"C:\\\\Users\\\\<user>\\\\x\""),
            ("jdoe:x:1000:/home/jdoe:/bin/bash", "jdoe:x:1000:/home/<user>:/bin/bash"),
            ("/HOME/jdoe/x", "/HOME/<user>/x"),
            ("USER=jdoe HOME=/root", "USER=<user> HOME=/root"),
            ("USERNAME=jdoe", "USERNAME=<user>"),
            ("LOGNAME=jdoe\n", "LOGNAME=<user>\n"),
        ],
    );
    check_same(
        &ONLY_USERS,
        &[
            "kwan2 kwanx -kwan",
            "MYUSER=jdoe XUSERNAME=a",
            "USER= x",
            "/home/ /homework/x /home",
            "/usr/share/homes/x",
        ],
    );
    assert_eq!(redact_ctx("user user", &ONLY_USERS, &[], &["user"]), "<user> <user>");
    assert_eq!(redact_with("/home/jdoe", &ONLY_HOST), "/home/jdoe");
}

#[test]
fn generic_account_and_host_names_are_not_redacted() {
    let accounts = ["root", "Nobody", "kwan"];
    assert_eq!(
        redact_ctx("root=LABEL=x Root Port chown root:root nobody kwan", &ONLY_USERS, &[], &accounts),
        "root=LABEL=x Root Port chown root:root nobody <user>"
    );
    assert_eq!(
        redact_ctx("drwxr-xr-x 2 root root 4096 .", &ONLY_USERS, &[], &["root"]),
        "drwxr-xr-x 2 root root 4096 ."
    );
    // The USER= variable is still a user name, whoever it names.
    assert_eq!(redact_ctx("USER=root", &ONLY_USERS, &[], &accounts), "USER=<user>");
    assert_eq!(
        redact_ctx("localhost:631 dut", &ONLY_HOST, &["localhost", "dut", "localhost.localdomain"], &[]),
        "localhost:631 <host>"
    );
    for generic in ["system", "daemon", "administrator", "local service", "network service"] {
        let text = format!("x {generic} y");
        assert_eq!(redact_ctx(&text, &ONLY_USERS, &[], &[generic]), text);
    }
    assert_eq!(
        redact_ctx("localhost.localdomain", &ONLY_HOST, &["Localhost.LocalDomain"], &[]),
        "localhost.localdomain"
    );
}

#[test]
fn ipv4() {
    check_all(
        &ONLY_ADDRESSES,
        &[
            ("ip 198.51.100.20 up", "ip <ipv4> up"),
            ("192.0.2.1/24", "<ipv4>/24"),
            ("192.0.2.1:8080", "<ipv4>:8080"),
            ("(192.0.2.1)", "(<ipv4>)"),
            ("at 192.0.2.1.", "at <ipv4>."),
            ("255.255.255.255 0.1.2.3", "<ipv4> <ipv4>"),
            ("inet 192.0.2.3 brd 192.0.2.255", "inet <ipv4> brd <ipv4>"),
            ("inet addr:192.0.2.3", "inet addr:<ipv4>"),
        ],
    );
    check_same(
        &ONLY_ADDRESSES,
        &[
            "127.0.0.1 0.0.0.0",
            "256.1.1.1",
            "1.2.3",
            "1.15.39229",
            "26.37.039980.21751",
            "1.2.3.4.5",
            "192.0.2.3.4",
            "v1.2.3.4",
            "foo-1.2.3.4",
            "1.2.3.4a",
            "1111.2.3.4",
            "1.2.3.4444",
            "a.192.0.2.3",
        ],
    );
}

#[test]
fn mac() {
    check_all(
        &ONLY_ADDRESSES,
        &[
            ("link/ether 08:00:27:4e:66:a1 brd", "link/ether <mac> brd"),
            ("08-00-27-4E-66-A1", "<mac>"),
            ("mac=08:00:27:4e:66:a1;", "mac=<mac>;"),
            ("mac:08:00:27:4e:66:a1", "mac:<mac>"),
            ("ff:ff:ff:ff:ff:ff", "<mac>"),
        ],
    );
    check_same(
        &ONLY_ADDRESSES,
        &[
            "08:00:27:4e:66",
            "08:00:27:4e:66:zz",
            "08:00-27:4e:66:a1",
            "x08:00:27:4e:66:a1",
            "08:00:27:4e:66:a1b",
            // Eight groups are an EUI-64 or WWN, not a MAC; they are caught as IPv6 instead.
            "00-11-22-33-44-55-66-77",
        ],
    );
}

#[test]
fn ipv6() {
    check_all(
        &ONLY_ADDRESSES,
        &[
            ("inet6 fe80::a00:27ff:fe4e:66a1/64 scope", "inet6 <ipv6>/64 scope"),
            ("2001:db8::1", "<ipv6>"),
            ("2001:db8:0:0:0:0:0:1", "<ipv6>"),
            ("[2001:db8::1]:443", "[<ipv6>]:443"),
            ("::ffff:192.0.2.3", "<ipv6>"),
            ("fe80::1%eth0", "<ipv6>%eth0"),
            ("addr fe80::1: up", "addr <ipv6>: up"),
            ("inet6 addr:fe80::1", "inet6 addr:<ipv6>"),
            ("::1", "<ipv6>"),
            // an address at the end of a sentence.
            ("connected to fe80::1.", "connected to <ipv6>."),
            ("peer 2001:db8::abcd.\n", "peer <ipv6>.\n"),
            ("::1.", "<ipv6>."),
            ("::ffff:192.0.2.3.", "<ipv6>."),
            ("1:2:3:4:5:6:7:8", "<ipv6>"),
        ],
    );
    check_same(
        &ONLY_ADDRESSES,
        &[
            "std::vector",
            "Add::Face",
            "::",
            "12:34:56",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "2001::db8::1",
            "12345::1",
            "x2001:db8::1",
            "2001:db8::1g",
            "C:\\Users",
            "fe80::1.5",
            "dead::beef.txt",
            "12:34:56.",
        ],
    );
}

#[test]
fn serials_and_uuids() {
    check_all(
        &ONLY_SERIALS,
        &[
            ("Serial Number: ABC123", "Serial Number: <serial>"),
            ("\tSerial Number: ABC 123 xyz\nNext: 1", "\tSerial Number: <serial>\nNext: 1"),
            ("serial_number=ABC123\r\nx", "serial_number=<serial>\r\nx"),
            ("SerialNumber : ABC123", "SerialNumber : <serial>"),
            ("serial: 99", "serial: <serial>"),
            ("board_serial=7", "board_serial=<serial>"),
            ("ProductSerial=7", "ProductSerial=<serial>"),
            ("UUID: 4C4C4544-0000-1000-8000-B8CA3A000001", "UUID: <uuid>"),
            ("UUID: not-a-uuid value", "UUID: <serial>"),
            ("uuid=abc", "uuid=<serial>"),
            (
                "BOOT_IMAGE=/vmlinuz root=UUID=0a1b2c3d-1111-2222-3333-444455556666 ro xe.force_probe=e20b quiet",
                "BOOT_IMAGE=/vmlinuz root=UUID=<uuid> ro xe.force_probe=e20b quiet",
            ),
            ("serial=ABC123,foo=1", "serial=<serial>,foo=1"),
            ("serial=ABC123 foo=1", "serial=<serial> foo=1"),
            ("{\"a\": (serial=A1) x}", "{\"a\": (serial=<serial>) x}"),
            ("serial=\"A1\" next", "serial=\"<serial>\" next"),
            ("serial = A1 b", "serial = <serial> b"),
            ("serial=,x serial= ", "serial=,x serial= "),
            ("Device Serial Number 00-11-22-33-44-55-66-77", "Device Serial Number <serial>"),
            (
                "Capabilities: [100 v1] Device Serial Number 00-11-22-33-44-55-66-77\nx",
                "Capabilities: [100 v1] Device Serial Number <serial>\nx",
            ),
            ("12345678-1234-1234-1234-123456789abc", "<uuid>"),
            ("id {12345678-ABCD-1234-abcd-123456789ABC}.", "id {<uuid>}."),
            ("x=12345678-1234-1234-1234-123456789abc y", "x=<uuid> y"),
            // A quoted value ends at its closing quote; an unquoted one at a double quote.
            ("serial: \"X\", y: 2", "serial: \"<serial>\", y: 2"),
            (
                "{\"msg\": \"Serial Number: ABC123\", \"level\": 2}",
                "{\"msg\": \"Serial Number: <serial>\", \"level\": 2}",
            ),
            ("serial: 'X Y' z", "serial: '<serial>' z"),
            // Over-redaction of an inline structure is the safe failure: no tail is left behind.
            ("Serial: ABC,12,13", "Serial: <serial>"),
            ("Serial Number: 1234, rev 2", "Serial Number: <serial>"),
            ("Serial Number: ABC   \nX", "Serial Number: <serial>   \nX"),
        ],
    );
    check_same(
        &ONLY_SERIALS,
        &[
            "Serial Number:",
            "Serial Number:   \nX",
            "Serial bus controller: Intel",
            "serial8250: ttyS0",
            "Serial ATA controller: x",
            "unserial: x",
            "Serial Number 00-11-22-33-44-55-66",
            "Serial Number 00-11-22-33-44-55-66-77-88",
            "12345678-1234-1234-1234-123456789abcd",
            "a12345678-1234-1234-1234-123456789abc",
            "12345678-1234-1234-1234-12345678gabc",
        ],
    );
    assert_eq!(redact_with("Serial Number: ABC", &ONLY_ADDRESSES), "Serial Number: ABC");
}

/// JSON-style serial keys in text.
#[test]
fn serial_keys_written_as_json_or_python_repr_in_text() {
    check_all(
        &ONLY_SERIALS,
        &[
            (
                "  \"serial_number\": \"ABC\",\n  \"gpu_serial\": 42,\n",
                "  \"serial_number\": \"<serial>\",\n  \"gpu_serial\": <serial>,\n",
            ),
            (
                "{\"serial_number\": \"ABC\", \"uuid\": \"u-1\"}",
                "{\"serial_number\": \"<serial>\", \"uuid\": \"<serial>\"}",
            ),
            ("\"serial\":\"ABC\"", "\"serial\":\"<serial>\""),
            ("'serial': 'ABC'", "'serial': '<serial>'"),
            ("{\"uuid\": \"12345678-1234-1234-1234-123456789abc\"}", "{\"uuid\": \"<uuid>\"}"),
            ("{\"serial_number\": \"ABC\"}", "{\"serial_number\": \"<serial>\"}"),
        ],
    );
    // Not a key: the word is quoted but nothing is assigned.
    check_same(&ONLY_SERIALS, &["\"serial\" and 'uuid' are words"]);
}

/// Syslog writes paths percent-encoded: `%2Fhome%2Fkwan%2Fx`.
#[test]
fn percent_encoded_separators() {
    check_all(
        &ONLY_USERS,
        &[
            ("%2Fhome%2Fkwan%2Fx", "%2Fhome%2F<user>%2Fx"),
            ("%2Fhome%2Fjdoe%2Fx", "%2Fhome%2F<user>%2Fx"),
            ("%2fhome%2fjdoe%2fx", "%2fhome%2f<user>%2fx"),
            ("%2FUsers%2FJDoe", "%2FUsers%2F<user>"),
            ("/home%2Fjdoe/x", "/home%2F<user>/x"),
            ("%5CUsers%5Cjdoe%5Cx", "%5CUsers%5C<user>%5Cx"),
            ("%2Fkwan%2F", "%2F<user>%2F"),
            ("a%20kwan%20b", "a%20<user>%20b"),
            ("%2Fops", "%2F<user>"),
        ],
    );
    assert_eq!(
        redact_ctx("dbus%2Ftesthost42%2Fx %2FTESTHOST42", &ONLY_HOST, &["testhost42"], &[]),
        "dbus%2F<host>%2Fx %2F<host>"
    );
    assert_eq!(redact_ctx("a%2Fkwan%2Fb", &ONLY_USERS, &[], &["kwan"]), "a%2F<user>%2Fb");
    check_same(
        &ONLY_USERS,
        &["%2F", "%2f", "%20", "ab%2Fcd", "%2Fhome", "%2Fhome%2F", "%2Fhomework%2Fx", "100%"],
    );
    assert_eq!(redact_ctx("ab%2Fcd %2F", &Rules::default(), &[], &[]), "ab%2Fcd %2F");
    // Without a separator before it, a name glued to hex digits is still part of a longer word.
    check_same(&ONLY_USERS, &["x2Fkwan", "xkwan", "%2Fkwanx"]);
}

#[test]
fn plural_keys_in_text() {
    check_all(
        &ONLY_SERIALS,
        &[
            ("serials: X", "serials: <serial>"),
            ("Serials=X1 y", "Serials=<serial> y"),
            ("uuids=abc", "uuids=<serial>"),
            ("UUIDs: abc", "UUIDs: <serial>"),
            ("Serial Numbers: X", "Serial Numbers: <serial>"),
            ("serial_numbers=X", "serial_numbers=<serial>"),
            ("serialnumbers: X", "serialnumbers: <serial>"),
        ],
    );
    check_same(&ONLY_SERIALS, &["serialised: x", "uuidgen: x", "serialise=x", "serialsx: y"]);
}

#[test]
fn values_that_must_survive() {
    let keep = [
        "0000:03:00.0",
        "03:00.0",
        "xe 0000:03:00.0: [drm] GT0: using firmware",
        "00:02.0 VGA compatible controller: Intel Corporation",
        "12:34:56",
        "Nov 09 12:34:56 host kernel: x",
        "2026-11-09T12:34:56.123456+00:00",
        "2026-11-09T12:34:56Z",
        "[   13.635418] xe 0000:03:00.0: [drm] Tile0",
        "[    0.000000] Linux version 7.2.0",
        "00: 86 80 0b e2 07 04 10 00 01 00 00 03 10 00 00 00",
        "10: 0c 00 00 91 00 00 00 00 0c 00 00 90 08 00 00 00",
        "ff: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
        "1.15.39229",
        "26.37.039980.21751",
        "version 2.3.0",
        "127.0.0.1",
        "0.0.0.0",
        "size 4294967296 bytes (4096 MiB)",
        "Region 0: Memory at 91000000 (64-bit, non-prefetchable) [size=16M]",
        "LnkSta: Speed 2.5GT/s, Width x1",
        "Capabilities: [40] Power Management version 3",
        "/dev/dri/renderD128",
        "std::chrono::seconds",
        "driver: xe, version: 1.2",
        // "root" must not be redacted even when a login under sudo names it.
        "root=LABEL=x",
        "Root Port",
        "xe.force_probe=e20b",
        "lo: <LOOPBACK,UP,LOWER_UP> mtu 65536",
        "inet 127.0.0.1/8 scope host lo",
    ];
    for text in keep {
        assert_eq!(redact(text), text, "input: {text:?}");
    }
}

/// the effective user under `sudo` is root; it must not rewrite kernel command lines,
/// lspci output or ownership listings, with every rule class active.
#[test]
fn root_user_name_does_not_rewrite_root_text() {
    let context = Context { hostnames: vec!["localhost".into()], user_names: vec!["root".into()] };
    for text in [
        "BOOT_IMAGE=/vmlinuz root=LABEL=x ro quiet",
        "00:1c.0 PCI bridge: Intel Root Port #1",
        "-rw-r--r-- 1 root root 4096 Nov 9 12:00 x",
        "Root Complex, localhost",
    ] {
        assert_eq!(redact_str(text, &Rules::default(), &context), text, "input: {text:?}");
    }
}

/// a hostname in angle brackets is still data; only our own token words are exempt.
#[test]
fn hostname_in_angle_brackets() {
    let rules = Rules::default();
    assert_eq!(
        redact_ctx("systemd[1]: Hostname set to <TESTHOST42>.", &rules, &["TESTHOST42"], &[]),
        "systemd[1]: Hostname set to <<host>>."
    );
    assert_eq!(redact_ctx("a <host> b", &rules, &["host"], &[]), "a <host> b");
    // The same holds for every token word.
    for word in ["host", "user", "ipv4", "ipv6", "mac", "serial", "uuid"] {
        let text = format!("a <{word}> b");
        assert_eq!(redact_ctx(&text, &ONLY_HOST, &[word], &[]), text);
        assert_eq!(redact_ctx(&text, &ONLY_USERS, &[], &[word]), text);
    }
}

/// an IPv6 address followed by a sentence-ending dot.
#[test]
fn ipv6_before_sentence_dot() {
    assert_eq!(
        redact_with("Link-local address is fe80::1.", &ONLY_ADDRESSES),
        "Link-local address is <ipv6>."
    );
    assert_eq!(redact_with("peer 2001:db8::abcd.\n", &ONLY_ADDRESSES), "peer <ipv6>.\n");
    // A dot followed by a digit is an IPv4 tail and must not leave anything behind.
    assert_eq!(redact_with("::ffff:192.0.2.3.", &ONLY_ADDRESSES), "<ipv6>.");
}

#[test]
fn redaction_composes() {
    assert_eq!(redact("kwan@testhost42 192.0.2.3 08:00:27:4e:66:a1"), "<user>@<host> <ipv4> <mac>");
    // Our own tokens are not re-scanned by a later rule.
    assert_eq!(redact("<serial> <host> <user>"), "<serial> <host> <user>");
    let once = redact("Serial Number: A\nkwan 192.0.2.3 /home/kwan");
    assert_eq!(redact(&once), once);
}

#[test]
fn real_world_journal_lines() {
    assert_eq!(
        redact("Nov 09 12:34:56 TESTHOST42 kernel: xe 0000:03:00.0: [drm] GT0: GuC firmware ok"),
        "Nov 09 12:34:56 <host> kernel: xe 0000:03:00.0: [drm] GT0: GuC firmware ok"
    );
    assert_eq!(
        redact(
            "Nov 09 12:34:56 TESTHOST42 sudo[1234]: kwan : TTY=pts/0 ; PWD=/home/kwan/git ; \
             USER=root ; COMMAND=/usr/bin/xpu-smi log"
        ),
        "Nov 09 12:34:56 <host> sudo[1234]: <user> : TTY=pts/0 ; PWD=/home/<user>/git ; \
         USER=<user> ; COMMAND=/usr/bin/xpu-smi log"
    );
}

#[test]
fn real_world_home_path() {
    assert_eq!(
        redact("/home/kwan/git/xpu-smi/builddir/xpu-smi"),
        "/home/<user>/git/xpu-smi/builddir/xpu-smi"
    );
    assert_eq!(redact_str("/home/other/x", &Rules::default(), &Context::default()), "/home/<user>/x");
}

#[test]
fn real_world_ip_addr() {
    let input = "2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n\
                 \x20   link/ether 00:00:5e:00:53:01 brd ff:ff:ff:ff:ff:ff\n\
                 \x20   inet 192.0.2.72/24 brd 192.0.2.255 scope global dynamic enp3s0\n\
                 \x20      valid_lft 3600sec preferred_lft 3600sec\n\
                 \x20   inet6 fe80::200:5eff:fe00:5301/64 scope link\n\
                 \x20   inet6 2001:db8:1::72/64 scope global\n\
                 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n\
                 \x20   inet 127.0.0.1/8 scope host lo\n\
                 \x20   inet6 ::1/128 scope host\n";
    let output = "2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n\
                  \x20   link/ether <mac> brd <mac>\n\
                  \x20   inet <ipv4>/24 brd <ipv4> scope global dynamic enp3s0\n\
                  \x20      valid_lft 3600sec preferred_lft 3600sec\n\
                  \x20   inet6 <ipv6>/64 scope link\n\
                  \x20   inet6 <ipv6>/64 scope global\n\
                  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n\
                  \x20   inet 127.0.0.1/8 scope host lo\n\
                  \x20   inet6 <ipv6>/128 scope host\n";
    assert_eq!(redact(input), output);
}

#[test]
fn real_world_lspci() {
    assert_eq!(
        redact(
            "\tCapabilities: [1a0 v1] Device Serial Number 00-11-22-33-44-55-66-77\n\
             \tCapabilities: [1b0 v1] Latency Tolerance Reporting\n"
        ),
        "\tCapabilities: [1a0 v1] Device Serial Number <serial>\n\
         \tCapabilities: [1b0 v1] Latency Tolerance Reporting\n"
    );
    let dump = "03:00.0 VGA compatible controller: Intel Corporation Device e20b\n\
                00: 86 80 0b e2 07 04 10 00 00 00 00 03 10 00 80 00\n\
                10: 0c 00 00 91 00 00 00 00 0c 00 00 90 08 00 00 00\n";
    assert_eq!(redact(dump), dump);
}

#[test]
fn real_world_boot_id_and_dmidecode() {
    assert_eq!(
        redact_with("Boot ID: 4c4c4544-0000-1000-8000-b8ca3a000001\n", &ONLY_SERIALS),
        "Boot ID: <uuid>\n"
    );
    assert_eq!(redact("-- Boot 4c4c454400001000800 --"), "-- Boot 4c4c454400001000800 --");
    assert_eq!(redact("-- Boot 4c4c4544-0000-1000-8000-b8ca3a000001 --"), "-- Boot <uuid> --");
    assert_eq!(
        redact(
            "System Information\n\tManufacturer: Intel\n\tProduct Name: X\n\tSerial Number: ABC123\n\
             \tUUID: 4c4c4544-0000-1000-8000-b8ca3a000001\n\tFamily: Y\n"
        ),
        "System Information\n\tManufacturer: Intel\n\tProduct Name: X\n\tSerial Number: <serial>\n\
         \tUUID: <uuid>\n\tFamily: Y\n"
    );
}

#[test]
fn binary_and_unusual_bytes() {
    let mut text = b"abc\0TESTHOST42".to_vec();
    text.push(0xff);
    text.extend_from_slice(" kwan \u{e9} 192.0.2.3".as_bytes());
    let out = redact_text(&text, &Rules::default(), &context());
    let has = |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
    assert!(has(b"<host>"));
    assert!(has(b"<user>"));
    assert!(has(b"<ipv4>"));
    assert_eq!(out.iter().position(|&b| b == 0), Some(3));
    assert!(has(&[0xff, b' ']));
    let odd = b"\xff\xfe:::::: ::\x01";
    assert_eq!(redact_text(odd, &Rules::default(), &context()), odd);
}

/// Deterministic pseudo-random bytes from an alphabet rich in the characters the scanners care
/// about: nothing may panic, whatever the bytes.
#[test]
fn random_inputs_do_not_panic() {
    let alphabet: &[u8] =
        b"0123456789abcdefABCDEF:.-_/\\<>=\"' \t\r\nsSuUlLeErRiIaAlLnNoOmMbBhHoOmMeE{}[](),;\xff\x00%";
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let context =
        Context { hostnames: vec!["ho".into(), "host.example".into()], user_names: vec!["me".into()] };
    for _ in 0..4000 {
        let len = usize::try_from(next() % 120).unwrap();
        let text: Vec<u8> =
            (0..len).map(|_| alphabet[usize::try_from(next()).unwrap() % alphabet.len()]).collect();
        let _ = redact_text(&text, &Rules::default(), &context);
        // Every prefix, to hit every end-of-buffer branch.
        for end in 0..text.len().min(40) {
            let _ = redact_text(&text[..end], &Rules::default(), &context);
        }
        let _ = redact_json_bytes(&text, &Rules::default(), &context);
    }
}

fn jctx() -> Context {
    context()
}

#[test]
fn redact_json_by_key_and_text() {
    let input = json!({
        "hostname": "testhost42",
        "Host_Name": "other",
        "serial": "S-1",
        "UUID": "u-1",
        "serial_number": "S-2",
        "device_uuid": "u-2",
        "empty": {"serial": ""},
        "count": 42,
        "serialCount": 3,
        "flag": true,
        "nothing": null,
        "path": "/home/kwan/x",
        "addr": "ip 192.0.2.3",
        "list": ["testhost42", 7, {"mac": "08:00:27:4e:66:a1"}, {"x": {"serial": "deep"}}],
        "nested": {"a": {"b": {"uuid": "q", "keep": "1.15.39229"}}},
    });
    let out = redact_json(input.clone(), &Rules::default(), &jctx());
    assert_eq!(out["hostname"], "<host>");
    assert_eq!(out["Host_Name"], "<host>");
    assert_eq!(out["serial"], "<serial>");
    assert_eq!(out["UUID"], "<uuid>");
    assert_eq!(out["serial_number"], "<serial>");
    assert_eq!(out["device_uuid"], "<uuid>");
    assert_eq!(out["empty"]["serial"], "");
    assert_eq!(out["count"], 42);
    assert_eq!(out["serialCount"], 3);
    assert_eq!(out["flag"], true);
    assert!(out["nothing"].is_null());
    assert_eq!(out["path"], "/home/<user>/x");
    assert_eq!(out["addr"], "ip <ipv4>");
    assert_eq!(out["list"][0], "<host>");
    assert_eq!(out["list"][1], 7);
    assert_eq!(out["list"][2]["mac"], "<mac>");
    assert_eq!(out["list"][3]["x"]["serial"], "<serial>");
    assert_eq!(out["nested"]["a"]["b"]["uuid"], "<uuid>");
    assert_eq!(out["nested"]["a"]["b"]["keep"], "1.15.39229");

    // Key order is kept.
    let keys: Vec<&str> = out.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(&keys[..4], ["hostname", "Host_Name", "serial", "UUID"]);

    // Rules gate key redaction.
    let host_only = redact_json(input.clone(), &ONLY_HOST, &jctx());
    assert_eq!(host_only["hostname"], "<host>");
    assert_eq!(host_only["serial"], "S-1");
    assert_eq!(host_only["path"], "/home/kwan/x");
    let serials_only = redact_json(input, &ONLY_SERIALS, &jctx());
    assert_eq!(serials_only["hostname"], "testhost42");
    assert_eq!(serials_only["serial"], "<serial>");
}

#[test]
fn redact_json_numbers_and_arrays_under_identifier_keys() {
    let numeric = json!({
        "serial": 1234567,
        "serials": ["A1", "B2"],
        "uuid": ["x"],
        "serial_number": {"value": "kwan"},
        "flags": {"serial": [true, null, "", {"note": "kwan"}]},
    });
    let masked = redact_json(numeric, &Rules::default(), &jctx());
    assert_eq!(masked["serial"], "<serial>");
    assert_eq!(masked["serials"], json!(["<serial>", "<serial>"]));
    assert_eq!(masked["uuid"], json!(["<uuid>"]));
    assert_eq!(masked["serial_number"]["value"], "<user>");
    assert_eq!(masked["flags"]["serial"], json!([true, null, "", {"note": "<user>"}]));
}

#[test]
fn redact_json_keys_are_kept() {
    let keyed = json!({"aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff", "/home/kwan": 1});
    let masked = redact_json(keyed, &Rules::default(), &jctx());
    assert_eq!(masked["aa:bb:cc:dd:ee:ff"], "<mac>");
    assert!(masked.as_object().unwrap().contains_key("/home/kwan"));
}

#[test]
fn redact_json_top_level_scalars() {
    assert_eq!(redact_json(json!("kwan"), &Rules::default(), &jctx()), json!("<user>"));
    assert_eq!(redact_json(json!(5), &Rules::default(), &jctx()), json!(5));
    assert!(redact_json(Value::Null, &Rules::default(), &jctx()).is_null());
}

#[test]
fn redact_json_key_variants() {
    let input = json!({
        "Serial-Number": "a", "host name": "b", "HOST-NAME": "c", "SerialNumbers": ["d"],
        "gpu_uuids": ["e"], "hostnames": "keep", "serialize": "keep"
    });
    let out = redact_json(input, &Rules::default(), &jctx());
    assert_eq!(out["Serial-Number"], "<serial>");
    assert_eq!(out["host name"], "<host>");
    assert_eq!(out["HOST-NAME"], "<host>");
    assert_eq!(out["SerialNumbers"], json!(["<serial>"]));
    assert_eq!(out["gpu_uuids"], json!(["<uuid>"]));
    assert_eq!(out["hostnames"], "keep");
    assert_eq!(out["serialize"], "keep");
}

#[test]
fn redact_json_bytes_formats_like_the_reference() {
    let input = br#"{"serial":"ABC","list":[1,2],"empty":{},"none":[],"path":"/home/kwan/x"}"#;
    let out = redact_json_bytes(input, &Rules::default(), &context());
    let expected = "{\n  \"serial\": \"<serial>\",\n  \"list\": [\n    1,\n    2\n  ],\n  \"empty\": {},\n  \
                    \"none\": [],\n  \"path\": \"/home/<user>/x\"\n}\n";
    assert_eq!(String::from_utf8(out).unwrap(), expected);
}

#[test]
fn redact_json_bytes_accepts_bom_and_trailing_whitespace() {
    let mut input = b"\xEF\xBB\xBF".to_vec();
    input.extend_from_slice(b" {\"hostname\": \"x\"} \n\n");
    let out = redact_json_bytes(&input, &Rules::default(), &context());
    assert_eq!(out, b"{\n  \"hostname\": \"<host>\"\n}\n");
}

/// a `.json` artifact that does not parse falls back to text redaction.
#[test]
fn json_parse_failure_falls_back_to_text() {
    let broken = b"{\"serial_number\": \"ABC\", \"host\": 192.0.2.3, truncated";
    let out = redact_json_bytes(broken, &Rules::default(), &context());
    assert_eq!(out, b"{\"serial_number\": \"<serial>\", \"host\": <ipv4>, truncated");
    // Not UTF-8 at all.
    let binary = b"{\"serial\": \"A\xff\"";
    assert_eq!(redact_json_bytes(binary, &Rules::default(), &context()), b"{\"serial\": \"<serial>\"");
    // Empty input is not a document either and stays empty.
    assert!(redact_json_bytes(b"", &Rules::default(), &context()).is_empty());
    // Trailing garbage after a document.
    let trailing = redact_json_bytes(b"{\"a\": 1} serial: 7", &Rules::default(), &context());
    assert_eq!(trailing, b"{\"a\": 1} serial: <serial>");
}

#[test]
fn redact_json_bytes_with_no_rules_still_parses_and_formats() {
    let out = redact_json_bytes(br#"{"serial":"ABC"}"#, &Rules::none(), &context());
    assert_eq!(out, b"{\n  \"serial\": \"ABC\"\n}\n");
}

#[test]
fn deep_json_nesting_falls_back_to_text() {
    let mut text = String::new();
    for _ in 0..1000 {
        text.push('[');
    }
    text.push_str("\"serial: x\"");
    for _ in 0..1000 {
        text.push(']');
    }
    let out = redact_json_bytes(text.as_bytes(), &Rules::default(), &context());
    assert!(String::from_utf8(out).unwrap().contains("serial: <serial>"));
}

/// The input of the linearity test: 16 MiB of realistic lines, then runs that make a scanner
/// quadratic when it rescans: long dotted and colon runs, and keys with unterminated quoted values
/// on one endless line.
fn adversarial_input() -> Vec<u8> {
    let chunk = "Nov 09 12:34:56 TESTHOST42 kernel: [   13.635418] xe 0000:03:00.0: [drm] GT0: ok 1.15.39229\n\
        00: 86 80 0b e2 07 04 10 00 01 00 00 03 10 00 00 00 aa:bb:cc:dd:ee:ff\n\
        kwan logged in from 192.0.2.72 port 22 fe80::200:5eff:fe00:5301 /home/kwan/git\n\
        \tSerial Number: ABC123\n\
        boot 4c4c4544-0000-1000-8000-b8ca3a000001 size 4294967296 bytes 26.37.039980.21751\n\
        the quick brown fox jumps over the lazy dog, deadbeef cafe add::face std::vector 12:34:56\n\
        a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829\n";
    const TARGET: usize = 16 * 1024 * 1024;
    let mut text = Vec::with_capacity(TARGET + chunk.len() + 8 * 1024 * 1024);
    while text.len() < TARGET {
        text.extend_from_slice(chunk.as_bytes());
    }
    for _ in 0..1024 * 1024 {
        text.extend_from_slice(b"1.");
    }
    for _ in 0..1024 * 1024 {
        text.extend_from_slice(b"a:");
    }
    for _ in 0..256 * 1024 {
        text.extend_from_slice(b" serial: \"a \"serial\": b uuid=\"c");
    }
    for _ in 0..512 * 1024 {
        text.extend_from_slice(b"%2Fhome%2Fkwan%2F%2F%5C%20%2f");
    }
    for _ in 0..512 * 1024 {
        text.extend_from_slice(b"%2%%2Fhome%2F%2Fusers%2F");
    }
    text
}

/// 16 MiB of mixed and adversarial input must redact in under 2 s in release:
/// `cargo test --release --locked redact -- --ignored`.
#[test]
#[ignore = "timing test: run in release with --ignored"]
fn linear_time_on_16_mib_mixed_and_adversarial_input() {
    let text = adversarial_input();
    let start = std::time::Instant::now();
    let out = redact_text(&text, &Rules::default(), &context());
    let elapsed = start.elapsed();
    eprintln!("redacted {} bytes in {} ms", text.len(), elapsed.as_millis());
    let has = |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
    assert!(!has(b"TESTHOST42"));
    assert!(!has(b"kwan"));
    assert!(!has(b"192.0.2.72"));
    assert!(!has(b"ABC123"));
    assert!(has(b"0000:03:00.0"));
    assert!(has(b"1.15.39229"));
    assert!(out.starts_with(b"Nov 09 12:34:56 <host> kernel: [   13.635418]"));
    assert!(elapsed < std::time::Duration::from_secs(2), "took {elapsed:?}");
}

/// A debug-build smoke version of the linearity test on a smaller input, so a quadratic scanner
/// shows up in a normal `cargo test` too.
#[test]
fn adversarial_runs_are_not_quadratic() {
    let mut text = Vec::new();
    for _ in 0..64 * 1024 {
        text.extend_from_slice(b"1.");
    }
    for _ in 0..64 * 1024 {
        text.extend_from_slice(b"a:");
    }
    for _ in 0..16 * 1024 {
        text.extend_from_slice(b" serial: \"a \"serial\": b uuid=\"c");
    }
    for _ in 0..16 * 1024 {
        text.extend_from_slice(b"/home/x/home/y USER=u LOGNAME=");
    }
    for _ in 0..16 * 1024 {
        text.extend_from_slice(b"%2%%2Fhome%2F%2Fusers%2F%2Fkwan%2F%5C%20");
    }
    let start = std::time::Instant::now();
    let out = redact_text(&text, &Rules::default(), &context());
    assert!(!out.is_empty());
    assert!(start.elapsed() < std::time::Duration::from_secs(10), "took {:?}", start.elapsed());
}
