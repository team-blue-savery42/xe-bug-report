// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/identity.rs`.

use super::*;

#[test]
fn host_names_come_from_proc_and_resolv_conf_without_dns() {
    // The names come from /proc and resolv.conf, never from a lookup.
    let context = identity_from(
        "gpu-box\n",
        "(none)\n",
        "# generated\nnameserver 127.0.0.53\nsearch lab.example example.com.\n",
        1000,
        None,
        Some("alice"),
        Some("alice"),
    );
    // The site's own search domain is a name too; `example.com` is public and stays readable.
    assert_eq!(context.hostnames, ["gpu-box", "gpu-box.lab.example", "gpu-box.example.com", "lab.example"]);
    assert_eq!(context.user_names, ["alice"]);
}

#[test]
fn root_and_numeric_names_are_never_redacted_and_sudo_user_is_added() {
    let context = identity_from("h", "", "", 0, Some("jdoe"), Some("root"), Some("root"));
    assert_eq!(context.user_names, ["jdoe"]);
    let context = identity_from("h", "", "", 0, None, Some("root"), None);
    assert!(context.user_names.is_empty());
    let context = identity_from("h", "", "", 1000, None, Some("1000"), Some("nobody"));
    assert!(context.user_names.is_empty());
    // The host names never contain a generic name that this module added.
    assert!(context.hostnames.iter().all(|n| n != "root"));
}

#[test]
fn passwd_lookup_is_by_id_and_tolerates_junk() {
    let passwd = "root:x:0:0:r:/root:/bin/sh\njdoe:x:1003:1003::/home/jdoe:/bin/zsh\n\n#c\nbad\n";
    assert_eq!(user_name_in(passwd, 1003).unwrap(), "jdoe");
    assert_eq!(user_name_in(passwd, 0).unwrap(), "root");
    assert!(user_name_in(passwd, 5).is_none());
    assert!(user_name_in("", 0).is_none());
}

#[test]
fn live_identity_and_description() {
    let description = os_description();
    assert!(!description.is_empty());
    assert!(description.contains("Linux"), "{description}");
    let lookup_free = local_identity_without_lookups();
    let full = local_identity();
    for context in [&lookup_free, &full] {
        assert!(context.user_names.iter().all(|n| n != "root" && n != "nobody" && !n.is_empty()));
    }
    assert!(full.user_names.len() >= lookup_free.user_names.len());
    println!("os_description: {description}");
    println!("identity without lookups: {lookup_free:?}");
    println!("identity: {full:?}");
}

#[test]
fn the_domain_of_the_host_name_and_the_search_domains_are_redacted_but_public_ones_are_not() {
    let context = identity_from(
        "dut01.fm.corp.example\n",
        "(none)\n",
        "search corp.example launchpad.net ubuntu.com com\n",
        1000,
        None,
        None,
        None,
    );
    for name in ["dut01.fm.corp.example", "dut01", "fm.corp.example", "corp.example"] {
        assert!(context.hostnames.iter().any(|n| n == name), "{name}: {:?}", context.hostnames);
    }
    for public in ["launchpad.net", "ubuntu.com", "com"] {
        assert!(!context.hostnames.iter().any(|n| n == public), "{public}");
    }
    let rules = redact::Rules::default();
    let text = "deb https://mirror.fm.corp.example/ubuntu noble main\ndeb https://archive.ubuntu.com/ubuntu noble main\n\
                see https://example.com/x and https://ppa.launchpadcontent.net/a/b";
    let out = redact::redact_str(text, &rules, &context);
    assert!(out.contains("deb https://mirror.<host>/ubuntu noble main"), "{out}");
    assert!(out.contains("https://archive.ubuntu.com/ubuntu"), "{out}");
    assert!(out.contains("https://example.com/x") && out.contains("ppa.launchpadcontent.net"), "{out}");
}

#[test]
fn private_domains_skip_single_labels_suffixes_and_public_services() {
    let none: Vec<String> = Vec::new();
    assert!(private_domains("host", &none).is_empty());
    assert!(private_domains("host.local", &none).is_empty());
    assert!(private_domains("host.co.uk", &none).is_empty());
    assert!(private_domains("host.example.com", &none).is_empty());
    assert!(private_domains("host.eu.launchpad.net", &none).is_empty());
    assert_eq!(private_domains("host.Lab.Example.", &none), ["lab.example"]);
    let resolver = vec!["lab.example".to_owned(), "LAB.example".to_owned(), "corp".to_owned()];
    assert_eq!(private_domains("host.lab.example", &resolver), ["lab.example"]);
}

#[test]
fn the_machine_id_is_redacted_like_a_host_name() {
    let id = "0123456789abcdef0123456789ABCDEF";
    assert_eq!(parse_machine_id(&format!("{id}\n")).as_deref(), Some("0123456789abcdef0123456789abcdef"));
    for bad in ["", "uninitialized\n", "0123456789abcdef", "zz23456789abcdef0123456789abcdef"] {
        assert_eq!(parse_machine_id(bad), None, "{bad}");
    }
    let context =
        with_machine_id(identity_from("gpu-box", "", "", 1000, None, None, None), &format!("{id}\n"));
    let text = "Journal file /var/log/journal/0123456789abcdef0123456789abcdef/system.journal is truncated";
    let out = redact::redact_str(text, &redact::Rules::default(), &context);
    assert_eq!(out, "Journal file /var/log/journal/<host>/system.journal is truncated");
    // No id (a container without /etc/machine-id) changes nothing.
    let same = with_machine_id(context.clone(), "");
    assert_eq!(same, context);
}
