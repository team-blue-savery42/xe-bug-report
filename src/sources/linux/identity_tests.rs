// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/identity.rs`.

use super::*;

#[test]
fn host_names_come_from_proc_and_resolv_conf_without_dns() {
    let context = identity_from(
        "gpu-box\n",
        "(none)\n",
        "# generated\nnameserver 127.0.0.53\nsearch lab.example example.com.\n",
        1000,
        None,
        Some("alice"),
        Some("alice"),
    );
    assert_eq!(context.hostnames, ["gpu-box", "gpu-box.lab.example", "gpu-box.example.com"]);
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
