// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/probes.rs`.

use super::*;
use crate::procio::PrivateTempDir;
use crate::sources::linux::testkit::{FsReader, put};

#[test]
fn values_are_trimmed_and_empty_ones_are_none() {
    let dir = PrivateTempDir::create("probes").unwrap();
    put(dir.path(), "a", "  42\n");
    put(dir.path(), "empty", "\n");
    assert_eq!(read_value(&FsReader::default(), &dir.path().join("a")).as_deref(), Some("42"));
    assert_eq!(read_value(&FsReader::default(), &dir.path().join("empty")), None);
    assert_eq!(read_value(&FsReader::default(), &dir.path().join("missing")), None);
}

#[test]
fn an_attribute_line_stays_on_one_line() {
    let dir = PrivateTempDir::create("probes").unwrap();
    put(dir.path(), "multi", "one\ntwo\n");
    put(dir.path(), "empty", "");
    let reader = FsReader::default();
    assert_eq!(attribute_line(&reader, "x", &dir.path().join("multi")), "x: one; two");
    assert_eq!(attribute_line(&reader, "x", &dir.path().join("empty")), "x: (empty)");
    assert_eq!(attribute_line(&reader, "x", &dir.path().join("nope")), "x: (absent)");
}

#[test]
fn prefixed_names_sort_by_number() {
    let dir = PrivateTempDir::create("probes").unwrap();
    for name in ["mei10", "mei2", "mei1", "other"] {
        put(dir.path(), name, "");
    }
    assert_eq!(list_prefixed(dir.path(), "mei"), ["mei1", "mei2", "mei10"]);
    assert!(list_names(&dir.path().join("none")).is_empty());
}

#[test]
fn a_link_name_is_the_last_component() {
    let dir = PrivateTempDir::create("probes").unwrap();
    std::os::unix::fs::symlink("../../x/0000:03:00.0/", dir.path().join("l")).unwrap();
    assert_eq!(link_name(&dir.path().join("l")).as_deref(), Some("0000:03:00.0"));
    assert_eq!(link_name(&dir.path().join("none")), None);
}
