// SPDX-License-Identifier: MIT
//! Unit tests for `src/error.rs`.

use super::*;

#[test]
fn messages_name_the_subject() {
    assert_eq!(Error::InvalidArgument("bad".into()).to_string(), "bad");
    assert_eq!(
        Error::UnknownDevice("0000:09:00.0".into()).to_string(),
        "No Intel GPU with PCI address 0000:09:00.0 was found on this system"
    );
    assert_eq!(Error::OutputExists(PathBuf::from("a.zip")).to_string(), "a.zip already exists");
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let text = Error::OutputUnwritable { path: PathBuf::from("/x/a.zip"), source: denied }.to_string();
    assert!(text.starts_with("cannot create /x/a.zip: "), "{text}");
    let full = std::io::Error::from(std::io::ErrorKind::StorageFull);
    let text = Error::WriteFailed { path: PathBuf::from("a.zip"), source: full }.to_string();
    assert!(text.starts_with("cannot write a.zip: "), "{text}");
    assert_eq!(Error::InvalidEntryName("a b".into()).to_string(), "invalid archive entry name \"a b\"");
}

#[test]
fn io_errors_convert() {
    let error: Error = std::io::Error::other("boom").into();
    assert_eq!(error.to_string(), "boom");
}
