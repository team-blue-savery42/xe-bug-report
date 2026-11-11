// SPDX-License-Identifier: MIT
//! Test helpers shared by the unit tests of the Linux sources: a reader over real files and a
//! helper that builds a small tree of files in a temporary directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use crate::bundle::source::{Keep, ReadOutcome, ReadResult, Reader};
use crate::units::Bytes;

/// Reads real files with std, recording every path it was asked for.
#[derive(Default)]
pub struct FsReader {
    /// The paths read, in order.
    pub asked: Mutex<Vec<String>>,
}

impl Reader for FsReader {
    fn read(&self, path: &Path, max: Bytes, _keep: Keep) -> ReadResult {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).push(path.to_string_lossy().into_owned());
        match fs::read(path) {
            Ok(mut data) => {
                let truncated = data.len() as u64 > max.get();
                data.truncate(max.get() as usize);
                ReadResult { outcome: ReadOutcome::Read, data, truncated, error: String::new() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ReadResult { outcome: ReadOutcome::Missing, ..Default::default() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                ReadResult { outcome: ReadOutcome::Denied, ..Default::default() }
            }
            Err(e) => ReadResult { outcome: ReadOutcome::Failed, error: e.to_string(), ..Default::default() },
        }
    }
}

/// Writes `contents` to `root/rel`, creating the directories.
pub fn put(root: &Path, rel: &str, contents: impl AsRef<[u8]>) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// The text of a produced artifact's data.
pub fn text_of(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}
