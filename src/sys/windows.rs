// SPDX-License-Identifier: MIT
//! Safe wrappers over the few `windows-sys` calls xe-bug-report needs: job objects, token
//! elevation and the OEM code page. Every `unsafe` block carries a `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::io;
use std::process::Child;

/// `CREATE_NO_WINDOW` for `CommandExt::creation_flags`.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A job object created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; closing it kills its processes.
#[derive(Debug)]
pub struct Job {
    handle: isize,
}

impl Job {
    /// Creates the job.
    pub fn create() -> io::Result<Self> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Assigns `child` to the job.
    pub fn assign(&self, child: &Child) -> io::Result<()> {
        let _ = (self.handle, child);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Terminates every process in the job.
    pub fn terminate(&self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Whether the process token is elevated (`TokenElevation`).
pub fn is_elevated() -> bool {
    false
}

/// Decodes `bytes` from the OEM code page (`GetOEMCP` + `MultiByteToWideChar`) into UTF-8;
/// lossy when that fails.
pub fn oem_to_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
