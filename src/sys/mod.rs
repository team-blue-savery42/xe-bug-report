// SPDX-License-Identifier: MIT
//! The only `unsafe` code: thin, documented wrappers over `libc` and `windows-sys`.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
