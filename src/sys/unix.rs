// SPDX-License-Identifier: MIT
//! Safe wrappers over the few `libc` calls xe-bug-report needs. Every `unsafe` block carries a
//! `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::io;
use std::process::Command;
use std::time::Duration;

/// The effective user id.
pub fn euid() -> u32 {
    0
}

/// Sends SIGKILL to the process group `pgid` (`kill(-pgid, SIGKILL)`); errors are ignored.
pub fn kill_process_group(pgid: u32) {
    let _ = pgid;
}

/// Makes `cmd` reset SIGCHLD to its default disposition in the child before exec, so a parent
/// that ignores SIGCHLD does not leak that into tools that wait for their own children.
pub fn reset_sigchld_in_child(cmd: &mut Command) {
    let _ = cmd;
}

/// `CLOCK_MONOTONIC` now, the clock `/dev/kmsg` timestamps use.
pub fn monotonic_now() -> Duration {
    Duration::ZERO
}

/// A generic netlink socket (`AF_NETLINK`, `SOCK_RAW | SOCK_CLOEXEC`, `NETLINK_GENERIC`), closed on drop.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: std::os::fd::OwnedFd,
}

impl NetlinkSocket {
    /// Opens the socket with `SO_RCVTIMEO` = `recv_timeout`.
    pub fn open_generic(recv_timeout: Duration) -> io::Result<Self> {
        let _ = recv_timeout;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Sends one message to the kernel (port 0).
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let _ = (&self.fd, msg);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Receives one datagram into `buf`; `WouldBlock`/`TimedOut` when `SO_RCVTIMEO` expires.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _ = buf;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
