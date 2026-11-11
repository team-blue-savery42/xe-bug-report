// SPDX-License-Identifier: MIT
//! Safe wrappers over the few `libc` calls xe-bug-report needs. Every `unsafe` block carries a
//! `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

/// `O_NOCTTY`: opening a terminal device must not make it the controlling terminal.
pub const O_NOCTTY: i32 = libc::O_NOCTTY;

/// `O_NONBLOCK`: reads of pipes, FIFOs and record devices such as `/dev/kmsg` fail with
/// `WouldBlock` instead of waiting for more data.
pub const O_NONBLOCK: i32 = libc::O_NONBLOCK;

/// `EPERM` (1): operation not permitted.
pub const EPERM: i32 = libc::EPERM;
/// `EACCES` (13): permission denied.
pub const EACCES: i32 = libc::EACCES;
/// `ENOENT` (2): no such file, or no such generic netlink family.
pub const ENOENT: i32 = libc::ENOENT;
/// `EIO` (5): input/output error.
pub const EIO: i32 = libc::EIO;
/// `EPROTONOSUPPORT`: the kernel has no netlink protocol.
pub const EPROTONOSUPPORT: i32 = libc::EPROTONOSUPPORT;
/// `EAFNOSUPPORT`: the kernel has no netlink address family.
pub const EAFNOSUPPORT: i32 = libc::EAFNOSUPPORT;

/// The effective user id.
pub fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Whether the effective user may read and write `path`, by the kernel's own permission check
/// (`faccessat(AT_FDCWD, path, R_OK | W_OK, AT_EACCESS)`: mode bits, ACLs and capabilities, without
/// opening the node, so a device driver is never entered). False for a path with a NUL byte.
pub fn can_read_write(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call; faccessat reads it
    // and touches no other memory.
    let rc = unsafe {
        libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), libc::R_OK | libc::W_OK, libc::AT_EACCESS)
    };
    rc == 0
}

/// Sends SIGKILL to the process group `pgid` (`kill(-pgid, SIGKILL)`); errors are ignored.
///
/// A `pgid` of 0 or one that does not fit a positive `pid_t` is refused: `kill(-0, ..)` would
/// signal the caller's own group.
pub fn kill_process_group(pgid: u32) {
    let Ok(pgid) = libc::pid_t::try_from(pgid) else {
        return;
    };
    if pgid <= 0 {
        return;
    }
    // SAFETY: kill takes two integers and touches no memory; `-pgid` is negative and non-zero, so it
    // names exactly one process group and never the caller's own group or "all processes".
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Prepares the child of `cmd` before exec: SIGCHLD back to its default disposition, so a parent
/// that ignores it does not leak that into tools that wait for their own children, and core dumps
/// off (`RLIMIT_CORE` 0), so a crashing tool does not leave a `core` file in the user's directory.
pub fn prepare_child(cmd: &mut Command) {
    set_sigchld_in_child(cmd, libc::SIG_DFL);
    disable_core_dumps_in_child(cmd);
}

fn disable_core_dumps_in_child(cmd: &mut Command) {
    // SAFETY: the closure runs between fork and exec, so it may only call async-signal-safe
    // functions; `setrlimit` is one (a single system call), it takes a pointer to a stack-local
    // struct, allocates nothing and takes no locks. A failure is ignored: the limit is a courtesy.
    unsafe {
        cmd.pre_exec(|| {
            let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            Ok(())
        });
    }
}

/// Makes `cmd` ignore SIGCHLD in the child (the disposition survives exec). Test support: it lets a
/// test run a copy of the test binary as a process whose SIGCHLD is ignored, without changing the
/// disposition of the multi-threaded test process itself.
#[cfg(test)]
pub(crate) fn ignore_sigchld_in_child(cmd: &mut Command) {
    set_sigchld_in_child(cmd, libc::SIG_IGN);
}

fn set_sigchld_in_child(cmd: &mut Command, handler: libc::sighandler_t) {
    // SAFETY: the closure runs between fork and exec, so it may only call async-signal-safe
    // functions; it calls `libc::signal`, which is one, allocates nothing and takes no locks.
    unsafe {
        cmd.pre_exec(move || {
            libc::signal(libc::SIGCHLD, handler);
            Ok(())
        });
    }
}

/// `CLOCK_MONOTONIC` now, the clock `/dev/kmsg` timestamps use.
pub fn monotonic_now() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return Duration::ZERO;
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u32::try_from(ts.tv_nsec).unwrap_or(0);
    Duration::new(secs, nanos)
}

/// A generic netlink socket (`AF_NETLINK`, `SOCK_RAW | SOCK_CLOEXEC`, `NETLINK_GENERIC`), closed on drop.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl NetlinkSocket {
    /// Opens the socket with `SO_RCVTIMEO` = `recv_timeout` (at least one millisecond: a zero
    /// timeout would mean "block forever").
    pub fn open_generic(recv_timeout: Duration) -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        // SAFETY: socket takes three integers and returns a new descriptor or -1.
        let raw = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_GENERIC)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: sockaddr_nl is plain data for which all-zero bytes is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0; // let the kernel choose the port id
        addr.nl_groups = 0;
        // SAFETY: `addr` is a valid sockaddr_nl and the length passed is its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let timeout = recv_timeout.max(Duration::from_millis(1));
        let tv = libc::timeval {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_usec: timeout.subsec_micros() as libc::suseconds_t, // below 1_000_000: fits
        };
        // SAFETY: `tv` is a valid timeval and the length passed is its size.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Sends one message to the kernel (port 0).
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        // SAFETY: sockaddr_nl is plain data for which all-zero bytes is a valid value.
        let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        dest.nl_pid = 0; // the kernel
        dest.nl_groups = 0;
        loop {
            // SAFETY: `msg` is valid for `msg.len()` bytes, `dest` is a valid sockaddr_nl and the
            // length passed is its size; the descriptor is owned by `self` and open.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                    0,
                    (&raw const dest).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if sent as usize != msg.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short netlink send"));
            }
            return Ok(());
        }
    }

    /// Receives one datagram into `buf`; `WouldBlock`/`TimedOut` when `SO_RCVTIMEO` expires.
    ///
    /// A datagram longer than `buf` is an `InvalidData` error instead of a silently cut message
    /// (`MSG_TRUNC`). Netlink dumps can fill 16 KiB or more per datagram: pass a buffer of at
    /// least 32 KiB.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        loop {
            // SAFETY: `buf` is valid for writes of `buf.len()` bytes; the descriptor is owned by
            // `self` and open. With MSG_TRUNC the kernel copies at most `buf.len()` bytes but
            // returns the real datagram length.
            let got = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let got = got as usize;
            if got > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink datagram larger than the receive buffer",
                ));
            }
            return Ok(got);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl NetlinkSocket {
    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn open_generic(recv_timeout: Duration) -> io::Result<Self> {
        let _ = recv_timeout;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let _ = (&self.fd, msg);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (&self.fd, buf);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "unix_tests.rs"]
mod tests;
