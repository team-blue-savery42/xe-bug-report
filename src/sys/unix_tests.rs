// SPDX-License-Identifier: MIT
//! Unit tests for `src/sys/unix.rs`.

use super::*;

#[test]
fn can_read_write_follows_the_permission_check() {
    use std::path::Path;
    assert!(can_read_write(Path::new("/dev/null")));
    assert!(!can_read_write(Path::new("/nonexistent/node")));
    assert!(!can_read_write(Path::new("/dev/nu\0ll")));
    if euid() != 0 {
        assert!(!can_read_write(Path::new("/proc/version")));
    }
}

#[test]
fn a_prepared_child_has_core_dumps_off() {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("ulimit -c");
    prepare_child(&mut cmd);
    let output = cmd.output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0");
}

#[test]
fn euid_matches_proc_status() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
    // "Uid:\treal\teffective\tsaved\tfs"
    let effective: u32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert_eq!(euid(), effective);
}

#[test]
fn monotonic_now_is_nonzero_and_does_not_go_back() {
    let a = monotonic_now();
    let b = monotonic_now();
    assert!(a > Duration::ZERO);
    assert!(b >= a);
}

#[test]
fn kill_process_group_refuses_dangerous_ids() {
    // 0 would be our own group, values above i32::MAX would wrap negative: both must be no-ops
    // (the test process surviving is the assertion).
    kill_process_group(0);
    kill_process_group(u32::MAX);
    kill_process_group(1 << 31);
}

#[test]
fn kill_process_group_kills_a_group() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let mut child = Command::new("sleep").arg("30").process_group(0).spawn().unwrap();
    kill_process_group(child.id());
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

const NLMSG_HDRLEN: usize = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLM_F_REQUEST: u16 = 1;

/// A CTRL_CMD_GETFAMILY request for "nlctrl".
fn getfamily_request() -> Vec<u8> {
    let name = b"nlctrl\0";
    let attr_len = 4 + name.len();
    let attr_padded = attr_len.div_ceil(4) * 4;
    let total = NLMSG_HDRLEN + 4 + attr_padded;
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as u32).to_ne_bytes());
    msg.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    msg.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&[CTRL_CMD_GETFAMILY, 1, 0, 0]); // genlmsghdr: cmd, version, reserved
    msg.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    msg.extend_from_slice(&CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
    msg.extend_from_slice(name);
    msg.resize(total, 0);
    msg
}

#[test]
fn netlink_getfamily_for_nlctrl_round_trips() {
    const CTRL_ATTR_FAMILY_ID: u16 = 1;

    let sock = match NetlinkSocket::open_generic(Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("generic netlink unavailable here ({e}); skipped");
            return;
        }
    };

    let msg = getfamily_request();
    sock.send(&msg).unwrap();
    let mut buf = vec![0u8; 32 * 1024];
    let n = sock.recv(&mut buf).unwrap();
    assert!(n >= NLMSG_HDRLEN + 4, "short reply: {n}");
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    assert_eq!(msg_type, GENL_ID_CTRL, "reply is not a controller message");

    // Walk the attributes after nlmsghdr + genlmsghdr and find the family id (nlctrl is 0x10).
    let mut off = NLMSG_HDRLEN + 4;
    let mut family_id = None;
    while off + 4 <= n {
        let len = usize::from(u16::from_ne_bytes([buf[off], buf[off + 1]]));
        let ty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]) & 0x3fff;
        if len < 4 || off + len > n {
            break;
        }
        if ty == CTRL_ATTR_FAMILY_ID && len >= 6 {
            family_id = Some(u16::from_ne_bytes([buf[off + 4], buf[off + 5]]));
        }
        off += len.div_ceil(4) * 4;
    }
    assert_eq!(family_id, Some(GENL_ID_CTRL));
}

#[test]
fn netlink_recv_reports_a_datagram_larger_than_the_buffer() {
    let Ok(sock) = NetlinkSocket::open_generic(Duration::from_secs(3)) else {
        return;
    };
    sock.send(&getfamily_request()).unwrap();
    let mut small = [0u8; 24];
    let err = sock.recv(&mut small).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
}

#[test]
fn netlink_recv_times_out() {
    let Ok(sock) = NetlinkSocket::open_generic(Duration::from_millis(50)) else {
        return;
    };
    let mut buf = [0u8; 64];
    let start = std::time::Instant::now();
    let err = sock.recv(&mut buf).unwrap_err();
    assert!(matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "{err}");
    assert!(start.elapsed() < Duration::from_secs(2));
}
