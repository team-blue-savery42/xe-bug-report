// SPDX-License-Identifier: MIT
//! A read-only client of the kernel's `drm-ras` generic netlink family, which reports the RAS error
//! counters of a GPU.
//!
//! Only three requests are ever sent, and the [`Request`] enum is closed over them: the family
//! lookup (`CTRL_CMD_GETFAMILY`), the node listing (`DRM_RAS_CMD_LIST_NODES`, dump) and the counter
//! dump (`DRM_RAS_CMD_GET_ERROR_COUNTER`, dump). The commands that clear a counter (3) or set a
//! threshold (6) are not representable. Message building and parsing are pure functions over
//! `&[u8]` with every length checked, so they are tested with crafted and malformed buffers; only
//! [`read_counters`] touches the socket.
//!
//! On CRI the counters come from System Controller firmware, which is why they are read from the
//! kernel and not from sysfs.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::bundle::source::{Gate, Produced, Status};
use crate::pci::PciAddress;
use crate::sys::unix::{EACCES, EAFNOSUPPORT, EIO, ENOENT, EPERM, EPROTONOSUPPORT, NetlinkSocket};

use super::debugfs::needs_text;

// Values of the generic netlink core and of the drm-ras UAPI (family "drm-ras", version 1).
/// The family name.
pub const FAMILY_NAME: &str = "drm-ras";
/// The family version put in the generic header.
pub const FAMILY_VERSION: u8 = 1;
/// The id of the generic netlink controller.
pub const GENL_ID_CTRL: u16 = 0x10;
/// `CTRL_CMD_GETFAMILY`.
pub const CTRL_CMD_GETFAMILY: u8 = 3;
/// `CTRL_ATTR_FAMILY_ID`.
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// `CTRL_ATTR_FAMILY_NAME`.
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
/// `DRM_RAS_CMD_LIST_NODES`.
pub const CMD_LIST_NODES: u8 = 1;
/// `DRM_RAS_CMD_GET_ERROR_COUNTER`.
pub const CMD_GET_ERROR_COUNTER: u8 = 2;
/// Node attribute: the node id (u32).
pub const NODE_ATTR_NODE_ID: u16 = 1;
/// Node attribute: the device name, a PCI address (string).
pub const NODE_ATTR_DEVICE_NAME: u16 = 2;
/// Node attribute: the node name (string).
pub const NODE_ATTR_NODE_NAME: u16 = 3;
/// Node attribute: the node type (u32).
pub const NODE_ATTR_NODE_TYPE: u16 = 4;
/// Counter attribute: the node id (u32).
pub const COUNTER_ATTR_NODE_ID: u16 = 1;
/// Counter attribute: the error id (u32).
pub const COUNTER_ATTR_ERROR_ID: u16 = 2;
/// Counter attribute: the error name (string).
pub const COUNTER_ATTR_ERROR_NAME: u16 = 3;
/// Counter attribute: the value (u64).
pub const COUNTER_ATTR_ERROR_VALUE: u16 = 4;
/// Counter attribute: the threshold.
pub const COUNTER_ATTR_ERROR_THRESHOLD: u16 = 5;
/// `NLM_F_REQUEST`.
pub const NLM_F_REQUEST: u16 = 0x1;
/// `NLM_F_DUMP` (`NLM_F_ROOT | NLM_F_MATCH`).
pub const NLM_F_DUMP: u16 = 0x300;
/// `NLMSG_NOOP`.
pub const NLMSG_NOOP: u16 = 1;
/// `NLMSG_ERROR`.
pub const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`.
pub const NLMSG_DONE: u16 = 3;

const NLMSG_HEADER_SIZE: usize = 16;
const GENL_HEADER_SIZE: usize = 4;
const ATTR_HEADER_SIZE: usize = 4;
const ALIGNMENT: usize = 4;
/// `NLA_TYPE_MASK`: the top two bits are NESTED and NET_BYTEORDER.
const ATTR_TYPE_MASK: u16 = 0x3fff;
const RECEIVE_BUFFER_SIZE: usize = 1 << 20;
/// One wait for the kernel (`SO_RCVTIMEO` is fixed when the socket opens).
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(3);
/// The whole read. The deadline is checked before each receive, and a receive that starts just
/// before it can wait up to [`RECEIVE_TIMEOUT`] more, so the last wait ends before 9 s: a slow
/// kernel is reported as "did not answer" before the source's own 10 s limit.
const READ_DEADLINE: Duration = Duration::from_secs(6);

/// Rounds `size` up to the 4-byte alignment of netlink.
const fn aligned(size: usize) -> usize {
    (size + (ALIGNMENT - 1)) & !(ALIGNMENT - 1)
}

fn load_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn load_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn load_i32(bytes: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// An unsigned number of 1, 2, 4 or 8 bytes; None for any other size.
fn unsigned_value(value: &[u8]) -> Option<u64> {
    match value.len() {
        1 => Some(u64::from(value[0])),
        2 => Some(u64::from(u16::from_ne_bytes(value.try_into().ok()?))),
        4 => Some(u64::from(u32::from_ne_bytes(value.try_into().ok()?))),
        8 => Some(u64::from_ne_bytes(value.try_into().ok()?)),
        _ => None,
    }
}

/// An unsigned number that fits 32 bits.
fn u32_value(value: &[u8]) -> Option<u32> {
    u32::try_from(unsigned_value(value)?).ok()
}

/// The characters before the first NUL, or all of them when there is none.
fn text_value(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

/// One netlink message of a datagram; the payload follows the 16-byte netlink header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    /// The bytes after the netlink header, without padding.
    pub payload: &'a [u8],
}

/// One netlink attribute; the value excludes the 4-byte attribute header and any padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    /// The type with the NESTED and byte-order flags removed.
    pub kind: u16,
    pub value: &'a [u8],
}

/// A RAS node: one class of counters of one device, e.g. `correctable-errors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: u32,
    /// The device it belongs to, a PCI address.
    pub device: String,
    /// The node name; empty when the kernel sent none.
    pub name: String,
}

/// One error counter of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    pub error_id: u32,
    /// The error name; empty when the kernel sent none.
    pub name: String,
    pub value: u64,
}

/// A node and its counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCounters {
    pub node: Node,
    pub counters: Vec<Counter>,
}

/// Whether the exchange goes on after a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEnd {
    /// A dump continues: receive again.
    More,
    /// The reply is complete.
    Done,
    /// The kernel answered with this error (a positive errno).
    Error(i32),
    /// The datagram is not well-formed netlink.
    Malformed,
}

/// What scanning one received datagram found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// How the exchange stands.
    pub end: ScanEnd,
    /// The generic netlink payload of each data message.
    pub payloads: Vec<Vec<u8>>,
}

/// An attribute holding a 32-bit number, padded to 4 bytes.
pub fn u32_attribute(kind: u16, value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTR_HEADER_SIZE + 4);
    out.extend_from_slice(&((ATTR_HEADER_SIZE + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&value.to_ne_bytes());
    out
}

/// An attribute holding a NUL-terminated string, padded to 4 bytes.
pub fn string_attribute(kind: u16, value: &str) -> Vec<u8> {
    let length = ATTR_HEADER_SIZE + value.len() + 1;
    let mut out = Vec::with_capacity(aligned(length));
    out.extend_from_slice(&(length.min(usize::from(u16::MAX)) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value.as_bytes());
    out.resize(aligned(length), 0); // the terminator and the padding
    out
}

/// A generic netlink request: netlink header, generic header, attributes.
pub fn build_request(family: u16, flags: u16, seq: u32, command: u8, attributes: &[u8]) -> Vec<u8> {
    let length = NLMSG_HEADER_SIZE + GENL_HEADER_SIZE + attributes.len();
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&(length as u32).to_ne_bytes());
    out.extend_from_slice(&family.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel assigns one
    out.push(command);
    out.push(FAMILY_VERSION);
    out.extend_from_slice(&0u16.to_ne_bytes()); // reserved
    out.extend_from_slice(attributes);
    out
}

/// Splits a datagram into its netlink messages, checking every length against the buffer. None
/// when a header is cut short or a length field is smaller than the header or past the end.
pub fn split_messages(mut datagram: &[u8]) -> Option<Vec<Message<'_>>> {
    let mut messages = Vec::new();
    while !datagram.is_empty() {
        if datagram.len() < NLMSG_HEADER_SIZE {
            return None;
        }
        let length = usize::try_from(load_u32(datagram)?).ok()?;
        if length < NLMSG_HEADER_SIZE || length > datagram.len() {
            return None;
        }
        messages.push(Message {
            kind: load_u16(&datagram[4..])?,
            flags: load_u16(&datagram[6..])?,
            seq: load_u32(&datagram[8..])?,
            payload: &datagram[NLMSG_HEADER_SIZE..length],
        });
        datagram = &datagram[aligned(length).min(datagram.len())..];
    }
    Some(messages)
}

/// Splits a run of netlink attributes, checking every length against the buffer; the nested and
/// byte-order flags are removed from the type. A nested attribute's value is itself a run of
/// attributes that can be passed to this function again. Trailing bytes too short for a header
/// are ignored, as the kernel does. None when a length field is smaller than the attribute header
/// or past the end.
pub fn parse_attributes(mut bytes: &[u8]) -> Option<Vec<Attribute<'_>>> {
    let mut attributes = Vec::new();
    while bytes.len() >= ATTR_HEADER_SIZE {
        let length = usize::from(load_u16(bytes)?);
        if length < ATTR_HEADER_SIZE || length > bytes.len() {
            return None;
        }
        attributes.push(Attribute {
            kind: load_u16(&bytes[2..])? & ATTR_TYPE_MASK,
            value: &bytes[ATTR_HEADER_SIZE..length],
        });
        bytes = &bytes[aligned(length).min(bytes.len())..];
    }
    Some(attributes)
}

/// The positive errno of a netlink error code, normally negative; `EIO` for the one value that
/// cannot be negated.
fn errno_of_code(code: i32) -> i32 {
    if code == i32::MIN { EIO } else { -code }
}

/// Interprets one received datagram of the reply to the request with sequence number `seq`.
///
/// Messages of another sequence number and `NLMSG_NOOP` are ignored. A reply that is not a dump
/// ends with its first message. A negative number in the payload of `NLMSG_DONE` is the error of a
/// dump that failed half way, and is reported like `NLMSG_ERROR`.
pub fn scan_datagram(datagram: &[u8], seq: u32, dump: bool) -> Scan {
    let mut scan = Scan { end: ScanEnd::More, payloads: Vec::new() };
    let Some(messages) = split_messages(datagram) else {
        scan.end = ScanEnd::Malformed;
        return scan;
    };
    let mut answered = false;
    for message in messages {
        if message.seq != seq || message.kind == NLMSG_NOOP {
            continue;
        }
        answered = true;
        match message.kind {
            NLMSG_DONE => {
                // A dump callback that failed reports its error as a negative number in the payload.
                scan.end = match load_i32(message.payload) {
                    Some(code) if code < 0 => ScanEnd::Error(errno_of_code(code)),
                    _ => ScanEnd::Done,
                };
                if matches!(scan.end, ScanEnd::Error(_)) {
                    scan.payloads.clear();
                }
                return scan;
            }
            NLMSG_ERROR => {
                scan.end = match load_i32(message.payload) {
                    None => ScanEnd::Malformed,
                    // An error of 0 is an acknowledgement.
                    Some(0) => ScanEnd::Done,
                    Some(code) => ScanEnd::Error(errno_of_code(code)),
                };
                return scan;
            }
            _ => scan.payloads.push(message.payload.to_vec()),
        }
    }
    if !dump && answered {
        scan.end = ScanEnd::Done;
    }
    scan
}

/// The attributes of a generic netlink payload: the 4-byte generic header, then the attributes.
fn payload_attributes(payload: &[u8]) -> Option<Vec<Attribute<'_>>> {
    parse_attributes(payload.get(GENL_HEADER_SIZE..)?)
}

fn find_value<'a>(attributes: &[Attribute<'a>], kind: u16) -> Option<&'a [u8]> {
    attributes.iter().find(|a| a.kind == kind).map(|a| a.value)
}

/// The family id in the reply to `CTRL_CMD_GETFAMILY`.
pub fn parse_family_id(payload: &[u8]) -> Option<u16> {
    let attributes = payload_attributes(payload)?;
    let id = u32_value(find_value(&attributes, CTRL_ATTR_FAMILY_ID)?)?;
    u16::try_from(id).ok()
}

/// A node from one LIST_NODES reply message; None when the payload is malformed or lacks the node
/// id or the device name.
pub fn parse_node(payload: &[u8]) -> Option<Node> {
    let attributes = payload_attributes(payload)?;
    let id = u32_value(find_value(&attributes, NODE_ATTR_NODE_ID)?)?;
    let device = text_value(find_value(&attributes, NODE_ATTR_DEVICE_NAME)?);
    let name = find_value(&attributes, NODE_ATTR_NODE_NAME).map(text_value).unwrap_or_default();
    Some(Node { id, device, name })
}

/// A counter from one GET_ERROR_COUNTER reply message; None when the payload is malformed or lacks
/// the error id or the value.
pub fn parse_counter(payload: &[u8]) -> Option<Counter> {
    let attributes = payload_attributes(payload)?;
    let error_id = u32_value(find_value(&attributes, COUNTER_ATTR_ERROR_ID)?)?;
    let value = unsigned_value(find_value(&attributes, COUNTER_ATTR_ERROR_VALUE)?)?;
    let name = find_value(&attributes, COUNTER_ATTR_ERROR_NAME).map(text_value).unwrap_or_default();
    Some(Counter { error_id, name, value })
}

/// The JSON document of a device's counters:
/// `{"source":"drm-ras","nodes":[{"name":"...","errors":{"<counter>":<value>,...}},...]}` and a
/// newline. A counter name that repeats within a node gets `-<error id>` appended; a counter with
/// no name is called `error-<error id>`.
pub fn counters_json(nodes: &[NodeCounters]) -> String {
    let mut node_values = Vec::with_capacity(nodes.len());
    for NodeCounters { node, counters } in nodes {
        let mut used: HashSet<String> = HashSet::new();
        let mut errors = Map::new();
        for counter in counters {
            let mut name = if counter.name.is_empty() {
                format!("error-{}", counter.error_id)
            } else {
                counter.name.clone()
            };
            while !used.insert(name.clone()) {
                let _ = write!(name, "-{}", counter.error_id);
            }
            errors.insert(name, Value::from(counter.value));
        }
        let mut object = Map::new();
        object.insert("name".to_owned(), Value::from(node.name.clone()));
        object.insert("errors".to_owned(), Value::Object(errors));
        node_values.push(Value::Object(object));
    }
    let mut root = Map::new();
    root.insert("source".to_owned(), Value::from(FAMILY_NAME));
    root.insert("nodes".to_owned(), Value::Array(node_values));
    let mut text = Value::Object(root).to_string();
    text.push('\n');
    text
}

/// How reading the counters ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStatus {
    /// Read; the nodes may still be empty when no node belongs to the device.
    Ok,
    /// The kernel has no drm-ras interface.
    NoFamily,
    /// The kernel refused the request for lack of privilege.
    Denied,
    /// The kernel did not answer.
    TimedOut,
    /// Any other failure; see [`CounterRead::error`].
    Failed,
}

/// The counters of one device, or why they could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterRead {
    pub status: ReadStatus,
    /// OS error text when `status` is [`ReadStatus::Failed`].
    pub error: String,
    /// The nodes of the device and their counters.
    pub nodes: Vec<NodeCounters>,
}

impl CounterRead {
    fn new(status: ReadStatus) -> Self {
        Self { status, error: String::new(), nodes: Vec::new() }
    }
}

/// The only requests this client sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// `CTRL_CMD_GETFAMILY` for `drm-ras`, to the controller.
    GetFamily,
    /// `DRM_RAS_CMD_LIST_NODES`, a dump.
    ListNodes,
    /// `DRM_RAS_CMD_GET_ERROR_COUNTER` for one node, a dump.
    GetErrorCounter {
        /// The node whose counters to dump.
        node_id: u32,
    },
}

impl Request {
    /// The generic netlink command.
    pub fn command(self) -> u8 {
        match self {
            Request::GetFamily => CTRL_CMD_GETFAMILY,
            Request::ListNodes => CMD_LIST_NODES,
            Request::GetErrorCounter { .. } => CMD_GET_ERROR_COUNTER,
        }
    }

    /// Whether it is a dump request, which ends with `NLMSG_DONE`.
    pub fn dump(self) -> bool {
        !matches!(self, Request::GetFamily)
    }

    /// The encoded attributes of the request.
    pub fn attributes(self) -> Vec<u8> {
        match self {
            Request::GetFamily => string_attribute(CTRL_ATTR_FAMILY_NAME, FAMILY_NAME),
            Request::ListNodes => Vec::new(),
            Request::GetErrorCounter { node_id } => u32_attribute(COUNTER_ATTR_NODE_ID, node_id),
        }
    }

    /// The whole message to send to `family` with sequence number `seq`.
    pub fn message(self, family: u16, seq: u32) -> Vec<u8> {
        let flags = if self.dump() { NLM_F_REQUEST | NLM_F_DUMP } else { NLM_F_REQUEST };
        build_request(family, flags, seq, self.command(), &self.attributes())
    }
}

/// How one request/reply exchange ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exchange {
    /// The payloads of the data messages.
    Ok(Vec<Vec<u8>>),
    /// A system call or the kernel failed with this positive errno.
    Errno(i32),
    /// No datagram arrived within the limit.
    TimedOut,
    /// The reply is not well-formed netlink.
    Malformed,
}

/// The positive errno of an I/O error; `EIO` when it has none.
fn errno_of(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(EIO)
}

/// The text of an errno without the `(os error N)` suffix Rust appends.
fn errno_text(errno: i32) -> String {
    let text = io::Error::from_raw_os_error(errno).to_string();
    match text.rfind(" (os error") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// Sends one request and collects its reply.
fn transact(socket: &NetlinkSocket, family: u16, request: Request, seq: u32, deadline: Instant) -> Exchange {
    if let Err(e) = socket.send(&request.message(family, seq)) {
        return Exchange::Errno(errno_of(&e));
    }
    let dump = request.dump();
    let mut buffer = vec![0u8; RECEIVE_BUFFER_SIZE];
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Exchange::TimedOut;
        }
        let got = match socket.recv(&mut buffer) {
            Ok(got) => got,
            Err(e) => match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return Exchange::TimedOut,
                _ => return Exchange::Errno(errno_of(&e)),
            },
        };
        // A datagram that fills the buffer may have been cut off.
        if got >= buffer.len() {
            return Exchange::Malformed;
        }
        let scan = scan_datagram(&buffer[..got], seq, dump);
        payloads.extend(scan.payloads);
        match scan.end {
            ScanEnd::More => continue,
            ScanEnd::Done => return Exchange::Ok(payloads),
            ScanEnd::Error(errno) => return Exchange::Errno(errno),
            ScanEnd::Malformed => return Exchange::Malformed,
        }
    }
}

fn status_of_errno(errno: i32) -> ReadStatus {
    if errno == EPERM || errno == EACCES { ReadStatus::Denied } else { ReadStatus::Failed }
}

/// The failed read of a non-Ok exchange; `no_family_on` is an errno that means the family does
/// not exist (0 for none).
fn failed_read(exchange: &Exchange, no_family_on: i32) -> CounterRead {
    match exchange {
        Exchange::TimedOut => CounterRead::new(ReadStatus::TimedOut),
        Exchange::Malformed => {
            let mut read = CounterRead::new(ReadStatus::Failed);
            read.error = "malformed reply from the kernel".to_owned();
            read
        }
        Exchange::Errno(errno) => {
            if no_family_on != 0 && *errno == no_family_on {
                return CounterRead::new(ReadStatus::NoFamily);
            }
            let mut read = CounterRead::new(status_of_errno(*errno));
            read.error = errno_text(*errno);
            read
        }
        Exchange::Ok(_) => CounterRead::new(ReadStatus::Failed),
    }
}

/// Runs the exchange sequence against any transport: family lookup, node listing, then one counter
/// dump per node of `device`.
fn read_counters_via(
    device: &PciAddress,
    transport: &mut dyn FnMut(u16, Request, u32) -> Exchange,
) -> CounterRead {
    let mut seq = 0u32;
    let mut next = |transport: &mut dyn FnMut(u16, Request, u32) -> Exchange, family, request| {
        seq += 1;
        transport(family, request, seq)
    };
    let family_reply = match next(transport, GENL_ID_CTRL, Request::GetFamily) {
        Exchange::Ok(payloads) => payloads,
        other => return failed_read(&other, ENOENT),
    };
    let Some(family) = family_reply.first().and_then(|p| parse_family_id(p)) else {
        let mut read = CounterRead::new(ReadStatus::Failed);
        read.error = "no family id in the reply of the kernel".to_owned();
        return read;
    };
    let node_payloads = match next(transport, family, Request::ListNodes) {
        Exchange::Ok(payloads) => payloads,
        other => return failed_read(&other, 0),
    };
    let mut read = CounterRead::new(ReadStatus::Failed);
    for payload in &node_payloads {
        let Some(node) = parse_node(payload) else {
            continue;
        };
        if PciAddress::parse(&node.device) != Some(*device) {
            continue;
        }
        let counter_payloads = match next(transport, family, Request::GetErrorCounter { node_id: node.id }) {
            Exchange::Ok(payloads) => payloads,
            other => return failed_read(&other, 0),
        };
        let counters = counter_payloads.iter().filter_map(|p| parse_counter(p)).collect();
        read.nodes.push(NodeCounters { node, counters });
    }
    read.status = ReadStatus::Ok;
    read
}

/// Reads the error counters of one device through the drm-ras family.
///
/// Opens one netlink socket for the call. No wait lasts more than 3 s and the whole read ends
/// within 9 s, so a slow kernel is reported as [`ReadStatus::TimedOut`] before the source's own
/// 10 s limit. Nodes of other devices are not queried.
pub fn read_counters(device: &PciAddress) -> CounterRead {
    let socket = match NetlinkSocket::open_generic(RECEIVE_TIMEOUT) {
        Ok(socket) => socket,
        Err(e) => {
            // No netlink in this kernel or build: there is no drm-ras interface either.
            if e.kind() == io::ErrorKind::Unsupported
                || matches!(e.raw_os_error(), Some(n) if n == EPROTONOSUPPORT || n == EAFNOSUPPORT)
            {
                return CounterRead::new(ReadStatus::NoFamily);
            }
            let errno = errno_of(&e);
            let mut read = CounterRead::new(status_of_errno(errno));
            read.error = errno_text(errno);
            return read;
        }
    };
    let deadline = Instant::now() + READ_DEADLINE;
    read_counters_via(device, &mut |family, request, seq| transact(&socket, family, request, seq, deadline))
}

/// The artifact for a counter read: Collected with the JSON document; Skipped `kernel has no
/// drm-ras interface`, `needs root` or `no drm-ras node for this device`; Failed
/// `drm-ras did not answer` or with the OS error.
pub fn counters_artifact(rel_path: &str, read: &CounterRead) -> Produced {
    let mut out = Produced {
        rel_path: rel_path.to_owned(),
        via: format!("{FAMILY_NAME} generic netlink"),
        ..Produced::default()
    };
    match read.status {
        ReadStatus::Ok => {
            if read.nodes.is_empty() {
                out.status = Status::Skipped;
                out.reason = "no drm-ras node for this device".to_owned();
            } else {
                out.data = counters_json(&read.nodes).into_bytes();
            }
        }
        ReadStatus::NoFamily => {
            out.status = Status::Skipped;
            out.reason = "kernel has no drm-ras interface".to_owned();
        }
        ReadStatus::Denied => {
            out.status = Status::Skipped;
            out.reason = needs_text(Gate::Root);
        }
        ReadStatus::TimedOut => {
            out.status = Status::Failed;
            out.reason = "drm-ras did not answer".to_owned();
        }
        ReadStatus::Failed => {
            out.status = Status::Failed;
            out.reason =
                if read.error.is_empty() { "drm-ras query failed".to_owned() } else { read.error.clone() };
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "drm_ras_tests.rs"]
mod tests;
