// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/drm_ras.rs`.

use super::*;

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(out.len().div_ceil(4) * 4, 0);
    out
}

fn u32b(value: u32) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn cstr(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

fn join(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn genl(attributes: &[u8]) -> Vec<u8> {
    let mut out = vec![1, FAMILY_VERSION, 0, 0];
    out.extend_from_slice(attributes);
    out
}

fn message(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().div_ceil(4) * 4, 0);
    out
}

fn node_payload(id: u32, device: &str, name: &str) -> Vec<u8> {
    genl(&join(&[
        attribute(NODE_ATTR_NODE_ID, &u32b(id)),
        attribute(NODE_ATTR_DEVICE_NAME, &cstr(device)),
        attribute(NODE_ATTR_NODE_NAME, &cstr(name)),
    ]))
}

fn counter_payload(node_id: u32, id: u32, name: &str, value: u32) -> Vec<u8> {
    genl(&join(&[
        attribute(COUNTER_ATTR_NODE_ID, &u32b(node_id)),
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(id)),
        attribute(COUNTER_ATTR_ERROR_NAME, &cstr(name)),
        attribute(COUNTER_ATTR_ERROR_VALUE, &u32b(value)),
    ]))
}

fn err_payload(code: i32) -> Vec<u8> {
    code.to_ne_bytes().to_vec()
}

#[test]
fn a_request_has_the_netlink_and_generic_headers_and_the_attributes() {
    let name = string_attribute(CTRL_ATTR_FAMILY_NAME, "drm-ras");
    let mut expect = vec![12, 0, 2, 0];
    expect.extend_from_slice(b"drm-ras\0");
    assert_eq!(name, expect);

    let request = build_request(GENL_ID_CTRL, NLM_F_REQUEST, 7, CTRL_CMD_GETFAMILY, &name);
    assert_eq!(request.len(), 16 + 4 + name.len());
    assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()) as usize, request.len());
    assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), GENL_ID_CTRL);
    assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 7);
    assert_eq!(request[16], CTRL_CMD_GETFAMILY);
    assert_eq!(request[17], FAMILY_VERSION);

    // A string whose length is a multiple of 4 plus the header still gets its terminator.
    assert_eq!(string_attribute(1, "abc"), [8, 0, 1, 0, b'a', b'b', b'c', 0]);
    assert_eq!(string_attribute(1, "abcd"), [9, 0, 1, 0, b'a', b'b', b'c', b'd', 0, 0, 0, 0]);
    assert_eq!(u32_attribute(NODE_ATTR_NODE_ID, 5), [8, 0, 1, 0, 5, 0, 0, 0]);

    let dump = build_request(0x1c, NLM_F_REQUEST | NLM_F_DUMP, 2, CMD_LIST_NODES, &[]);
    assert_eq!(dump.len(), 20);
    assert_eq!(dump[16], CMD_LIST_NODES);
}

#[test]
fn only_the_three_read_only_requests_exist() {
    // CLEAR (3 in the drm-ras family) and SET_THRESHOLD (6) are not representable; the three
    // requests are the controller lookup and the two dumps.
    let node = Request::GetErrorCounter { node_id: 9 };
    assert_eq!((Request::GetFamily.command(), Request::GetFamily.dump()), (3, false));
    assert_eq!((Request::ListNodes.command(), Request::ListNodes.dump()), (1, true));
    assert_eq!((node.command(), node.dump()), (2, true));
    let m = node.message(0x2a, 4);
    assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 0x2a);
    assert_eq!(u16::from_ne_bytes(m[6..8].try_into().unwrap()), NLM_F_REQUEST | NLM_F_DUMP);
    assert_eq!(&m[20..], u32_attribute(COUNTER_ATTR_NODE_ID, 9));
    let f = Request::GetFamily.message(GENL_ID_CTRL, 1);
    assert_eq!(u16::from_ne_bytes(f[6..8].try_into().unwrap()), NLM_F_REQUEST);
}

#[test]
fn netlink_messages_are_split_with_their_lengths_checked() {
    let first = message(0x1c, 3, &[9, 9, 9, 9, 9]);
    let second = message(NLMSG_DONE, 3, &[]);
    let both = join(&[first.clone(), second]);
    let split = split_messages(&both).unwrap();
    assert_eq!(split.len(), 2);
    assert_eq!(split[0].kind, 0x1c);
    assert_eq!(split[0].seq, 3);
    assert_eq!(split[0].payload.len(), 5);
    assert_eq!(split[1].kind, NLMSG_DONE);
    assert!(split[1].payload.is_empty());

    assert!(split_messages(&[]).unwrap().is_empty());
    // A header cut short, for every length below the header size.
    for n in 1..16 {
        assert!(split_messages(&first[..n]).is_none(), "{n}");
    }
    // A length that runs past the buffer.
    assert!(split_messages(&first[..first.len() - 5]).is_none());
    // A length smaller than the header, and zero.
    for bad in [8u8, 0, 15] {
        let mut tiny = first.clone();
        tiny[0] = bad;
        assert!(split_messages(&tiny).is_none(), "{bad}");
    }
    // A huge length field.
    let mut huge = first.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert!(split_messages(&huge).is_none());
    // The last message may lack its padding.
    let unpadded = message(0x1c, 3, &[1, 2, 3, 4, 5]);
    assert!(split_messages(&unpadded[..21]).is_some());
}

#[test]
fn attributes_are_parsed_by_type_with_flags_removed() {
    let bytes = join(&[attribute(1, &u32b(42)), attribute(0x8003, &cstr("nested")), attribute(4, &[])]);
    let attributes = parse_attributes(&bytes).unwrap();
    assert_eq!(attributes.len(), 3);
    assert_eq!((attributes[0].kind, attributes[0].value.len()), (1, 4));
    assert_eq!(attributes[1].kind, 3); // NLA_F_NESTED is not part of the type
    assert_eq!(attributes[2].kind, 4);
    assert!(attributes[2].value.is_empty());

    assert!(parse_attributes(&[]).unwrap().is_empty());
    // Trailing bytes too short for a header are ignored, as the kernel does.
    assert_eq!(parse_attributes(&join(&[attribute(1, &u32b(1)), vec![1, 2]])).unwrap().len(), 1);
    // nla_len below the header size (including 0), and past the end.
    assert!(parse_attributes(&[3, 0, 1, 0]).is_none());
    assert!(parse_attributes(&[0, 0, 1, 0]).is_none());
    assert!(parse_attributes(&[12, 0, 1, 0, 1, 2, 3, 4]).is_none());
    assert!(parse_attributes(&[0xff, 0xff, 1, 0]).is_none());
    // A zero-length attribute after a good one stops the parse as malformed, not as a loop.
    assert!(parse_attributes(&join(&[attribute(1, &u32b(1)), vec![0, 0, 0, 0]])).is_none());
}

#[test]
fn nested_attributes_are_parsed_one_level_at_a_time() {
    let inner = join(&[attribute(1, &u32b(7)), attribute(2, &cstr("in"))]);
    let outer = attribute(0x8000 | 5, &inner);
    let top = parse_attributes(&outer).unwrap();
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].kind, 5);
    let nested = parse_attributes(top[0].value).unwrap();
    assert_eq!(nested.len(), 2);
    assert_eq!(u32_value(nested[0].value), Some(7));
    assert_eq!(text_value(nested[1].value), "in");
    // A nested run that is malformed inside a well-formed outer attribute.
    let bad = attribute(0x8000 | 5, &[0, 0, 1, 0]);
    let top = parse_attributes(&bad).unwrap();
    assert!(parse_attributes(top[0].value).is_none());
    // A nested attribute is not mistaken for the scalar the node expects.
    let payload = genl(&join(&[attribute(0x8000 | NODE_ATTR_NODE_ID, &inner)]));
    assert!(parse_node(&payload).is_none());
}

#[test]
fn the_family_id_comes_from_the_controller_reply() {
    let payload = genl(&join(&[
        attribute(CTRL_ATTR_FAMILY_NAME, &cstr("drm-ras")),
        attribute(CTRL_ATTR_FAMILY_ID, &0x2au16.to_ne_bytes()),
    ]));
    assert_eq!(parse_family_id(&payload), Some(0x2a));
    // Missing attribute, short payloads, an id that does not fit 16 bits, an odd-sized value.
    assert_eq!(parse_family_id(&genl(&attribute(CTRL_ATTR_FAMILY_NAME, &cstr("drm-ras")))), None);
    assert_eq!(parse_family_id(&[1, 1]), None);
    assert_eq!(parse_family_id(&[]), None);
    assert_eq!(parse_family_id(&genl(&attribute(CTRL_ATTR_FAMILY_ID, &u32b(0x10000)))), None);
    assert_eq!(parse_family_id(&genl(&attribute(CTRL_ATTR_FAMILY_ID, &[1, 2, 3]))), None);
    // A truncated attribute inside the payload.
    let mut cut = payload.clone();
    cut.truncate(cut.len() - 3);
    assert_eq!(parse_family_id(&cut), None);
}

#[test]
fn nodes_and_counters_are_decoded() {
    let node = parse_node(&node_payload(3, "0000:03:00.0", "correctable-errors")).unwrap();
    assert_eq!(node, Node { id: 3, device: "0000:03:00.0".into(), name: "correctable-errors".into() });
    // Missing node id, missing device, a payload shorter than the generic header.
    assert!(parse_node(&genl(&attribute(NODE_ATTR_NODE_ID, &u32b(1)))).is_none());
    assert!(parse_node(&genl(&attribute(NODE_ATTR_DEVICE_NAME, &cstr("x")))).is_none());
    assert!(parse_node(&[1, 1, 0]).is_none());
    assert!(parse_node(&[]).is_none());
    let bare =
        genl(&join(&[attribute(NODE_ATTR_NODE_ID, &u32b(1)), attribute(NODE_ATTR_DEVICE_NAME, &cstr("x"))]));
    assert!(parse_node(&bare).unwrap().name.is_empty());

    let counter = parse_counter(&counter_payload(3, 4, "core-compute", 17)).unwrap();
    assert_eq!(counter, Counter { error_id: 4, name: "core-compute".into(), value: 17 });

    // A 64-bit value, and a value attribute of an odd size.
    let wide = genl(&join(&[
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(1)),
        attribute(COUNTER_ATTR_ERROR_VALUE, &0x1_0000_0001u64.to_ne_bytes()),
    ]));
    assert_eq!(parse_counter(&wide).unwrap().value, 0x1_0000_0001);
    let odd = genl(&join(&[
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(1)),
        attribute(COUNTER_ATTR_ERROR_VALUE, &[1, 2, 3]),
    ]));
    assert!(parse_counter(&odd).is_none());
    assert!(parse_counter(&genl(&attribute(COUNTER_ATTR_ERROR_VALUE, &u32b(1)))).is_none());
    // The threshold attribute is not needed and does not disturb the parse.
    let with_threshold = genl(&join(&[
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(1)),
        attribute(COUNTER_ATTR_ERROR_THRESHOLD, &u32b(9)),
        attribute(COUNTER_ATTR_ERROR_VALUE, &u32b(3)),
    ]));
    assert_eq!(parse_counter(&with_threshold).unwrap().value, 3);
    // A name without a terminator is taken whole; a payload cut inside an attribute is rejected.
    let unterminated = genl(&join(&[
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(1)),
        attribute(COUNTER_ATTR_ERROR_NAME, b"ab"),
        attribute(COUNTER_ATTR_ERROR_VALUE, &u32b(0)),
    ]));
    assert_eq!(parse_counter(&unterminated).unwrap().name, "ab");
    let mut cut = counter_payload(1, 1, "x", 1);
    cut.truncate(cut.len() - 6);
    assert!(parse_counter(&cut).is_none());
    // Non-UTF-8 in a name is replaced, never a panic.
    let raw = genl(&join(&[
        attribute(COUNTER_ATTR_ERROR_ID, &u32b(1)),
        attribute(COUNTER_ATTR_ERROR_NAME, &[b'a', 0xff, 0]),
        attribute(COUNTER_ATTR_ERROR_VALUE, &u32b(0)),
    ]));
    assert_eq!(parse_counter(&raw).unwrap().name, "a\u{fffd}");
}

#[test]
fn a_datagram_is_scanned_for_data_completion_and_errors() {
    let node = node_payload(1, "0000:03:00.0", "uncorrectable-errors");

    // A dump continues until NLMSG_DONE; messages of other requests are ignored.
    let part = join(&[message(0x1c, 5, &node), message(0x1c, 99, &node)]);
    let scan = scan_datagram(&part, 5, true);
    assert_eq!(scan.end, ScanEnd::More);
    assert_eq!(scan.payloads, std::slice::from_ref(&node));

    let scan = scan_datagram(&join(&[message(0x1c, 5, &node), message(NLMSG_DONE, 5, &u32b(0))]), 5, true);
    assert_eq!(scan.end, ScanEnd::Done);
    assert_eq!(scan.payloads.len(), 1);

    // A reply that is not a dump is complete after its first datagram.
    assert_eq!(scan_datagram(&message(0x10, 2, &node), 2, false).end, ScanEnd::Done);

    // A kernel error: negative errno in the first four bytes.
    assert_eq!(scan_datagram(&message(NLMSG_ERROR, 5, &err_payload(-1)), 5, true).end, ScanEnd::Error(1));
    assert_eq!(scan_datagram(&message(NLMSG_ERROR, 5, &err_payload(-2)), 5, false).end, ScanEnd::Error(2));
    // An error of zero is an acknowledgement.
    assert_eq!(scan_datagram(&message(NLMSG_ERROR, 5, &err_payload(0)), 5, true).end, ScanEnd::Done);
    // The most negative number cannot be negated; the errno stays positive (EIO).
    assert_eq!(
        scan_datagram(&message(NLMSG_ERROR, 5, &err_payload(i32::MIN)), 5, true).end,
        ScanEnd::Error(5)
    );
    // An error message too short to hold the code.
    assert_eq!(scan_datagram(&message(NLMSG_ERROR, 5, &[1, 2]), 5, true).end, ScanEnd::Malformed);

    // Note: a dump that failed half way says so in the payload of NLMSG_DONE, and what it
    // delivered before is not a result.
    let failed =
        scan_datagram(&join(&[message(0x1c, 5, &node), message(NLMSG_DONE, 5, &err_payload(-5))]), 5, true);
    assert_eq!(failed.end, ScanEnd::Error(5));
    assert!(failed.payloads.is_empty());
    assert_eq!(scan_datagram(&message(NLMSG_DONE, 5, &err_payload(-1)), 5, true).end, ScanEnd::Error(1));
    assert_eq!(scan_datagram(&message(NLMSG_DONE, 5, &err_payload(0)), 5, true).end, ScanEnd::Done);
    // A DONE payload too short for a code is a plain end.
    assert_eq!(scan_datagram(&message(NLMSG_DONE, 5, &[1, 2]), 5, true).end, ScanEnd::Done);
    assert_eq!(
        scan_datagram(&message(NLMSG_DONE, 5, &err_payload(i32::MIN)), 5, true).end,
        ScanEnd::Error(5)
    );

    // A reply that is not a dump is not complete until a message of its own sequence number arrives.
    assert_eq!(scan_datagram(&message(0x10, 9, &node), 2, false).end, ScanEnd::More);
    assert_eq!(scan_datagram(&[1, 2, 3], 5, true).end, ScanEnd::Malformed);
    assert_eq!(scan_datagram(&message(NLMSG_NOOP, 5, &[]), 5, true).end, ScanEnd::More);
    // A second message cut off inside its header.
    let mut broken = message(0x1c, 5, &node);
    broken.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    assert_eq!(scan_datagram(&broken, 5, true).end, ScanEnd::Malformed);
}

#[test]
fn counters_are_shaped_as_json() {
    let nodes = vec![
        NodeCounters {
            node: Node { id: 1, device: "0000:03:00.0".into(), name: "correctable-errors".into() },
            counters: vec![
                Counter { error_id: 1, name: "core-compute".into(), value: 0 },
                Counter { error_id: 2, name: "soc-internal".into(), value: 5 },
            ],
        },
        NodeCounters {
            node: Node { id: 2, device: "0000:03:00.0".into(), name: "uncorrectable-errors".into() },
            counters: vec![Counter { error_id: 1, name: "core-compute".into(), value: u64::MAX }],
        },
    ];
    assert_eq!(
        counters_json(&nodes),
        concat!(
            r#"{"source":"drm-ras","nodes":[{"name":"correctable-errors","errors":{"core-compute":0,"soc-internal":5}},"#,
            r#"{"name":"uncorrectable-errors","errors":{"core-compute":18446744073709551615}}]}"#,
            "\n"
        )
    );
    assert_eq!(counters_json(&[]), "{\"source\":\"drm-ras\",\"nodes\":[]}\n");

    // Repeated and missing names stay distinct keys; quotes and control characters are escaped.
    let counter = |error_id, name: &str, value| Counter { error_id, name: name.into(), value };
    let node = |name: &str, counters| NodeCounters {
        node: Node { id: 1, device: "d".into(), name: name.into() },
        counters,
    };
    let odd =
        counters_json(&[node("a\"b\\c\n", vec![counter(1, "x", 1), counter(2, "x", 2), counter(3, "", 3)])]);
    let parsed: Value = serde_json::from_str(&odd).unwrap();
    assert_eq!(parsed["nodes"][0]["name"], "a\"b\\c\n");
    assert_eq!(parsed["nodes"][0]["errors"], serde_json::json!({"x": 1, "x-2": 2, "error-3": 3}));
    // A generated name that is taken too still gets a unique key.
    let clash =
        counters_json(&[node("n", vec![counter(1, "x", 1), counter(5, "x-2", 2), counter(2, "x", 3)])]);
    assert_eq!(
        clash,
        "{\"source\":\"drm-ras\",\"nodes\":[{\"name\":\"n\",\"errors\":{\"x\":1,\"x-2\":2,\"x-2-2\":3}}]}\n"
    );
}

#[test]
fn each_read_outcome_becomes_the_artifact_the_bundle_promises() {
    let rel = "devices/0000-03-00.0/ras-counters.json";
    let mut read = CounterRead::new(ReadStatus::NoFamily);
    let p = counters_artifact(rel, &read);
    assert_eq!(p.rel_path, rel);
    assert_eq!((p.status, p.reason.as_str()), (Status::Skipped, "kernel has no drm-ras interface"));

    read.status = ReadStatus::Denied;
    let p = counters_artifact(rel, &read);
    assert_eq!((p.status, p.reason.as_str()), (Status::Skipped, "needs root"));

    read.status = ReadStatus::TimedOut;
    let p = counters_artifact(rel, &read);
    assert_eq!((p.status, p.reason.as_str()), (Status::Failed, "drm-ras did not answer"));

    read.status = ReadStatus::Failed;
    read.error = "Operation not supported".into();
    let p = counters_artifact(rel, &read);
    assert_eq!((p.status, p.reason.as_str()), (Status::Failed, "Operation not supported"));
    read.error.clear();
    assert!(!counters_artifact(rel, &read).reason.is_empty());

    read.status = ReadStatus::Ok;
    let p = counters_artifact(rel, &read);
    assert_eq!((p.status, p.reason.as_str()), (Status::Skipped, "no drm-ras node for this device"));

    read.nodes.push(NodeCounters {
        node: Node { id: 1, device: "0000:03:00.0".into(), name: "correctable-errors".into() },
        counters: vec![Counter { error_id: 1, name: "core-compute".into(), value: 2 }],
    });
    let p = counters_artifact(rel, &read);
    assert_eq!(p.status, Status::Collected);
    assert!(String::from_utf8_lossy(&p.data).contains("\"core-compute\":2"));
}

/// A fake kernel: replies per request, and a log of what was asked.
fn run_fake(
    device: PciAddress,
    mut reply: impl FnMut(u16, Request) -> Exchange,
) -> (CounterRead, Vec<(u16, Request, u32)>) {
    let mut asked = Vec::new();
    let read = read_counters_via(&device, &mut |family, request, seq| {
        asked.push((family, request, seq));
        reply(family, request)
    });
    (read, asked)
}

const DEV: PciAddress = PciAddress { domain: 0, bus: 3, device: 0, function: 0 };

fn family_reply(id: u16) -> Exchange {
    Exchange::Ok(vec![genl(&join(&[
        attribute(CTRL_ATTR_FAMILY_NAME, &cstr("drm-ras")),
        attribute(CTRL_ATTR_FAMILY_ID, &id.to_ne_bytes()),
    ]))])
}

#[test]
fn the_exchange_sequence_reads_only_the_nodes_of_the_device() {
    let (read, asked) = run_fake(DEV, |family, request| match request {
        Request::GetFamily => {
            assert_eq!(family, GENL_ID_CTRL);
            family_reply(0x2a)
        }
        Request::ListNodes => Exchange::Ok(vec![
            node_payload(1, "0000:03:00.0", "correctable-errors"),
            node_payload(2, "0000:84:00.0", "correctable-errors"),
            node_payload(3, "0000:03:00.0", "uncorrectable-errors"),
            vec![1, 2],
        ]),
        Request::GetErrorCounter { node_id } => {
            Exchange::Ok(vec![counter_payload(node_id, 1, "core-compute", node_id * 10), vec![9]])
        }
    });
    assert_eq!(read.status, ReadStatus::Ok);
    assert_eq!(read.nodes.len(), 2);
    assert_eq!(read.nodes[0].node.id, 1);
    assert_eq!(read.nodes[1].counters, [Counter { error_id: 1, name: "core-compute".into(), value: 30 }]);
    // The family lookup, one listing, then a dump for each of the two nodes of this device.
    let commands: Vec<u8> = asked.iter().map(|(_, r, _)| r.command()).collect();
    assert_eq!(commands, [3, 1, 2, 2]);
    assert!(asked.iter().all(|(_, r, _)| matches!(r.command(), 1..=3)));
    assert_eq!(asked[1].0, 0x2a);
    assert_eq!(asked.iter().map(|a| a.2).collect::<Vec<_>>(), [1, 2, 3, 4]);
}

#[test]
fn a_kernel_without_the_family_or_with_a_failing_dump_is_reported() {
    // ENOENT for the family lookup: no drm-ras in this kernel.
    let (read, asked) = run_fake(DEV, |_, _| Exchange::Errno(ENOENT));
    assert_eq!(read.status, ReadStatus::NoFamily);
    assert_eq!(asked.len(), 1);
    // The same errno later is a failure, not "no family".
    let (read, _) = run_fake(DEV, |_, r| match r {
        Request::GetFamily => family_reply(0x2a),
        _ => Exchange::Errno(ENOENT),
    });
    assert_eq!(read.status, ReadStatus::Failed);
    assert_eq!(read.error, "No such file or directory");
    // Permission denied.
    let (read, _) = run_fake(DEV, |_, r| match r {
        Request::GetFamily => family_reply(0x2a),
        Request::ListNodes => Exchange::Ok(vec![node_payload(1, "0000:03:00.0", "n")]),
        Request::GetErrorCounter { .. } => Exchange::Errno(EPERM),
    });
    assert_eq!(read.status, ReadStatus::Denied);
    assert!(read.nodes.is_empty());
    // A dump that failed half way, seen through scan_datagram, ends the read as failed.
    let done_error = scan_datagram(&message(NLMSG_DONE, 3, &err_payload(-5)), 3, true);
    assert_eq!(done_error.end, ScanEnd::Error(5));
    let (read, _) = run_fake(DEV, |_, r| match r {
        Request::GetFamily => family_reply(0x2a),
        Request::ListNodes => Exchange::Ok(vec![node_payload(1, "0000:03:00.0", "n")]),
        Request::GetErrorCounter { .. } => Exchange::Errno(5),
    });
    assert_eq!(read.status, ReadStatus::Failed);
    assert!(read.nodes.is_empty());
    // Timeouts and malformed replies.
    let (read, _) = run_fake(DEV, |_, _| Exchange::TimedOut);
    assert_eq!(read.status, ReadStatus::TimedOut);
    let (read, _) = run_fake(DEV, |_, _| Exchange::Malformed);
    assert_eq!(read.status, ReadStatus::Failed);
    assert_eq!(read.error, "malformed reply from the kernel");
    // A family reply without an id.
    let (read, asked) = run_fake(DEV, |_, _| Exchange::Ok(vec![genl(&[])]));
    assert_eq!(read.status, ReadStatus::Failed);
    assert_eq!(read.error, "no family id in the reply of the kernel");
    assert_eq!(asked.len(), 1);
    let (read, _) = run_fake(DEV, |_, _| Exchange::Ok(Vec::new()));
    assert_eq!(read.status, ReadStatus::Failed);
    // No node for the device: Ok and empty.
    let (read, _) = run_fake(DEV, |_, r| match r {
        Request::GetFamily => family_reply(0x2a),
        _ => Exchange::Ok(vec![node_payload(1, "0000:84:00.0", "n")]),
    });
    assert_eq!(read.status, ReadStatus::Ok);
    assert!(read.nodes.is_empty());
}

#[test]
fn errno_text_has_no_rust_suffix() {
    assert_eq!(errno_text(EPERM), "Operation not permitted");
    assert!(!errno_text(99999).is_empty());
    assert_eq!(status_of_errno(EACCES), ReadStatus::Denied);
    assert_eq!(status_of_errno(5), ReadStatus::Failed);
}

#[test]
fn reading_the_live_kernel_always_reports_a_status() {
    // On a kernel without drm-ras, or without privilege, this is Skipped; with the family and
    // root it reads the counters. Every outcome is acceptable; the point is that it returns.
    let read = read_counters(&PciAddress { domain: 0, bus: 0xff, device: 0x1f, function: 7 });
    if read.status == ReadStatus::Ok {
        assert!(read.nodes.is_empty());
    }
    assert!(!counters_artifact("x", &read).reason.is_empty());
}
