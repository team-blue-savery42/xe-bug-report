// SPDX-License-Identifier: MIT
//! Unit tests for `src/bundle/manifest.rs`.

use std::collections::HashMap;
use std::time::Duration;

use super::*;
use crate::bundle::source::{Gate, GpuDevice, Profile, SourceOptions, Status};
use crate::pci::PciAddress;
use crate::redact::{Context, Rules};
use crate::units::Bytes;

const KEYS: &str = include_str!("../../tests/golden/manifest-keys.txt");
const SAMPLE: &str = include_str!("../../tests/golden/manifest-sample.json");
const DEFAULT_SAMPLE: &str = include_str!("../../tests/golden/manifest-default-sample.json");

fn request() -> BundleRequest {
    BundleRequest {
        output: PathBuf::from("x.zip"),
        options: SourceOptions { profile: Profile::Full, ..SourceOptions::default() },
        rules: Rules::default(),
        deadline: None,
    }
}

fn input<'a>(
    artifacts: &'a [Artifact],
    request: &'a BundleRequest,
    identity: &'a Context,
    compression: Compression,
) -> ManifestInput<'a> {
    ManifestInput {
        artifacts,
        request,
        created: "2026-11-09T15:23:00Z",
        compression,
        identity,
        identity_partial: false,
        xpu_smi: None,
        os: "Ubuntu 24.04 LTS, Linux 7.2 x86_64",
    }
}

fn artifact(status: Status, gate: Gate) -> Artifact {
    Artifact { status, gate, files: 1, ..Artifact::default() }
}

fn three_artifacts() -> Vec<Artifact> {
    let collected = Artifact {
        rel_path: "kernel/kmsg.txt".into(),
        via: "journalctl -k -b 0".into(),
        bytes: Bytes(812_345),
        exit: Some(0),
        elapsed: Duration::from_millis(140),
        ..artifact(Status::Collected, Gate::None)
    };
    let skipped = Artifact {
        rel_path: "devices/0000-03-00.0/debugfs/".into(),
        reason: "needs root".into(),
        files: 0,
        elapsed: Duration::from_millis(3),
        ..artifact(Status::Skipped, Gate::Root)
    };
    let failed = Artifact { exit: Some(2), denied: 1, ..artifact(Status::Failed, Gate::None) };
    vec![collected, skipped, failed]
}

/// The scope -> ordered (key, required) table of `manifest-keys.txt`.
fn key_table() -> HashMap<&'static str, Vec<(&'static str, bool)>> {
    let mut table: HashMap<&str, Vec<(&str, bool)>> = HashMap::new();
    for line in KEYS.lines().filter(|line| !line.starts_with('#') && !line.trim().is_empty()) {
        let (scope, key) = line.split_once(' ').unwrap();
        let (key, required) = match key.strip_suffix('?') {
            Some(key) => (key, false),
            None => (key, true),
        };
        table.entry(scope).or_default().push((key, required));
    }
    table
}

/// Requires the keys of `object` to be the table's keys for `scope`, in order, with every
/// required key present and no unknown key.
fn assert_scope_order(object: &Map<String, Value>, scope: &str, what: &str) {
    let table = key_table();
    let spec = &table[scope];
    let mut cursor = 0;
    for key in object.keys() {
        let Some(found) = spec[cursor..].iter().position(|(name, _)| name == key) else {
            panic!("{what}: key {key:?} unknown or out of order in scope {scope}; keys {:?}", object.keys());
        };
        cursor += found + 1;
    }
    for (name, required) in spec {
        assert!(!required || object.contains_key(*name), "{what}: missing required key {name:?}");
    }
}

fn assert_document_order(doc: &Value, what: &str) {
    let top = doc.as_object().unwrap();
    assert_scope_order(top, "top", what);
    assert_scope_order(top["tool"].as_object().unwrap(), "tool", what);
    if let Some(xpu_smi) = top.get("xpu_smi") {
        assert_scope_order(xpu_smi.as_object().unwrap(), "xpu_smi", what);
    }
    for source in top["sources"].as_array().unwrap() {
        assert_scope_order(source.as_object().unwrap(), "source", what);
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[test]
fn golden_samples_follow_the_key_list() {
    for (name, text) in [("manifest-sample.json", SAMPLE), ("manifest-default-sample.json", DEFAULT_SAMPLE)] {
        let doc: Value = serde_json::from_str(text).unwrap();
        assert_document_order(&doc, name);
    }
}

#[test]
fn emitter_keys_follow_the_key_list_in_every_optional_combination() {
    let mut request = request();
    request.options.since = Some(Duration::from_secs(7200));
    request.options.devices = vec![GpuDevice {
        bdf: PciAddress { domain: 0, bus: 3, device: 0, function: 0 },
        os_path: "/sys/x".into(),
    }];
    let artifacts = three_artifacts();
    let identity = Context::default();
    let smi = XpuSmiInfo { path: PathBuf::from("/usr/bin/xpu-smi"), version: "xpu-smi 1.3".into() };
    let mut full = input(&artifacts, &request, &identity, Compression::Deflate);
    full.identity_partial = true;
    full.xpu_smi = Some(&smi);
    assert_document_order(&manifest_json(&full), "all optional keys");

    let bare_request = BundleRequest { rules: Rules::none(), ..self::request() };
    let mut bare = input(&[], &bare_request, &identity, Compression::Stored);
    bare.os = "";
    assert_document_order(&manifest_json(&bare), "no optional keys");
    let text = json_text(&manifest_json(&full), MANIFEST_INDENT);
    assert!(text.starts_with("{\n  \"schema\": 1,\n  \"tool\": {\n    \"version\": "), "{text}");
}

#[test]
fn value_types_match_the_golden_samples() {
    let mut golden: HashMap<(&str, String), &'static str> = HashMap::new();
    for text in [SAMPLE, DEFAULT_SAMPLE] {
        let doc: Value = serde_json::from_str(text).unwrap();
        let top = doc.as_object().unwrap();
        for (key, value) in top {
            golden.insert(("top", key.clone()), type_name(value));
        }
        for (key, value) in top["tool"].as_object().unwrap() {
            golden.insert(("tool", key.clone()), type_name(value));
        }
        for source in top["sources"].as_array().unwrap() {
            for (key, value) in source.as_object().unwrap() {
                golden.insert(("source", key.clone()), type_name(value));
            }
        }
    }
    let mut request = request();
    request.options.since = Some(Duration::from_secs(1800));
    request.options.devices = vec![GpuDevice {
        bdf: PciAddress { domain: 0, bus: 3, device: 0, function: 0 },
        os_path: String::new(),
    }];
    let artifacts = three_artifacts();
    let identity = Context::default();
    let doc = manifest_json(&input(&artifacts, &request, &identity, Compression::Deflate));
    let top = doc.as_object().unwrap();
    for (key, value) in top {
        if let Some(expected) = golden.get(&("top", key.clone())) {
            assert_eq!(type_name(value), *expected, "top.{key}");
        }
    }
    for (key, value) in top["tool"].as_object().unwrap() {
        assert_eq!(type_name(value), golden[&("tool", key.clone())], "tool.{key}");
    }
    for source in top["sources"].as_array().unwrap() {
        for (key, value) in source.as_object().unwrap() {
            assert_eq!(type_name(value), golden[&("source", key.clone())], "source.{key}");
        }
    }
}

#[test]
fn top_level_and_per_source_fields() {
    let mut request = request();
    request.options.devices = vec![GpuDevice {
        bdf: PciAddress { domain: 0, bus: 3, device: 0, function: 0 },
        os_path: "/sys/x".into(),
    }];
    let artifacts = three_artifacts();
    let identity = Context::default();
    let doc = manifest_json(&input(&artifacts, &request, &identity, Compression::Deflate));

    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["created"], "2026-11-09T15:23:00Z");
    assert_eq!(doc["profile"], "full");
    assert_eq!(doc["devices"], serde_json::json!(["0000:03:00.0"]));
    assert_eq!(doc["compression"], "deflate");
    assert_eq!(doc["tool"]["version"], build_info::VERSION);
    assert!(doc["tool"].get("path").is_some());
    assert!(doc.get("os").is_some());
    assert!(doc.get("identity").is_none());
    assert!(doc.get("xpu_smi").is_none());
    assert!(doc.get("since_minutes").is_none());
    assert_eq!(doc["sources"].as_array().unwrap().len(), 3);

    let first = &doc["sources"][0];
    assert_eq!(first["path"], "kernel/kmsg.txt");
    assert_eq!(first["status"], "collected");
    assert_eq!(first["via"], "journalctl -k -b 0");
    assert_eq!(first["bytes"], 812_345);
    assert_eq!(first["ms"], 140);
    for absent in ["gate", "reason", "exit", "files", "denied"] {
        assert!(first.get(absent).is_none(), "{absent}");
    }

    let second = &doc["sources"][1];
    assert_eq!(second["status"], "skipped");
    assert_eq!(second["gate"], "root");
    assert_eq!(second["reason"], "needs root");
    assert_eq!(second["files"], 0);
    assert_eq!(second["ms"], 3);
    assert!(second.get("bytes").is_none());
    assert!(second.get("via").is_none());

    let third = &doc["sources"][2];
    assert_eq!(third["status"], "failed");
    assert_eq!(third["exit"], 2);
    assert_eq!(third["denied"], 1);
    assert_eq!(third["ms"], 0);
    assert!(third.get("files").is_none());
}

#[test]
fn since_is_recorded_in_minutes_only_when_set() {
    let mut request = request();
    let identity = Context::default();
    let doc = manifest_json(&input(&[], &request, &identity, Compression::Stored));
    assert!(doc.get("since_minutes").is_none());
    request.options.since = Some(Duration::from_secs(2 * 3600));
    let doc = manifest_json(&input(&[], &request, &identity, Compression::Stored));
    assert_eq!(doc["since_minutes"], 120);
    request.options.since = Some(Duration::from_secs(30 * 60));
    let doc = manifest_json(&input(&[], &request, &identity, Compression::Stored));
    assert_eq!(doc["since_minutes"], 30);
}

#[test]
fn optional_top_level_keys() {
    let request = BundleRequest { rules: Rules::none(), ..request() };
    let identity = Context::default();
    let mut bare = input(&[], &request, &identity, Compression::Stored);
    bare.os = "";
    let doc = manifest_json(&bare);
    assert!(doc.get("devices").is_none());
    assert!(doc.get("os").is_none());
    assert_eq!(doc["redaction"], serde_json::json!([]));
    assert_eq!(doc["compression"], "stored");
    assert_eq!(doc["sources"], serde_json::json!([]));
}

#[test]
fn identity_and_xpu_smi_are_additive_keys() {
    let request = request();
    let identity = Context::default();
    let smi = XpuSmiInfo { path: PathBuf::from("/opt/xpu-smi"), version: "Intel XPU Manager 1.3".into() };
    let mut with = input(&[], &request, &identity, Compression::Deflate);
    with.identity_partial = true;
    with.xpu_smi = Some(&smi);
    let doc = manifest_json(&with);
    assert_eq!(doc["identity"], "partial");
    assert_eq!(doc["xpu_smi"]["path"], "/opt/xpu-smi");
    assert_eq!(doc["xpu_smi"]["version"], "Intel XPU Manager 1.3");
}

#[test]
fn redaction_rules_are_listed() {
    let request = request();
    let identity = Context::default();
    let doc = manifest_json(&input(&[], &request, &identity, Compression::Stored));
    assert!(doc["redaction"].is_array());
}

#[test]
fn redaction_rules_exact_list() {
    let request = request();
    let identity = Context::default();
    let doc = manifest_json(&input(&[], &request, &identity, Compression::Stored));
    assert_eq!(doc["redaction"], serde_json::json!(["serials", "hostname", "users", "addresses"]));
}

#[test]
fn via_is_redacted_but_reason_is_not() {
    let request = request();
    let identity = Context { hostnames: vec!["secrethost".into()], user_names: vec!["alice".into()] };
    let one = Artifact {
        via: "ssh alice@secrethost".into(),
        reason: "needs root; secrethost refused alice".into(),
        ..artifact(Status::Failed, Gate::None)
    };
    let doc = manifest_json(&input(std::slice::from_ref(&one), &request, &identity, Compression::Stored));
    let entry = &doc["sources"][0];
    let via = entry["via"].as_str().unwrap();
    assert!(!via.contains("secrethost") && !via.contains("alice"), "{via}");
    assert_eq!(entry["reason"], "needs root; secrethost refused alice");
}

#[test]
fn a_root_user_name_does_not_change_reasons() {
    let request = request();
    let identity = Context { hostnames: Vec::new(), user_names: vec!["root".into()] };
    let one = Artifact { reason: "needs root".into(), ..artifact(Status::Skipped, Gate::Root) };
    let doc = manifest_json(&input(std::slice::from_ref(&one), &request, &identity, Compression::Stored));
    assert_eq!(doc["sources"][0]["reason"], "needs root");
}

#[test]
fn json_text_compact_and_pretty() {
    let doc = serde_json::json!({"n": 1, "list": [1, 2], "empty": [], "o": {}});
    assert_eq!(json_text(&doc, 0), r#"{"n":1,"list":[1,2],"empty":[],"o":{}}"#);
    assert_eq!(
        json_text(&doc, 2),
        "{\n  \"n\": 1,\n  \"list\": [\n    1,\n    2\n  ],\n  \"empty\": [],\n  \"o\": {}\n}"
    );
    assert_eq!(json_text(&serde_json::json!({"n": 1}), 4), "{\n    \"n\": 1\n}");
    assert_eq!(json_text(&serde_json::json!({"n": 1}), 2), "{\n  \"n\": 1\n}");
}

#[test]
fn json_text_escapes_and_keeps_replacement_characters() {
    let doc = serde_json::json!({"f": String::from_utf8_lossy(b"bad\xff\n\"")});
    assert_eq!(json_text(&doc, 0), "{\"f\":\"bad\u{fffd}\\n\\\"\"}");
}

#[test]
fn pretty_output_round_trips_the_golden_sample() {
    let doc: Value = serde_json::from_str(SAMPLE).unwrap();
    // The golden sample was written with two-space indent and key order intact.
    assert_eq!(json_text(&doc, MANIFEST_INDENT), SAMPLE.trim_end_matches('\n'));
}
