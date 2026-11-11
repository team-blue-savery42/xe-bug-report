// SPDX-License-Identifier: MIT
//! Unit tests for `src/bundle/identity.rs`.

use super::*;

fn context(host: &str, user: &str) -> redact::Context {
    redact::Context { hostnames: vec![host.to_owned()], user_names: vec![user.to_owned()] }
}

#[test]
fn a_finished_lookup_is_complete() {
    let resolved = from_lookup(Some(context("full", "alice")), || panic!("the fallback must not run"));
    assert!(!resolved.partial);
    assert_eq!(resolved.context, context("full", "alice"));
}

#[test]
fn a_missed_lookup_uses_the_fallback_and_is_partial() {
    let resolved = from_lookup(None, || context("lookup-free", "bob"));
    assert!(resolved.partial);
    assert_eq!(resolved.context, context("lookup-free", "bob"));
}

#[test]
fn the_resolved_identity_never_contains_root() {
    let resolved = resolve_identity(IDENTITY_LIMIT);
    assert!(resolved.context.user_names.iter().all(|n| n != "root"));
}
