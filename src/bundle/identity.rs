// SPDX-License-Identifier: MIT
//! Resolves this machine's redaction context, falling back to the lookup-free variant when the
//! name service does not answer in time.

use std::time::Duration;

use crate::guard::Guard;
use crate::redact;
use crate::sources::{local_identity, local_identity_without_lookups};

/// How long the name-service lookup may take.
pub const IDENTITY_LIMIT: Duration = Duration::from_secs(5);

/// The guard group of the identity lookup.
const IDENTITY_GROUP: &str = "identity";

/// A resolved identity.
#[derive(Debug, Clone, Default)]
pub struct ResolvedIdentity {
    pub context: redact::Context,
    /// true: the lookup did not return in time and the lookup-free variant was used.
    pub partial: bool,
}

/// Chooses between a finished lookup and the fallback: `looked_up` is None when the lookup missed
/// its limit, in which case `fallback` runs and the result is marked partial.
pub fn from_lookup(
    looked_up: Option<redact::Context>,
    fallback: impl FnOnce() -> redact::Context,
) -> ResolvedIdentity {
    match looked_up {
        Some(context) => ResolvedIdentity { context, partial: false },
        None => ResolvedIdentity { context: fallback(), partial: true },
    }
}

/// Runs `sources::local_identity` under a guard with `limit`, falling back to
/// `sources::local_identity_without_lookups` (and setting `partial`) when it does not return.
pub fn resolve_identity(limit: Duration) -> ResolvedIdentity {
    let guard = Guard::new(limit);
    from_lookup(guard.bounded(IDENTITY_GROUP, local_identity), local_identity_without_lookups)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "identity_tests.rs"]
mod tests;
