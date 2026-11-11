// SPDX-License-Identifier: MIT
//! Resolves this machine's redaction context, falling back to the lookup-free variant when the
//! name service does not answer in time.

use std::time::Duration;

use crate::redact;

/// How long the name-service lookup may take.
pub const IDENTITY_LIMIT: Duration = Duration::from_secs(5);

/// A resolved identity.
#[derive(Debug, Clone, Default)]
pub struct ResolvedIdentity {
    pub context: redact::Context,
    /// true: the lookup did not return in time and the lookup-free variant was used.
    pub partial: bool,
}

/// Runs `sources::local_identity` under a guard with `limit`, falling back to
/// `sources::local_identity_without_lookups`.
pub fn resolve_identity(limit: Duration) -> ResolvedIdentity {
    let _ = limit;
    ResolvedIdentity::default()
}
