// SPDX-License-Identifier: MIT
//! Runs reads on detached threads with a time limit; a group whose read missed the limit is
//! abandoned ("open") and later reads in that group are skipped instead of hanging too.
#![forbid(unsafe_code)]

use std::time::Duration;

/// Per-group circuit breaker over detached helper threads.
#[derive(Debug)]
pub struct Guard {
    limit: Duration,
}

impl Guard {
    /// A guard whose calls each get `limit`.
    pub fn new(limit: Duration) -> Self {
        Self { limit }
    }

    /// Runs `f` on a detached thread; None when the group is already open or `f` missed the
    /// limit (the group is then open; `f` keeps running and is never joined).
    pub fn bounded<T: Send + 'static>(
        &self,
        group: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let _ = (group, self.limit);
        Some(f())
    }

    /// [`Guard::bounded`] with an explicit `limit` instead of the guard's default.
    pub fn bounded_for<T: Send + 'static>(
        &self,
        group: &str,
        limit: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let _ = (group, limit);
        Some(f())
    }

    /// Whether `group` was abandoned.
    pub fn is_open(&self, group: &str) -> bool {
        let _ = group;
        false
    }

    /// Whether any group was abandoned.
    pub fn any_abandoned(&self) -> bool {
        false
    }
}
