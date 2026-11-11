// SPDX-License-Identifier: MIT
//! Runs reads on detached threads with a time limit; a group whose read missed the limit is
//! abandoned ("open") and later reads in that group are skipped instead of hanging too.

use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

/// Per-group circuit breaker over detached helper threads.
///
/// Some kernel and driver calls never return when the hardware below them stops answering, and the
/// thread that made them cannot be interrupted. Each call here runs on its own helper thread and the
/// caller waits at most the limit. A call that misses the limit is abandoned (its thread is never
/// joined) and opens its group: later calls of the group return `None` at once without running, since
/// they would most likely block on the same stuck state. An open group stays open.
///
/// Thread-safe: all methods take `&self`.
#[derive(Debug)]
pub struct Guard {
    limit: Duration,
    open: Mutex<HashSet<String>>,
}

impl Guard {
    /// A guard whose calls each get `limit`.
    pub fn new(limit: Duration) -> Self {
        Self { limit, open: Mutex::new(HashSet::new()) }
    }

    /// The set of open groups; a poisoned lock (a panic elsewhere while it was held) is not an error.
    fn groups(&self) -> MutexGuard<'_, HashSet<String>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` on a detached thread; None when the group is already open or `f` missed the
    /// limit (the group is then open; `f` keeps running and is never joined).
    ///
    /// Also `None`, without opening the group, when `f` panicked: the thread ended, nothing is stuck.
    pub fn bounded<T: Send + 'static>(
        &self,
        group: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.bounded_for(group, self.limit, f)
    }

    /// [`Guard::bounded`] with an explicit `limit` instead of the guard's default.
    pub fn bounded_for<T: Send + 'static>(
        &self,
        group: &str,
        limit: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        if self.is_open(group) {
            return None;
        }
        let (tx, rx) = mpsc::sync_channel::<T>(1);
        let spawned = thread::Builder::new().name("xe-guard".to_owned()).spawn(move || {
            // The receiver is gone when the call was abandoned; the result is then dropped here.
            let _ = tx.send(f());
        });
        if spawned.is_err() {
            // The worker could not be started: the call is as good as abandoned.
            self.groups().insert(group.to_owned());
            return None;
        }
        // The JoinHandle is dropped on purpose: the thread is detached and never joined.
        match rx.recv_timeout(limit) {
            Ok(value) => Some(value),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.groups().insert(group.to_owned());
                None
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Marks `group` abandoned without running anything: for a caller that has seen the group's
    /// work miss its limit by other means (a child process killed at its time limit), so that the
    /// later calls of the group fail fast instead of each waiting for the same stuck state.
    pub fn open(&self, group: &str) {
        self.groups().insert(group.to_owned());
    }

    /// Whether `group` was abandoned.
    pub fn is_open(&self, group: &str) -> bool {
        self.groups().contains(group)
    }

    /// Whether any group was abandoned.
    pub fn any_abandoned(&self) -> bool {
        !self.groups().is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "guard_tests.rs"]
mod tests;
