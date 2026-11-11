// SPDX-License-Identifier: MIT
//! Unit tests for `src/guard.rs`.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

#[test]
fn returns_the_value_and_leaves_the_group_closed() {
    let guard = Guard::new(Duration::from_secs(5));
    assert_eq!(guard.bounded("host", || 42), Some(42));
    assert!(!guard.is_open("host"));
    assert!(!guard.any_abandoned());
}

#[test]
fn a_sleeping_closure_is_abandoned_at_the_limit_and_opens_its_group() {
    let guard = Guard::new(Duration::from_millis(100));
    let start = Instant::now();
    let got = guard.bounded("device:0000:03:00.0", || {
        thread::sleep(Duration::from_secs(3));
        1
    });
    let took = start.elapsed();
    assert_eq!(got, None);
    assert!(took >= Duration::from_millis(100), "{took:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert!(guard.is_open("device:0000:03:00.0"));
    assert!(guard.any_abandoned());
}

#[test]
fn later_calls_in_an_open_group_do_not_run() {
    let guard = Guard::new(Duration::from_secs(5));
    assert_eq!(
        guard.bounded_for("g", Duration::from_millis(50), || {
            thread::sleep(Duration::from_secs(2));
        }),
        None
    );
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let start = Instant::now();
    assert_eq!(guard.bounded("g", move || flag.store(true, Ordering::SeqCst)), None);
    // The default limit is 5 s: an open group must answer without waiting for it.
    assert!(start.elapsed() < Duration::from_secs(2), "an open group must fail fast");
    thread::sleep(Duration::from_millis(50));
    assert!(!ran.load(Ordering::SeqCst), "the closure of an open group must not run");
}

#[test]
fn other_groups_are_unaffected() {
    let guard = Guard::new(Duration::from_millis(50));
    assert_eq!(guard.bounded("a", || thread::sleep(Duration::from_secs(2))), None);
    assert!(guard.is_open("a"));
    assert!(!guard.is_open("b"));
    // A generous limit: starting the worker thread must not race the 50 ms default on a busy host.
    assert_eq!(guard.bounded_for("b", Duration::from_secs(5), || "fine"), Some("fine"));
    assert!(guard.is_open("a"));
}

#[test]
fn bounded_for_uses_its_own_limit() {
    let guard = Guard::new(Duration::from_millis(20));
    // The default would abandon this; the explicit limit lets it finish.
    let got = guard.bounded_for("slow-ok", Duration::from_secs(5), || {
        thread::sleep(Duration::from_millis(150));
        7
    });
    assert_eq!(got, Some(7));
    assert!(!guard.is_open("slow-ok"));

    let got = guard.bounded_for("slow-bad", Duration::from_millis(30), || {
        thread::sleep(Duration::from_secs(2));
        7
    });
    assert_eq!(got, None);
    assert!(guard.is_open("slow-bad"));
}

#[test]
fn a_panicking_closure_returns_none_without_opening_the_group() {
    let guard = Guard::new(Duration::from_secs(5));
    let got: Option<u8> = guard.bounded("p", || panic!("boom (expected by the test)"));
    assert_eq!(got, None);
    assert!(!guard.is_open("p"));
    assert_eq!(guard.bounded("p", || 1), Some(1));
}

#[test]
fn the_abandoned_thread_is_not_joined_and_finishes_on_its_own() {
    let guard = Guard::new(Duration::from_millis(30));
    let done = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&done);
    assert_eq!(
        guard.bounded("slow", move || {
            thread::sleep(Duration::from_millis(300));
            flag.fetch_add(1, Ordering::SeqCst);
        }),
        None
    );
    assert_eq!(done.load(Ordering::SeqCst), 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while done.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(done.load(Ordering::SeqCst), 1);
    // The group stays open even though the call eventually returned.
    assert!(guard.is_open("slow"));
}

#[test]
fn a_poisoned_lock_does_not_panic() {
    let guard = Arc::new(Guard::new(Duration::from_secs(1)));
    let other = Arc::clone(&guard);
    let _ = thread::spawn(move || {
        let _held = other.open.lock().unwrap();
        panic!("poison the mutex (expected by the test)");
    })
    .join();
    assert!(guard.open.is_poisoned());
    assert!(!guard.is_open("x"));
    assert!(!guard.any_abandoned());
    assert_eq!(guard.bounded_for("x", Duration::from_secs(5), || 3), Some(3));
    assert_eq!(
        guard.bounded_for("y", Duration::from_millis(20), || thread::sleep(Duration::from_secs(1))),
        None
    );
    assert!(guard.is_open("y"));
    assert!(guard.any_abandoned());
}

#[test]
fn shared_between_threads() {
    let guard = Arc::new(Guard::new(Duration::from_secs(5)));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let g = Arc::clone(&guard);
            thread::spawn(move || g.bounded(&format!("g{i}"), move || i * 2))
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        assert_eq!(h.join().unwrap(), Some(i * 2));
    }
    assert!(!guard.any_abandoned());
}

#[test]
fn a_group_can_be_opened_by_hand_and_then_fails_fast() {
    let guard = Guard::new(Duration::from_secs(5));
    assert!(!guard.is_open("usermode"));
    guard.open("usermode");
    assert!(guard.is_open("usermode") && guard.any_abandoned());
    assert!(!guard.is_open("host"));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    assert_eq!(guard.bounded("usermode", move || flag.store(true, Ordering::SeqCst)), None);
    assert!(!ran.load(Ordering::SeqCst));
    assert_eq!(guard.bounded("host", || 1), Some(1));
}
