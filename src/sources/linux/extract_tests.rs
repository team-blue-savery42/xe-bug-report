// SPDX-License-Identifier: MIT
//! Unit tests for `src/sources/linux/extract.rs`.

use super::*;
use std::fmt::Write as _;

#[test]
fn firmware_lines_are_recognised() {
    for line in [
        "[    2.1] xe 0000:03:00.0: [drm] Tile0: GT0: Using GuC firmware from xe/bmg_guc_70.bin version 70.65.0",
        "[    2.2] xe 0000:03:00.0: [drm] Tile0: GT1: Using HuC firmware from xe/bmg_huc.bin version 8.2.10",
        "[    2.3] xe 0000:03:00.0: [drm] Finished loading DMC firmware i915/bmg_dmc.bin (v2.6)",
        "[    2.4] xe 0000:03:00.0: [drm] GSC proxy init completed",
        "[    2.5] xe 0000:03:00.0: [drm] late bind firmware not found",
        "[    2.6] iwlwifi: firmware load failed",
    ] {
        assert!(is_firmware_line(line), "{line}");
    }
    for line in
        ["[    2.7] usb 1-1: new high-speed USB device", "[    2.9] eth0: link up", "[    3.0] firmware ok"]
    {
        assert!(!is_firmware_line(line), "{line}");
    }
}

#[test]
fn error_lines_are_recognised() {
    for line in [
        "xe 0000:03:00.0: [drm] *ERROR* Tile0: GT0: GuC mmio request failed SIGID=12345",
        "WARNING: CPU: 3 PID: 1 at drivers/gpu/drm/xe/xe_gt.c:10",
        "BUG: unable to handle page fault",
        "Call Trace:",
        "RIP: 0010:xe_gt_reset+0x10",
        "INFO: task kworker:1 blocked; hung task detected",
        "xe 0000:03:00.0: [drm] GT reset started",
        "xe 0000:03:00.0: [drm] device wedged",
        "pcieport 0000:00:01.0: AER: Corrected error received",
        "DMAR: DRHD: handling fault status reg 3",
        "xe 0000:03:00.0: [drm] TDR triggered",
        "mei_gsc: probe failed with error -5",
        "intel_pmt: telemetry read timed out",
        "iommu: unable to attach device",
        "i915 request timeout",
    ] {
        assert!(is_error_line(line), "{line}");
    }
    for line in [
        "usb 1-1: new device",
        "media0: registered",
        "pmtu ok",
        "enp3s0: link is up",
        "ACPI: DMAR 0x0000000074463000 000050 (v02 INTEL  EDK2)",
        "DMAR: Host address width 39",
        "DMAR-IR: Queued invalidation will be enabled to support x2apic",
        "iommu: DMA domain TLB invalidation policy: lazy mode",
        "mei_me 0000:00:16.0: enabling device (0000 -> 0002)",
        "pcieport 0000:00:1c.0: AER: enabled with IRQ 124",
    ] {
        assert!(!is_error_line(line), "{line}");
    }
}

#[test]
fn whole_words_need_a_boundary() {
    assert!(contains_word("mei: x", "mei"));
    assert!(contains_word("x mei_me y", "mei"));
    assert!(!contains_word("media", "mei"));
    assert!(!contains_word("immei", "mei"));
    assert!(contains_word("mei", "mei"));
}

#[test]
fn the_extract_has_a_header_firmware_and_error_sections() {
    let log = "[  1.0] boot\n[  2.0] xe: Using GuC firmware from xe/a.bin version 70.1.0\n[  3.0] noise\n\
               [  4.0] xe: *ERROR* first failure\n[  4.1] context one\n[  4.2] context two\n[  4.3] beyond\n";
    let text = extract_kernel_log(log, "kernel/kmsg.txt", false);
    assert!(text.starts_with("# extract of kernel/kmsg.txt: 7 lines in the log\n"), "{text}");
    assert!(text.contains("# firmware and load status: 1 lines\n[  2.0] xe: Using GuC firmware"));
    assert!(text.contains("# errors, warnings, hangs and resets: 1 matching lines\n[  4.0] xe: *ERROR* first failure\n[  4.1] context one\n[  4.2] context two\n"));
    assert!(!text.contains("beyond") && !text.contains("noise"));
    assert!(extract_kernel_log(log, "x", true).contains("(the log was cut at its size limit)"));
}

#[test]
fn a_storm_cannot_hide_the_first_error() {
    let mut log = String::new();
    for i in 0..1000 {
        let _ = writeln!(log, "[{i}] xe: *ERROR* storm {i}");
        let _ = writeln!(log, "[{i}] filler\n[{i}] filler\n[{i}] filler");
    }
    let text = extract_kernel_log(&log, "kmsg", false);
    assert!(text.contains("storm 0\n"));
    assert!(text.contains("storm 199\n"));
    assert!(!text.contains("storm 200\n"));
    assert!(text.contains("storm 800\n") && text.contains("storm 999\n"));
    assert!(text.contains("# ... 600 matching lines omitted ...\n"));
    assert!(text.contains("the first 200 and the last 200 shown"));
    assert!(text.len() <= EXTRACT_MAX_BYTES);
}

#[test]
fn nearby_matches_share_their_context_and_distant_ones_are_separated() {
    assert_eq!(context_ranges(&[1, 2, 10], 20), [(1, 5), (10, 13)]);
    assert_eq!(context_ranges(&[18], 20), [(18, 20)]);
    assert!(context_ranges(&[], 20).is_empty());
    let log = "a\nb *ERROR* one\nc\nd\ne\nf\ng *ERROR* two\nh\n";
    let text = extract_kernel_log(log, "k", false);
    assert!(text.contains("b *ERROR* one\nc\nd\n--\ng *ERROR* two\nh\n"), "{text}");
}

#[test]
fn long_lines_and_huge_logs_stay_within_the_limits() {
    let long = format!("*ERROR* {}", "x".repeat(5000));
    let text = extract_kernel_log(&long, "k", false);
    assert!(text.contains(" ...\n"));
    assert!(text.lines().all(|l| l.chars().count() <= LINE_MAX_CHARS + 4), "a line is too long");
    // Non-ASCII text is cut on a character boundary.
    let wide = format!("*ERROR* {}", "é".repeat(1000));
    assert!(extract_kernel_log(&wide, "k", false).contains(" ...\n"));

    let mut huge = String::new();
    for i in 0..5000 {
        let _ = writeln!(huge, "[{i}] Using GuC firmware {}", "y".repeat(300));
    }
    let text = extract_kernel_log(&huge, "k", false);
    assert!(text.len() <= EXTRACT_MAX_BYTES);
    assert!(text.contains("the first 200 shown"));
}

#[test]
fn an_empty_log_gives_only_the_headers() {
    let text = extract_kernel_log("", "k", false);
    assert!(text.contains("0 lines in the log") && text.contains("0 matching lines"), "{text}");
}

#[test]
fn routine_lines_that_only_contain_the_marker_letters_are_not_errors() {
    for line in [
        "[    1.0] iommu: Default domain type: Translated",
        "[    1.0] kerneloops[2069]: started",
        "[    1.0] [ 2069]   120  2069     3188      268 kerneloops",
        "[    1.0] debug: something routine",
        "[    1.0] xe 0000:03:00.0: [drm] debug: ok",
    ] {
        assert!(!is_error_line(line), "{line}");
    }
    for line in [
        "[    1.0] BUG: unable to handle page fault",
        "[    1.0] Oops: 0000 [#1] PREEMPT SMP",
        "[    1.0] DMAR: [DMA Read NO_PASID] Request device [03:00.0] fault addr 0x1000",
    ] {
        assert!(is_error_line(line), "{line}");
    }
}

#[test]
fn context_shared_across_the_split_between_the_groups_is_not_repeated() {
    // 250 matches, three lines apart: the first and last groups are contiguous with no gap.
    let mut log = String::new();
    for i in 0..250 {
        let _ = writeln!(log, "m{i} *ERROR* x\nc{i}a\nc{i}b");
    }
    let text = extract_kernel_log(&log, "k", false);
    assert!(!text.contains("omitted"), "{text}");
    for i in [0, 199, 200, 249] {
        assert_eq!(text.matches(&format!("m{i} *ERROR*")).count(), 1, "match {i}");
        assert_eq!(text.matches(&format!("c{i}a\n")).count(), 1, "context {i}");
    }
    assert!(!text.contains("\n--\n"), "touching blocks are one block");
    // 450 matches, spaced apart: the note and the separator appear once, between the groups.
    let mut log = String::new();
    for i in 0..450 {
        let _ = writeln!(log, "m{i} *ERROR* x\nf1\nf2\nf3\nf4");
    }
    let text = extract_kernel_log(&log, "k", false);
    assert_eq!(text.matches("matching lines omitted").count(), 1);
    assert!(text.contains("# ... 50 matching lines omitted ...\nm250 *ERROR*"), "{text}");
}
