<!-- SPDX-License-Identifier: MIT -->
# xe-bug-report

A standalone GPU diagnostic collector for Linux and Windows. It writes one redacted zip bundle
of kernel logs, sysfs and debugfs attributes, PCI state, package lists and `xpu-smi` output,
in the same layout `xpu-smi log` writes. It links no Level Zero or GPU library, so it still runs
when the loader is missing or the driver is wedged, and records why each source could not be
collected.

## Usage



## What is collected

## Access required

## Manifest

## Privacy

## Exit codes
