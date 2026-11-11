// SPDX-License-Identifier: MIT
//! The diagnostic sources of this OS, and the host facts they depend on.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use crate::bundle::source::{GpuDevice, Source, SourceOptions};
use crate::bundle::summary::Privilege;
use crate::pci::PciAddress;
use crate::redact;

/// What the RAS counter query prints when this xpu-smi does not know the fields.
pub const RAS_COUNTERS_UNSUPPORTED_MARKER: &str = "No valid metrics matched";

/// The query fields of the RAS error counters (every `ras.*` and `ecc.errors.*` field of xpu-smi).
pub const RAS_QUERY_FIELDS: &[&str] = &[];

/// The xpu-smi arguments that print the RAS counters of `bdf` as CSV.
pub fn ras_counters_args(bdf: &PciAddress) -> Vec<String> {
    let _ = bdf;
    Vec::new()
}

/// The xpu-smi executable: `explicit` when given, else `xpu-smi` on PATH, else next to this executable.
pub fn find_xpu_smi(explicit: Option<&Path>) -> Option<PathBuf> {
    let _ = explicit;
    None
}

/// The first line of `xpu-smi -v`, or None when it does not run.
pub fn xpu_smi_version(xpu_smi: &Path) -> Option<String> {
    let _ = xpu_smi;
    None
}

/// Sources common to every OS (the xpu-smi views), in table order, before profile filtering.
pub fn common_sources(options: &SourceOptions) -> Vec<Source> {
    let _ = options;
    Vec::new()
}

/// The Intel GPUs the OS sees, without any driver call, in BDF order.
pub fn gpus_from_os() -> Vec<GpuDevice> {
    Vec::new()
}

/// Common + platform sources, profile-filtered, in table order.
pub fn sources(options: &SourceOptions) -> Vec<Source> {
    let _ = options;
    Vec::new()
}

/// This machine's host names and user names; may do name-service lookups.
pub fn local_identity() -> redact::Context {
    redact::Context::default()
}

/// This machine's names without any lookup; never blocks.
pub fn local_identity_without_lookups() -> redact::Context {
    redact::Context::default()
}

/// One line naming the OS, e.g. "Ubuntu 24.04.3 LTS, Linux 7.2.0 x86_64".
pub fn os_description() -> String {
    String::new()
}

/// The privilege of this process.
pub fn current_privilege() -> Privilege {
    Privilege::Unprivileged
}
