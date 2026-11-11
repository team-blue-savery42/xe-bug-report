// SPDX-License-Identifier: MIT
//! xe-bug-report: a standalone GPU diagnostic collector.
//!
//! Writes a redacted zip bundle of kernel logs, sysfs and debugfs attributes, PCI state, package
//! lists and `xpu-smi` output, without linking Level Zero or any GPU library. Every read and every
//! child process is bounded in time, so a wedged driver cannot hang the collection.

pub mod archive;
pub mod build_info;
pub mod bundle;
pub mod cli;
pub mod config;
pub mod diag;
pub mod error;
pub mod guard;
pub mod pci;
pub mod procio;
pub mod redact;
pub mod sources;
pub mod sys;
pub mod timefmt;
pub mod units;

pub use archive::zip::{Compression, ZipWriter};
pub use bundle::source::{
    Builtin, Content, Gate, GpuDevice, Keep, Produced, Profile, ReadOutcome, ReadResult, Reader, Source,
    SourceOptions, Spec, Status,
};
pub use bundle::writer::{Artifact, BundleRequest, BundleResult, write_bundle};
pub use error::Error;
pub use pci::PciAddress;
pub use units::Bytes;
