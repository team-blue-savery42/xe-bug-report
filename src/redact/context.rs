// SPDX-License-Identifier: MIT
//! Which identifiers to redact, and this machine's names.

/// Which classes of identifier to replace. Default: all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    /// Serial numbers and UUIDs.
    pub serials: bool,
    /// This machine's names.
    pub hostname: bool,
    /// User names, including home directory components.
    pub users: bool,
    /// IPv4, IPv6 and MAC addresses.
    pub addresses: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self { serials: true, hostname: true, users: true, addresses: true }
    }
}

impl Rules {
    /// Rules that select nothing (`--no-redact`).
    pub const fn none() -> Self {
        Self { serials: false, hostname: false, users: false, addresses: false }
    }
    /// Whether at least one class is selected.
    pub const fn any(&self) -> bool {
        self.serials || self.hostname || self.users || self.addresses
    }
}

/// The identifiers of this machine and user, which no pattern can recognise on its own.
/// Generic names such as "root" and "localhost" are ignored by the rules: they identify no one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    /// Short and fully qualified names of this machine.
    pub hostnames: Vec<String>,
    /// The invoking user and, if different, the login user.
    pub user_names: Vec<String>,
}
