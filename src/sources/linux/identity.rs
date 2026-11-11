// SPDX-License-Identifier: MIT
//! This machine's names for the redactor, and the one-line OS description.
//!
//! No `getaddrinfo`, no NSS call and no child process: the host names come from `/proc` and the
//! domains from `/etc/resolv.conf`, and the account names from the environment and `/etc/passwd`.
//! A lookup that waits on a network name service is exactly what the collector must not do.

use crate::redact;
use crate::sys::unix::euid;
use crate::units::Bytes;

use super::system::{read_capped, read_small};
use super::text::{
    format_os_description, host_name_variants, parse_account_names, parse_pretty_name, redactable_user_names,
    resolver_domains, trim, with_resolver_domains,
};

/// The value of an environment variable, lossy; None when unset.
fn environment_name(variable: &str) -> Option<String> {
    std::env::var_os(variable).map(|v| v.to_string_lossy().into_owned())
}

/// The passwd name of `uid` in the text of `/etc/passwd`.
pub fn user_name_in(passwd: &str, uid: u32) -> Option<String> {
    parse_account_names(passwd, 2).into_iter().find(|(id, _)| *id == uid).map(|(_, name)| name)
}

/// The context from given host files and environment; pure so the edge cases are testable.
pub fn identity_from(
    proc_hostname: &str,
    proc_domainname: &str,
    resolv_conf: &str,
    effective_uid: u32,
    sudo_user: Option<&str>,
    user: Option<&str>,
    logname: Option<&str>,
) -> redact::Context {
    let domains = resolver_domains(resolv_conf);
    let hostnames =
        with_resolver_domains(host_name_variants(proc_hostname, proc_hostname, proc_domainname), &domains);
    let user_names = redactable_user_names(effective_uid, None, &[sudo_user, user, logname]);
    redact::Context { hostnames, user_names }
}

/// This machine's names without any lookup; never blocks.
///
/// Host names: the kernel host name, its short form, the NIS domain name and `<short>.<domain>` for
/// each `search` or `domain` line of resolv.conf. User names: `SUDO_USER`, `USER` and `LOGNAME`;
/// never `root`, `nobody` or a numeric name.
pub fn local_identity_without_lookups() -> redact::Context {
    identity_from(
        &read_small("/proc/sys/kernel/hostname"),
        &read_small("/proc/sys/kernel/domainname"),
        &read_small("/etc/resolv.conf"),
        euid(),
        environment_name("SUDO_USER").as_deref(),
        environment_name("USER").as_deref(),
        environment_name("LOGNAME").as_deref(),
    )
}

/// This machine's names: [`local_identity_without_lookups`] plus the account names of the login
/// user (`/proc/self/loginuid`) and of the effective user, from `/etc/passwd`.
pub fn local_identity() -> redact::Context {
    let mut context = local_identity_without_lookups();
    let passwd = read_capped("/etc/passwd", Bytes::kib(512));
    let login = trim(&read_small("/proc/self/loginuid")).parse::<u32>().ok().filter(|uid| *uid != u32::MAX);
    let login_name = login.and_then(|uid| user_name_in(&passwd, uid));
    let effective = euid();
    let effective_name = user_name_in(&passwd, effective);
    for name in redactable_user_names(effective, effective_name.as_deref(), &[login_name.as_deref()]) {
        if !context.user_names.contains(&name) {
            context.user_names.push(name);
        }
    }
    context
}

/// One line naming the OS, e.g. `Ubuntu 24.04.3 LTS, Linux 7.2.0 x86_64`.
pub fn os_description() -> String {
    let pretty = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|path| parse_pretty_name(&read_small(path)))
        .unwrap_or_default();
    let field = |name: &str| trim(&read_small(format!("/proc/sys/kernel/{name}"))).to_owned();
    let (sysname, release) = (field("ostype"), field("osrelease"));
    if release.is_empty() {
        return if pretty.is_empty() { "Linux".to_owned() } else { pretty };
    }
    let sysname = if sysname.is_empty() { "Linux".to_owned() } else { sysname };
    let machine = field("arch");
    let machine = if machine.is_empty() { std::env::consts::ARCH.to_owned() } else { machine };
    format_os_description(&pretty, &sysname, &release, &machine)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "identity_tests.rs"]
mod tests;
