// SPDX-License-Identifier: MIT
//! The host-wide builtin sources (`uname`, environment, identity, container, device nodes,
//! firmware, links) and the privilege facts of this process.
//!
//! Builtins read files only through the [`Reader`] they are given, so a hanging `/proc` or sysfs
//! file costs one source. Directory listings and `stat` calls use `std::fs` directly; the
//! collector runs every builtin on a guarded helper thread.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::bundle::source::{Gate, Produced, ReadOutcome, ReadResult, Reader};
use crate::bundle::summary::Privilege;
use crate::procio::find_in_path;
use crate::sys::unix::{can_read_write, euid};
use crate::units::Bytes;

use super::debugfs::{PROBE_MAX, collected, needs_text, read_head, skipped};
use super::text::{
    filter_environment, format_dev_line, format_probe_line, link_target_name, parse_account_names,
    parse_cap_eff, parse_id_list, status_field, trim,
};

/// Capability bit of `CAP_SYS_ADMIN`.
pub const CAP_SYS_ADMIN: u32 = 21;
/// Capability bit of `CAP_SYSLOG`.
pub const CAP_SYSLOG: u32 = 34;
/// Capability bit of `CAP_PERFMON`.
pub const CAP_PERFMON: u32 = 38;

/// Size cap of `/proc/self/status`.
const STATUS_MAX: Bytes = Bytes::kib(64);
/// Size cap of the account files.
const ACCOUNTS_MAX: Bytes = Bytes::kib(512);
/// The most firmware files listed per directory.
const FIRMWARE_LISTING_MAX: usize = 5000;

/// The public DMI fields; the serial numbers and the UUID are separate, gated sources.
pub const DMI_PUBLIC_FIELDS: &[&str] = &[
    "sys_vendor",
    "product_name",
    "product_version",
    "product_family",
    "board_vendor",
    "board_name",
    "board_version",
    "bios_vendor",
    "bios_version",
    "bios_date",
    "bios_release",
];

/// A small attribute file to report as `label: value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The label printed before the value.
    pub label: String,
    pub path: String,
}

/// The capabilities of this process that matter to the sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The raw effective capability mask.
    pub effective: u64,
}

impl Capabilities {
    /// Whether capability bit `bit` is in the effective set.
    pub const fn has(self, bit: u32) -> bool {
        self.effective >> bit & 1 == 1
    }

    /// `CAP_SYS_ADMIN`.
    pub const fn sys_admin(self) -> bool {
        self.has(CAP_SYS_ADMIN)
    }

    /// `CAP_SYSLOG`.
    pub const fn syslog(self) -> bool {
        self.has(CAP_SYSLOG)
    }

    /// `CAP_PERFMON`.
    pub const fn perfmon(self) -> bool {
        self.has(CAP_PERFMON)
    }
}

/// The effective capabilities in a `/proc/self/status` text; None when it has no `CapEff` line.
pub fn capabilities_from_status(status: &str) -> Option<Capabilities> {
    parse_cap_eff(status).map(|effective| Capabilities { effective })
}

/// Reads a small local text file whole, at most 64 KiB; empty when it is absent, unreadable or
/// empty. For the host facts that have no [`Reader`] (identity, GPU enumeration).
pub fn read_small(path: impl AsRef<Path>) -> String {
    read_capped(path, STATUS_MAX)
}

/// [`read_small`] with a chosen cap. A file larger than `max` is cut back to its last complete
/// line, so a record is never half read.
pub fn read_capped(path: impl AsRef<Path>, max: Bytes) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut data = Vec::new();
    if file.take(max.get().saturating_add(1)).read_to_end(&mut data).is_err() {
        return String::new();
    }
    if data.len() as u64 > max.get() {
        data.truncate(max.get() as usize);
        let complete = data.iter().rposition(|&b| b == b'\n').map_or(0, |at| at + 1);
        data.truncate(complete);
    }
    String::from_utf8_lossy(&data).into_owned()
}

/// The effective capabilities of this process, from `/proc/self/status`.
pub fn capabilities() -> Option<Capabilities> {
    capabilities_from_status(&read_small("/proc/self/status"))
}

/// Whether this process holds `CAP_SYS_ADMIN` (for the sources that need it to read PCI config);
/// when the capabilities cannot be read, whether it is root.
pub fn has_sys_admin() -> bool {
    capabilities().map_or_else(|| euid() == 0, Capabilities::sys_admin)
}

/// The privilege of this process: root or `CAP_SYS_ADMIN` is privileged.
pub fn current_privilege() -> Privilege {
    privilege_of(euid(), capabilities())
}

/// [`current_privilege`] for given facts.
pub fn privilege_of(euid: u32, capabilities: Option<Capabilities>) -> Privilege {
    if euid == 0 || capabilities.is_some_and(Capabilities::sys_admin) {
        Privilege::Privileged
    } else {
        Privilege::Unprivileged
    }
}

/// Whether this process can open a DRM render node for reading and writing: at least one
/// `/dev/dri/renderD*` node passes the kernel's permission check (mode bits, ACLs, capabilities;
/// the node itself is never opened, so the driver is not entered).
pub fn any_render_node_accessible() -> bool {
    let Ok(entries) = fs::read_dir("/dev/dri") else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("renderD"))
        .any(|e| can_read_write(&e.path()))
}

/// The `.txt` of one-line `label: value` probes, one per file.
pub fn probe_builtin(reader: &dyn Reader, rel_path: &str, probes: &[Probe]) -> Vec<Produced> {
    let mut text = String::new();
    for probe in probes {
        text.push_str(&format_probe_line(
            &probe.label,
            &read_head(reader, Path::new(&probe.path), PROBE_MAX),
        ));
        text.push('\n');
    }
    vec![collected(rel_path, text, "")]
}

/// The kernel and LSM settings that restrict GPU and log access: sysctls labelled by their dotted
/// name, the other files by path.
pub fn security_probes() -> Vec<Probe> {
    [
        "/proc/sys/kernel/dmesg_restrict",
        "/proc/sys/kernel/kptr_restrict",
        "/proc/sys/kernel/perf_event_paranoid",
        "/proc/sys/dev/xe/observation_paranoid",
        "/proc/sys/dev/i915/perf_stream_paranoid",
        "/sys/module/apparmor/parameters/enabled",
        "/sys/fs/selinux/enforce",
        "/sys/kernel/security/lockdown",
    ]
    .iter()
    .map(|path| {
        let label = match path.strip_prefix("/proc/sys/") {
            Some(sysctl) => sysctl.replace('/', "."),
            None => (*path).to_owned(),
        };
        Probe { label, path: (*path).to_owned() }
    })
    .collect()
}

/// The public DMI fields as probes.
pub fn dmi_probes() -> Vec<Probe> {
    DMI_PUBLIC_FIELDS
        .iter()
        .map(|field| Probe { label: (*field).to_owned(), path: format!("/sys/class/dmi/id/{field}") })
        .collect()
}

/// The `uname(2)` fields, from `/proc/sys/kernel`.
pub fn uname_builtin(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let field = |name: &str| -> Option<String> {
        let read = read_head(reader, Path::new(&format!("/proc/sys/kernel/{name}")), PROBE_MAX);
        let text = String::from_utf8_lossy(&read.data);
        (read.outcome == ReadOutcome::Read && !trim(&text).is_empty()).then(|| trim(&text).to_owned())
    };
    let sysname = field("ostype").unwrap_or_else(|| "Linux".to_owned());
    let nodename = field("hostname").unwrap_or_default();
    let release = field("osrelease").unwrap_or_default();
    let version = field("version").unwrap_or_default();
    let machine = field("arch").unwrap_or_else(|| std::env::consts::ARCH.to_owned());
    let text = format!(
        "sysname: {sysname}\nnodename: {nodename}\nrelease: {release}\nversion: {version}\nmachine: {machine}\n"
    );
    vec![collected(rel_path, text, "")]
}

/// The tools whose location on PATH is recorded in `system/env.txt` instead of the whole PATH.
const ENV_TOOLS: &[&str] =
    &["xpu-smi", "clinfo", "vainfo", "vulkaninfo", "eglinfo", "intel_gpu_top", "iclg", "igsc", "lspci"];

/// The environment variables that change GPU runtime behaviour, as sorted `KEY=value` lines, then
/// where the diagnostic tools resolve on PATH (the PATH itself lists directories that say nothing
/// about the GPU and often name the user's tools).
pub fn env_builtin(rel_path: &str) -> Vec<Produced> {
    let environment: Vec<String> = std::env::vars_os()
        .map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
        .collect();
    let mut text = filter_environment(&environment);
    for tool in ENV_TOOLS {
        let location =
            find_in_path(tool).map_or_else(|| "(not found)".to_owned(), |p| p.to_string_lossy().into_owned());
        let _ = writeln!(text, "# {tool}: {location}");
    }
    vec![collected(rel_path, text, "")]
}

/// The id-to-name tables of `/etc/passwd` and `/etc/group`.
struct Accounts {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl Accounts {
    fn load(reader: &dyn Reader) -> Self {
        let table = |path: &str| -> HashMap<u32, String> {
            let read = read_head(reader, Path::new(path), ACCOUNTS_MAX);
            let text = String::from_utf8_lossy(&read.data);
            // The first entry of an id wins, as getpwuid does.
            let mut map = HashMap::new();
            for (id, name) in parse_account_names(&text, 2) {
                map.entry(id).or_insert(name);
            }
            map
        };
        Self { users: table("/etc/passwd"), groups: table("/etc/group") }
    }

    fn user(&self, uid: u32) -> String {
        self.users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
    }

    fn group(&self, gid: u32) -> String {
        self.groups.get(&gid).cloned().unwrap_or_else(|| gid.to_string())
    }
}

/// The text of `system/id.txt` for the given `/proc/self/status` contents and account tables.
fn id_text(status: Option<&str>, accounts: &Accounts) -> String {
    let status_text = status.unwrap_or("");
    let ids = |name: &str| -> (Option<u32>, Option<u32>) {
        let values = status_field(status_text, name).map(|v| parse_id_list(&v)).unwrap_or_default();
        (values.first().copied(), values.get(1).copied())
    };
    let (uid, euid) = ids("Uid");
    let (gid, egid) = ids("Gid");
    let user_line = |label: &str, id: Option<u32>| match id {
        Some(id) => format!("{label}: {id} ({})\n", accounts.user(id)),
        None => format!("{label}: (unavailable)\n"),
    };
    let group_line = |label: &str, id: Option<u32>| match id {
        Some(id) => format!("{label}: {id} ({})\n", accounts.group(id)),
        None => format!("{label}: (unavailable)\n"),
    };
    let mut text = String::new();
    text.push_str(&user_line("uid", uid));
    text.push_str(&user_line("euid", euid));
    text.push_str(&group_line("gid", gid));
    text.push_str(&group_line("egid", egid));
    let mut groups = status_field(status_text, "Groups").map(|v| parse_id_list(&v)).unwrap_or_default();
    if let Some(egid) = egid
        && !groups.contains(&egid)
    {
        groups.push(egid);
    }
    text.push_str("groups:");
    for gid in groups {
        let _ = write!(text, " {gid}({})", accounts.group(gid));
    }
    text.push('\n');
    let cap_eff = status_field(status_text, "CapEff");
    let _ = writeln!(text, "CapEff: {}", cap_eff.as_deref().unwrap_or("(unavailable)"));
    match capabilities_from_status(status_text) {
        Some(caps) => {
            let held: Vec<&str> = [
                (caps.sys_admin(), "CAP_SYS_ADMIN"),
                (caps.syslog(), "CAP_SYSLOG"),
                (caps.perfmon(), "CAP_PERFMON"),
            ]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| *name)
            .collect();
            if held.is_empty() {
                text.push_str("capabilities: none of CAP_SYS_ADMIN, CAP_SYSLOG, CAP_PERFMON\n");
            } else {
                let _ = writeln!(text, "capabilities: {}", held.join(" "));
            }
        }
        None => text.push_str("capabilities: (unavailable)\n"),
    }
    text
}

/// The user, groups and capabilities this process runs with. `CapEff` is `(unavailable)` when the
/// status file cannot be read.
pub fn id_builtin(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let status = read_head(reader, Path::new("/proc/self/status"), STATUS_MAX);
    let status_text =
        (status.outcome == ReadOutcome::Read).then(|| String::from_utf8_lossy(&status.data).into_owned());
    let accounts = Accounts::load(reader);
    vec![collected(rel_path, id_text(status_text.as_deref(), &accounts), "")]
}

/// The file system types whose mounts say how the container sees the system.
const MOUNT_TYPES: &[&str] = &["sysfs", "devtmpfs", "cgroup", "cgroup2", "overlay", "debugfs"];
/// Mount points that decide whether a GPU stack can work.
const MOUNT_POINTS: &[&str] = &[
    "/dev/dri",
    "/dev/dxg",
    "/sys/kernel/debug",
    "/lib/firmware",
    "/lib/x86_64-linux-gnu/dri",
    "/usr/share/vulkan",
    "/etc/OpenCL",
    "/usr/lib/wsl",
];

/// One mountinfo line as `(mount point, file system type, source)`. The root of the mount in its
/// file system (the field before the mount point) is left out: for a bind mount it names a host
/// directory.
pub fn parse_mount(line: &str) -> Option<(&str, &str, &str)> {
    let (before, after) = line.split_once(" - ")?;
    let mount_point = before.split(' ').nth(4)?;
    let mut tail = after.split(' ');
    let (fs_type, source) = (tail.next()?, tail.next()?);
    Some((mount_point, fs_type, source))
}

/// The mounts that decide whether a GPU stack can work inside a container, as
/// `<mount point> <type> <source>`: the device nodes, firmware, driver and loader directories, and
/// the sysfs, devtmpfs, cgroup, overlay and debugfs mounts. In mountinfo order, at most 40.
pub fn gpu_mounts(mountinfo: &str) -> Vec<String> {
    mountinfo
        .lines()
        .filter_map(parse_mount)
        .filter(|(point, fs_type, _)| {
            // Overlay mounts of other containers sit under the container runtime's directory on a
            // host; only the root and the system file systems are the container's own view.
            (MOUNT_TYPES.contains(fs_type)
                && (*point == "/" || point.starts_with("/sys") || point.starts_with("/dev")))
                || MOUNT_POINTS.iter().any(|marker| point.contains(marker))
        })
        .map(|(point, fs_type, source)| format!("{point} {fs_type} {source}"))
        .take(40)
        .collect()
}

/// Whether the process runs inside a container or a virtual machine that passes the GPU through:
/// the marker files, the cgroup paths of PID 1 and of this process, the user namespace id maps,
/// the GPU-related mounts and the signs of a Windows Subsystem for Linux guest.
pub fn container_builtin(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    for marker in ["/.dockerenv", "/run/.containerenv", "/dev/dxg", "/usr/lib/wsl"] {
        let _ = writeln!(text, "{marker}: {}", if Path::new(marker).exists() { "present" } else { "absent" });
    }
    let release = read_head(reader, Path::new("/proc/sys/kernel/osrelease"), PROBE_MAX);
    let wsl = String::from_utf8_lossy(&release.data).to_ascii_lowercase().contains("microsoft");
    let _ = writeln!(text, "kernel release names Microsoft (WSL): {}", if wsl { "yes" } else { "no" });
    for cgroup in ["/proc/1/cgroup", "/proc/self/cgroup"] {
        text.push_str(&format_probe_line(cgroup, &read_head(reader, Path::new(cgroup), PROBE_MAX)));
        text.push('\n');
    }
    for map in ["/proc/self/uid_map", "/proc/self/gid_map"] {
        let line = format_probe_line(map, &read_head(reader, Path::new(map), PROBE_MAX));
        text.push_str(&line.lines().map(trim).collect::<Vec<_>>().join("; "));
        text.push('\n');
    }
    let mountinfo = read_head(reader, Path::new("/proc/self/mountinfo"), ACCOUNTS_MAX);
    let mountinfo = String::from_utf8_lossy(&mountinfo.data).into_owned();
    let mounts = gpu_mounts(&mountinfo);
    let _ = writeln!(text, "GPU-related mounts: {}", if mounts.is_empty() { "none" } else { "" });
    for mount in mounts {
        let _ = writeln!(text, "  {mount}");
    }
    vec![collected(rel_path, text, "")]
}

/// The major number of a device id, as glibc's `major()`.
pub const fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// The minor number of a device id, as glibc's `minor()`.
pub const fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Ownership, mode and device number of the GPU device nodes: the non-directory entries of
/// `/dev/dri` and `/dev/dri/by-path`, sorted.
pub fn dev_dri_builtin(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let accounts = Accounts::load(reader);
    let mut text = String::new();
    for dir in ["/dev/dri", "/dev/dri/by-path"] {
        let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
            Ok(entries) => entries.filter_map(Result::ok).map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        };
        entries.sort();
        for path in entries {
            let Ok(link) = fs::symlink_metadata(&path) else {
                continue;
            };
            if link.is_dir() {
                continue;
            }
            let mut target = String::new();
            let mut node = link.clone();
            if link.file_type().is_symlink() {
                target = fs::read_link(&path).map(|t| t.to_string_lossy().into_owned()).unwrap_or_default();
                if let Ok(meta) = fs::metadata(&path) {
                    node = meta;
                }
            }
            let kind = node.file_type();
            let device = (kind.is_char_device() || kind.is_block_device())
                .then(|| (dev_major(node.rdev()), dev_minor(node.rdev())));
            text.push_str(&format_dev_line(
                &path.to_string_lossy(),
                link.mode(),
                &accounts.user(link.uid()),
                &accounts.group(link.gid()),
                device,
                &target,
            ));
            text.push('\n');
        }
    }
    vec![collected(rel_path, text, "")]
}

/// The GPU firmware blobs installed on the host: the relative path and size of every regular file
/// below the xe and i915 firmware directories, at most 5000 per directory. Symlinks are listed
/// under their own names (alias names are what the driver requests) and never entered.
pub fn firmware_builtin(rel_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    for dir in ["/lib/firmware/xe", "/lib/firmware/i915"] {
        let lines = list_firmware(Path::new(dir), FIRMWARE_LISTING_MAX);
        let _ = writeln!(text, "{dir}:{}", if lines.is_empty() { " (none)" } else { "" });
        for line in lines {
            let _ = writeln!(text, "  {line}");
        }
    }
    vec![collected(rel_path, text, "")]
}

/// `<relative path> <size>` for every regular file below `root`, sorted, at most `limit`.
pub fn list_firmware(root: &Path, limit: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    'walk: while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(link) = fs::symlink_metadata(&path) else {
                continue;
            };
            if link.is_dir() {
                pending.push(path);
                continue;
            }
            // A symlink to a file counts as a file; its size is the target's.
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            lines.push(format!("{rel} {}", meta.len()));
            if lines.len() >= limit {
                break 'walk;
            }
        }
    }
    lines.sort();
    lines
}

/// The driver binding, IOMMU group and parent function of a device: the last component of each
/// link target, or `(absent)`.
pub fn links_builtin(rel_path: &str, os_path: &str) -> Vec<Produced> {
    let mut text = String::new();
    for name in ["driver", "iommu_group", "physfn", "firmware_node"] {
        let value = match fs::read_link(Path::new(os_path).join(name)) {
            Ok(target) => link_target_name(&target.to_string_lossy()),
            Err(_) => "(absent)".to_owned(),
        };
        let _ = writeln!(text, "{name}: {value}");
    }
    text.push_str(&virtual_functions(Path::new(os_path)));
    vec![collected(rel_path, text, "")]
}

/// The most virtual functions listed.
const VIRTUAL_FUNCTIONS_MAX: usize = 64;

/// The virtual functions of an SR-IOV physical function, one line each:
/// `virtfn0: 0000:03:00.1, driver vfio-pci`. Empty when the device has none.
pub fn virtual_functions(device_dir: &Path) -> String {
    let Ok(entries) = fs::read_dir(device_dir) else {
        return String::new();
    };
    let mut functions: Vec<(u32, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let number = name.strip_prefix("virtfn")?.parse().ok()?;
            Some((number, e.path()))
        })
        .collect();
    functions.sort();
    let mut text = String::new();
    for (number, path) in functions.iter().take(VIRTUAL_FUNCTIONS_MAX) {
        let function = fs::read_link(path)
            .map_or_else(|_| "(unknown)".to_owned(), |t| link_target_name(&t.to_string_lossy()));
        let driver = fs::read_link(path.join("driver"))
            .map_or_else(|_| "none".to_owned(), |t| link_target_name(&t.to_string_lossy()));
        let _ = writeln!(text, "virtfn{number}: {function}, driver {driver}");
    }
    if functions.len() > VIRTUAL_FUNCTIONS_MAX {
        let _ = writeln!(text, "... and {} more", functions.len() - VIRTUAL_FUNCTIONS_MAX);
    }
    text
}

/// Distribution identification from `/usr/lib/os-release`, for hosts without `/etc/os-release`:
/// one Collected artifact, or Skipped (`needs root` when denied, otherwise `not present`).
pub fn os_release_fallback_builtin(reader: &dyn Reader, rel_path: &str) -> Vec<Produced> {
    let result: ReadResult = read_head(reader, Path::new("/usr/lib/os-release"), PROBE_MAX);
    if result.outcome != ReadOutcome::Read {
        let reason = if result.outcome == ReadOutcome::Denied {
            needs_text(Gate::Root)
        } else {
            "not present".to_owned()
        };
        return vec![skipped(rel_path, reason)];
    }
    vec![collected(rel_path, result.data, "/usr/lib/os-release")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "system_tests.rs"]
mod tests;
