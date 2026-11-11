<!-- SPDX-License-Identifier: MIT -->
# xe-bug-report

GPU diagnostic collector for Linux and Windows. Writes one redacted zip of kernel logs, sysfs and
debugfs attributes, PCI state, package lists and `xpu-smi` output, with a `manifest.json` that
records what was collected, what was not, and why.

This tool is created for my own benefit as a user of a B70 Pro card while working on native Intel GPU support for Modular's MAX. Bring-up problems span the firmware, the kernel driver, Level Zero and the compute runtime, and a useful report needs all of them from the same moment, including from machines where the GPU stack does not start. The tool does not use or require MAX, and is in no way related to, endorsed by, or supported by Modular or MAX.

> [!NOTE]
> xe-bug-report is an independent project. It is not affiliated with, endorsed by, sponsored by or supported by Intel Corporation. 

> [!WARNING]
> AI disclaimer. Coding LLMs were used in Windows development, Markdown files, GitHub CI, and some unit testing as well as code review.

## Contents

- [Install](#install)
- [Dependencies](#dependencies)
- [Usage](#usage)
- [Profiles](#profiles)
- [Exit codes](#exit-codes)
- [What is collected](#what-is-collected)
  - [Linux](#linux)
  - [Windows](#windows)
- [Access required](#access-required)
- [Privacy](#privacy)
- [Bundle layout](#bundle-layout)
- [Manifest](#manifest)
- [Hang safety and signals](#hang-safety-and-signals)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Install

Build from source with Rust 1.99 or newer (`rust-toolchain.toml` pins 1.99.1, the toolchain CI uses):

```sh
cargo build --release --locked
# the binary is target/release/xe-bug-report
```

Packages are built by `scripts/package.sh`. It runs the same release build, then writes to `dist/`:

| File | When |
|---|---|
| `xe-bug-report-<version>-<target>.tar.gz` (binary, `LICENSE`, `README.md`) | always |
| `xe-bug-report_<version>_<arch>.deb` (installs `/usr/bin/xe-bug-report`; depends on `libc6 (>= <glibc it was built against>)` and `libgcc-s1`) | `dpkg-deb` is installed |
| `xe-bug-report-<version>-1<dist>.<arch>.rpm` (installs `/usr/bin/xe-bug-report`) | `rpmbuild` is installed |

The Linux binary depends only on glibc (`libc`, `libgcc_s`), at the version it was built against
(the `.deb` records it; check with `objdump -T xe-bug-report | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1`). No installation is needed to run it:
the binary can be executed from wherever it was copied.

## Dependencies

The binary needs only glibc on Linux. On Windows the C runtime is linked in, so it needs nothing
beyond Windows itself. Every tool below is optional: a missing one leaves its sources `skipped` with
`<tool> not installed`, and the rest of the bundle is collected. Tools are found on
PATH.

Linux:

| Tool | From | Collects |
|---|---|---|
| `xpu-smi` | [Intel XPU Manager](https://github.com/intel/xpumanager) | `xpu-smi/` |
| `lspci` | pciutils | `pci/` |
| `journalctl` | systemd | the kernel log (`kernel/kmsg*.txt`) |
| `systemd-detect-virt` | systemd | `system/virt.txt`, `system/virt-container.txt` |
| `modinfo` | kmod | `kernel/modinfo-*.txt` |
| `dkms` | DKMS | `kernel/dkms.txt` |
| `ldconfig` | glibc | `system/ldconfig.txt` |
| `dpkg-query` | dpkg | `packages/dpkg.txt` |
| `rpm` | RPM | `packages/rpm*.txt` |
| `clinfo` | [clinfo](https://github.com/Oblomov/clinfo) | `tools/clinfo*.txt` |
| `vainfo` | [libva-utils](https://github.com/intel/libva-utils) | `tools/vainfo.txt` |

Windows (all but `xpu-smi` ship with Windows):

| Tool | From | Collects |
|---|---|---|
| `xpu-smi` | [Intel XPU Manager](https://github.com/intel/xpumanager) | `xpu-smi/` |
| `powershell.exe` | Windows | GPU enumeration and the WMI, registry and counter queries |
| `reg` | Windows | `devices/*-registry.txt`, `kernel/*-registry.txt` |
| `pnputil` | Windows | `devices/pnputil-*.txt` |
| `wevtutil` | Windows | `kernel/*-events.txt`, `kernel/System.evtx` |
| `systeminfo` | Windows | `system/systeminfo.txt` |
| `driverquery` | Windows | `packages/driverquery.csv` |
| `whoami` | Windows | `system/id.txt` |
| `dxdiag` | Windows | `tools/dxdiag/` (`--full`) |

Related Intel projects:

- [Level Zero loader](https://github.com/oneapi-src/level-zero): needed by
  `xpu-smi`.
- [igsc](https://github.com/intel/igsc): GPU firmware update tool; its location is
  recorded in `system/env.txt`.

## Usage

```text
Collect GPU diagnostics into a redacted zip bundle

Usage: xe-bug-report [--output <file>] [--device <bdf,...>] [--minimal | --full] [--samples <n>]
       [--since <duration>] [--no-redact] [--list] [--json] [--xpu-smi <path>] [--timeout <seconds>]
       [--verbose]
       xe-bug-report --version | -v
       xe-bug-report --help | -h

Options:
      --output <file>      The zip file to write (default: xe-bug-report-<UTC time>.zip in the current directory)
      --device <bdf,...>   PCI addresses (dddd:bb:dd.f) of the GPUs to include, comma-separated
      --minimal            Collect only the essentials, no samples
      --full               Also collect large and slow sources
      --samples <n>        Metric samples per GPU, 1 s apart (default: 5, 0 disables, at most 3600)
      --since <duration>   Time window of the kernel and event logs: <n>m, <n>h, <n>d or hours (1 minute to 365 days)
      --no-redact          Keep host names, user names, serial numbers and addresses
      --list               List the sources that would be collected and exit
      --json               Print the result as JSON
      --xpu-smi <path>     The xpu-smi executable (default: xpu-smi on PATH, then next to xe-bug-report)
      --timeout <seconds>  Seconds for the whole run (default: 600, 0 disables the deadline)
      --verbose            Log progress to stderr and list every source that was not collected completely
  -v, --version            Print the version and exit
  -h, --help               Print help
```

Examples:

```sh
# The default bundle in the current directory; use sudo on Linux for the full bundle.
sudo xe-bug-report

# A chosen file, one GPU only.
xe-bug-report --output gpu_debug.zip --device 0000:03:00.0

# A smaller bundle (no samples), and a larger one with extra tools.
xe-bug-report --minimal
sudo xe-bug-report --full --samples 10

# The kernel log of the last 30 minutes, across reboots (Linux).
sudo xe-bug-report --since 30m

# Show what would be collected, without collecting it.
xe-bug-report --list --full

# Use an xpu-smi that is not on PATH; machine-readable result.
xe-bug-report --xpu-smi /opt/intel/bin/xpu-smi --json
```

Windows, from an elevated prompt, with the last 24 hours of events:

```text
xe-bug-report.exe --since 24h --output C:\Temp\gpu_debug.zip
```

Details of the options:

- `--output` names the archive. The default is `xe-bug-report-<YYYYMMDDTHHMMSSZ>.zip` (UTC time, no
  host name) in the current directory. An existing file is never overwritten: the run stops with
  `<path> already exists` and exit code 1. While running, the archive is written as
  `<output>.partial` and renamed into place when complete.
- `--device` takes PCI addresses (`dddd:bb:dd.f`, for example `0000:03:00.0`), comma separated. An
  address that is not an Intel GPU on this system is an error that names it. Without `--device`
  every Intel GPU is included. Device indices are not accepted.
- `--samples` is the number of metric samples per GPU, taken one second apart through
  `xpu-smi dump`. The default is 5, `0` disables sampling, the maximum is 3600. `--minimal` forces 0.
- `--since` limits the kernel log (Linux) and the event logs (Windows) to a window: `<n>m`,
  `<n>h`, `<n>d`, or a bare integer meaning hours; 1 minute to 365 days. Without it Linux collects
  the current and the previous boot, and Windows the last 72 hours. On Linux a window is read from
  the journal across reboots (`journalctl _TRANSPORT=kernel`), so `kernel/kmsg-prev-boot.txt` is not
  written; a window with no messages gives the one-line note "no kernel messages in the last
  <window>" and the file is still `collected`. The window is recorded as `since_minutes`.
- `--xpu-smi` names the `xpu-smi` executable. The default is `xpu-smi` on PATH, then next to
  `xe-bug-report` itself. If none is found, every `xpu-smi/*` source is skipped with the reason
  `xpu-smi not found` and everything else is still collected.
- `--timeout` is the number of seconds for the whole run (default 600, `0` disables the deadline).
- `--json` prints the result as JSON on stdout instead of the report (below), and nothing else: the
  per-access breakdown is then only in the manifest (`gate` and `reason`).
- `--verbose` logs progress to stderr and adds a `Not complete:` list (state, path, reason of every
  source that was not collected completely) to the report.

Output. On success one report goes to stdout and nothing goes to stderr (except with `--verbose`):

```text
Wrote xe-bug-report-20261110T163000Z.zip (712.8 KiB)
  53 sources: 39 complete, 6 partial, 8 not collected
  needs root: 4 not collected, 2 partial
  needs root or CAP_SYS_ADMIN: 1 not collected, 4 partial
  other reasons: 3 not collected
Re-run with sudo for the full bundle.
Details: unzip -p xe-bug-report-20261110T163000Z.zip manifest.json (or run with --verbose)
```

A `partial` source is in the archive but incomplete (size cap, or some files denied); a `not
collected` one is absent (skipped, timed out or failed; the totals line then ends with, for example,
`(1 timed out, 1 failed)`). The `needs` lines and the hint are described under
[Access required](#access-required); `other reasons` counts sources that are absent, unsupported or
withheld. A complete run prints only the first two lines. With `--verbose` the `Not complete:` list
comes before the `Details:` line, which then has no hint.

With `--json`, stdout is the result object, and on failure an error object (exit code 1):

```json
{
    "status": "OK",
    "file": "gpu_debug.zip",
    "collected": 39,
    "truncated": 6,
    "skipped": 8,
    "timed_out": 0,
    "failed": 0,
    "bytes": 729907
}
```

```json
{
    "errno": 1,
    "error": "gpu_debug.zip already exists"
}
```

Non-UTF-8 file names are converted lossily, so the JSON is always valid.

## Profiles

The profile of a source is the smallest profile that includes it.

| Profile | Selected by | Contents |
|---|---|---|
| `minimal` | `--minimal` | The essentials: versions, kernel log of the current boot, PCI identity and link state, device sysfs attributes, the package list, `xpu-smi` discovery. No samples. |
| `default` | no flag | `minimal` plus host layout, previous-boot log, debugfs, PCI detail, per-device `xpu-smi` queries and samples. |
| `full` | `--full` | `default` plus large or slow sources: the system log, `clinfo` and `vainfo` on Linux; `dxdiag` and the raw System event log on Windows. |

`--minimal` and `--full` cannot be combined. `--list` prints the sources the chosen options would
collect.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The archive was written, whatever was skipped. Also `--list`, `--help`, `--version`. |
| 1 | Invalid arguments, a `--device` that is not present, an output file that already exists or cannot be created, or a write failure. Nothing was written. |
| 124 | The backstop fired: the collection did not finish 60 seconds after the `--timeout` deadline. No archive is left behind. |

## What is collected

Each row is one source. `<dev>` stands for a PCI address written with `-` instead of `:` (for
example `0000-03-00.0`), once per selected GPU; `<bridge>` for an upstream PCI bridge of the GPU.
`--list` prints the same table for the options you give it, with the real device names. The
columns are the ones `--list` prints: `PROFILE`, `NEEDS` (the access gate, see
[Access required](#access-required); `-` means none), `PATH` and `WHY`.

### Linux

| Profile | Needs | Path | Why |
|---|---|---|---|
| minimal | - | `xpu-smi/version.txt` | build provenance and the Level Zero loader in use |
| minimal | - | `system/os-release` | Distribution identification. |
| minimal | - | `system/uname.txt` | Kernel release and machine type. |
| minimal | - | `system/cmdline` | Kernel command line. |
| minimal | - | `system/modules` | Loaded kernel modules. |
| default | - | `system/cpuinfo` | Host CPU, memory and interrupt layout. |
| default | - | `system/meminfo` | Host CPU, memory and interrupt layout. |
| default | - | `system/interrupts` | Host CPU, memory and interrupt layout. |
| default | - | `system/iomem` | Host CPU, memory and interrupt layout. |
| minimal | - | `system/env.txt` | Environment variables that change GPU runtime behaviour. |
| minimal | - | `system/id.txt` | Which user, groups and capabilities the collection ran with. |
| minimal | - | `system/container.txt` | Whether the collection ran inside a container. |
| default | - | `system/virt.txt` | Virtualisation the host runs under. |
| minimal | - | `system/security.txt` | Kernel and LSM settings that restrict GPU and log access. |
| minimal | - | `system/dev-dri.txt` | Ownership and permissions of the GPU device nodes. |
| minimal | - | `system/dmi.txt` | Platform vendor, model and BIOS version. |
| minimal | root | `system/dmi-serials/` | Platform serial numbers and UUID; omitted while redacting. |
| minimal | - | `system/ldconfig.txt` | Which GPU runtime libraries the loader can find. |
| minimal | kernel_log | `kernel/kmsg.txt` | Kernel log of the current boot, with driver and GPU messages. |
| default | kernel_log | `kernel/kmsg-prev-boot.txt` | Kernel log of the previous boot, for crashes and hangs. |
| minimal | - | `kernel/modinfo-xe.txt` | Version and parameters of the xe kernel driver. |
| default | - | `kernel/modinfo-i915.txt` | Version and parameters of the i915 kernel driver. |
| default | - | `kernel/dkms.txt` | Out-of-tree kernel modules. |
| default | - | `kernel/firmware.txt` | GPU firmware blobs installed on the host. |
| default | root | `kernel/xe-parameters/` | Current xe driver module parameters. |
| default | root | `kernel/drm-debug.txt` | DRM debug message mask. |
| minimal | root | `devices/<dev>/sysfs/` | PCI, power, link, frequency and engine attributes from sysfs. |
| minimal | - | `devices/<dev>/links.txt` | Driver binding, IOMMU group and parent function of the device. |
| default | root | `devices/<dev>/debugfs/` | Driver internals: engines, topology, firmware state. |
| minimal | root | `dumps/<dev>/` | Device coredumps the driver captured after a hang or crash. |
| default | root | `dumps/<dev>/pmt-crashlog*.bin` | Raw firmware crash log regions of the platform telemetry interface. |
| default | root | `dumps/<dev>/pmt-crashlog*.txt` | Identity and state of each firmware crash log region. |
| minimal | root | `devices/<dev>/ras-counters.json` | Error counters of the device from the kernel's drm-ras interface. |
| default | - | `pci/lspci-nn.txt` | PCI devices with numeric ids. |
| default | - | `pci/lspci-tree.txt` | PCI topology as a tree. |
| minimal | sys_admin | `pci/<dev>/lspci-vvv-<dev>.txt` | PCI capabilities, link state and errors of the GPU. |
| default | sys_admin | `pci/<dev>/lspci-vvv-<bridge>.txt` | PCI capabilities and link state of an upstream bridge. |
| default | sys_admin | `pci/<dev>/lspci-xxxx.txt` | Raw PCI configuration space, including extended capabilities. |
| minimal | - | `packages/dpkg.txt` | Installed GPU-related Debian packages. |
| minimal | - | `packages/rpm.txt` | Installed GPU-related RPM packages. |
| default | - | `packages/dpkg-log.txt` | Recent Debian package installs and upgrades. |
| default | - | `packages/apt-history.log` | Recent apt transactions. |
| default | - | `packages/rpm-last.txt` | RPM packages by install time. |
| full | kernel_log | `system/syslog` | Host system log. |
| full | device_access | `tools/clinfo.txt` | OpenCL platforms and devices. |
| full | device_access | `tools/vainfo.txt` | Video acceleration capabilities. |
| minimal | device_access | `xpu-smi/discovery.json` | Devices as the driver reports them. |
| default | device_access | `xpu-smi/topology.txt` | GPU, NIC and CPU affinity matrix. |
| default | device_access | `xpu-smi/<dev>/discovery.json` | Detailed properties of the device. |
| default | device_access | `xpu-smi/<dev>/stats.json` | Current power, temperature, clocks and memory. |
| default | device_access | `xpu-smi/<dev>/config.txt` | Frequency, power, scheduler and standby settings. |
| default | device_access | `xpu-smi/<dev>/health.json` | Component health status. |
| default | device_access | `xpu-smi/<dev>/ras-counters.csv` | RAS error counters as the query fields report them. |
| default | device_access | `xpu-smi/raslog/` | Hardware RAS error records (CPER) of all devices. |
| default | root | `xpu-smi/<dev>/crashlog/` | Firmware crash log records. |
| default | device_access | `xpu-smi/<dev>/samples.csv` | Metric samples taken one second apart. |

Notes on the Linux table:

- `packages/rpm.txt` and `packages/rpm-last.txt` exist only where `rpm` is installed;
  `packages/dpkg.txt` only where `dpkg-query` is. A missing tool is "not installed", never "needs
  root".
- `xpu-smi/<dev>/crashlog/` exists only where `iclg` is installed.
- `xpu-smi/<dev>/samples.csv` is absent with `--minimal` or `--samples 0`.
- With `--since` the previous-boot row is replaced: `kernel/kmsg.txt` covers the window across
  reboots.
- `system/dmi-serials/` is an identifying source: it holds platform serial numbers and is skipped
  while redacting; use `--no-redact` to collect it.
- `xpu-smi/<dev>/ras-counters.csv` is skipped as "not supported by this xpu-smi build" while the installed
  `xpu-smi` does not know the `ras.*` and `ecc.errors.*` query fields; `xpu-smi/raslog/` likewise
  on an `xpu-smi` without that subcommand.
- `devices/<dev>/ras-counters.json` is read from the kernel's `drm-ras` generic netlink interface
  (read only; counters are never cleared). It is skipped with "kernel has no drm-ras interface"
  where the kernel lacks it.
- The `xpu-smi` queries run the `xpu-smi` executable as a child process with a time limit. Except
  `version.txt` (no gate) and `crashlog/` (`root`), they are listed under `device_access` because
  they need a render node.

### Windows

| Profile | Needs | Path | Why |
|---|---|---|---|
| minimal | - | `xpu-smi/version.txt` | build provenance and the Level Zero loader in use |
| minimal | - | `system/os.txt` | operating system name, version, build and boot time |
| default | - | `system/systeminfo.txt` | systeminfo: hardware, firmware and hotfix summary |
| minimal | - | `system/env.txt` | environment variables that change GPU runtime behaviour |
| minimal | - | `system/id.txt` | invoking user, groups and privileges |
| minimal | - | `system/wmi-video.txt` | display adapters as the WMI video controller class |
| minimal | - | `system/wmi-display-drivers.txt` | installed display driver packages and their signatures |
| minimal | - | `devices/pnputil-devices.txt` | display devices, their problem status and driver candidates |
| default | - | `devices/pnputil-drivers.txt` | display drivers in the driver store |
| default | - | `devices/display-class-registry.txt` | display device class registry key |
| minimal | - | `kernel/graphicsdrivers-registry.txt` | graphics kernel settings (TDR, scheduler) |
| minimal | - | `kernel/system-events.txt` | display, power and hardware-error events from the System log |
| default | - | `kernel/application-events.txt` | application crash and error-reporting events |
| full | - | `kernel/` (`System.evtx`) | the System event log as a binary .evtx export |
| default | - | `kernel/setupapi.dev.log` | device and driver installation log |
| default | elevated | `dumps/listings.txt` | crash dump and GPU hang report files, listed but not copied |
| default | - | `packages/driverquery.csv` | all loaded drivers with versions and dates |
| full | - | `tools/dxdiag/` | DirectX diagnostic report |
| minimal | - | `xpu-smi/discovery.json` | xpu-smi device discovery |
| default | - | `xpu-smi/topology.txt` | xpu-smi topology matrix |
| default | - | `xpu-smi/<dev>/discovery.json` | xpu-smi discovery of one device |
| default | - | `xpu-smi/<dev>/stats.json` | xpu-smi statistics of one device |
| default | - | `xpu-smi/<dev>/config.txt` | xpu-smi configuration of one device |
| default | - | `xpu-smi/<dev>/ras-counters.csv` | xpu-smi RAS error counters of one device |
| default | - | `xpu-smi/<dev>/samples.csv` | xpu-smi metric samples, one second apart |

Notes on the Windows table:

- Event queries use the `--since` window (72 hours by default).
- `kernel/System.evtx` is an identifying binary source: it is collected only with `--full` and
  `--no-redact`.
- Output of `systeminfo`, `pnputil` and `wevtutil`, which print in the OEM code page when piped, is
  converted to UTF-8.
- The `health`, `raslog` and `crashlog` views, the coredumps, firmware crash logs and `drm-ras`
  counters exist on Linux only. GPUs are found with one PowerShell query of the PnP devices.

## Access required

An ordinary user, with no group membership and no `sudo`, still collects most of the bundle: the
operating system, kernel version and command line, the readable sysfs attributes of the GPU, the PCI
listings, the package list, the kernel log where the system allows it, and, where the user may open a
render node, the `xpu-smi` queries.

Every source is attempted. A source that is denied is not an error: the archive is still written,
the source is recorded in the manifest as `skipped` (or `truncated` when part of it was readable)
with the access it needs, and the report on stdout counts it under the access it needs. The `NEEDS` column
and the manifest `gate` entry use these five names:

| Gate | Needs (exact text) | Covers |
|---|---|---|
| `kernel_log` | root, CAP_SYSLOG, membership of the 'adm' or 'systemd-journal' group, or sysctl kernel.dmesg_restrict=0 | `kernel/kmsg.txt`, `kernel/kmsg-prev-boot.txt`, `system/syslog` |
| `device_access` | membership of the 'render' group, or root | the `xpu-smi` queries, `clinfo`, `vainfo` |
| `root` | root | debugfs, coredumps, firmware crash logs, `drm-ras` counters, owner-only sysfs attributes, most `xe` module parameters, the `drm.debug` mask, DMI serial numbers, `iclg` crash logs |
| `sys_admin` | root or CAP_SYS_ADMIN | PCI configuration space beyond the first 64 bytes: `lspci -vvv` link and AER detail, `lspci -xxxx` |
| `elevated` | an elevated (Administrator) prompt | Windows: `dumps/listings.txt` |

The report prints one line per missing access with the text above (`needs root: 4 not collected,
2 partial`) and ends with `Re-run with sudo for the full bundle.` (`Re-run from an elevated prompt for
the full bundle.` for `elevated`). Root also satisfies `kernel_log` and `device_access`; nothing more
is ever requested, so a first run as a normal user is safe.

When the process already has root or CAP_SYS_ADMIN and a source is still denied, the cause is outside
the tool (kernel lockdown, a container, SELinux or AppArmor). The report then prints `denied even
with root privileges (kernel lockdown, container or security policy): N not collected, M partial`
with no hint, and the manifest keeps each `gate` and `reason`.

## Privacy

Redaction is on by default. Before anything is written, every text source and every string value of
a JSON source has these replaced:

| Token | Replaces | Manifest rule |
|---|---|---|
| `<serial>`, `<uuid>` | serial numbers and UUIDs | `serials` |
| `<host>` | the names of this machine, short and fully qualified | `hostname` |
| `<user>` | the invoking and login user names, including home directory components | `users` |
| `<ipv4>`, `<ipv6>`, `<mac>` | IP and MAC addresses | `addresses` |

Collected by default: PCI addresses and device ids, driver, firmware and package versions, the
kernel and event logs, device attributes and the `xpu-smi` output, all redacted as above.

Never collected, with or without `--no-redact`:

- Windows crash dumps: they are listed, not copied.

Opt-in:

- `system/dmi-serials/` (Linux platform serial numbers): only with `--no-redact`, as root.
- `kernel/System.evtx` (the raw Windows System log): only with `--full` and `--no-redact`.
- `system/syslog` (the host system log, redacted like any text): only with `--full`.

`--no-redact` turns all replacement off; the manifest `redaction` array is then empty.

Collected as written; review before sharing:

- device coredumps (`dumps/<dev>/devcoredump-N.txt`): GPU engine and VM state, command stream
  snapshots, context images and the name and pid of the faulting process, as the driver wrote them
  (up to 32 MiB);
- any identifier a pattern misses, such as a host name inside a longer word. The manifest `identity`
  key is `partial` when the lookup of this machine's names timed out; a fully qualified name may
  then remain.

Matching rules:

- Host and user names match as whole words, case-insensitively, longest first, also after `/home/`,
  `/Users/`, `\Users\` and in `USER=`, `USERNAME=` and `LOGNAME=` values. They come from the kernel,
  the account files and `/etc/resolv.conf`; no DNS query is made. Percent-encoded separators (`%2F`)
  count as word boundaries.
- Common account names (`root`, `nobody`, `daemon`, `system`, `administrator`, `localhost`, ...) are
  never replaced, so `root=LABEL=...` and `Root Port` stay intact.
- Serials: values of `serial`, `serial number`, `serial_number`, `serialnumber` and `uuid` keys, and
  any 8-4-4-4-12 UUID.
- Addresses: MAC, IPv4 and IPv6. Loopback, `0.0.0.0`, PCI addresses, times and version numbers are
  left alone.
- JSON: values under keys ending in `serial`, `serialnumber` or `uuid`, or named `hostname` or
  `host_name`, become the token; other strings get text redaction; keys never change.

## Bundle layout

The archive has the same layout on Linux and Windows. `manifest.json` is the last entry. Entry names
are UTF-8 with `/` separators, never absolute, with no `.` or `..` segment. Each entry's modification
time is the time collection started. Entries are deflated when that is smaller (`compression` in
the manifest is `deflate` if any entry was, else `stored`); `unzip -t` accepts every archive.

```text
xe-bug-report-20261110T163000Z.zip
  manifest.json
  xpu-smi/   version.txt  discovery.json  topology.txt  raslog/
             <dev>/       discovery.json  stats.json  config.txt  health.json
                          ras-counters.csv  samples.csv  crashlog/
  system/    operating system, hardware and process environment
  kernel/    kernel log, driver modules and parameters, event logs
  devices/   <dev>/ sysfs attributes, debugfs, drm-ras counters (Linux);
             driver and device listings (Windows)
  pci/       lspci output per GPU and upstream bridge (Linux)
  dumps/     <dev>/ device coredumps and raw firmware crash logs (Linux);
             crash dump listings (Windows)
  packages/  installed GPU stack packages, or the driver list (Windows)
  tools/     clinfo, vainfo, dxdiag (--full only)
```

## Manifest

`manifest.json` (schema 1) lists every source, whether it was collected, and what explains the
bundle: which tool wrote it, on what, with which options.

Top-level keys:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `schema` | integer | always | The manifest format; currently `1`. |
| `tool` | object | always | `version` always; `describe`, `commit` and `built` (UTC build time) when the build recorded them; `path` of the running executable when the OS reports it (redacted). |
| `created` | string | always | UTC time collection started, ISO-8601 to the second. |
| `os` | string | when known | Operating system description, redacted. |
| `profile` | string | always | `minimal`, `default` or `full`. |
| `since_minutes` | integer | only with `--since` | The time window in minutes. |
| `devices` | array | when GPUs were selected | PCI addresses of the GPUs included. |
| `redaction` | array | always | The active rules: `serials`, `hostname`, `users`, `addresses`. Empty with `--no-redact`. |
| `compression` | string | always | `deflate` or `stored`. |
| `identity` | string | only when degraded | `partial`: see [Privacy](#privacy). |
| `xpu_smi` | object | when `xpu-smi` was found | `path` of the executable and `version`, the version line of `xpu-smi -v`. |
| `sources` | array | always | One entry per source, or per file of a source that produces several (the PMT crash logs, the coredumps), in collection order. |

Keys of each entry of `sources`:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `path` | string | always | The entry in the archive. A path ending in `/` is a directory source; `files` counts what it holds. |
| `status` | string | always | `collected`, `truncated`, `skipped`, `timed_out` or `failed`. |
| `via` | string | when a command or file produced it | The command line, file or interface the data came from (redacted). |
| `gate` | string | when a denial caused a skip or truncation | The access that was missing: `kernel_log`, `device_access`, `root`, `sys_admin` or `elevated`. |
| `reason` | string | when not `collected` | Why, in the tool's own words or the OS error text. Not redacted. |
| `exit` | integer | when a command exited non-zero | The exit code; a process killed by a signal is 128 plus the signal. |
| `bytes` | integer | when not zero | Bytes written to the archive, after the size cap and redaction. |
| `files` | integer | when not 1 | Files written by a directory source; `0` when none. |
| `denied` | integer | when not 0 | Files of a directory source that were denied. |
| `ms` | integer | always | Wall time of the whole source, in milliseconds. |

Status values:

- `collected`: the source was read completely and written to the archive.
- `truncated`: part of the source is in the archive. Either it reached its size cap, or part of a
  directory or command output was denied (`reason` says how many files, for example `4 of 156 files
  denied; needs root`, and `gate` the access that would give the rest), or only the end of a file
  was kept.
- `skipped`: nothing was written and `reason` says why: the access was denied (with `gate`), the
  file or tool is absent (`not present`, `<tool> not installed`, `xpu-smi not found`), the kernel or
  this `xpu-smi` does not support it, there was nothing to collect, redaction withheld it, an
  earlier read of the same group hung (below), or the deadline was reached (`collector deadline
  reached`).
- `timed_out`: the source did not finish within its time limit, or a file read did not return within
  5 seconds.
- `failed`: the source ran and produced no usable result: a non-zero exit with no output, an error
  other than a denial, or the archive could not take the file.

An excerpt of a manifest written by an ordinary user on a Linux workstation with one GPU
(`--minimal`; entries omitted). It is already redacted:

```json
{
  "schema": 1,
  "tool": {
    "version": "0.1.0",
    "describe": "4e9a9d4",
    "commit": "4e9a9d416d79",
    "built": "2026-11-10 16:29:32 UTC",
    "path": "/usr/local/bin/xe-bug-report"
  },
  "created": "2026-11-10T16:37:22Z",
  "os": "Ubuntu 24.04.3 LTS, Linux 7.2.0-generic x86_64",
  "profile": "minimal",
  "devices": ["0000:03:00.0"],
  "redaction": ["serials", "hostname", "users", "addresses"],
  "compression": "deflate",
  "xpu_smi": {
    "path": "/usr/bin/xpu-smi",
    "version": "Version: 2.0.1.20250225"
  },
  "sources": [
    {
      "path": "xpu-smi/version.txt",
      "status": "collected",
      "via": "xpu-smi -v",
      "bytes": 138,
      "ms": 329
    },
    {
      "path": "system/os-release",
      "status": "collected",
      "bytes": 400,
      "ms": 4
    },
    {
      "path": "system/dmi-serials/",
      "status": "skipped",
      "reason": "withheld because it cannot be redacted; use --no-redact",
      "ms": 0
    },
    {
      "path": "kernel/kmsg.txt",
      "status": "collected",
      "via": "journalctl -k -b 0 -n 200000 --no-pager -q -o short-monotonic",
      "bytes": 3430187,
      "ms": 4706
    },
    {
      "path": "devices/0000-03-00.0/sysfs/",
      "status": "truncated",
      "gate": "root",
      "reason": "4 of 156 files denied; needs root",
      "bytes": 1039,
      "files": 152,
      "denied": 4,
      "ms": 517
    },
    {
      "path": "devices/0000-03-00.0/ras-counters.json",
      "status": "skipped",
      "via": "drm-ras generic netlink",
      "reason": "kernel has no drm-ras interface",
      "ms": 3
    },
    {
      "path": "pci/0000-03-00.0/lspci-vvv-0000-03-00.0.txt",
      "status": "truncated",
      "via": "lspci -vvv -nn -s 0000:03:00.0",
      "gate": "sys_admin",
      "reason": "needs root or CAP_SYS_ADMIN",
      "bytes": 715,
      "ms": 55
    },
    {
      "path": "xpu-smi/discovery.json",
      "status": "collected",
      "via": "xpu-smi discovery -j",
      "bytes": 407,
      "ms": 502
    }
  ]
}
```

Triage tips. Start with the manifest, not the files:

```sh
unzip -p bundle.zip manifest.json | jq -r '.sources[] | select(.status != "collected") | [.status, .gate // "-", .path, .reason // ""] | @tsv'
```

`system/id.txt` shows which user, groups and capabilities the collection ran with, so a pile of
`skipped` `root` rows from an unprivileged run is expected, not a finding. `exit`, `via` and
`reason` of a `failed` source tell what the child printed or why it could not start.

## Hang safety and signals

A GPU problem often comes with a hung driver, and a hung read must not hang the collection.

- Every file read runs on a helper thread with a limit (5 seconds). Every child process has a time
  limit of its own (10 seconds by default; longer for the slow sources) and is killed with its whole
  process group (Linux) or job object (Windows) at the limit.
- Sources are grouped: the sources of one GPU form a group, all the others (host files, host
  tools) form another. When one read in a group does not return in time, the helper is abandoned,
  that source is recorded as `timed_out`, and the remaining sources of the group are skipped with
  `an earlier read in this group did not return within 5 s` instead of hanging too. Sources of
  other groups are collected normally.
- `--timeout` bounds the whole run (default 600 seconds, `0` disables it). When it is reached, the
  remaining sources are recorded as `skipped` ("collector deadline reached") and the archive is still
  finished and written.
- If the main thread is stuck somewhere no limit covers, a backstop thread ends the process with
  exit code 124 sixty seconds after the deadline, after removing `<output>.partial`.
- A child process in uninterruptible kernel sleep cannot be killed. After a backstop exit, children
  are not tracked: on Linux a child may keep running; on Windows children are in a kill-on-close
  job that normally ends with the process, but one that escaped the job (it was started in the
  instant between spawn and assignment) may outlive the exit.
- There is no signal handler. SIGTERM, SIGINT or SIGHUP end the process at once and leave
  `<output>.partial` (and a command output directory in the temporary directory) behind. An
  incomplete archive is never renamed into place: delete the `.partial` file and run again.
- The report goes to stdout. `--json` replaces it with the JSON result and prints nothing else;
  stderr carries only errors, warnings and, with `--verbose`, progress.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `needs ...` lines, or `denied even with root privileges`, in the report | Missing access: see [Access required](#access-required). The bundle is usable as it is; the manifest says what is missing. |
| every `xpu-smi/*` source `skipped`, `xpu-smi not found` | `xpu-smi` is not on PATH or beside `xe-bug-report`. Install it, or pass `--xpu-smi <path>`. The rest of the bundle is unaffected. |
| a source is `timed_out`, later ones `an earlier read in this group did not return` | The device or its sysfs/debugfs hung. That is itself the finding; check `kernel/kmsg.txt` for resets and timeouts. |
| `<path> already exists` (exit 1) | The tool never overwrites. Choose another `--output` or remove the file. |
| `No Intel GPU with PCI address ... was found` (exit 1) | Check the address with `lspci -nn` and write it as `dddd:bb:dd.f`; or drop `--device`. |
| `the collection did not finish in time` (exit 124) | The backstop fired. Re-run with `--minimal`, a larger `--timeout`, or `--timeout 0`. |
| a `<output>.partial` file is left | The run was killed by a signal. Delete it and run again. |
| `--since` finds nothing | `no kernel messages in the last <window>` is a result, not an error: the kernel logged nothing in that window. |
| `identity: partial` in the manifest | The name lookup timed out; a fully qualified host name may remain in the text. Review before sharing. |
| `xe-bug-report: warn: --xpu-smi <path>: not an existing file` | The `--xpu-smi` path does not exist; the `xpu-smi` sources are skipped. |

To check an archive: `unzip -t bundle.zip`. To see what a run would collect before running it:
`xe-bug-report --list --full`.

## Development

Build, test, commit and release rules: [CONTRIBUTING.md](CONTRIBUTING.md). License: MIT
(`LICENSE`).
