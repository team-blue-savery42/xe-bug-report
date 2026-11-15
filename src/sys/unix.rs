// SPDX-License-Identifier: MIT
//! Safe wrappers over the few `libc` calls xe-bug-report needs. Every `unsafe` block carries a
//! `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

/// `O_NOCTTY`: opening a terminal device must not make it the controlling terminal.
pub const O_NOCTTY: i32 = libc::O_NOCTTY;

/// `O_NONBLOCK`: reads of pipes, FIFOs and record devices such as `/dev/kmsg` fail with
/// `WouldBlock` instead of waiting for more data.
pub const O_NONBLOCK: i32 = libc::O_NONBLOCK;

/// `EPERM` (1): operation not permitted.
pub const EPERM: i32 = libc::EPERM;
/// `EACCES` (13): permission denied.
pub const EACCES: i32 = libc::EACCES;
/// `ENOENT` (2): no such file, or no such generic netlink family.
pub const ENOENT: i32 = libc::ENOENT;
/// `EIO` (5): input/output error.
pub const EIO: i32 = libc::EIO;
/// `EPROTONOSUPPORT`: the kernel has no netlink protocol.
pub const EPROTONOSUPPORT: i32 = libc::EPROTONOSUPPORT;
/// `EAFNOSUPPORT`: the kernel has no netlink address family.
pub const EAFNOSUPPORT: i32 = libc::EAFNOSUPPORT;

/// The effective user id.
pub fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Whether the effective user may read and write `path`, by the kernel's own permission check
/// (`faccessat(AT_FDCWD, path, R_OK | W_OK, AT_EACCESS)`: mode bits, ACLs and capabilities, without
/// opening the node, so a device driver is never entered). False for a path with a NUL byte.
pub fn can_read_write(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call; faccessat reads it
    // and touches no other memory.
    let rc = unsafe {
        libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), libc::R_OK | libc::W_OK, libc::AT_EACCESS)
    };
    rc == 0
}

/// Sends SIGKILL to the process group `pgid` (`kill(-pgid, SIGKILL)`); errors are ignored.
///
/// A `pgid` of 0 or one that does not fit a positive `pid_t` is refused: `kill(-0, ..)` would
/// signal the caller's own group.
pub fn kill_process_group(pgid: u32) {
    let Ok(pgid) = libc::pid_t::try_from(pgid) else {
        return;
    };
    if pgid <= 0 {
        return;
    }
    // SAFETY: kill takes two integers and touches no memory; `-pgid` is negative and non-zero, so it
    // names exactly one process group and never the caller's own group or "all processes".
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Prepares the child of `cmd` before exec: SIGCHLD back to its default disposition, so a parent
/// that ignores it does not leak that into tools that wait for their own children, and core dumps
/// off (`RLIMIT_CORE` 0), so a crashing tool does not leave a `core` file in the user's directory.
pub fn prepare_child(cmd: &mut Command) {
    set_sigchld_in_child(cmd, libc::SIG_DFL);
    disable_core_dumps_in_child(cmd);
}

fn disable_core_dumps_in_child(cmd: &mut Command) {
    // SAFETY: the closure runs between fork and exec, so it may only call async-signal-safe
    // functions; `setrlimit` is one (a single system call), it takes a pointer to a stack-local
    // struct, allocates nothing and takes no locks. A failure is ignored: the limit is a courtesy.
    unsafe {
        cmd.pre_exec(|| {
            let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            Ok(())
        });
    }
}

/// Makes `cmd` ignore SIGCHLD in the child (the disposition survives exec). Test support: it lets a
/// test run a copy of the test binary as a process whose SIGCHLD is ignored, without changing the
/// disposition of the multi-threaded test process itself.
#[cfg(test)]
pub(crate) fn ignore_sigchld_in_child(cmd: &mut Command) {
    set_sigchld_in_child(cmd, libc::SIG_IGN);
}

fn set_sigchld_in_child(cmd: &mut Command, handler: libc::sighandler_t) {
    // SAFETY: the closure runs between fork and exec, so it may only call async-signal-safe
    // functions; it calls `libc::signal`, which is one, allocates nothing and takes no locks.
    unsafe {
        cmd.pre_exec(move || {
            libc::signal(libc::SIGCHLD, handler);
            Ok(())
        });
    }
}

/// `CLOCK_MONOTONIC` now, the clock `/dev/kmsg` timestamps use.
pub fn monotonic_now() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return Duration::ZERO;
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u32::try_from(ts.tv_nsec).unwrap_or(0);
    Duration::new(secs, nanos)
}

/// A generic netlink socket (`AF_NETLINK`, `SOCK_RAW | SOCK_CLOEXEC`, `NETLINK_GENERIC`), closed on drop.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl NetlinkSocket {
    /// Opens the socket with `SO_RCVTIMEO` = `recv_timeout` (at least one millisecond: a zero
    /// timeout would mean "block forever").
    pub fn open_generic(recv_timeout: Duration) -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        // SAFETY: socket takes three integers and returns a new descriptor or -1.
        let raw = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_GENERIC)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: sockaddr_nl is plain data for which all-zero bytes is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0; // let the kernel choose the port id
        addr.nl_groups = 0;
        // SAFETY: `addr` is a valid sockaddr_nl and the length passed is its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let timeout = recv_timeout.max(Duration::from_millis(1));
        let tv = libc::timeval {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_usec: timeout.subsec_micros() as libc::suseconds_t, // below 1_000_000: fits
        };
        // SAFETY: `tv` is a valid timeval and the length passed is its size.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Sends one message to the kernel (port 0).
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        // SAFETY: sockaddr_nl is plain data for which all-zero bytes is a valid value.
        let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        dest.nl_pid = 0; // the kernel
        dest.nl_groups = 0;
        loop {
            // SAFETY: `msg` is valid for `msg.len()` bytes, `dest` is a valid sockaddr_nl and the
            // length passed is its size; the descriptor is owned by `self` and open.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                    0,
                    (&raw const dest).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if sent as usize != msg.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short netlink send"));
            }
            return Ok(());
        }
    }

    /// Receives one datagram into `buf`; `WouldBlock`/`TimedOut` when `SO_RCVTIMEO` expires.
    ///
    /// A datagram longer than `buf` is an `InvalidData` error instead of a silently cut message
    /// (`MSG_TRUNC`). Netlink dumps can fill 16 KiB or more per datagram: pass a buffer of at
    /// least 32 KiB.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        loop {
            // SAFETY: `buf` is valid for writes of `buf.len()` bytes; the descriptor is owned by
            // `self` and open. With MSG_TRUNC the kernel copies at most `buf.len()` bytes but
            // returns the real datagram length.
            let got = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let got = got as usize;
            if got > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink datagram larger than the receive buffer",
                ));
            }
            return Ok(got);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl NetlinkSocket {
    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn open_generic(recv_timeout: Duration) -> io::Result<Self> {
        let _ = recv_timeout;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let _ = (&self.fd, msg);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Netlink exists on Linux only; always `Unsupported` here.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (&self.fd, buf);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Flushes nothing and runs no exit handlers: `_exit(code)`. For the Level Zero probe child, whose
/// loaded driver may hang in its own exit handlers on a wedged GPU after the result is written.
pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: `_exit` takes an integer, never returns and touches no memory of this process.
    unsafe { libc::_exit(code) }
}

/// A minimal, safe binding of the Level Zero loader (`libze_loader.so.1`), loaded at run time with
/// `dlopen`, for the liveness probe. Struct layouts, `stype` values and signatures follow
/// `level_zero/ze_api.h` (Level Zero 1.x); every descriptor is passed with `pNext = NULL`.
///
/// Handles are created only by this module, from successful calls. The context, the device memory
/// and the command list free themselves on drop, in the order their borrows force (memory and list
/// before their context). A caller that must not wait for a stuck GPU can `std::mem::forget`
/// them instead; the process then exits without freeing them.
#[cfg(target_os = "linux")]
pub mod level_zero {
    use std::ffi::{CStr, c_char, c_void};

    /// `ze_result_t`.
    pub type ZeResult = u32;
    /// `ZE_RESULT_SUCCESS`.
    pub const ZE_RESULT_SUCCESS: ZeResult = 0;
    /// `ZE_RESULT_NOT_READY`: the wait timed out.
    pub const ZE_RESULT_NOT_READY: ZeResult = 1;
    /// `ZE_INIT_FLAG_GPU_ONLY`.
    pub const ZE_INIT_FLAG_GPU_ONLY: u32 = 1;

    /// The loader's file name.
    pub const LOADER: &str = "libze_loader.so.1";
    /// The byte the probe fills device memory with.
    pub static FILL_PATTERN: u8 = 0xa5;

    const ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES: u32 = 0x3;
    const ZE_STRUCTURE_TYPE_CONTEXT_DESC: u32 = 0xd;
    const ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC: u32 = 0xe;
    const ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC: u32 = 0x15;
    /// `ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS`: appends return at once and the host waits explicitly,
    /// so a fill that never completes cannot block the append itself.
    const ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS: u32 = 2;
    const ZE_COMMAND_QUEUE_PRIORITY_NORMAL: u32 = 0;
    const ZE_MAX_DEVICE_NAME: usize = 256;
    const ZE_MAX_DEVICE_UUID_SIZE: usize = 16;

    type Handle = *mut c_void;

    /// `ze_device_properties_t`.
    #[repr(C)]
    struct ZeDeviceProperties {
        stype: u32,
        p_next: *mut c_void,
        device_type: u32,
        vendor_id: u32,
        device_id: u32,
        flags: u32,
        subdevice_id: u32,
        core_clock_rate: u32,
        max_mem_alloc_size: u64,
        max_hardware_contexts: u32,
        max_command_queue_priority: u32,
        num_threads_per_eu: u32,
        physical_eu_simd_width: u32,
        num_eus_per_subslice: u32,
        num_subslices_per_slice: u32,
        num_slices: u32,
        timer_resolution: u64,
        timestamp_valid_bits: u32,
        kernel_timestamp_valid_bits: u32,
        uuid: [u8; ZE_MAX_DEVICE_UUID_SIZE],
        name: [c_char; ZE_MAX_DEVICE_NAME],
    }

    /// `ze_context_desc_t`.
    #[repr(C)]
    struct ZeContextDesc {
        stype: u32,
        p_next: *const c_void,
        flags: u32,
    }

    /// `ze_device_mem_alloc_desc_t`.
    #[repr(C)]
    struct ZeDeviceMemAllocDesc {
        stype: u32,
        p_next: *const c_void,
        flags: u32,
        ordinal: u32,
    }

    /// `ze_command_queue_desc_t`.
    #[repr(C)]
    struct ZeCommandQueueDesc {
        stype: u32,
        p_next: *const c_void,
        ordinal: u32,
        index: u32,
        flags: u32,
        mode: u32,
        priority: u32,
    }

    // The x86-64 and AArch64 layouts of the header, checked at compile time.
    const _: () = assert!(std::mem::size_of::<ZeDeviceProperties>() == 368);
    const _: () = assert!(std::mem::offset_of!(ZeDeviceProperties, max_mem_alloc_size) == 40);
    const _: () = assert!(std::mem::offset_of!(ZeDeviceProperties, name) == 112);
    const _: () = assert!(std::mem::size_of::<ZeContextDesc>() == 24);
    const _: () = assert!(std::mem::size_of::<ZeDeviceMemAllocDesc>() == 24);
    const _: () = assert!(std::mem::size_of::<ZeCommandQueueDesc>() == 40);

    type ZeInit = unsafe extern "C" fn(u32) -> ZeResult;
    type ZeDriverGet = unsafe extern "C" fn(*mut u32, *mut Handle) -> ZeResult;
    type ZeDeviceGet = unsafe extern "C" fn(Handle, *mut u32, *mut Handle) -> ZeResult;
    type ZeDeviceGetProperties = unsafe extern "C" fn(Handle, *mut ZeDeviceProperties) -> ZeResult;
    type ZeContextCreate = unsafe extern "C" fn(Handle, *const ZeContextDesc, *mut Handle) -> ZeResult;
    type ZeOneHandle = unsafe extern "C" fn(Handle) -> ZeResult;
    type ZeMemAllocDevice = unsafe extern "C" fn(
        Handle,
        *const ZeDeviceMemAllocDesc,
        usize,
        usize,
        Handle,
        *mut *mut c_void,
    ) -> ZeResult;
    type ZeMemFree = unsafe extern "C" fn(Handle, *mut c_void) -> ZeResult;
    type ZeCommandListCreateImmediate =
        unsafe extern "C" fn(Handle, Handle, *const ZeCommandQueueDesc, *mut Handle) -> ZeResult;
    type ZeCommandListAppendMemoryFill = unsafe extern "C" fn(
        Handle,
        *mut c_void,
        *const c_void,
        usize,
        usize,
        Handle,
        u32,
        *mut Handle,
    ) -> ZeResult;
    type ZeCommandListHostSynchronize = unsafe extern "C" fn(Handle, u64) -> ZeResult;

    /// The entry points the probe calls.
    struct Functions {
        init: ZeInit,
        driver_get: ZeDriverGet,
        device_get: ZeDeviceGet,
        device_get_properties: ZeDeviceGetProperties,
        device_get_status: ZeOneHandle,
        context_create: ZeContextCreate,
        context_destroy: ZeOneHandle,
        mem_alloc_device: ZeMemAllocDevice,
        mem_free: ZeMemFree,
        command_list_create_immediate: ZeCommandListCreateImmediate,
        command_list_destroy: ZeOneHandle,
        command_list_append_memory_fill: ZeCommandListAppendMemoryFill,
        command_list_host_synchronize: ZeCommandListHostSynchronize,
    }

    /// The loaded Level Zero loader. The library is never closed: drivers start threads that may
    /// outlive any point at which closing it would be safe.
    pub struct LevelZero {
        functions: Functions,
    }

    /// The text of the last `dlopen`/`dlsym` error.
    fn last_dl_error() -> String {
        // SAFETY: dlerror returns NULL or a pointer to a NUL-terminated string that stays valid
        // until the next dl* call on this thread; it is copied before any such call.
        let text = unsafe { libc::dlerror() };
        if text.is_null() {
            return "unknown error".to_owned();
        }
        // SAFETY: `text` is non-null and NUL-terminated (see above).
        unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
    }

    /// Resolves `name` in `library` as a function of type `F`.
    ///
    /// # Safety
    /// `F` must be the `unsafe extern "C" fn` type of the symbol's real signature.
    unsafe fn symbol<F: Copy>(library: *mut c_void, name: &CStr) -> Result<F, String> {
        // SAFETY: `library` is a live handle from dlopen and `name` is NUL-terminated.
        let address = unsafe { libc::dlsym(library, name.as_ptr()) };
        if address.is_null() {
            return Err(format!("{}: {}", name.to_string_lossy(), last_dl_error()));
        }
        // SAFETY: a function pointer has the size of a data pointer on the platforms dlsym
        // serves, and the caller guarantees `F` is the symbol's signature.
        Ok(unsafe { std::mem::transmute_copy::<*mut c_void, F>(&address) })
    }

    /// A driver handle.
    #[derive(Debug, Clone, Copy)]
    pub struct Driver(Handle);
    /// A device handle.
    #[derive(Debug, Clone, Copy)]
    pub struct Device(Handle);

    /// What the probe records of a device.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceProperties {
        /// `ze_device_type_t` (1 = GPU).
        pub device_type: u32,
        pub vendor_id: u32,
        pub device_id: u32,
        pub max_mem_alloc_size: u64,
        pub name: String,
    }

    /// Calls `f(count, NULL)` then `f(count, buffer)`, the Level Zero enumeration pattern.
    fn enumerate(f: impl Fn(*mut u32, *mut Handle) -> ZeResult) -> Result<Vec<Handle>, ZeResult> {
        let mut count = 0u32;
        let result = f(&mut count, std::ptr::null_mut());
        if result != ZE_RESULT_SUCCESS {
            return Err(result);
        }
        let mut handles = vec![std::ptr::null_mut(); count as usize];
        let result = f(&mut count, handles.as_mut_ptr());
        if result != ZE_RESULT_SUCCESS {
            return Err(result);
        }
        handles.truncate(count as usize);
        Ok(handles)
    }

    impl LevelZero {
        /// Loads the loader and resolves every entry point; the error is the `dlopen` or `dlsym`
        /// text.
        pub fn load() -> Result<Self, String> {
            let name = c"libze_loader.so.1";
            debug_assert_eq!(name.to_bytes(), LOADER.as_bytes());
            // SAFETY: `name` is NUL-terminated; dlopen runs the library's initialisers, which is
            // what loading the Level Zero loader means.
            let library = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if library.is_null() {
                return Err(last_dl_error());
            }
            // SAFETY: `library` is the live handle from dlopen above, and each function type is the
            // signature `ze_api.h` declares for that symbol.
            let functions = unsafe {
                Functions {
                    init: symbol(library, c"zeInit")?,
                    driver_get: symbol(library, c"zeDriverGet")?,
                    device_get: symbol(library, c"zeDeviceGet")?,
                    device_get_properties: symbol(library, c"zeDeviceGetProperties")?,
                    device_get_status: symbol(library, c"zeDeviceGetStatus")?,
                    context_create: symbol(library, c"zeContextCreate")?,
                    context_destroy: symbol(library, c"zeContextDestroy")?,
                    mem_alloc_device: symbol(library, c"zeMemAllocDevice")?,
                    mem_free: symbol(library, c"zeMemFree")?,
                    command_list_create_immediate: symbol(library, c"zeCommandListCreateImmediate")?,
                    command_list_destroy: symbol(library, c"zeCommandListDestroy")?,
                    command_list_append_memory_fill: symbol(library, c"zeCommandListAppendMemoryFill")?,
                    command_list_host_synchronize: symbol(library, c"zeCommandListHostSynchronize")?,
                }
            };
            Ok(Self { functions })
        }

        /// `zeInit(flags)`.
        pub fn init(&self, flags: u32) -> ZeResult {
            // SAFETY: zeInit takes a flag word and may be called more than once.
            unsafe { (self.functions.init)(flags) }
        }

        /// `zeDriverGet`.
        pub fn drivers(&self) -> Result<Vec<Driver>, ZeResult> {
            // SAFETY: `count` points to a live u32 and `handles` is NULL or holds `*count` slots.
            let handles = enumerate(|count, handles| unsafe { (self.functions.driver_get)(count, handles) })?;
            Ok(handles.into_iter().map(Driver).collect())
        }

        /// `zeDeviceGet`.
        pub fn devices(&self, driver: Driver) -> Result<Vec<Device>, ZeResult> {
            // SAFETY: `driver` came from zeDriverGet; the pointers are as for `drivers`.
            let handles =
                enumerate(|count, handles| unsafe { (self.functions.device_get)(driver.0, count, handles) })?;
            Ok(handles.into_iter().map(Device).collect())
        }

        /// `zeDeviceGetProperties`.
        pub fn device_properties(&self, device: Device) -> Result<DeviceProperties, ZeResult> {
            // SAFETY: the struct is plain data for which all-zero bytes is a valid value.
            let mut properties: ZeDeviceProperties = unsafe { std::mem::zeroed() };
            properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
            properties.p_next = std::ptr::null_mut();
            // SAFETY: `device` came from zeDeviceGet and `properties` is a writable struct of the
            // header's layout.
            let result = unsafe { (self.functions.device_get_properties)(device.0, &mut properties) };
            if result != ZE_RESULT_SUCCESS {
                return Err(result);
            }
            // The last byte is forced to NUL so a driver that fills the whole array cannot make
            // the read run past it.
            properties.name[ZE_MAX_DEVICE_NAME - 1] = 0;
            // SAFETY: `name` is NUL-terminated within its array (see above).
            let name = unsafe { CStr::from_ptr(properties.name.as_ptr()) }.to_string_lossy().into_owned();
            Ok(DeviceProperties {
                device_type: properties.device_type,
                vendor_id: properties.vendor_id,
                device_id: properties.device_id,
                max_mem_alloc_size: properties.max_mem_alloc_size,
                name,
            })
        }

        /// `zeDeviceGetStatus`.
        pub fn device_status(&self, device: Device) -> ZeResult {
            // SAFETY: `device` came from zeDeviceGet.
            unsafe { (self.functions.device_get_status)(device.0) }
        }

        /// `zeContextCreate` with default flags.
        pub fn create_context(&self, driver: Driver) -> Result<Context<'_>, ZeResult> {
            let desc =
                ZeContextDesc { stype: ZE_STRUCTURE_TYPE_CONTEXT_DESC, p_next: std::ptr::null(), flags: 0 };
            let mut handle: Handle = std::ptr::null_mut();
            // SAFETY: `driver` came from zeDriverGet, `desc` and `handle` are live for the call.
            let result = unsafe { (self.functions.context_create)(driver.0, &desc, &mut handle) };
            if result != ZE_RESULT_SUCCESS {
                return Err(result);
            }
            Ok(Context { ze: self, handle })
        }
    }

    /// A context; destroyed on drop.
    pub struct Context<'a> {
        ze: &'a LevelZero,
        handle: Handle,
    }

    impl Context<'_> {
        /// `zeMemAllocDevice` of `size` bytes from the device's memory ordinal 0.
        pub fn alloc_device(
            &self,
            device: Device,
            size: usize,
            alignment: usize,
        ) -> Result<DeviceMemory<'_>, ZeResult> {
            let desc = ZeDeviceMemAllocDesc {
                stype: ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC,
                p_next: std::ptr::null(),
                flags: 0,
                ordinal: 0,
            };
            let mut pointer: *mut c_void = std::ptr::null_mut();
            // SAFETY: the context and device handles are live, `desc` and `pointer` are live for
            // the call.
            let result = unsafe {
                (self.ze.functions.mem_alloc_device)(
                    self.handle,
                    &desc,
                    size,
                    alignment,
                    device.0,
                    &mut pointer,
                )
            };
            if result != ZE_RESULT_SUCCESS {
                return Err(result);
            }
            Ok(DeviceMemory { context: self, pointer, size })
        }

        /// `zeCommandListCreateImmediate` on queue group `ordinal`, index 0, asynchronous.
        pub fn create_immediate_list(
            &self,
            device: Device,
            ordinal: u32,
        ) -> Result<ImmediateList<'_>, ZeResult> {
            let desc = ZeCommandQueueDesc {
                stype: ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC,
                p_next: std::ptr::null(),
                ordinal,
                index: 0,
                flags: 0,
                mode: ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS,
                priority: ZE_COMMAND_QUEUE_PRIORITY_NORMAL,
            };
            let mut handle: Handle = std::ptr::null_mut();
            // SAFETY: the context and device handles are live, `desc` and `handle` are live for
            // the call.
            let result = unsafe {
                (self.ze.functions.command_list_create_immediate)(self.handle, device.0, &desc, &mut handle)
            };
            if result != ZE_RESULT_SUCCESS {
                return Err(result);
            }
            Ok(ImmediateList { context: self, handle })
        }
    }

    impl Drop for Context<'_> {
        fn drop(&mut self) {
            // SAFETY: the handle came from zeContextCreate; every object made from it borrows it,
            // so they are gone (or forgotten) by now.
            unsafe { (self.ze.functions.context_destroy)(self.handle) };
        }
    }

    /// A device allocation; freed on drop.
    pub struct DeviceMemory<'c> {
        context: &'c Context<'c>,
        pointer: *mut c_void,
        size: usize,
    }

    impl Drop for DeviceMemory<'_> {
        fn drop(&mut self) {
            // SAFETY: the pointer came from zeMemAllocDevice on this context.
            unsafe { (self.context.ze.functions.mem_free)(self.context.handle, self.pointer) };
        }
    }

    /// An immediate command list; destroyed on drop.
    pub struct ImmediateList<'c> {
        context: &'c Context<'c>,
        handle: Handle,
    }

    impl ImmediateList<'_> {
        /// `zeCommandListAppendMemoryFill` of all of `memory` with the byte [`FILL_PATTERN`], no
        /// events.
        pub fn fill(&self, memory: &DeviceMemory<'_>) -> ZeResult {
            // SAFETY: the list and the allocation are live and belong to the same context; the
            // pattern is a static, so it outlives the fill however late the device executes it.
            unsafe {
                (self.context.ze.functions.command_list_append_memory_fill)(
                    self.handle,
                    memory.pointer,
                    (&raw const FILL_PATTERN).cast::<c_void>(),
                    1,
                    memory.size,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                )
            }
        }

        /// `zeCommandListHostSynchronize` with a timeout in nanoseconds.
        pub fn host_synchronize(&self, timeout_ns: u64) -> ZeResult {
            // SAFETY: the list handle is live.
            unsafe { (self.context.ze.functions.command_list_host_synchronize)(self.handle, timeout_ns) }
        }
    }

    impl Drop for ImmediateList<'_> {
        fn drop(&mut self) {
            // SAFETY: the handle came from zeCommandListCreateImmediate on this context.
            unsafe { (self.context.ze.functions.command_list_destroy)(self.handle) };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "unix_tests.rs"]
mod tests;
