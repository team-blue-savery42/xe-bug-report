// SPDX-License-Identifier: MIT
//! Safe wrappers over the few `windows-sys` calls xe-bug-report needs: job objects, token
//! elevation and the OEM code page. Every `unsafe` block carries a `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::Child;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `CREATE_NO_WINDOW` for `CommandExt::creation_flags`.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A job object created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; closing it kills its processes.
#[derive(Debug)]
pub struct Job {
    handle: isize,
}

impl Job {
    /// Creates the job.
    pub fn create() -> io::Result<Self> {
        // SAFETY: both arguments may be null (default security, unnamed job); the call returns a
        // new handle or null.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // Owned from here on: dropped (and closed) on every early return below.
        let job = Self { handle: handle as isize };

        // SAFETY: the struct is plain data for which all-zero bytes is a valid value.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `handle` is a live job handle; `limits` is a valid structure of the class named,
        // and the size passed is its size.
        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Assigns `child` to the job.
    pub fn assign(&self, child: &Child) -> io::Result<()> {
        // SAFETY: the job handle is live while `self` exists, and the process handle is live while
        // `child` is borrowed.
        let ok = unsafe { AssignProcessToJobObject(self.handle as HANDLE, child.as_raw_handle() as HANDLE) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Terminates every process in the job.
    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: the job handle is live while `self` exists.
        let ok = unsafe { TerminateJobObject(self.handle as HANDLE, 1) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: `handle` is owned by this value and closed exactly once; with
        // KILL_ON_JOB_CLOSE this also kills whatever is still in the job.
        unsafe {
            CloseHandle(self.handle as HANDLE);
        }
    }
}

/// Whether the process token is elevated (`TokenElevation`).
pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; `token` is a valid
    // out pointer.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY access; `elevation` is a valid
    // buffer of the size passed; `returned` is a valid out pointer.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was opened above and is closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Decodes `bytes` from the OEM code page (`GetOEMCP` + `MultiByteToWideChar`) into UTF-8;
/// lossy when that fails.
pub fn oem_to_utf8(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let Ok(len) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    // SAFETY: GetOEMCP takes no arguments and touches no memory.
    let code_page = unsafe { GetOEMCP() };
    // SAFETY: `bytes` is valid for `len` bytes; a null output buffer with size 0 asks for the
    // required length.
    let needed = unsafe { MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0u16; needed as usize];
    // SAFETY: `bytes` is valid for `len` bytes and `wide` for `needed` UTF-16 units, the size
    // passed.
    let written =
        unsafe { MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), needed) };
    if written <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    wide.truncate(written as usize);
    String::from_utf16_lossy(&wide)
}

/// Protected DACL: owner, Administrators and SYSTEM get full control, inherited by children;
/// nothing is inherited from the parent directory.
const PRIVATE_DIR_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

/// Creates the directory `path` (its parent must exist) with a protected DACL that grants access
/// to the owner, Administrators and SYSTEM only, whatever the parent's ACL allows. Fails closed: if
/// the descriptor cannot be built the directory is not created. An existing `path` is an
/// `AlreadyExists` error.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    wide_path.push(0);
    let sddl: Vec<u16> = PRIVATE_DIR_SDDL.encode_utf16().chain(std::iter::once(0)).collect();

    let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `sddl` is a NUL-terminated UTF-16 string; `descriptor` is a valid out pointer and the
    // size out parameter may be null.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide_path` is NUL-terminated; `attributes` and the descriptor it points to are valid
    // for the duration of the call.
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    let result = if created == 0 { Err(io::Error::last_os_error()) } else { Ok(()) };
    // SAFETY: `descriptor` was allocated by the conversion above with LocalAlloc and is freed
    // exactly once, on success and failure alike.
    unsafe {
        LocalFree(descriptor);
    }
    result
}
