//! DACL edits on the writable roots. Every edit first looks for an equivalent
//! ACE so repeated launches leave the ACLs unchanged. Masks follow codex
//! `windows-sandbox-rs/src/acl.rs`.

use std::ffi::c_void;
use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};

use super::{check, wide};

/// No WRITE_DAC (the child cannot rewrite ACLs) and no FILE_DELETE_CHILD (it
/// would override the deny ACEs on protected children); DELETE rides on each child.
const WRITE_ALLOW: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
const WRITE_DENY: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | FILE_DELETE_CHILD;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const CONTAINER_AND_OBJECT_INHERIT: u32 = 3;

struct LocalAlloc(*mut c_void);

impl Drop for LocalAlloc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the security APIs, freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// Whether `dacl` has an ACE of `ace_type` for `sid` with exactly `mask` and `inherit` flags.
///
/// # Safety
/// `dacl` is null or a valid ACL; `sid` is a valid SID.
unsafe fn has_ace(
    dacl: *const ACL,
    sid: *mut c_void,
    ace_type: u8,
    mask: u32,
    inherit: u32,
) -> bool {
    if dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return false;
    }
    (0..info.AceCount).any(|i| {
        let mut p: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut p) } == 0 {
            return false;
        }
        let header = unsafe { &*(p as *const ACE_HEADER) };
        // the INHERITED bit (0x10) only says where the ACE came from
        if header.AceType != ace_type || u32::from(header.AceFlags & 0x0f) != inherit {
            return false;
        }
        // allowed and denied ACEs share one layout: header, mask, SID
        let ace = p as *const ACCESS_ALLOWED_ACE;
        unsafe {
            (*ace).Mask == mask && EqualSid((&raw const (*ace).SidStart) as *mut c_void, sid) != 0
        }
    })
}

fn ensure_ace(
    path: &Path,
    sid: *mut c_void,
    deny: bool,
    mask: u32,
    inherit: u32,
) -> io::Result<bool> {
    let path = wide(path.as_os_str());
    let (ace_type, mode) = if deny {
        (ACCESS_DENIED_ACE_TYPE, DENY_ACCESS)
    } else {
        (ACCESS_ALLOWED_ACE_TYPE, GRANT_ACCESS)
    };
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: *mut c_void = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated, `sid` is valid, out pointers are valid and
    // the allocations are released by the guards.
    unsafe {
        check(GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        ))?;
        let _sd = LocalAlloc(sd);
        if has_ace(dacl, sid, ace_type, mask, inherit) {
            return Ok(false);
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: mode,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
            },
        };
        let mut new: *mut ACL = std::ptr::null_mut();
        check(SetEntriesInAclW(1, &entry, dacl, &mut new))?;
        let _new = LocalAlloc(new.cast());
        check(SetNamedSecurityInfoW(
            path.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new,
            std::ptr::null(),
        ))?;
    }
    Ok(true)
}

/// Let `sid` read, write and delete under `root` (inherited by everything below).
pub fn grant_write(root: &Path, sid: *mut c_void) -> io::Result<bool> {
    ensure_ace(root, sid, false, WRITE_ALLOW, CONTAINER_AND_OBJECT_INHERIT)
}

/// Deny `sid` writes to `path`; a directory's deny is inherited by its children.
pub fn deny_write(path: &Path, sid: *mut c_void) -> io::Result<bool> {
    let inherit = if path.is_dir() {
        CONTAINER_AND_OBJECT_INHERIT
    } else {
        0
    };
    ensure_ace(path, sid, true, WRITE_DENY, inherit)
}
