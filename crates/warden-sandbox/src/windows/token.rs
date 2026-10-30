//! Restricted primary token: write access needs a grant to one of the
//! restricting SIDs (the capability SIDs, the logon SID, Everyone); reads are
//! unaffected. Derived from codex `windows-sandbox-rs/src/token.rs`.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, HANDLE, HLOCAL, LUID, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
    GetLengthSid, GetTokenInformation, LUA_TOKEN, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE,
    TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenDefaultDacl, TokenGroups, WRITE_RESTRICTED,
    WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::cap::Sid;
use super::{check, wide};

const GENERIC_ALL: u32 = 0x1000_0000;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

fn logon_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0;
    // SAFETY: size query with a null buffer.
    unsafe { GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed) };
    // u64 backing keeps the TOKEN_GROUPS header aligned
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `needed` bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer now holds a TOKEN_GROUPS whose SID pointers point inside it.
    unsafe {
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            .iter()
            .find(|g| g.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            .map(|g| {
                std::slice::from_raw_parts(g.Sid as *const u8, GetLengthSid(g.Sid) as usize)
                    .to_vec()
            })
            .ok_or_else(|| io::Error::other("no logon SID on the token"))
    }
}

fn everyone_sid() -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 68]; // SECURITY_MAX_SID_SIZE
    let mut size = buf.len() as u32;
    // SAFETY: `buf` is `size` bytes.
    if unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// Confine the token's default DACL to its own logon session, so other launches'
/// processes cannot open this one. OWNER RIGHTS suppresses the owner's implicit WRITE_DAC.
fn set_default_dacl(token: HANDLE, logon: *mut c_void) -> io::Result<()> {
    let owner_rights = Sid::parse("S-1-3-4")?;
    let entries =
        [(logon, GENERIC_ALL), (owner_rights.as_ptr(), READ_CONTROL)].map(|(sid, mask)| {
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: 0,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: sid.cast(),
                },
            }
        });
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `entries` reference SIDs that outlive the calls; `dacl` is freed below.
    unsafe {
        check(SetEntriesInAclW(
            2,
            entries.as_ptr(),
            std::ptr::null(),
            &mut dacl,
        ))?;
        let info = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
        let ok = SetTokenInformation(
            token,
            TokenDefaultDacl,
            (&info as *const TOKEN_DEFAULT_DACL).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        );
        let err = io::Error::last_os_error();
        LocalFree(dacl as HLOCAL);
        if ok == 0 {
            return Err(err);
        }
    }
    Ok(())
}

/// DISABLE_MAX_PRIVILEGE drops SeChangeNotifyPrivilege too; without it nothing
/// can traverse a directory it has no access to.
fn enable_change_notify(token: HANDLE) -> io::Result<()> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: valid NUL-terminated name and out pointer; `tp` is fully initialised.
    unsafe {
        if LookupPrivilegeValueW(
            std::ptr::null(),
            wide("SeChangeNotifyPrivilege".as_ref()).as_ptr(),
            &mut luid,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let ok =
            AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
        // success with ERROR_NOT_ALL_ASSIGNED means the privilege was not enabled
        let err = io::Error::last_os_error();
        if ok == 0 || err.raw_os_error() == Some(ERROR_NOT_ALL_ASSIGNED as i32) {
            return Err(err);
        }
    }
    Ok(())
}

/// A restricted copy of this process's token whose write access is limited to
/// what the `caps` SIDs (plus logon SID and Everyone) are granted.
pub fn restricted(caps: &[&Sid]) -> io::Result<OwnedHandle> {
    let mut base: HANDLE = std::ptr::null_mut();
    let access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    // SAFETY: out pointer is valid; the handle is owned right after.
    let base = unsafe {
        if OpenProcessToken(GetCurrentProcess(), access, &mut base) == 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(base)
    };
    use std::os::windows::io::AsRawHandle;
    let base_raw = base.as_raw_handle();

    let mut logon = logon_sid(base_raw)?;
    let mut everyone = everyone_sid()?;
    let mut restricting: Vec<SID_AND_ATTRIBUTES> = caps
        .iter()
        .map(|c| c.as_ptr())
        .chain([logon.as_mut_ptr().cast(), everyone.as_mut_ptr().cast()])
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        })
        .collect();

    let mut new: HANDLE = std::ptr::null_mut();
    // SAFETY: all SID pointers stay alive across the call.
    let token = unsafe {
        if CreateRestrictedToken(
            base_raw,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            restricting.len() as u32,
            restricting.as_mut_ptr(),
            &mut new,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(new)
    };
    set_default_dacl(token.as_raw_handle(), logon.as_mut_ptr().cast())?;
    enable_change_notify(token.as_raw_handle())?;
    Ok(token)
}
