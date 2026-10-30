//! Create the harness under the restricted token, born inside a kill-on-close
//! job, with an explicit environment and only the three std handles inherited.
//! Derived from codex `windows-sandbox-rs/src/{process.rs,proc_thread_attr.rs}`.

use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use warden_core::SandboxSpec;
use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};

use super::{cap, cmdline, wide};

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;

/// The running harness: its process and the job that holds its whole tree.
/// Dropping the job handle kills every process still in it.
pub struct Child {
    pub process: OwnedHandle,
    pub job: OwnedHandle,
}

fn new_job() -> io::Result<OwnedHandle> {
    // SAFETY: plain object creation; the handle is owned right away.
    let job = unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(h)
    };
    // no JOB_OBJECT_LIMIT_BREAKAWAY_OK: descendants cannot leave the job
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` is the structure the information class expects.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

/// The three std handles, made inheritable, without duplicates (the handle list rejects them).
fn std_handles() -> io::Result<[HANDLE; 3]> {
    let mut hs = [std::ptr::null_mut(); 3];
    for (h, kind) in hs
        .iter_mut()
        .zip([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE])
    {
        // SAFETY: querying and flagging our own std handles.
        *h = unsafe { GetStdHandle(kind) };
        if h.is_null() || *h == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "warden has no standard handles to pass on",
            ));
        }
        if unsafe { SetHandleInformation(*h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(hs)
}

/// Process/thread attribute list holding the job and handle-list attributes.
struct Attributes(Vec<u64>);

impl Attributes {
    fn new(job: &HANDLE, handles: &[HANDLE]) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: size query, then initialise a buffer of that size (u64 for alignment).
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
        let mut list = Self(vec![0u64; size.div_ceil(8)]);
        unsafe {
            if InitializeProcThreadAttributeList(list.ptr(), 2, 0, &mut size) == 0 {
                return Err(io::Error::last_os_error());
            }
            // a job that cannot be honoured must fail the spawn rather than run uncontained
            list.set(
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                (job as *const HANDLE).cast(),
                size_of::<HANDLE>(),
            )?;
            list.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr().cast(),
                size_of_val(handles),
            )?;
        }
        Ok(list)
    }

    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }

    /// # Safety
    /// `value` must stay valid until the process is created.
    unsafe fn set(&mut self, attr: usize, value: *const c_void, size: usize) -> io::Result<()> {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.ptr(),
                0,
                attr,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new`.
        unsafe { DeleteProcThreadAttributeList(self.ptr()) };
    }
}

pub fn spawn(
    token: &OwnedHandle,
    argv: &[OsString],
    spec: &SandboxSpec,
) -> io::Result<(u32, Child)> {
    let job = new_job()?;
    let mut cmd = cmdline::command_line(argv)?;
    let env = cmdline::env_block(&spec.env);
    // cmd.exe and friends reject the `\\?\` form that canonicalize() yields
    let cwd = wide(cap::canonical(&spec.cwd).as_os_str());
    // restricted tokens can fail DLL init without an explicit desktop (see codex process.rs)
    let mut desktop = wide("Winsta0\\Default".as_ref());

    let std = std_handles()?;
    let mut inherited = std.to_vec();
    inherited.sort();
    inherited.dedup();
    let job_raw: HANDLE = job.as_raw_handle();
    let mut attrs = Attributes::new(&job_raw, &inherited)?;

    // SAFETY: zeroed STARTUPINFOEXW is valid; all pointers outlive the call.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = std[0];
    si.StartupInfo.hStdOutput = std[1];
    si.StartupInfo.hStdError = std[2];
    si.lpAttributeList = attrs.ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            env.as_ptr().cast(),
            cwd.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateProcessAsUserW returned two fresh handles that we now own.
    let (process, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess),
            OwnedHandle::from_raw_handle(pi.hThread),
        )
    };
    Ok((pi.dwProcessId, Child { process, job }))
}
