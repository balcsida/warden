//! Windows backend, phase A: a restricted token limits writes to the writable
//! roots (ACL grants to per-root capability SIDs) and a kill-on-close job object
//! owns the harness's whole process tree. Network egress and deny-read are NOT
//! enforced yet (phase B needs a sandbox user and firewall rules), so `preflight`
//! refuses unless policy opts in with `sandbox_allow_degraded`.
//! Derived from openai/codex `windows-sandbox-rs` (see THIRD_PARTY_NOTICES.md).

mod acl;
mod cap;
mod cmdline;
mod console;
mod process;
mod token;

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;

use warden_core::{LaunchedChild, Sandbox, SandboxError, SandboxSpec, Signal};
use windows_sys::Win32::Foundation::WIN32_ERROR;
use windows_sys::Win32::System::Console::{CTRL_C_EVENT, GenerateConsoleCtrlEvent};
use windows_sys::Win32::System::JobObjects::TerminateJobObject;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

pub use console::ignore_console_interrupts;

/// NUL-terminated UTF-16 for a Win32 `PCWSTR`.
fn wide(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain([0]).collect()
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    match code {
        0 => Ok(()),
        c => Err(io::Error::from_raw_os_error(c as i32)),
    }
}

pub struct WindowsSandbox;

impl Sandbox for WindowsSandbox {
    fn name(&self) -> &str {
        "windows-restricted-token"
    }

    fn preflight(&self, spec: &SandboxSpec) -> Result<(), SandboxError> {
        if !spec.sandbox_allow_degraded {
            return Err(SandboxError::Preflight(
                "the Windows sandbox cannot yet block network egress or deny reads, so warden refuses to launch; \
                 set `sandbox_allow_degraded` in the policy bundle defaults to run with only the write limit and process-tree kill"
                    .into(),
            ));
        }
        Ok(())
    }

    fn degraded(&self) -> Option<&'static str> {
        Some(
            "degraded Windows sandbox: writes are limited to the writable roots and the process tree is killed on exit, \
             but network egress and deny-read paths are NOT enforced on Windows yet",
        )
    }

    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError> {
        let roots: Vec<_> = spec
            .read_write
            .iter()
            .filter(|p| p.exists())
            .cloned()
            .collect();
        let caps = cap::for_roots(&spec.data_dir, &roots)?;
        for c in &caps {
            acl::grant_write(&c.root, c.sid.as_ptr())?;
        }
        // keep .git/hooks and .git/config read-only (as on macOS and Linux): a planted
        // hook would run outside the sandbox on the developer's next commit. Deny the
        // capability of every root containing them, since a parent root's grant is
        // inherited into them; other roots (the per-launch temp dir) stay untouched so
        // repeated launches add no ACEs.
        let mut protected: Vec<_> = caps
            .iter()
            .flat_map(|c| {
                [
                    c.root.join(".git").join("hooks"),
                    c.root.join(".git").join("config"),
                ]
            })
            .filter(|p| p.exists())
            .collect();
        protected.sort();
        protected.dedup();
        for p in &protected {
            for c in caps.iter().filter(|c| p.starts_with(&c.root)) {
                acl::deny_write(p, c.sid.as_ptr())?;
            }
        }
        // `.git` itself must not be renamed or replaced either: a renamed copy with a
        // planted hook moved back would dodge the denies above. The deny is not
        // inherited, so writes inside `.git` (objects, refs) keep working.
        let mut git_dirs: Vec<_> = caps
            .iter()
            .map(|c| c.root.join(".git"))
            .filter(|p| p.is_dir())
            .collect();
        git_dirs.sort();
        git_dirs.dedup();
        for g in &git_dirs {
            for c in caps.iter().filter(|c| g.starts_with(&c.root)) {
                acl::deny_delete(g, c.sid.as_ptr())?;
            }
        }
        let sids: Vec<&cap::Sid> = caps.iter().map(|c| &c.sid).collect();
        let token = token::restricted(&sids)?;
        let (pid, child) = process::spawn(&token, argv, spec)?;
        Ok(LaunchedChild::new(pid, child))
    }

    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
        let c: &mut process::Child = child.inner_mut().expect("windows child");
        let process = c.process.as_raw_handle();
        let mut code = 0u32;
        // SAFETY: valid process handle owned by `c`.
        unsafe {
            if WaitForSingleObject(process, INFINITE) != 0
                || GetExitCodeProcess(process, &mut code) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(ExitStatus::from_raw(code))
    }

    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError> {
        let c: &process::Child = child.inner_ref().expect("windows child");
        // SAFETY: valid job handle owned by `c`; group 0 is every process on the console.
        let ok = unsafe {
            match sig {
                Signal::Interrupt => GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0),
                Signal::Terminate | Signal::Hangup => TerminateJobObject(c.job.as_raw_handle(), 1),
            }
        };
        if ok == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}
