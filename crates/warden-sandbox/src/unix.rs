//! Spawn/wait/signal shared by the Unix backends. The child inherits stdio, so
//! the terminal talks to the harness directly; warden only waits and relays
//! SIGTERM/SIGHUP. SIGINT reaches the child from the tty on its own.

use std::ffi::OsString;
use std::process::{Child, Command, ExitStatus, Stdio};

use warden_core::{LaunchedChild, SandboxError, SandboxSpec, Signal};

pub fn spawn(
    program: &OsString,
    args: &[OsString],
    spec: &SandboxSpec,
) -> Result<LaunchedChild, SandboxError> {
    let child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(&spec.env)
        .current_dir(&spec.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(LaunchedChild::new(child.id(), child))
}

pub fn wait(child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
    let c: &mut Child = child.inner_mut().expect("unix child");
    Ok(c.wait()?)
}

pub fn signum(sig: Signal) -> libc::c_int {
    match sig {
        Signal::Interrupt => libc::SIGINT,
        Signal::Terminate => libc::SIGTERM,
        Signal::Hangup => libc::SIGHUP,
    }
}

pub fn signal(child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError> {
    let signum = signum(sig);
    // SAFETY: kill(2) with a pid we spawned; no memory is touched.
    let rc = unsafe { libc::kill(child.pid as libc::pid_t, signum) };
    if rc != 0 {
        return Err(SandboxError::Spawn(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Exit code warden should exit with for a finished child.
pub fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}
