//! `Unsupported`: the Windows stub for milestone 1. `NoSandbox`: policy-gated
//! escape hatch that still injects credentials and routes through the proxy.

use std::ffi::OsString;
use std::process::ExitStatus;

use warden_core::{LaunchedChild, Sandbox, SandboxError, SandboxSpec, Signal};

pub struct Unsupported;

impl Sandbox for Unsupported {
    fn name(&self) -> &str {
        "unsupported"
    }
    fn preflight(&self, _spec: &SandboxSpec) -> Result<(), SandboxError> {
        Err(SandboxError::Unsupported(
            "Windows sandboxing lands in milestone 2; warden refuses to launch unsandboxed unless policy grants launchUnsandboxed (see docs/THREAT_MODEL.md)".into(),
        ))
    }
    fn spawn(&self, spec: &SandboxSpec, _argv: &[OsString]) -> Result<LaunchedChild, SandboxError> {
        self.preflight(spec).map(|_| unreachable!())
    }
    fn wait(&self, _child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
        Err(SandboxError::Unsupported("no child".into()))
    }
    fn signal(&self, _child: &LaunchedChild, _sig: Signal) -> Result<(), SandboxError> {
        Ok(())
    }
}

/// No OS sandbox. Only reachable when the bundle permits `launchUnsandboxed`.
pub struct NoSandbox;

impl Sandbox for NoSandbox {
    fn name(&self) -> &str {
        "none"
    }
    fn preflight(&self, _spec: &SandboxSpec) -> Result<(), SandboxError> {
        Ok(())
    }
    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError> {
        #[cfg(unix)]
        {
            crate::unix::spawn(&argv[0], &argv[1..], spec)
        }
        #[cfg(not(unix))]
        {
            let child = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .env_clear()
                .envs(&spec.env)
                .current_dir(&spec.cwd)
                .spawn()?;
            Ok(LaunchedChild::new(child.id(), child))
        }
    }
    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
        let c: &mut std::process::Child = child.inner_mut().expect("child");
        Ok(c.wait()?)
    }
    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError> {
        #[cfg(unix)]
        {
            crate::unix::signal(child, sig)
        }
        #[cfg(not(unix))]
        {
            let _ = (child, sig);
            Ok(())
        }
    }
}
