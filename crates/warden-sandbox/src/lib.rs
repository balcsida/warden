//! Platform sandbox backends plus the egress proxy every backend forces the
//! harness through. See docs/DESIGN.md §2.3–2.4.

pub mod proxy;

#[cfg(unix)]
pub mod credsock;
#[cfg(not(unix))]
pub mod credsock {
    pub const ENV: &str = "WARDEN_CREDENTIAL_SOCK";
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::exit_code;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod seatbelt;

#[cfg(windows)]
pub mod windows;

pub mod unsandboxed;

use warden_core::Sandbox;

/// The native backend for this platform.
pub fn native() -> Box<dyn Sandbox> {
    #[cfg(target_os = "macos")]
    {
        Box::new(seatbelt::Seatbelt)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSandbox::default())
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsSandbox)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Box::new(unsandboxed::Unsupported)
    }
}

/// Which proxy listener the native backend wants.
pub fn preferred_listen(tmp: &std::path::Path) -> proxy::Listen {
    if cfg!(target_os = "linux") {
        proxy::Listen::Unix(tmp.join("proxy.sock"))
    } else {
        proxy::Listen::Tcp
    }
}
