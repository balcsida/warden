//! `warden __probe <read> <write> <host:port>`: acts as the "harness" in the
//! sandbox integration tests. Prints one `KEY=ok|denied` line per check.

use std::io::Write;
use std::process::ExitCode;

pub fn run(
    read: &std::path::Path,
    write: &std::path::Path,
    connect: &str,
    pid: Option<u32>,
) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let r = std::fs::read(read).is_ok();
    let _ = writeln!(out, "read={}", if r { "ok" } else { "denied" });
    let w = std::fs::write(write, b"probe").is_ok();
    let _ = writeln!(out, "write={}", if w { "ok" } else { "denied" });
    let direct = std::net::TcpStream::connect_timeout(
        &connect
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:9".parse().unwrap()),
        std::time::Duration::from_secs(2),
    )
    .is_ok();
    let _ = writeln!(out, "direct={}", if direct { "ok" } else { "denied" });
    // Err names the failing step so a flaky CI run says why (e.g. `connect: ConnectionRefused`).
    let via_proxy = (|| -> Result<bool, String> {
        let p = std::env::var("HTTPS_PROXY").map_err(|_| "no HTTPS_PROXY".to_string())?;
        let addr = p.trim_start_matches("http://").to_string();
        let step = |what: &str, e: std::io::Error| format!("{what}: {:?}", e.kind());
        let mut s = std::net::TcpStream::connect(addr).map_err(|e| step("connect", e))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .map_err(|e| step("timeout", e))?;
        write!(s, "CONNECT {connect} HTTP/1.1\r\nHost: {connect}\r\n\r\n")
            .map_err(|e| step("write", e))?;
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).map_err(|e| step("read", e))?;
        Ok(String::from_utf8_lossy(&buf[..n]).contains(" 200 "))
    })();
    let _ = match via_proxy {
        Ok(true) => writeln!(out, "proxy=ok"),
        Ok(false) => writeln!(out, "proxy=denied"),
        Err(why) => writeln!(out, "proxy=unavailable ({why})"),
    };
    #[cfg(windows)]
    open_process(&mut out, pid);
    #[cfg(not(windows))]
    let _ = pid;
    ExitCode::SUCCESS
}

/// Prints `open_<right>=ok|denied` for `OpenProcess` on `pid` (default: the
/// parent, i.e. warden) with each right a sandboxed child must not get.
#[cfg(windows)]
fn open_process(out: &mut impl Write, pid: Option<u32>) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_VM_WRITE,
    };
    let Some(pid) = pid.or_else(parent_pid) else {
        let _ = writeln!(out, "open=no-target");
        return;
    };
    for (name, right) in [
        ("vm_write", PROCESS_VM_WRITE),
        ("create_thread", PROCESS_CREATE_THREAD),
        ("dup_handle", PROCESS_DUP_HANDLE),
    ] {
        // SAFETY: plain query; a returned handle is closed right away.
        let h = unsafe { OpenProcess(right, 0, pid) };
        let _ = writeln!(
            out,
            "open_{name}={}",
            if h.is_null() { "denied" } else { "ok" }
        );
        if !h.is_null() {
            // SAFETY: `h` is a valid handle owned here.
            unsafe { CloseHandle(h) };
        }
    }
}

#[cfg(windows)]
fn parent_pid() -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    let me = std::process::id();
    // SAFETY: the snapshot handle is closed below; the entry is zeroed with `dwSize` set.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut more = Process32FirstW(snap, &mut e) != 0;
        while more {
            if e.th32ProcessID == me {
                found = Some(e.th32ParentProcessID);
                break;
            }
            more = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
        found
    }
}
