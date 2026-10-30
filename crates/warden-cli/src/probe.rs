//! `warden __probe <read> <write> <host:port>`: acts as the "harness" in the
//! sandbox integration tests. Prints one `KEY=ok|denied` line per check.

use std::io::Write;
use std::process::ExitCode;

pub fn run(read: &std::path::Path, write: &std::path::Path, connect: &str) -> ExitCode {
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
    ExitCode::SUCCESS
}
