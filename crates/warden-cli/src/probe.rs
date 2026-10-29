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
    let via_proxy = std::env::var("HTTPS_PROXY").ok().and_then(|p| {
        let addr = p.trim_start_matches("http://").to_string();
        let mut s = std::net::TcpStream::connect(addr).ok()?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok()?;
        write!(s, "CONNECT {connect} HTTP/1.1\r\nHost: {connect}\r\n\r\n").ok()?;
        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut s, &mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf[..n]).contains(" 200 "))
    });
    let _ = writeln!(
        out,
        "proxy={}",
        match via_proxy {
            Some(true) => "ok",
            Some(false) => "denied",
            None => "unavailable",
        }
    );
    ExitCode::SUCCESS
}
