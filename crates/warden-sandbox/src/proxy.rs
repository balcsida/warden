//! Allowlisting egress proxy: HTTP CONNECT, plain HTTP forward (sent on in origin-form)
//! and SOCKS5 CONNECT with hostname addressing. No TLS interception. Runs
//! outside the sandbox; the sandbox lets the child reach only this listener.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use warden_core::HostRule;

pub type DeniedHook = Arc<dyn Fn(&str, u16) + Send + Sync>;

#[derive(Debug, Clone)]
pub enum Listen {
    /// 127.0.0.1 on an ephemeral port.
    Tcp,
    /// A Unix socket at this path (parent dir must exist and be private).
    Unix(PathBuf),
}

#[derive(Debug, Clone)]
pub enum Bound {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

pub struct ProxyServer {
    pub bound: Bound,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProxyServer {
    /// Start the proxy on its own thread with a current-thread tokio runtime.
    pub fn start(
        rules: Vec<HostRule>,
        listen: Listen,
        on_denied: DeniedHook,
    ) -> std::io::Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let rules = Arc::new(rules);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (bound, accept_loop): (
            Bound,
            std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        ) = match listen {
            Listen::Tcp => {
                let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
                std_listener.set_nonblocking(true)?;
                let addr = std_listener.local_addr()?;
                let rules = rules.clone();
                (
                    Bound::Tcp(addr),
                    Box::pin(async move {
                        let listener = TcpListener::from_std(std_listener).expect("tokio listener");
                        loop {
                            let Ok((stream, _)) = listener.accept().await else {
                                break;
                            };
                            let rules = rules.clone();
                            let hook = on_denied.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle(stream, &rules, &hook).await {
                                    tracing::debug!("proxy connection ended: {e}");
                                }
                            });
                        }
                    }),
                )
            }
            #[cfg(unix)]
            Listen::Unix(path) => {
                let _ = std::fs::remove_file(&path);
                let std_listener = std::os::unix::net::UnixListener::bind(&path)?;
                std_listener.set_nonblocking(true)?;
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                let rules = rules.clone();
                (
                    Bound::Unix(path),
                    Box::pin(async move {
                        let listener = tokio::net::UnixListener::from_std(std_listener)
                            .expect("tokio listener");
                        loop {
                            let Ok((stream, _)) = listener.accept().await else {
                                break;
                            };
                            let rules = rules.clone();
                            let hook = on_denied.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle(stream, &rules, &hook).await {
                                    tracing::debug!("proxy connection ended: {e}");
                                }
                            });
                        }
                    }),
                )
            }
            #[cfg(not(unix))]
            Listen::Unix(_) => return Err(std::io::Error::other("unix sockets unsupported here")),
        };
        let thread = std::thread::Builder::new()
            .name("warden-proxy".into())
            .spawn(move || {
                rt.block_on(async {
                    tokio::select! { _ = accept_loop => {}, _ = rx => {} }
                });
            })?;
        Ok(Self {
            bound,
            shutdown: Some(tx),
            thread: Some(thread),
        })
    }

    /// URL the child should put in `HTTP_PROXY` etc. For a Unix listener this is
    /// the loopback port the in-sandbox bridge exposes.
    pub fn url_for_child(&self, bridge_port: u16) -> String {
        match &self.bound {
            Bound::Tcp(a) => format!("http://{a}"),
            Bound::Unix(_) => format!("http://127.0.0.1:{bridge_port}"),
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Bound::Unix(p) = &self.bound {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn allowed(rules: &[HostRule], host: &str, port: u16) -> bool {
    rules.iter().any(|r| r.matches(host, port))
}

async fn handle<S>(mut client: S, rules: &[HostRule], on_denied: &DeniedHook) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    if client.read_exact(&mut first).await.is_err() {
        return Ok(());
    }
    if first[0] == 0x05 {
        return socks5(client, rules, on_denied).await;
    }
    http(client, first[0], rules, on_denied).await
}

// ------------------------------------------------------------------ HTTP

async fn http<S>(
    mut client: S,
    first: u8,
    rules: &[HostRule],
    on_denied: &DeniedHook,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = vec![first];
    let mut buf = [0u8; 1024];
    // The first read often carries part of the body too; everything read is forwarded.
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return respond(&mut client, "431 Request Header Fields Too Large").await;
        }
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return respond(&mut client, "400 Bad Request").await;
    };

    let (host, port, connect) = if method.eq_ignore_ascii_case("CONNECT") {
        let Some((h, p)) = split_host_port(target, 443) else {
            return respond(&mut client, "400 Bad Request").await;
        };
        (h, p, true)
    } else if let Some(rest) = target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or_default();
        let Some((h, p)) = split_host_port(authority, 80) else {
            return respond(&mut client, "400 Bad Request").await;
        };
        (h, p, false)
    } else {
        return respond(&mut client, "400 Bad Request").await;
    };

    if !allowed(rules, &host, port) {
        on_denied(&host, port);
        return respond(&mut client, "403 Forbidden").await;
    }
    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => return respond(&mut client, "502 Bad Gateway").await,
    };
    if connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        let Some(head) = origin_form(&head) else {
            return respond(&mut client, "400 Bad Request").await;
        };
        upstream.write_all(&head).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Rewrite a proxy request (`GET http://host/p HTTP/1.1`) to the origin-form an
/// origin server expects (`GET /p HTTP/1.1`; RFC 9112 §3.2.1), force
/// `Connection: close` (later requests on a kept-alive connection would be piped
/// unparsed, still in absolute form) and replace the client's `Host` with the
/// target's authority, so the child cannot name another virtual host on an
/// allowlisted address. Works on bytes: header values need not be UTF-8. Rejects
/// obs-fold and bare LF (RFC 9112 §5.2). Bytes after the header (body) pass through.
fn origin_form(head: &[u8]) -> Option<Vec<u8>> {
    let end = head.windows(4).position(|w| w == b"\r\n\r\n")?;
    let block = &head[..end];
    if block
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || block[i - 1] != b'\r'))
    {
        return None;
    }
    let mut lines = block
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = std::str::from_utf8(lines.next()?).ok()?;
    let mut parts = request_line.split_whitespace();
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let rest = target.strip_prefix("http://")?;
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = (&rest[..split], &rest[split..]);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let mut out = format!("{method} {path} {version}\r\nHost: {authority}\r\n").into_bytes();
    for line in lines {
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            return None;
        }
        let name = line
            .split(|&b| b == b':')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        let drop = [
            "host",
            "connection",
            "proxy-connection",
            "keep-alive",
            "proxy-authorization",
            "te",
            "upgrade",
        ];
        if !drop.iter().any(|h| name.eq_ignore_ascii_case(h.as_bytes())) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&head[end + 4..]);
    Some(out)
}

async fn respond<S: tokio::io::AsyncWrite + Unpin>(
    client: &mut S,
    status: &str,
) -> std::io::Result<()> {
    let body = format!("warden: {status}\n");
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(msg.as_bytes()).await?;
    client.shutdown().await
}

fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((s.to_string(), default_port)),
    }
}

// ------------------------------------------------------------------ SOCKS5

async fn socks5<S>(mut client: S, rules: &[HostRule], on_denied: &DeniedHook) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let n = client.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x01 {
        return socks_reply(&mut client, 0x07).await; // command not supported
    }
    let host = match hdr[3] {
        0x01 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let len = client.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            client.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        0x04 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return socks_reply(&mut client, 0x08).await,
    };
    let port = client.read_u16().await?;
    if !allowed(rules, &host, port) {
        on_denied(&host, port);
        return socks_reply(&mut client, 0x02).await; // not allowed by ruleset
    }
    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => return socks_reply(&mut client, 0x04).await,
    };
    socks_reply(&mut client, 0x00).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn socks_reply<S: tokio::io::AsyncWrite + Unpin>(
    client: &mut S,
    rep: u8,
) -> std::io::Result<()> {
    client
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    if rep != 0 {
        client.shutdown().await?;
    }
    Ok(())
}

// ------------------------------------------------------------------ bridge (Linux)

/// Inside the sandbox's network namespace: accept on 127.0.0.1:`port` and pipe
/// each connection to the proxy's Unix socket. Blocks forever.
#[cfg(unix)]
pub fn run_bridge(uds: &std::path::Path, port: u16) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let uds = uds.to_path_buf();
    rt.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        loop {
            let (mut tcp, _) = listener.accept().await?;
            let uds = uds.clone();
            tokio::spawn(async move {
                if let Ok(mut unix) = tokio::net::UnixStream::connect(&uds).await {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                }
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Mutex;

    fn echo_server() -> u16 {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut b = [0u8; 64];
                    while let Ok(n) = s.read(&mut b) {
                        if n == 0 || s.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    type Denied = Arc<Mutex<Vec<(String, u16)>>>;
    fn start(rules: Vec<HostRule>) -> (ProxyServer, Denied) {
        let denied = Arc::new(Mutex::new(Vec::new()));
        let d2 = denied.clone();
        let hook: DeniedHook = Arc::new(move |h, p| d2.lock().unwrap().push((h.to_string(), p)));
        (
            ProxyServer::start(rules, Listen::Tcp, hook).unwrap(),
            denied,
        )
    }

    fn connect(proxy: &ProxyServer) -> std::net::TcpStream {
        let Bound::Tcp(a) = proxy.bound else { panic!() };
        std::net::TcpStream::connect(a).unwrap()
    }

    fn read_some(s: &mut std::net::TcpStream) -> String {
        let mut b = vec![0u8; 4096];
        s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let n = s.read(&mut b).unwrap();
        String::from_utf8_lossy(&b[..n]).into_owned()
    }

    #[test]
    fn connect_allowed_and_denied() {
        let echo = echo_server();
        let (proxy, denied) = start(vec![HostRule {
            host: "127.0.0.1".into(),
            port: echo,
        }]);

        let mut s = connect(&proxy);
        write!(
            s,
            "CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n"
        )
        .unwrap();
        assert!(read_some(&mut s).starts_with("HTTP/1.1 200"));
        s.write_all(b"ping").unwrap();
        assert_eq!(read_some(&mut s), "ping");

        let mut s = connect(&proxy);
        write!(s, "CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(read_some(&mut s).starts_with("HTTP/1.1 403"));
        // same host, other port: denied too
        let mut s = connect(&proxy);
        write!(s, "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo + 1).unwrap();
        assert!(read_some(&mut s).starts_with("HTTP/1.1 403"));
        assert_eq!(
            denied.lock().unwrap().as_slice(),
            [
                ("example.com".to_string(), 443),
                ("127.0.0.1".into(), echo + 1)
            ]
        );
    }

    #[test]
    fn plain_http_forward_and_bad_request() {
        let echo = echo_server();
        let (proxy, _) = start(vec![HostRule {
            host: "127.0.0.1".into(),
            port: echo,
        }]);
        let mut s = connect(&proxy);
        write!(
            s,
            "GET http://127.0.0.1:{echo}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        // echo server mirrors the forwarded head back, now in origin-form
        assert!(read_some(&mut s).starts_with("GET /x HTTP/1.1\r\n"));
        let mut s = connect(&proxy);
        write!(s, "GET /relative HTTP/1.1\r\n\r\n").unwrap();
        assert!(read_some(&mut s).starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn origin_form_rewrites_target_and_hop_headers() {
        let head = b"POST http://gw:4000/v1/chat?x=1 HTTP/1.1\r\nHost: gw:4000\r\nProxy-Connection: keep-alive\r\nconnection: keep-alive\r\nAuthorization: Bearer k\r\n\r\n{\"a\":1}";
        let out = String::from_utf8(origin_form(head).unwrap()).unwrap();
        assert_eq!(
            out,
            "POST /v1/chat?x=1 HTTP/1.1\r\nHost: gw:4000\r\nAuthorization: Bearer k\r\nConnection: close\r\n\r\n{\"a\":1}"
        );
        let bare = origin_form(b"GET http://gw HTTP/1.1\r\n\r\n").unwrap();
        assert!(bare.starts_with(b"GET / HTTP/1.1\r\nHost: gw\r\n"));
        assert!(bare.starts_with(b"GET / HTTP/1.1\r\n"));
        let query = origin_form(b"GET http://gw?q HTTP/1.1\r\n\r\n").unwrap();
        assert!(query.starts_with(b"GET /?q HTTP/1.1\r\n"));
    }

    #[test]
    fn origin_form_host_comes_from_target() {
        let out = origin_form(
            b"GET http://allowed.example:8080/ HTTP/1.1\r\nhost: other.internal\r\nTE: trailers\r\nUpgrade: websocket\r\nX: 1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            out,
            b"GET / HTTP/1.1\r\nHost: allowed.example:8080\r\nX: 1\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn origin_form_passes_non_utf8_header_bytes() {
        let out = origin_form(b"GET http://gw/ HTTP/1.1\r\nX-Name: caf\xe9\r\n\r\n").unwrap();
        assert!(out.windows(5).any(|w| w == b"caf\xe9\r"));
    }

    #[test]
    fn origin_form_rejects_obs_fold_and_bare_lf() {
        assert!(origin_form(b"GET http://gw/ HTTP/1.1\r\nA: b\r\n c\r\n\r\n").is_none());
        assert!(origin_form(b"GET http://gw/ HTTP/1.1\r\nA: b\r\n\tc\r\n\r\n").is_none());
        assert!(origin_form(b"GET http://gw/ HTTP/1.1\r\nA: b\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn socks5_domain_allowed_and_denied() {
        let echo = echo_server();
        let (proxy, denied) = start(vec![HostRule {
            host: "localhost".into(),
            port: echo,
        }]);
        let mut s = connect(&proxy);
        s.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).unwrap();
        assert_eq!(r, [0x05, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&echo.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0x00);
        s.write_all(b"hi").unwrap();
        assert_eq!(read_some(&mut s), "hi");

        let mut s = connect(&proxy);
        s.write_all(&[0x05, 0x01, 0x00]).unwrap();
        s.read_exact(&mut r).unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"example.org");
        req.extend_from_slice(&443u16.to_be_bytes());
        s.write_all(&req).unwrap();
        s.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0x02);
        assert_eq!(
            denied.lock().unwrap().as_slice(),
            [("example.org".to_string(), 443)]
        );
    }

    #[test]
    fn host_rule_matching() {
        let r = HostRule {
            host: "*.github.com".into(),
            port: 443,
        };
        assert!(r.matches("api.github.com", 443));
        assert!(!r.matches("github.com", 443));
        assert!(!r.matches("evilgithub.com", 443));
        assert!(!r.matches("api.github.com", 80));
        let r = HostRule {
            host: "GW.example.com".into(),
            port: 443,
        };
        assert!(r.matches("gw.example.com", 443));
        assert_eq!(split_host_port("[::1]:8080", 1), Some(("::1".into(), 8080)));
        assert_eq!(split_host_port("host", 7), Some(("host".into(), 7)));
    }
}
