//! Credential helper socket. The parent keeps the secret; the harness runs
//! `warden __credential`, which connects to `$WARDEN_CREDENTIAL_SOCK`, reads the
//! current token and prints it. The socket is `0600` in a private directory.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};

pub const ENV: &str = "WARDEN_CREDENTIAL_SOCK";

pub struct CredentialServer {
    pub path: PathBuf,
    secret: Arc<Mutex<SecretString>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CredentialServer {
    pub fn start(path: &Path, secret: SecretString) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::remove_file(path);
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let secret = Arc::new(Mutex::new(secret));
        let s2 = secret.clone();
        let thread = std::thread::Builder::new()
            .name("warden-credsock".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let token = s2
                        .lock()
                        .map(|s| s.expose_secret().to_string())
                        .unwrap_or_default();
                    let _ = stream.write_all(token.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            secret,
            thread: Some(thread),
        })
    }

    /// Replace the token handed to future helper invocations (credential rotation).
    pub fn rotate(&self, secret: SecretString) {
        if let Ok(mut s) = self.secret.lock() {
            *s = secret;
        }
    }
}

impl Drop for CredentialServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        // Unblock accept() by connecting once; the listener then sees a closed socket and exits.
        if let Some(t) = self.thread.take() {
            let _ = std::os::unix::net::UnixStream::connect(&self.path);
            let _ = t.join_timeout();
        }
    }
}

trait JoinTimeout {
    fn join_timeout(self) -> Option<()>;
}
impl JoinTimeout for std::thread::JoinHandle<()> {
    fn join_timeout(self) -> Option<()> {
        // The thread exits once the listener errors after unlink+connect; don't hang if it doesn't.
        if self.is_finished() {
            self.join().ok()
        } else {
            None
        }
    }
}

/// Client side: `warden __credential`.
pub fn fetch(path: &Path) -> std::io::Result<String> {
    let mut s = std::os::unix::net::UnixStream::connect(path)?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cred.sock");
        let server = CredentialServer::start(&p, SecretString::from("one")).unwrap();
        assert_eq!(fetch(&p).unwrap(), "one");
        server.rotate(SecretString::from("two"));
        assert_eq!(fetch(&p).unwrap(), "two");
        drop(server);
        assert!(!p.exists());
    }
}
