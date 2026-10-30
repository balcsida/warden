//! Capability SIDs: one random SID per canonical writable root, persisted in
//! warden's data dir so the ACL grants made for a root stay valid (and
//! idempotent) across launches. Derived from codex `windows-sandbox-rs/src/cap.rs`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

use super::wide;

const FILE: &str = "cap_sids.json";
const LOCK: &str = "cap_sids.lock";

#[derive(Serialize, Deserialize, Default)]
struct CapSids {
    /// Lower-cased canonical root path -> `S-1-5-21-a-b-c-d`.
    writable_root_by_path: HashMap<String, String>,
}

/// A SID allocated by `ConvertStringSidToSidW`, freed with `LocalFree`.
pub struct Sid(*mut c_void);

impl Sid {
    pub fn parse(s: &str) -> io::Result<Self> {
        let mut psid = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and `psid` is a valid out pointer.
        if unsafe { ConvertStringSidToSidW(wide(s.as_ref()).as_ptr(), &mut psid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(psid))
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: the pointer came from ConvertStringSidToSidW and is freed once.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

pub struct Cap {
    pub root: PathBuf,
    pub sid: Sid,
}

/// The path as the kernel names it, without the `\\?\` prefix `canonicalize` adds to drive paths.
pub fn canonical(p: &Path) -> PathBuf {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    match c.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => c,
    }
}

pub fn random_sid() -> io::Result<String> {
    let mut b = [0u8; 16];
    // SAFETY: `b` is a valid 16-byte buffer; the flag selects the system RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            b.as_mut_ptr(),
            b.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!("BCryptGenRandom: {status:#x}")));
    }
    let n = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    Ok(format!("S-1-5-21-{}-{}-{}-{}", n(0), n(1), n(2), n(3)))
}

/// Held while `cap_sids.json` is read-modify-written, so concurrent launches
/// cannot lose each other's entries. The lock is a file created with `create_new`.
struct Lock(PathBuf);

impl Lock {
    fn acquire(path: PathBuf) -> io::Result<Self> {
        let create = || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        };
        // shortcut: a lock held past the retries is taken to be left by a crash and
        // removed; fine while the critical section is a few milliseconds
        for _ in 0..100 {
            match create() {
                Ok(_) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(e),
            }
        }
        let _ = std::fs::remove_file(&path);
        create().map(|_| Self(path))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The stored map; an unparsable file is moved aside to `.bad` and replaced.
fn load(file: &Path) -> io::Result<CapSids> {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(CapSids::default()),
        Err(e) => return Err(e),
    };
    serde_json::from_str(&text).or_else(|e| {
        let bad = file.with_extension("json.bad");
        eprintln!(
            "warden: {} is corrupt ({e}); moved to {} and starting a new one",
            file.display(),
            bad.display()
        );
        std::fs::rename(file, &bad)?;
        Ok(CapSids::default())
    })
}

/// One capability SID per distinct root, created and persisted on first use.
/// Entries whose path no longer exists are dropped when the file is saved.
pub fn for_roots(data_dir: &Path, roots: &[PathBuf]) -> io::Result<Vec<Cap>> {
    std::fs::create_dir_all(data_dir)?;
    let _lock = Lock::acquire(data_dir.join(LOCK))?;
    let file = data_dir.join(FILE);
    let mut caps = load(&file)?;
    let stored = caps.writable_root_by_path.len();
    caps.writable_root_by_path
        .retain(|path, _| Path::new(path).exists());
    let mut changed = caps.writable_root_by_path.len() != stored;
    let mut out: Vec<Cap> = Vec::new();
    for root in roots {
        let root = canonical(root);
        if out.iter().any(|c| c.root == root) {
            continue;
        }
        let key = root.to_string_lossy().to_lowercase();
        let sid = match caps.writable_root_by_path.get(&key) {
            Some(s) => s.clone(),
            None => {
                let s = random_sid()?;
                caps.writable_root_by_path.insert(key, s.clone());
                changed = true;
                s
            }
        };
        out.push(Cap {
            root,
            sid: Sid::parse(&sid)?,
        });
    }
    if changed {
        let tmp = file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&caps).map_err(io::Error::other)?)?;
        std::fs::rename(&tmp, &file)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_strings(data: &Path, roots: &[PathBuf]) -> Vec<String> {
        let caps = for_roots(data, roots).unwrap();
        let json: CapSids =
            serde_json::from_slice(&std::fs::read(data.join(FILE)).unwrap()).unwrap();
        caps.iter()
            .map(|c| json.writable_root_by_path[&c.root.to_string_lossy().to_lowercase()].clone())
            .collect()
    }

    #[test]
    fn sids_persist_per_canonical_root() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let a = dir.path().join("Alpha");
        let b = dir.path().join("beta");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let first = sid_strings(&data, &[a.clone(), b.clone()]);
        assert_ne!(first[0], first[1]);
        assert!(first[0].starts_with("S-1-5-21-"));

        // later launch, different spelling and order: same SIDs, nothing new minted
        let upper = PathBuf::from(a.to_string_lossy().to_uppercase());
        let second = sid_strings(&data, &[b.clone(), upper]);
        assert_eq!(second, [first[1].clone(), first[0].clone()]);
        let json: CapSids =
            serde_json::from_slice(&std::fs::read(data.join(FILE)).unwrap()).unwrap();
        assert_eq!(json.writable_root_by_path.len(), 2);
    }

    #[test]
    fn prunes_entries_for_missing_roots() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let keep = dir.path().join("keep");
        let gone = dir.path().join("gone");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&gone).unwrap();
        for_roots(&data, &[keep.clone(), gone.clone()]).unwrap();

        std::fs::remove_dir(&gone).unwrap();
        for_roots(&data, std::slice::from_ref(&keep)).unwrap();
        let json: CapSids =
            serde_json::from_slice(&std::fs::read(data.join(FILE)).unwrap()).unwrap();
        let keys: Vec<_> = json.writable_root_by_path.keys().collect();
        assert_eq!(keys, [&canonical(&keep).to_string_lossy().to_lowercase()]);
    }

    #[test]
    fn corrupt_file_is_moved_aside_and_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join(FILE), "{ truncated").unwrap();

        let sids = sid_strings(&data, &[root]);
        assert_eq!(sids.len(), 1);
        assert_eq!(
            std::fs::read_to_string(data.join("cap_sids.json.bad")).unwrap(),
            "{ truncated"
        );
        assert!(!data.join(LOCK).exists());
    }

    #[test]
    fn concurrent_launches_keep_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let roots: Vec<PathBuf> = (0..8).map(|i| dir.path().join(format!("r{i}"))).collect();
        for r in &roots {
            std::fs::create_dir_all(r).unwrap();
        }
        std::thread::scope(|s| {
            for r in &roots {
                s.spawn(|| {
                    for_roots(&data, std::slice::from_ref(r)).unwrap();
                });
            }
        });
        let json: CapSids =
            serde_json::from_slice(&std::fs::read(data.join(FILE)).unwrap()).unwrap();
        assert_eq!(json.writable_root_by_path.len(), 8);
    }
}
