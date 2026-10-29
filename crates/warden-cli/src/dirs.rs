//! Where warden looks for things. Overridable with `WARDEN_CONFIG` / `WARDEN_DATA`.

use std::path::PathBuf;

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn config_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("WARDEN_CONFIG") {
        return p.into();
    }
    if cfg!(target_os = "macos") {
        home().join("Library/Application Support/warden")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home)
            .join("warden")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".config"))
            .join("warden")
    }
}

pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("WARDEN_DATA") {
        return p.into();
    }
    if cfg!(target_os = "macos") {
        home().join("Library/Application Support/warden/data")
    } else if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home)
            .join("warden")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/share"))
            .join("warden")
    }
}

/// Root-owned system directory: trusted keys live here.
pub fn system_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/warden")
    } else if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("warden")
    } else {
        PathBuf::from("/etc/warden")
    }
}

pub fn trusted_keys_path(explicit: Option<&PathBuf>) -> PathBuf {
    explicit
        .cloned()
        .unwrap_or_else(|| system_dir().join("trusted-keys"))
}

pub fn bundle_path(explicit: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p.clone();
    }
    let user = config_dir().join("policy.bundle");
    if user.exists() {
        user
    } else {
        system_dir().join("policy.bundle")
    }
}

pub fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "other"
    }
}
