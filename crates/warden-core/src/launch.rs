//! Launch orchestration lives in the CLI crate for milestone 1 (it needs every
//! leaf crate). This module holds the pieces that are pure logic.

use std::path::{Path, PathBuf};

/// Default per-user deny list for the filesystem sandbox: secret stores a coding
/// agent has no business reading. Orgs extend it through the policy catalog.
pub fn default_deny_read(home: &Path) -> Vec<PathBuf> {
    [
        ".ssh",
        ".aws",
        ".gnupg",
        ".azure",
        ".kube",
        ".config/gcloud",
        ".docker/config.json",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".cargo/credentials.toml",
        ".cargo/credentials",
        ".config/gh",
        ".local/share/warden",
        "Library/Keychains",
        ".password-store",
    ]
    .iter()
    .map(|p| home.join(p))
    .collect()
}
