//! Child environment composition. Nothing from the parent is inherited unless
//! it is on this allowlist, so a personal `ANTHROPIC_API_KEY` or `LITELLM_*`
//! never reaches the harness.

use std::collections::BTreeMap;

const PASSTHROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TMPDIR",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "NO_COLOR",
    "FORCE_COLOR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    // Windows essentials
    "SYSTEMROOT",
    "COMSPEC",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "PATHEXT",
];
const PASSTHROUGH_PREFIX: &[&str] = &["LC_"];

/// Variables that may be passed only when policy explicitly allows them.
pub const OPTIONAL: &[&str] = &["SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "GPG_TTY"];

pub fn base_from_parent(
    parent: impl Iterator<Item = (String, String)>,
    optional: &[&str],
) -> BTreeMap<String, String> {
    parent
        .filter(|(k, _)| {
            PASSTHROUGH.contains(&k.as_str())
                || PASSTHROUGH_PREFIX.iter().any(|p| k.starts_with(p))
                || optional.contains(&k.as_str())
        })
        .collect()
}

/// Proxy variables every common tool honours. `NO_PROXY` is set to the empty
/// string on purpose: inside the sandbox nothing is reachable without the proxy.
pub fn proxy_vars(proxy_url: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for k in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NPM_CONFIG_PROXY",
        "NPM_CONFIG_HTTPS_PROXY",
        "YARN_HTTP_PROXY",
        "YARN_HTTPS_PROXY",
        "PIP_PROXY",
        "BUNDLE_HTTP_PROXY",
        "BUNDLE_HTTPS_PROXY",
        "CARGO_HTTP_PROXY",
    ] {
        m.insert(k.into(), proxy_url.into());
    }
    m.insert("NO_PROXY".into(), String::new());
    m.insert("no_proxy".into(), String::new());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_provider_keys() {
        let parent = [
            ("PATH", "/bin"),
            ("ANTHROPIC_API_KEY", "sk"),
            ("LITELLM_API_KEY", "sk"),
            ("LC_ALL", "C"),
            ("SSH_AUTH_SOCK", "/s"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let env = base_from_parent(parent.clone().into_iter(), &[]);
        assert_eq!(env.keys().collect::<Vec<_>>(), ["LC_ALL", "PATH"]);
        let env = base_from_parent(parent.into_iter(), &["SSH_AUTH_SOCK"]);
        assert!(env.contains_key("SSH_AUTH_SOCK"));
    }
}
