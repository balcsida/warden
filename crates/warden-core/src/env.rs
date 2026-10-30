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
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "PROGRAMDATA",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "TEMP",
    "TMP",
];
const PASSTHROUGH_PREFIX: &[&str] = &["LC_"];

/// Variables that may be passed only when policy explicitly allows them.
pub const OPTIONAL: &[&str] = &["SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "GPG_TTY"];

/// Windows variable names are case-insensitive (`SystemRoot`, `Path`), so match
/// and key them in upper case there; other platforms match exactly.
pub fn base_from_parent(
    parent: impl Iterator<Item = (String, String)>,
    optional: &[&str],
) -> BTreeMap<String, String> {
    parent
        .map(|(k, v)| (if cfg!(windows) { k.to_uppercase() } else { k }, v))
        .filter(|(k, _)| {
            PASSTHROUGH.contains(&k.as_str())
                || PASSTHROUGH_PREFIX.iter().any(|p| k.starts_with(p))
                || optional.iter().any(|o| {
                    if cfg!(windows) {
                        o.eq_ignore_ascii_case(k)
                    } else {
                        o == k
                    }
                })
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

    #[cfg(windows)]
    #[test]
    fn windows_names_match_case_insensitively() {
        let parent = [
            ("SystemRoot", r"C:\Windows"),
            ("Path", "x"),
            ("ssh_auth_sock", "s"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let env = base_from_parent(parent.into_iter(), &["ssh_auth_sock"]);
        assert_eq!(
            env.keys().collect::<Vec<_>>(),
            ["PATH", "SSH_AUTH_SOCK", "SYSTEMROOT"]
        );
    }
}
