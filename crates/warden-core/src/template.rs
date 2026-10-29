//! `${name}` expansion for adapter templates. `$$` is a literal `$`.

use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("unknown template variable `${{{0}}}`")]
    Unknown(String),
    #[error("unterminated `${{` in template")]
    Unterminated,
}

pub type Vars = BTreeMap<String, String>;

pub fn expand(input: &str, vars: &Vars) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        if let Some(r) = rest.strip_prefix('$') {
            out.push('$');
            rest = r;
        } else if let Some(r) = rest.strip_prefix('{') {
            let end = r.find('}').ok_or(TemplateError::Unterminated)?;
            let name = &r[..end];
            out.push_str(
                vars.get(name)
                    .ok_or_else(|| TemplateError::Unknown(name.into()))?,
            );
            rest = &r[end + 1..];
        } else {
            out.push('$');
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        [("home", "/h"), ("model", "m1")]
            .map(|(k, v)| (k.into(), v.into()))
            .into()
    }

    #[test]
    fn expands_and_escapes() {
        assert_eq!(expand("${home}/x ${model}", &vars()).unwrap(), "/h/x m1");
        assert_eq!(expand("$$${home}", &vars()).unwrap(), "$/h");
        assert_eq!(expand("$HOME plain", &vars()).unwrap(), "$HOME plain");
    }

    #[test]
    fn errors() {
        assert_eq!(
            expand("${nope}", &vars()),
            Err(TemplateError::Unknown("nope".into()))
        );
        assert_eq!(expand("${home", &vars()), Err(TemplateError::Unterminated));
    }
}
