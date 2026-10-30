//! Command line and environment block for `CreateProcessAsUserW`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt;

/// Appends `arg` quoted so the MSVCRT/`CommandLineToArgvW` parser reads it back verbatim.
fn quote_arg(arg: &[u16], out: &mut Vec<u16>) {
    let plain = !arg.is_empty()
        && !arg
            .iter()
            .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x22));
    if plain {
        out.extend_from_slice(arg);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0;
    for &c in arg {
        match c {
            c if c == b'\\' as u16 => backslashes += 1,
            c if c == b'"' as u16 => {
                // double the backslashes in front of a quote, then escape the quote
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                backslashes = 0;
                out.push(c);
            }
            c => {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // double trailing backslashes so they do not escape the closing quote
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    out.push(b'"' as u16);
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// NUL-terminated command line for `argv`. Windows runs `.cmd`/`.bat` targets
/// through cmd.exe, whose quoting differs from the MSVCRT rules above, so (like
/// Rust's std) arguments that cannot be passed safely to them are refused.
pub fn command_line(argv: &[OsString]) -> io::Result<Vec<u16>> {
    let is_batch = argv.first().is_some_and(|a| {
        let a = a.to_string_lossy().to_lowercase();
        a.ends_with(".cmd") || a.ends_with(".bat")
    });
    if is_batch
        && let Some(a) = argv[1..]
            .iter()
            .find(|a| a.to_string_lossy().contains(['"', '%', '\r', '\n']))
    {
        return Err(invalid(format!(
            "argument {a:?} contains a quote, percent sign or line break, which cmd.exe would misread when running {:?}",
            argv[0]
        )));
    }
    let mut line = Vec::new();
    for (i, a) in argv.iter().enumerate() {
        let wide: Vec<u16> = a.encode_wide().collect();
        if wide.contains(&0) {
            return Err(invalid("argument contains a NUL".into()));
        }
        if i > 0 {
            line.push(b' ' as u16);
        }
        quote_arg(&wide, &mut line);
    }
    line.push(0);
    Ok(line)
}

/// Unicode environment block: `KEY=value\0…\0\0`, sorted case-insensitively
/// with duplicate spellings of a name dropped (Windows names are case-insensitive).
pub fn env_block(env: &BTreeMap<String, String>) -> io::Result<Vec<u16>> {
    if let Some((k, _)) = env
        .iter()
        .find(|(k, v)| k.contains('\0') || v.contains('\0'))
    {
        return Err(invalid(format!(
            "environment variable {k:?} contains a NUL"
        )));
    }
    let mut entries: Vec<(&String, &String)> = env.iter().collect();
    entries.sort_by_key(|(k, _)| k.to_uppercase());
    entries.dedup_by(|a, b| a.0.eq_ignore_ascii_case(b.0));
    let mut block = Vec::new();
    for (k, v) in entries {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    if env.is_empty() {
        block.push(0);
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> String {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let w = command_line(&argv).unwrap();
        String::from_utf16(&w[..w.len() - 1]).unwrap()
    }

    #[test]
    fn quotes_like_msvcrt() {
        assert_eq!(line(&["a", "b"]), "a b");
        assert_eq!(line(&["a b"]), r#""a b""#);
        assert_eq!(line(&[""]), r#""""#);
        assert_eq!(line(&[r#"a"b"#]), r#""a\"b""#);
        assert_eq!(line(&[r"a\b"]), r"a\b");
        assert_eq!(line(&[r"a b\"]), r#""a b\\""#);
        assert_eq!(line(&[r#"a\"b"#]), r#""a\\\"b""#);
        assert_eq!(
            line(&[r"C:\Program Files\x\", "y"]),
            r#""C:\Program Files\x\\" y"#
        );
    }

    #[test]
    fn rejects_nul() {
        assert!(command_line(&[OsString::from("a\0b")]).is_err());
    }

    #[test]
    fn batch_targets_refuse_arguments_cmd_would_misread() {
        let argv = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            line(&["C:\\npm\\claude.CMD", "-p", "fix the bug"]),
            r#"C:\npm\claude.CMD -p "fix the bug""#
        );
        for bad in ["say \"hi\"", "100%", "a\nb", "a\rb"] {
            for exe in ["x.cmd", "X.BAT"] {
                assert!(command_line(&argv(&[exe, bad])).is_err(), "{exe} {bad:?}");
            }
            // other targets keep the MSVCRT quoting
            assert!(command_line(&argv(&["x.exe", bad])).is_ok(), "{bad:?}");
        }
    }

    #[test]
    fn env_values_with_nul_are_rejected() {
        let env = BTreeMap::from([("A".to_string(), "1\02".to_string())]);
        assert!(env_block(&env).is_err());
    }

    #[test]
    fn env_block_is_sorted_deduped_and_double_nul_terminated() {
        let env = BTreeMap::from([
            ("b".to_string(), "2".to_string()),
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "3".to_string()),
        ]);
        let block = env_block(&env).unwrap();
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(text, "A=1\0B=3\0\0");
        assert_eq!(env_block(&BTreeMap::new()).unwrap(), [0, 0]);
    }
}
