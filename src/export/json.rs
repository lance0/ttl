use anyhow::Result;
use std::io::Write;

use crate::state::Session;

/// Export session to JSON
pub fn export_json<W: Write>(session: &Session, writer: W) -> Result<()> {
    serde_json::to_writer_pretty(writer, session)?;
    Ok(())
}

/// Export session to JSON string
#[allow(dead_code)]
pub fn export_json_string(session: &Session) -> Result<String> {
    Ok(serde_json::to_string_pretty(session)?)
}

/// Export session to file with auto-generated name.
/// The target name is sanitized to prevent path traversal.
pub fn export_json_file(session: &Session) -> Result<String> {
    let timestamp = session.started_at.format("%Y%m%d-%H%M%S");
    let target = sanitize_filename(&session.target.original);
    let filename = format!("ttl-{}-{}.json", target, timestamp);

    export_json_to_path(session, std::path::Path::new(&filename))?;

    Ok(filename)
}

fn export_json_to_path(session: &Session, path: &std::path::Path) -> Result<()> {
    crate::persistence::atomic_write(path, false, |writer| export_json(session, writer))
}

/// Sanitize a string for safe use as a filename component.
/// Replaces path separators, control characters, and other unsafe chars with `_`.
fn sanitize_filename(s: &str) -> String {
    let mut sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Cap length so the final `ttl-<target>-<timestamp>.json` stays within the
    // filesystem's per-component limit (255 bytes on Linux/macOS). A legitimate
    // max-length FQDN (253 chars) plus the ~25-byte fixed overhead would otherwise
    // exceed it and fail export with ENAMETOOLONG. Truncate on a char boundary.
    const MAX_TARGET_BYTES: usize = 200;
    if sanitized.len() > MAX_TARGET_BYTES {
        let mut end = MAX_TARGET_BYTES;
        while !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized.truncate(end);
    }

    sanitized.truncate(sanitized.trim_end_matches([' ', '.']).len());
    if sanitized.is_empty() {
        return "_".to_string();
    }

    let base_name = sanitized
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(
        base_name.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        sanitized.insert(0, '_');
    }

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_exports_replace_with_complete_replayable_json() {
        use crate::{config::Config, state::Target};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let mut session = Session::new(
            Target::new("example.test".into(), "192.0.2.1".parse().unwrap()),
            Config::default(),
        );
        session.target.hostname = Some("a long previous hostname".into());
        export_json_to_path(&session, &path).unwrap();
        session.target.hostname = None;
        export_json_to_path(&session, &path).unwrap();
        let loaded: Session = serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(loaded.target.original, session.target.original);
        assert!(loaded.target.hostname.is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn test_sanitize_filename_replaces_path_and_control_chars() {
        assert_eq!(
            sanitize_filename("a/b\\c:d*e?f\"g<h>i|j"),
            "a_b_c_d_e_f_g_h_i_j"
        );
        assert_eq!(sanitize_filename("host\u{0085}name"), "host_name");
    }

    #[test]
    fn test_sanitize_filename_handles_windows_invalid_components() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_filename("router. "), "router");
        assert_eq!(sanitize_filename("..."), "_");
    }

    #[test]
    fn test_sanitize_filename_caps_length() {
        // ASCII: capped to <= 200 bytes.
        assert!(sanitize_filename(&"a".repeat(500)).len() <= 200);
        // Multibyte: must truncate on a char boundary (no panic) and stay bounded.
        let multibyte = sanitize_filename(&"é".repeat(300));
        assert!(multibyte.len() <= 200);
        assert!(multibyte.chars().all(|c| c == 'é'));
    }
}
