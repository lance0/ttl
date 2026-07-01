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

    let file = std::fs::File::create(&filename)?;
    export_json(session, file)?;

    Ok(filename)
}

/// Sanitize a string for safe use as a filename component.
/// Replaces path separators, control characters, and other unsafe chars with `_`.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_control()
                || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
            {
                '_'
            } else {
                c
            }
        })
        .collect()
}
