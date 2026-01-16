pub mod asn;
pub mod geo;
pub mod ix;
pub mod rdns;

/// Sanitize a string for safe terminal display by removing control characters.
///
/// This filters out ASCII control characters (0x00-0x1F, 0x7F) and Unicode control
/// characters that could be used to inject terminal escape sequences.
pub(crate) fn sanitize_display(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect()
}
