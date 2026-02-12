use anyhow::Result;
use std::io::Write;

use crate::state::Session;

/// Export session to CSV format
pub fn export_csv<W: Write>(session: &Session, mut writer: W) -> Result<()> {
    // Write header
    writeln!(
        writer,
        "ttl,ip,hostname,loss_pct,sent,recv,last_ms,avg_ms,min_ms,max_ms,stddev_ms,jitter_ms,jitter_avg_ms,jitter_max_ms"
    )?;

    // Write rows for each hop (only up to destination)
    let max_ttl = session.dest_ttl.unwrap_or(session.config.max_ttl);
    for hop in &session.hops {
        if hop.sent == 0 || hop.ttl > max_ttl {
            continue;
        }

        let (ip, hostname, last, avg, min, max, stddev, jitter, jitter_avg, jitter_max) =
            if let Some(stats) = hop.primary_stats() {
                let hostname = stats.hostname.clone().unwrap_or_default();
                if stats.received > 0 {
                    (
                        stats.ip.to_string(),
                        hostname,
                        stats
                            .last_rtt()
                            .map(|d| format!("{:.2}", d.as_secs_f64() * 1000.0))
                            .unwrap_or_default(),
                        format!("{:.2}", stats.avg_rtt().as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.min_rtt.as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.max_rtt.as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.stddev().as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.jitter().as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.jitter_avg().as_secs_f64() * 1000.0),
                        format!("{:.2}", stats.jitter_max().as_secs_f64() * 1000.0),
                    )
                } else {
                    (
                        stats.ip.to_string(),
                        hostname,
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    )
                }
            } else {
                (
                    "*".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            };

        writeln!(
            writer,
            "{},{},{},{:.1},{},{},{},{},{},{},{},{},{},{}",
            hop.ttl,
            ip,
            escape_csv(&hostname),
            hop.loss_pct(),
            hop.sent,
            hop.received,
            last,
            avg,
            min,
            max,
            stddev,
            jitter,
            jitter_avg,
            jitter_max,
        )?;
    }

    Ok(())
}

/// Escape a string for CSV (quote if contains comma, quote, or newline)
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::Target;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    /// Parse a CSV row respecting quoted fields (handles commas inside quotes)
    fn parse_csv_row(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if in_quotes => {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                '"' if !in_quotes => in_quotes = true,
                ',' if !in_quotes => {
                    fields.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            }
        }
        fields.push(current);
        fields
    }

    /// Find a column's index by name from the CSV header
    fn col_index(header: &str, name: &str) -> usize {
        parse_csv_row(header)
            .iter()
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("column '{}' not found in header: {}", name, header))
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
    }

    #[test]
    fn test_parse_csv_row() {
        assert_eq!(parse_csv_row("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(parse_csv_row("a,\"b,c\",d"), vec!["a", "b,c", "d"]);
        assert_eq!(parse_csv_row("a,\"b\"\"c\",d"), vec!["a", "b\"c", "d"]);
        assert_eq!(parse_csv_row(",,"), vec!["", "", ""]);
    }

    #[test]
    fn test_csv_header_column_count() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let session = Session::new(target, Config::default());
        let mut buf = Vec::new();
        export_csv(&session, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let header = output.lines().next().unwrap();
        let cols = parse_csv_row(header);
        assert_eq!(cols.len(), 14);
        assert_eq!(cols[0], "ttl");
        assert_eq!(cols[6], "last_ms");
        assert_eq!(cols[12], "jitter_avg_ms");
        assert_eq!(cols[13], "jitter_max_ms");
    }

    #[test]
    fn test_csv_row_field_count_matches_header() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(8),
            );
        }
        session.dest_ttl = Some(1);
        let mut buf = Vec::new();
        export_csv(&session, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        let header_cols = parse_csv_row(lines[0]);
        let row_cols = parse_csv_row(lines[1]);
        assert_eq!(
            header_cols.len(),
            row_cols.len(),
            "row field count must match header"
        );
    }

    #[test]
    fn test_csv_no_response_row_field_count() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_sent();
        }
        session.dest_ttl = Some(1);
        let mut buf = Vec::new();
        export_csv(&session, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        let header_cols = parse_csv_row(lines[0]);
        let row_cols = parse_csv_row(lines[1]);
        assert_eq!(
            header_cols.len(),
            row_cols.len(),
            "no-response row must still have 14 fields"
        );
    }

    #[test]
    fn test_csv_last_ms_value_correctness() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(12),
            );
        }
        session.dest_ttl = Some(1);
        let mut buf = Vec::new();
        export_csv(&session, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let mut lines = output.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        let fields = parse_csv_row(row);
        let last_idx = col_index(header, "last_ms");
        // Last response was 12ms
        let last_val: f64 = fields[last_idx].parse().expect("last_ms should be numeric");
        assert!(
            (last_val - 12.0).abs() < 0.1,
            "last_ms should be ~12.00, got {}",
            last_val
        );
    }

    #[test]
    fn test_csv_last_ms_empty_after_replay() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
        }
        let json = serde_json::to_string(&session).unwrap();
        let replayed: Session = serde_json::from_str(&json).unwrap();
        let mut buf = Vec::new();
        export_csv(&replayed, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let mut lines = output.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        let last_idx = col_index(header, "last_ms");
        let fields = parse_csv_row(row);
        assert_eq!(
            fields[last_idx], "",
            "last_ms should be empty after JSON replay"
        );
    }

    #[test]
    fn test_csv_quoted_hostname() {
        let target = Target::new("test.com".into(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
            // Inject a hostname with comma and quote to exercise CSV escaping
            if let Some(stats) = hop.responders.values_mut().next() {
                stats.hostname = Some("host,with\"special".to_string());
            }
        }
        session.dest_ttl = Some(1);
        let mut buf = Vec::new();
        export_csv(&session, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let mut lines = output.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        let header_fields = parse_csv_row(header);
        let row_fields = parse_csv_row(row);
        assert_eq!(
            header_fields.len(),
            row_fields.len(),
            "quoted hostname must not break field count"
        );
        let hostname_idx = col_index(header, "hostname");
        assert_eq!(row_fields[hostname_idx], "host,with\"special");
    }
}
