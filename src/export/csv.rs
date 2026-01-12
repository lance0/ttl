use anyhow::Result;
use std::io::Write;

use crate::state::Session;

/// Export session to CSV format
pub fn export_csv<W: Write>(session: &Session, mut writer: W) -> Result<()> {
    // Write header
    writeln!(
        writer,
        "ttl,ip,hostname,loss_pct,sent,recv,avg_ms,min_ms,max_ms,stddev_ms,jitter_ms"
    )?;

    // Write rows for each hop
    for hop in &session.hops {
        if hop.sent == 0 {
            continue;
        }

        let (ip, hostname, avg, min, max, stddev, jitter) = if let Some(stats) = hop.primary_stats()
        {
            let hostname = stats.hostname.clone().unwrap_or_default();
            if stats.received > 0 {
                (
                    stats.ip.to_string(),
                    hostname,
                    format!("{:.2}", stats.avg_rtt().as_secs_f64() * 1000.0),
                    format!("{:.2}", stats.min_rtt.as_secs_f64() * 1000.0),
                    format!("{:.2}", stats.max_rtt.as_secs_f64() * 1000.0),
                    format!("{:.2}", stats.stddev().as_secs_f64() * 1000.0),
                    format!("{:.2}", stats.jitter().as_secs_f64() * 1000.0),
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
            )
        };

        writeln!(
            writer,
            "{},{},{},{:.1},{},{},{},{},{},{},{}",
            hop.ttl,
            ip,
            escape_csv(&hostname),
            hop.loss_pct(),
            hop.sent,
            hop.received,
            avg,
            min,
            max,
            stddev,
            jitter
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

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
    }
}
