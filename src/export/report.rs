use std::io::Write;

use crate::lookup::sanitize_display;
use crate::state::Session;

/// Generate a text report similar to mtr --report
pub fn generate_report<W: Write>(session: &Session, mut writer: W) -> std::io::Result<()> {
    // Sanitize user-supplied strings to prevent terminal output injection
    let target_orig = sanitize_display(&session.target.original);
    let target_resolved = session.target.resolved.to_string();
    writeln!(
        writer,
        "ttl report for {} ({})",
        target_orig, target_resolved
    )?;
    writeln!(
        writer,
        "Started: {}",
        session.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    )?;
    if let Some(ref iface) = session.config.interface {
        let safe_iface = sanitize_display(iface);
        writeln!(writer, "Interface: {}", safe_iface)?;
    }
    writeln!(writer)?;

    // Header
    writeln!(
        writer,
        "{:>3}  {:<46} {:>6} {:>6} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "#", "Host", "Loss%", "Sent", "Avg", "Min", "Max", "StdDev", "Jitter"
    )?;
    writeln!(writer, "{}", "-".repeat(116))?;

    // Only show hops up to the destination
    let max_ttl = session.dest_ttl.unwrap_or(session.config.max_ttl);
    for hop in &session.hops {
        if hop.sent == 0 || hop.ttl > max_ttl {
            continue;
        }

        let host = if let Some(stats) = hop.primary_stats() {
            if let Some(ref hostname) = stats.hostname {
                format!("{} ({})", hostname, stats.ip)
            } else {
                stats.ip.to_string()
            }
        } else if hop.received == 0 {
            "* * *".to_string()
        } else {
            "???".to_string()
        };

        let (avg, min, max, stddev, jitter) = if let Some(stats) = hop.primary_stats() {
            if stats.received > 0 {
                (
                    format!("{:.1}ms", stats.avg_rtt().as_secs_f64() * 1000.0),
                    format!("{:.1}ms", stats.min_rtt.as_secs_f64() * 1000.0),
                    format!("{:.1}ms", stats.max_rtt.as_secs_f64() * 1000.0),
                    format!("{:.1}ms", stats.stddev().as_secs_f64() * 1000.0),
                    format!("{:.1}ms", stats.jitter().as_secs_f64() * 1000.0),
                )
            } else {
                ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
            }
        } else {
            ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
        };

        writeln!(
            writer,
            "{:>3}  {:<46} {:>5.1}% {:>6} {:>8} {:>8} {:>8} {:>8} {:>8}",
            hop.ttl,
            host,
            hop.loss_pct(),
            hop.sent,
            avg,
            min,
            max,
            stddev,
            jitter
        )?;
    }

    Ok(())
}

/// Generate report to string
#[allow(dead_code)]
pub fn generate_report_string(session: &Session) -> String {
    let mut buf = Vec::new();
    generate_report(session, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}
