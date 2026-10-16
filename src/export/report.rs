use std::io::Write;

use crate::lookup::sanitize_display;
use crate::state::{ResponderStats, Session};

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

        // Include every responder's extensions, including non-primary ECMP
        // responders, and keep shared reports stable across HashMap order.
        let mut responders: Vec<_> = hop.responders.values().collect();
        responders.sort_by_key(|stats| stats.ip);
        for stats in responders {
            write_extensions(&mut writer, stats)?;
        }
    }

    let mut errors: Vec<_> = session
        .hops
        .iter()
        .filter(|hop| hop.sent > 0 && hop.ttl <= max_ttl)
        .flat_map(|hop| {
            hop.responders.values().filter_map(move |stats| {
                stats
                    .last_icmp_error
                    .and_then(|error| error.processing_error_message())
                    .map(|message| (hop.ttl, stats.ip, message))
            })
        })
        .collect();
    errors.sort_by_key(|(ttl, ip, _)| (*ttl, *ip));
    if !errors.is_empty() {
        writeln!(writer, "\nICMPv6 rejections (last observed per responder):")?;
        for (ttl, ip, message) in errors {
            writeln!(writer, "  Hop {ttl}, from {ip}: {message}")?;
        }
    }

    Ok(())
}

fn write_extensions<W: Write>(writer: &mut W, stats: &ResponderStats) -> std::io::Result<()> {
    if let Some(labels) = &stats.mpls_labels
        && !labels.is_empty()
    {
        let stack = labels
            .iter()
            .map(|label| {
                format!(
                    "{} (TC {}, S {}, TTL {})",
                    label.label,
                    label.exp,
                    u8::from(label.bottom),
                    label.ttl
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        writeln!(writer, "     MPLS [{}]: {}", stats.ip, stack)?;
    }
    if let Some(interfaces) = &stats.interface_info {
        for iface in interfaces {
            let mut fields = Vec::new();
            if let Some(name) = &iface.name {
                fields.push(format!("{:?}", sanitize_display(name)));
            }
            if let Some(ip) = iface.ip_addr {
                fields.push(format!("IP {}", ip));
            }
            if let Some(index) = iface.if_index {
                fields.push(format!("ifIndex {}", index));
            }
            if let Some(mtu) = iface.mtu {
                fields.push(format!("MTU {}", mtu));
            }
            let detail = if fields.is_empty() {
                "(no details)".into()
            } else {
                fields.join(", ")
            };
            writeln!(
                writer,
                "     Interface [{}] {}: {}",
                stats.ip,
                iface.role.as_str(),
                detail
            )?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        state::{IcmpInterfaceInfo, InterfaceRole, MplsLabel, Target},
    };
    use std::time::Duration;

    fn session() -> Session {
        Session::new(
            Target::new("example.test".into(), "192.0.2.10".parse().unwrap()),
            Config::default(),
        )
    }

    #[test]
    fn report_includes_full_interface_details_and_mpls() {
        let mut session = session();
        let hop = session.hop_mut(1).unwrap();
        hop.record_sent();
        let interfaces = [
            InterfaceRole::IncomingIp,
            InterfaceRole::SubIpComponent,
            InterfaceRole::OutgoingIp,
            InterfaceRole::IpNextHop,
        ]
        .map(|role| IcmpInterfaceInfo {
            role,
            if_index: Some(1000001),
            ip_addr: Some("2001:db8::1".parse().unwrap()),
            name: Some("Ethernet123/456@a-router-with-a-long-hostname.example.net".into()),
            mtu: Some(9000),
        })
        .to_vec();
        hop.record_response_with_extensions(
            "192.0.2.1".parse().unwrap(),
            Duration::from_millis(5),
            Some(vec![MplsLabel {
                label: 416760,
                exp: 3,
                bottom: true,
                ttl: 1,
            }]),
            Some(interfaces),
        );
        let report = generate_report_string(&session);
        for role in ["Incoming", "Sub-IP", "Outgoing", "Next-Hop"] {
            assert!(report.contains(&format!("Interface [192.0.2.1] {role}:")));
        }
        assert!(report.contains("Ethernet123/456@a-router-with-a-long-hostname.example.net"));
        assert!(report.contains("IP 2001:db8::1, ifIndex 1000001, MTU 9000"));
        assert!(report.contains("MPLS [192.0.2.1]: 416760 (TC 3, S 1, TTL 1)"));
        assert!(report.contains("0.0%"));
    }

    #[test]
    fn report_keeps_secondary_responder_extensions_in_ip_order() {
        let mut session = session();
        let hop = session.hop_mut(1).unwrap();
        for ip in ["2001:db8::2", "2001:db8::1", "2001:db8::2"] {
            hop.record_sent();
            hop.record_response_with_extensions(
                ip.parse().unwrap(),
                Duration::from_millis(5),
                None,
                Some(vec![IcmpInterfaceInfo {
                    role: InterfaceRole::IncomingIp,
                    if_index: None,
                    ip_addr: None,
                    name: None,
                    mtu: Some(1500),
                }]),
            );
        }
        let report = generate_report_string(&session);
        let first = report.find("Interface [2001:db8::1]").unwrap();
        let second = report.find("Interface [2001:db8::2]").unwrap();
        assert!(first < second);
        assert!(!report.contains("ifIndex"));
    }

    #[test]
    fn report_sanitizes_remote_interface_names() {
        let mut stats = ResponderStats::new("192.0.2.1".parse().unwrap());
        stats.interface_info = Some(vec![IcmpInterfaceInfo {
            role: InterfaceRole::IncomingIp,
            if_index: None,
            ip_addr: None,
            name: Some("eth\x1b[31m\n\t\u{0085}1".into()),
            mtu: None,
        }]);
        let mut bytes = Vec::new();
        write_extensions(&mut bytes, &stats).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("eth[31m1"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn report_without_extensions_has_no_extra_rows() {
        let mut session = session();
        let hop = session.hop_mut(1).unwrap();
        hop.record_sent();
        hop.record_response("192.0.2.1".parse().unwrap(), Duration::from_millis(5));
        let report = generate_report_string(&session);
        assert!(!report.contains("Interface ["));
        assert!(!report.contains("MPLS ["));
        assert!(report.contains("192.0.2.1"));
        assert!(report.contains("5.0ms"));
    }
}
