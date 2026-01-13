use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

use crate::state::Hop;
use crate::tui::theme::Theme;
use crate::tui::widgets::sparkline_string;

/// Expanded hop detail view (modal overlay)
pub struct HopDetailView<'a> {
    hop: &'a Hop,
    theme: &'a Theme,
}

impl<'a> HopDetailView<'a> {
    pub fn new(hop: &'a Hop, theme: &'a Theme) -> Self {
        Self { hop, theme }
    }
}

impl Widget for HopDetailView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate centered popup area
        let popup_width = area.width.saturating_sub(10).min(80);
        let popup_height = area.height.saturating_sub(6).min(25);
        let popup_x = (area.width - popup_width) / 2 + area.x;
        let popup_y = (area.height - popup_height) / 2 + area.y;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear the popup area
        Clear.render(popup_area, buf);

        let stats = self.hop.primary_stats();
        let ip = stats.map(|s| s.ip.to_string()).unwrap_or_else(|| "* * *".to_string());
        let title = format!(" Hop {}: {} ", self.hop.ttl, ip);

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let mut lines = Vec::new();

        if let Some(stats) = stats {
            // Hostname
            if let Some(ref hostname) = stats.hostname {
                lines.push(Line::from(vec![
                    Span::styled("  Hostname:  ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(hostname.clone()),
                ]));
            }

            // IP address
            lines.push(Line::from(vec![
                Span::styled("  IP:        ", Style::default().fg(self.theme.text_dim)),
                Span::raw(stats.ip.to_string()),
            ]));

            // ASN (if available)
            if let Some(ref asn) = stats.asn {
                lines.push(Line::from(vec![
                    Span::styled("  ASN:       ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("AS{} ({})", asn.number, asn.name)),
                ]));
                if let Some(ref prefix) = asn.prefix {
                    lines.push(Line::from(vec![
                        Span::styled("  Prefix:    ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(prefix.clone()),
                    ]));
                }
            }

            // Geo (if available)
            if let Some(ref geo) = stats.geo {
                let location = [
                    geo.city.as_deref(),
                    geo.region.as_deref(),
                    Some(geo.country.as_str()),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");

                lines.push(Line::from(vec![
                    Span::styled("  Location:  ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(location),
                ]));
            }

            lines.push(Line::from(""));

            // Sparkline visualization
            let recent: Vec<_> = stats.recent.iter().cloned().collect();
            let sparkline = sparkline_string(&recent, (inner.width - 4) as usize);
            if !sparkline.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  Latency:   ", Style::default().fg(self.theme.text_dim)),
                    Span::styled(sparkline, Style::default().fg(self.theme.success)),
                ]));
            }

            lines.push(Line::from(""));

            // Stats
            lines.push(Line::from(vec![
                Span::styled("  Sent: ", Style::default().fg(self.theme.text_dim)),
                Span::raw(format!("{:<8}", stats.sent)),
                Span::styled("Received: ", Style::default().fg(self.theme.text_dim)),
                Span::raw(format!("{:<8}", stats.received)),
                Span::styled("Loss: ", Style::default().fg(self.theme.text_dim)),
                Span::styled(
                    format!("{:.1}%", stats.loss_pct()),
                    if stats.loss_pct() > 10.0 {
                        Style::default().fg(self.theme.error)
                    } else {
                        Style::default().fg(self.theme.success)
                    },
                ),
            ]));

            lines.push(Line::from(""));

            // RTT stats
            if stats.received > 0 {
                // Basic latency stats
                lines.push(Line::from(vec![
                    Span::styled("  Min: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms    ", stats.min_rtt.as_secs_f64() * 1000.0)),
                    Span::styled("Avg: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms    ", stats.avg_rtt().as_secs_f64() * 1000.0)),
                    Span::styled("Max: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms", stats.max_rtt.as_secs_f64() * 1000.0)),
                ]));

                // Last RTT and StdDev
                let last_rtt = stats
                    .last_rtt()
                    .map(|d| format!("{:.2}ms", d.as_secs_f64() * 1000.0))
                    .unwrap_or_else(|| "-".to_string());
                lines.push(Line::from(vec![
                    Span::styled("  Last: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:<9}", last_rtt)),
                    Span::styled("StdDev: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms", stats.stddev().as_secs_f64() * 1000.0)),
                ]));

                // Percentiles (if we have enough samples)
                if let (Some(p50), Some(p95), Some(p99)) = (stats.p50(), stats.p95(), stats.p99()) {
                    lines.push(Line::from(vec![
                        Span::styled("  p50: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{:.2}ms    ", p50.as_secs_f64() * 1000.0)),
                        Span::styled("p95: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{:.2}ms    ", p95.as_secs_f64() * 1000.0)),
                        Span::styled("p99: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{:.2}ms", p99.as_secs_f64() * 1000.0)),
                    ]));
                }

                lines.push(Line::from(""));

                // Jitter stats (RTT variance between consecutive probes)
                // "Smoothed" = RFC 3550 exponential average, "Avg/Max" = raw sample deltas
                lines.push(Line::from(vec![
                    Span::styled("  Jitter (smoothed): ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms  ", stats.jitter().as_secs_f64() * 1000.0)),
                    Span::styled("Avg: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms  ", stats.jitter_avg().as_secs_f64() * 1000.0)),
                    Span::styled("Max: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms", stats.jitter_max().as_secs_f64() * 1000.0)),
                ]));
            }

            // MPLS labels (if present)
            if let Some(ref labels) = stats.mpls_labels {
                lines.push(Line::from(""));
                let label_str = labels
                    .iter()
                    .map(|l| format!("{} (TTL {})", l.label, l.ttl))
                    .collect::<Vec<_>>()
                    .join(" → ");
                lines.push(Line::from(vec![
                    Span::styled("  MPLS: ", Style::default().fg(self.theme.text_dim)),
                    Span::styled(label_str, Style::default().fg(self.theme.shortcut)),
                ]));
            }

            // NAT detection info (if present)
            if let Some(ref nat_info) = self.hop.nat_info {
                lines.push(Line::from(""));
                if nat_info.has_nat() {
                    lines.push(Line::from(vec![Span::styled(
                        "  NAT Detected!",
                        Style::default().fg(self.theme.warning),
                    )]));
                    lines.push(Line::from(vec![
                        Span::styled("  Port matches: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", nat_info.port_matched)),
                        Span::styled("  Rewrites: ", Style::default().fg(self.theme.text_dim)),
                        Span::styled(
                            format!("{} ({:.0}%)", nat_info.port_rewritten, nat_info.nat_percentage()),
                            Style::default().fg(self.theme.warning),
                        ),
                    ]));

                    // Show rewrite samples (original → returned)
                    if !nat_info.rewrite_samples.is_empty() {
                        let samples: Vec<String> = nat_info.rewrite_samples
                            .iter()
                            .take(3)
                            .map(|(orig, ret)| format!("{}->{}", orig, ret))
                            .collect();
                        lines.push(Line::from(vec![
                            Span::styled("  Samples: ", Style::default().fg(self.theme.text_dim)),
                            Span::raw(samples.join(", ")),
                        ]));
                    }

                    // Warning about ECMP accuracy
                    if self.hop.flow_paths.len() > 1 {
                        lines.push(Line::from(vec![Span::styled(
                            "  Warning: ECMP results may be inaccurate due to NAT",
                            Style::default().fg(self.theme.error),
                        )]));
                    }
                } else if nat_info.total_checks() > 0 {
                    // Port checks passed - no NAT detected
                    lines.push(Line::from(vec![
                        Span::styled("  NAT: ", Style::default().fg(self.theme.text_dim)),
                        Span::styled("No", Style::default().fg(self.theme.success)),
                        Span::styled(
                            format!(" ({} checks)", nat_info.total_checks()),
                            Style::default().fg(self.theme.text_dim),
                        ),
                    ]));
                }
            }

            // Per-flow paths (Paris/Dublin traceroute ECMP detection)
            if !self.hop.flow_paths.is_empty() && self.hop.has_ecmp() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "  Per-Flow Paths (ECMP detected):",
                    Style::default().fg(self.theme.warning),
                )]));

                let ecmp_paths = self.hop.ecmp_paths();
                let num_paths = self.hop.path_count();
                for (flow_id, responder_ip) in &ecmp_paths {
                    // Look up hostname from responders map
                    let hostname = self.hop.responders.get(responder_ip)
                        .and_then(|s| s.hostname.as_ref())
                        .map(|h| format!(" ({})", h))
                        .unwrap_or_default();

                    // Mark if this is a unique path
                    let is_unique = ecmp_paths.iter()
                        .filter(|(_, ip)| ip == responder_ip)
                        .count() == 1;
                    let marker = if is_unique && num_paths > 1 { " ← alt path" } else { "" };

                    lines.push(Line::from(vec![
                        Span::raw(format!("    Flow {}: ", flow_id)),
                        Span::raw(format!("{}{}", responder_ip, hostname)),
                        Span::styled(marker, Style::default().fg(self.theme.shortcut)),
                    ]));
                }
            } else if !self.hop.flow_paths.is_empty() && self.hop.flow_paths.len() > 1 {
                // Show flows even without ECMP (all same path)
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  Flows: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{} (single path)", self.hop.flow_paths.len())),
                ]));
            }

            // Other responders (aggregate view)
            if self.hop.responders.len() > 1 {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "  Other responders at this TTL:",
                    Style::default().fg(self.theme.warning),
                )]));

                for (ip, other_stats) in &self.hop.responders {
                    if *ip != stats.ip {
                        let hostname = other_stats
                            .hostname
                            .as_ref()
                            .map(|h| format!(" ({})", h))
                            .unwrap_or_default();
                        lines.push(Line::from(vec![
                            Span::raw("    "),
                            Span::raw(format!("{}{}", ip, hostname)),
                            Span::styled(
                                format!(" - {} responses, avg {:.1}ms", other_stats.received, other_stats.avg_rtt().as_secs_f64() * 1000.0),
                                Style::default().fg(self.theme.text_dim),
                            ),
                        ]));
                    }
                }
            }
        } else {
            lines.push(Line::from("  No responses received at this TTL"));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  [Esc] back", Style::default().fg(self.theme.text_dim)),
        ]));

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}
