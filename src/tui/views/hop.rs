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
                lines.push(Line::from(vec![
                    Span::styled("  Min: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms    ", stats.min_rtt.as_secs_f64() * 1000.0)),
                    Span::styled("Avg: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms    ", stats.avg_rtt().as_secs_f64() * 1000.0)),
                    Span::styled("Max: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms", stats.max_rtt.as_secs_f64() * 1000.0)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("  StdDev: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms    ", stats.stddev().as_secs_f64() * 1000.0)),
                    Span::styled("Jitter: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.2}ms", stats.jitter().as_secs_f64() * 1000.0)),
                ]));
            }

            // Other responders
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
