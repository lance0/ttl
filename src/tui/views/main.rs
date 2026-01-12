use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, Widget};

use crate::state::Session;
use crate::tui::theme::Theme;
use crate::tui::widgets::loss_sparkline_string;

/// Truncate a string to max_len characters, adding ellipsis if truncated
fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let truncated: String = s.chars().take(max_len - 1).collect();
        format!("{}…", truncated)
    }
}

/// Main table view showing all hops
pub struct MainView<'a> {
    session: &'a Session,
    selected: Option<usize>,
    paused: bool,
    theme: &'a Theme,
}

impl<'a> MainView<'a> {
    pub fn new(session: &'a Session, selected: Option<usize>, paused: bool, theme: &'a Theme) -> Self {
        Self {
            session,
            selected,
            paused,
            theme,
        }
    }
}

impl Widget for MainView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Build title
        let target_str = if let Some(ref hostname) = self.session.target.hostname {
            format!(
                "{} ({})",
                self.session.target.resolved, hostname
            )
        } else {
            self.session.target.resolved.to_string()
        };

        let status = if self.paused { " [PAUSED]" } else { "" };
        let probe_count = self.session.total_sent;
        let interval_ms = self.session.config.interval.as_millis();

        let title = format!(
            "ttl \u{2500}\u{2500} {} \u{2500}\u{2500} {} probes \u{2500}\u{2500} {}ms interval{}",
            target_str, probe_count, interval_ms, status
        );

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        // Build header
        let header = Row::new(vec![
            Cell::from("#").style(Style::default().bold()),
            Cell::from("Host").style(Style::default().bold()),
            Cell::from("Loss%").style(Style::default().bold()),
            Cell::from("Sent").style(Style::default().bold()),
            Cell::from("Avg").style(Style::default().bold()),
            Cell::from("Min").style(Style::default().bold()),
            Cell::from("Max").style(Style::default().bold()),
            Cell::from("StdDev").style(Style::default().bold()),
            Cell::from("Jitter").style(Style::default().bold()),
            Cell::from("").style(Style::default().bold()), // Sparkline
        ])
        .height(1);

        // Build rows - only show hops up to the destination
        let max_display_ttl = self.session.dest_ttl.unwrap_or(self.session.config.max_ttl);
        let rows: Vec<Row> = self
            .session
            .hops
            .iter()
            .filter(|h| h.sent > 0 && h.ttl <= max_display_ttl)
            .enumerate()
            .map(|(idx, hop)| {
                let is_selected = self.selected == Some(idx);

                let host = if let Some(stats) = hop.primary_stats() {
                    let display = if let Some(ref hostname) = stats.hostname {
                        hostname.clone()
                    } else {
                        stats.ip.to_string()
                    };
                    truncate_with_ellipsis(&display, 28)
                } else if hop.received == 0 {
                    "* * *".to_string()
                } else {
                    "???".to_string()
                };

                // Generate sparkline from hop-level results (shows both responses and timeouts)
                let recent: Vec<_> = hop.recent_results.iter().cloned().collect();
                let sparkline = loss_sparkline_string(&recent, 10);

                // Color sparkline based on recent loss rate
                let recent_loss = if recent.is_empty() {
                    0.0
                } else {
                    let failures = recent.iter().filter(|&&r| !r).count();
                    (failures as f64 / recent.len() as f64) * 100.0
                };
                let sparkline_color = if recent_loss > 50.0 {
                    self.theme.error
                } else if recent_loss > 10.0 {
                    self.theme.warning
                } else {
                    self.theme.success
                };

                let (avg, min, max, stddev, jitter) =
                    if let Some(stats) = hop.primary_stats() {
                        if stats.received > 0 {
                            (
                                format!("{:.1}", stats.avg_rtt().as_secs_f64() * 1000.0),
                                format!("{:.1}", stats.min_rtt.as_secs_f64() * 1000.0),
                                format!("{:.1}", stats.max_rtt.as_secs_f64() * 1000.0),
                                format!("{:.1}", stats.stddev().as_secs_f64() * 1000.0),
                                format!("{:.1}", stats.jitter().as_secs_f64() * 1000.0),
                            )
                        } else {
                            ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
                        }
                    } else {
                        ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
                    };

                let loss_style = if hop.loss_pct() > 50.0 {
                    Style::default().fg(self.theme.error)
                } else if hop.loss_pct() > 10.0 {
                    Style::default().fg(self.theme.warning)
                } else {
                    Style::default().fg(self.theme.success)
                };

                let row_style = if is_selected {
                    Style::default()
                        .bg(self.theme.highlight_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(hop.ttl.to_string()),
                    Cell::from(host),
                    Cell::from(format!("{:.1}%", hop.loss_pct())).style(loss_style),
                    Cell::from(hop.sent.to_string()),
                    Cell::from(avg),
                    Cell::from(min),
                    Cell::from(max),
                    Cell::from(stddev),
                    Cell::from(jitter),
                    Cell::from(sparkline).style(Style::default().fg(sparkline_color)),
                ])
                .style(row_style)
            })
            .collect();

        let widths = [
            Constraint::Length(3),  // #
            Constraint::Min(20),    // Host
            Constraint::Length(7),  // Loss%
            Constraint::Length(6),  // Sent
            Constraint::Length(8),  // Avg
            Constraint::Length(8),  // Min
            Constraint::Length(8),  // Max
            Constraint::Length(8),  // StdDev
            Constraint::Length(8),  // Jitter
            Constraint::Length(12), // Sparkline
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .highlight_style(Style::default().bg(self.theme.highlight_bg));

        table.render(inner, buf);
    }
}
