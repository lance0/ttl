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
    /// Current target index (1-indexed) for multi-target display
    target_index: Option<usize>,
    /// Total number of targets
    num_targets: usize,
}

impl<'a> MainView<'a> {
    pub fn new(session: &'a Session, selected: Option<usize>, paused: bool, theme: &'a Theme) -> Self {
        Self {
            session,
            selected,
            paused,
            theme,
            target_index: None,
            num_targets: 1,
        }
    }

    /// Set target info for multi-target display
    pub fn with_target_info(mut self, index: usize, total: usize) -> Self {
        if total > 1 {
            self.target_index = Some(index);
            self.num_targets = total;
        }
        self
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

        // Target indicator for multi-target mode
        let target_indicator = if let Some(idx) = self.target_index {
            format!("[{}/{}] ", idx, self.num_targets)
        } else {
            String::new()
        };

        let status = if self.paused { " [PAUSED]" } else { "" };
        let nat_warn = if self.session.has_nat() { " [NAT]" } else { "" };
        let has_rate_limit = self.session.hops.iter()
            .any(|h| h.rate_limit.as_ref().map(|r| r.suspected).unwrap_or(false));
        let rl_warn = if has_rate_limit { " [RL?]" } else { "" };
        let probe_count = self.session.total_sent;
        let interval_ms = self.session.config.interval.as_millis();

        // Show interface binding if specified
        let iface_str = self
            .session
            .config
            .interface
            .as_ref()
            .map(|i| format!(" via {}", i))
            .unwrap_or_default();

        let title = format!(
            "ttl \u{2500}\u{2500} {}{}{} \u{2500}\u{2500} {} probes \u{2500}\u{2500} {}ms interval{}{}{}",
            target_indicator, target_str, iface_str, probe_count, interval_ms, status, nat_warn, rl_warn
        );

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        // Check if multi-flow mode is enabled (Paris/Dublin traceroute)
        let multi_flow = self.session.config.flows > 1;

        // Build header - add "Paths" column if multi-flow enabled
        let mut header_cells = vec![
            Cell::from("#").style(Style::default().bold()),
            Cell::from("Host").style(Style::default().bold()),
            Cell::from("ASN").style(Style::default().bold()),
            Cell::from("Loss%").style(Style::default().bold()),
            Cell::from("Sent").style(Style::default().bold()),
            Cell::from("Avg").style(Style::default().bold()),
            Cell::from("Min").style(Style::default().bold()),
            Cell::from("Max").style(Style::default().bold()),
            Cell::from("StdDev").style(Style::default().bold()),
            Cell::from("Jitter").style(Style::default().bold()),
        ];
        if multi_flow {
            header_cells.push(Cell::from("NAT").style(Style::default().bold()));
            header_cells.push(Cell::from("Paths").style(Style::default().bold()));
        }
        header_cells.push(Cell::from("").style(Style::default().bold())); // Sparkline

        let header = Row::new(header_cells).height(1);

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

                let (host, asn_display) = if let Some(stats) = hop.primary_stats() {
                    let display = if let Some(ref hostname) = stats.hostname {
                        hostname.clone()
                    } else {
                        stats.ip.to_string()
                    };
                    let asn = if let Some(ref asn_info) = stats.asn {
                        truncate_with_ellipsis(&asn_info.name, 12)
                    } else {
                        String::new()
                    };
                    (truncate_with_ellipsis(&display, 28), asn)
                } else if hop.received == 0 {
                    ("* * *".to_string(), String::new())
                } else {
                    ("???".to_string(), String::new())
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

                // Determine if rate limiting is suspected
                let rate_limited = hop.rate_limit.as_ref().map(|r| r.suspected).unwrap_or(false);

                let loss_style = if rate_limited {
                    // Rate limited: show in different color to indicate it's not real loss
                    Style::default().fg(self.theme.shortcut)
                } else if hop.loss_pct() > 50.0 {
                    Style::default().fg(self.theme.error)
                } else if hop.loss_pct() > 10.0 {
                    Style::default().fg(self.theme.warning)
                } else {
                    Style::default().fg(self.theme.success)
                };

                // Format loss with "RL" indicator if rate limited
                let loss_display = if rate_limited {
                    format!("{:.0}%RL", hop.loss_pct())
                } else {
                    format!("{:.1}%", hop.loss_pct())
                };

                let row_style = if is_selected {
                    Style::default()
                        .bg(self.theme.highlight_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let mut cells = vec![
                    Cell::from(hop.ttl.to_string()),
                    Cell::from(host),
                    Cell::from(asn_display).style(Style::default().fg(self.theme.text_dim)),
                    Cell::from(loss_display).style(loss_style),
                    Cell::from(hop.sent.to_string()),
                    Cell::from(avg),
                    Cell::from(min),
                    Cell::from(max),
                    Cell::from(stddev),
                    Cell::from(jitter),
                ];

                // Add "NAT" and "Paths" columns if multi-flow mode
                if multi_flow {
                    // NAT indicator
                    let nat_display = if hop.has_nat() { "!" } else { "" };
                    let nat_style = if hop.has_nat() {
                        Style::default().fg(self.theme.warning)
                    } else {
                        Style::default()
                    };
                    cells.push(Cell::from(nat_display).style(nat_style));

                    // Paths (ECMP detection)
                    let path_count = hop.path_count();
                    let paths_style = if hop.has_ecmp() {
                        // ECMP detected - highlight with warning color
                        Style::default().fg(self.theme.warning)
                    } else {
                        Style::default()
                    };
                    cells.push(Cell::from(path_count.to_string()).style(paths_style));
                }

                cells.push(Cell::from(sparkline).style(Style::default().fg(sparkline_color)));

                Row::new(cells).style(row_style)
            })
            .collect();

        // Build column widths - conditional on multi-flow mode
        let mut widths: Vec<Constraint> = vec![
            Constraint::Length(3),  // #
            Constraint::Min(16),    // Host
            Constraint::Length(13), // ASN
            Constraint::Length(7),  // Loss%
            Constraint::Length(5),  // Sent
            Constraint::Length(7),  // Avg
            Constraint::Length(7),  // Min
            Constraint::Length(7),  // Max
            Constraint::Length(7),  // StdDev
            Constraint::Length(7),  // Jitter
        ];
        if multi_flow {
            widths.push(Constraint::Length(4)); // NAT
            widths.push(Constraint::Length(6)); // Paths
        }
        widths.push(Constraint::Length(11)); // Sparkline

        let table = Table::new(rows, widths)
            .header(header)
            .highlight_style(Style::default().bg(self.theme.highlight_bg));

        table.render(inner, buf);
    }
}
