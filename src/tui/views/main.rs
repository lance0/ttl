use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, Widget};

use crate::prefs::DisplayMode;
use crate::state::{PmtudPhase, Session};
use crate::tui::theme::Theme;
use crate::tui::widgets::loss_sparkline_string;

/// Column width limits for autosize mode
const MAX_HOST_WIDTH: u16 = 60;
const MAX_ASN_WIDTH: u16 = 30;
const COMPACT_HOST: u16 = 20;
const COMPACT_ASN: u16 = 12;
const WIDE_HOST: u16 = 45;
const WIDE_ASN: u16 = 24;
const MIN_HOST: u16 = 12;
const MIN_ASN: u16 = 8;

/// Computed column widths for rendering
struct ColumnWidths {
    host: u16,
    asn: u16,
}

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
    /// Display mode for column widths (auto/compact/wide)
    display_mode: DisplayMode,
}

impl<'a> MainView<'a> {
    pub fn new(
        session: &'a Session,
        selected: Option<usize>,
        paused: bool,
        theme: &'a Theme,
    ) -> Self {
        Self {
            session,
            selected,
            paused,
            theme,
            target_index: None,
            num_targets: 1,
            display_mode: DisplayMode::Auto,
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

    /// Set display mode for column widths
    pub fn with_display_mode(mut self, display_mode: DisplayMode) -> Self {
        self.display_mode = display_mode;
        self
    }

    /// Compute column widths based on display mode and content
    fn compute_column_widths(&self, max_display_ttl: u8) -> ColumnWidths {
        match self.display_mode {
            DisplayMode::Compact => ColumnWidths {
                host: COMPACT_HOST,
                asn: COMPACT_ASN,
            },
            DisplayMode::Wide => ColumnWidths {
                host: WIDE_HOST,
                asn: WIDE_ASN,
            },
            DisplayMode::Auto => {
                let mut max_host: usize = MIN_HOST as usize;
                let mut max_asn: usize = MIN_ASN as usize;

                for hop in self
                    .session
                    .hops
                    .iter()
                    .filter(|h| h.sent > 0 && h.ttl <= max_display_ttl)
                {
                    if let Some(stats) = hop.primary_stats() {
                        // Host length + room for indicators
                        let host_len = stats
                            .hostname
                            .as_ref()
                            .map(|h| h.chars().count())
                            .unwrap_or_else(|| stats.ip.to_string().len())
                            + 4; // space for " !~^"
                        max_host = max_host.max(host_len);

                        // ASN column shows "AS##### name", account for full format
                        if let Some(ref asn) = stats.asn {
                            // "AS" (2) + digits + " " (1) + name
                            let digits = asn.number.checked_ilog10().unwrap_or(0) as usize + 1;
                            let asn_len = 3 + digits + asn.name.chars().count();
                            max_asn = max_asn.max(asn_len);
                        }
                    }
                }

                ColumnWidths {
                    host: (max_host as u16).clamp(MIN_HOST, MAX_HOST_WIDTH),
                    asn: (max_asn as u16).clamp(MIN_ASN, MAX_ASN_WIDTH),
                }
            }
        }
    }
}

impl Widget for MainView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Build title
        // If original was a hostname (not an IP), show "hostname -> IP"
        // If original was an IP, show "IP (hostname)" with reverse DNS
        let target_str = if self
            .session
            .target
            .original
            .parse::<std::net::IpAddr>()
            .is_err()
        {
            // Was a hostname, show hostname -> IP
            format!(
                "{} -> {}",
                self.session.target.display_name(),
                self.session.target.resolved
            )
        } else {
            // Was an IP, show IP (hostname) as before
            if let Some(ref hostname) = self.session.target.hostname {
                format!("{} ({})", self.session.target.resolved, hostname)
            } else {
                self.session.target.resolved.to_string()
            }
        };

        // Target indicator for multi-target mode
        let target_indicator = if let Some(idx) = self.target_index {
            format!("[{}/{}] ", idx, self.num_targets)
        } else {
            String::new()
        };

        let status = if self.paused { " [PAUSED]" } else { "" };
        let nat_warn = if self.session.has_nat() { " [NAT]" } else { "" };
        let has_rate_limit = self
            .session
            .hops
            .iter()
            .any(|h| h.rate_limit.as_ref().map(|r| r.suspected).unwrap_or(false));
        let rl_warn = if has_rate_limit { " [RL?]" } else { "" };
        let has_asymmetry = self.session.hops.iter().any(|h| h.has_asymmetry());
        let asym_warn = if has_asymmetry { " [ASYM]" } else { "" };
        let has_ttl_manip = self.session.hops.iter().any(|h| h.has_ttl_manip());
        let ttl_warn = if has_ttl_manip { " [TTL!]" } else { "" };

        // Warning if destination not found and using default max_ttl=30
        let max_ttl_warn = if self.session.dest_ttl.is_none() && self.session.config.max_ttl == 30 {
            " [max_ttl=30]"
        } else {
            ""
        };

        // PMTUD status indicator
        let pmtud_status = self
            .session
            .pmtud
            .as_ref()
            .map(|p| match p.phase {
                PmtudPhase::WaitingForDestination => String::new(),
                PmtudPhase::Searching => format!(" [MTU: {}-{}]", p.min_size, p.max_size),
                PmtudPhase::Complete => p
                    .discovered_mtu
                    .map(|mtu| format!(" [MTU: {}]", mtu))
                    .unwrap_or_default(),
            })
            .unwrap_or_default();

        let probe_count = self.session.total_sent;
        let interval_ms = self.session.config.interval.as_millis();

        // Show routing info: interface name, source IP, and gateway
        let routing_str = {
            let iface = self.session.config.interface.as_ref();
            let src_ip = self.session.source_ip;
            let gateway = self.session.gateway;

            match (iface, src_ip, gateway) {
                // Full info: interface (source → gateway)
                (Some(i), Some(src), Some(gw)) => {
                    format!(" {} ({} → {})", i, src, gw)
                }
                // Interface with source only
                (Some(i), Some(src), None) => {
                    format!(" {} ({})", i, src)
                }
                // Interface only (fallback)
                (Some(i), None, _) => {
                    format!(" via {}", i)
                }
                // No interface but have routing info
                (None, Some(src), Some(gw)) => {
                    format!(" {} → {}", src, gw)
                }
                // Source only
                (None, Some(src), None) => {
                    format!(" {}", src)
                }
                // No routing info
                (None, None, _) => String::new(),
            }
        };

        let title = format!(
            "ttl \u{2500}\u{2500} {}{}{} \u{2500}\u{2500} {} probes \u{2500}\u{2500} {}ms interval{}{}{}{}{}{}{}",
            target_indicator,
            target_str,
            routing_str,
            probe_count,
            interval_ms,
            status,
            nat_warn,
            rl_warn,
            asym_warn,
            ttl_warn,
            max_ttl_warn,
            pmtud_status
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
        let col_widths = self.compute_column_widths(max_display_ttl);
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
                        // Use computed ASN width (minus 1 for padding)
                        // Show "AS##### name" so ASN number is always visible even when truncated
                        let asn_max_len = (col_widths.asn as usize).saturating_sub(1);
                        truncate_with_ellipsis(
                            &format!("AS{} {}", asn_info.number, asn_info.name),
                            asn_max_len,
                        )
                    } else {
                        String::new()
                    };
                    // Add indicators:
                    // ! = route flap (single-flow only)
                    // ~ = asymmetric routing (single-flow only)
                    // ^ = TTL manipulation (all flow modes)
                    let has_flap = !multi_flow && !hop.route_changes.is_empty();
                    let has_asym = !multi_flow && hop.has_asymmetry();
                    let has_ttl = hop.has_ttl_manip();
                    // Build indicator string
                    let mut ind = String::new();
                    if has_flap {
                        ind.push('!');
                    }
                    if has_asym {
                        ind.push('~');
                    }
                    if has_ttl {
                        ind.push('^');
                    }
                    let indicators = if ind.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", ind)
                    };
                    // Use computed host width for truncation
                    let max_len = (col_widths.host as usize).saturating_sub(indicators.len());
                    let truncated = truncate_with_ellipsis(&display, max_len);
                    (format!("{}{}", truncated, indicators), asn)
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

                let (avg, min, max, stddev, jitter) = if let Some(stats) = hop.primary_stats() {
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
                let rate_limited = hop
                    .rate_limit
                    .as_ref()
                    .map(|r| r.suspected)
                    .unwrap_or(false);

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

        // Build column widths - use computed widths from display mode
        let mut widths: Vec<Constraint> = vec![
            Constraint::Length(3),                  // #
            Constraint::Min(col_widths.host),       // Host (dynamic)
            Constraint::Length(col_widths.asn + 1), // ASN (dynamic, +1 for padding)
            Constraint::Length(7),                  // Loss%
            Constraint::Length(5),                  // Sent
            Constraint::Length(7),                  // Avg
            Constraint::Length(7),                  // Min
            Constraint::Length(7),                  // Max
            Constraint::Length(7),                  // StdDev
            Constraint::Length(7),                  // Jitter
        ];
        if multi_flow {
            widths.push(Constraint::Length(4)); // NAT
            widths.push(Constraint::Length(6)); // Paths
        }
        widths.push(Constraint::Length(11)); // Sparkline

        let table = Table::new(rows, widths)
            .header(header)
            .row_highlight_style(Style::default().bg(self.theme.highlight_bg));

        table.render(inner, buf);
    }
}
