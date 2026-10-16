use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, StatefulWidget, Table, TableState, Widget};

use crate::prefs::DisplayMode;
use crate::state::{PmtudPhase, Session};
use crate::tui::theme::Theme;
use crate::tui::widgets::loss_sparkline_string;

/// Column width limits for autosize mode
const MAX_HOST_WIDTH: u16 = 60;
const MAX_ASN_WIDTH: u16 = 40;
const COMPACT_HOST: u16 = 20;
const COMPACT_ASN: u16 = 12;
const WIDE_HOST: u16 = 45;
const WIDE_ASN: u16 = 36;
const MIN_HOST: u16 = 12;
const MIN_ASN: u16 = 8;

/// Computed column widths for rendering
struct ColumnWidths {
    host: u16,
    asn: u16,
}

/// Select whole columns that fit, preserving readable numeric cells. Extra
/// statistics remain available in the hop detail view at every terminal size.
struct TableLayout {
    indices: Vec<usize>,
    widths: Vec<Constraint>,
    host: u16,
    asn: u16,
}

fn table_layout(available: u16, preferred: &ColumnWidths, wide: bool, multi: bool) -> TableLayout {
    let mut sizes = vec![3, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7];
    if wide {
        sizes.extend([7, 7]);
    }
    if multi {
        sizes.extend([3, 5]);
    }
    sizes.push(10);
    let mut indices: Vec<usize> = (0..sizes.len()).collect();
    // Drop secondary statistics before identity, loss, counts, and latency.
    let mut remove = Vec::new();
    if wide {
        remove.extend([12, 11]);
    }
    remove.extend([10, 9, 7, 8, 2, sizes.len() - 1]);
    if multi {
        remove.extend([sizes.len() - 2, sizes.len() - 3]);
    }
    remove.extend([5, 4, 6, 3]);
    let total = |columns: &[usize], sizes: &[u16]| -> u16 {
        columns.iter().map(|&i| sizes[i]).sum::<u16>() + columns.len().saturating_sub(1) as u16
    };
    for i in remove {
        if total(&indices, &sizes) <= available {
            break;
        }
        indices.retain(|&column| column != i);
    }
    // Identity can consume spare space, but never steal numeric column widths.
    let spare = available.saturating_sub(total(&indices, &sizes));
    let host_extra = spare.min(preferred.host.saturating_sub(sizes[1]));
    sizes[1] += host_extra;
    if indices.contains(&2) {
        sizes[2] += (spare - host_extra).min(preferred.asn.saturating_sub(sizes[2]));
    } else {
        sizes[1] += spare - host_extra;
    }
    // Very small windows still get a host cell without arithmetic overflow.
    if available < 12 {
        indices = vec![1];
        sizes[1] = available;
    }
    TableLayout {
        widths: indices
            .iter()
            .map(|&i| Constraint::Length(sizes[i]))
            .collect(),
        indices,
        host: sizes[1],
        asn: sizes[2],
    }
}

fn build_header_cells(wide: bool, multi: bool) -> Vec<Cell<'static>> {
    let mut names = vec![
        "#", "Host", "ASN", "Loss%", "Sent", "Last ms", "Avg ms", "Min ms", "Max ms", "StdDev",
        "Jit ms",
    ];
    if wide {
        names.extend(["JAvg ms", "JMax ms"]);
    }
    if multi {
        names.extend(["NAT", "Paths"]);
    }
    names.push("Recent");
    names
        .into_iter()
        .map(|name| Cell::from(name).style(Style::default().bold()))
        .collect()
}

/// Scientific notation keeps unusually large counters/RTTs readable rather
/// than silently clipping digits. RTTs are still expressed in milliseconds.
fn numeric_cell(value: String) -> String {
    if value.len() <= 7 {
        return value;
    }
    value
        .parse::<f64>()
        .map(|n| format!("{n:.1e}"))
        .unwrap_or(value)
}

fn build_hop_indicators(
    multi_flow: bool,
    has_ecmp: bool,
    has_route_changes: bool,
    has_asymmetry: bool,
    has_ttl_manip: bool,
    has_extensions: bool,
) -> String {
    let show_ecmp_marker = !multi_flow && has_ecmp;
    let has_flap = !multi_flow && has_route_changes && !has_ecmp;
    let has_asym = !multi_flow && has_asymmetry;
    let has_ttl = has_ttl_manip;

    let mut ind = String::new();
    if show_ecmp_marker {
        ind.push('E');
    }
    if has_flap {
        ind.push('!');
    }
    if has_asym {
        ind.push('~');
    }
    if has_ttl {
        ind.push('^');
    }

    if has_extensions {
        ind.push('+');
    }

    if ind.is_empty() {
        String::new()
    } else {
        format!(" {}", ind)
    }
}

/// Truncate a string to max_len characters, adding ellipsis if truncated
fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    super::fit_text(s, max_len as u16)
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
                            + 5; // space for " E~^+" / " !~^+"
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
                    .unwrap_or_else(|| " [MTU: unconfirmed]".to_string()),
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

        let flags =
            format!("{status}{nat_warn}{rl_warn}{asym_warn}{ttl_warn}{pmtud_status}{max_ttl_warn}");
        let title = format!(
            "ttl{flags} ── {target_indicator}{target_str}{routing_str} ── {probe_count} probes ── {interval_ms}ms interval ── RTT ms"
        );
        let title = super::fit_text(&title, area.width.saturating_sub(2));

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        // Check if multi-flow mode is enabled (Paris/Dublin traceroute)
        let multi_flow = self.session.config.flows > 1;
        let is_wide = matches!(self.display_mode, DisplayMode::Wide);

        let max_display_ttl = self.session.dest_ttl.unwrap_or(self.session.config.max_ttl);
        let preferred = self.compute_column_widths(max_display_ttl);
        let layout = table_layout(inner.width, &preferred, is_wide, multi_flow);
        let col_widths = ColumnWidths {
            host: layout.host,
            asn: layout.asn,
        };
        let all_headers = build_header_cells(is_wide, multi_flow);
        let header = Row::new(
            layout
                .indices
                .iter()
                .map(|&i| all_headers[i].clone())
                .collect::<Vec<_>>(),
        );
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
                    // E = ECMP detected (single-flow only)
                    // ! = route flap (single-flow only, suppressed when ECMP is detected)
                    // ~ = asymmetric routing (single-flow only)
                    // ^ = TTL manipulation (all flow modes)
                    // + = ICMP interface/MPLS details available (Enter)
                    let indicators = build_hop_indicators(
                        multi_flow,
                        hop.has_ecmp(),
                        !hop.route_changes.is_empty(),
                        hop.has_asymmetry(),
                        hop.has_ttl_manip(),
                        hop.responders.values().any(|stats| {
                            stats.interface_info.as_ref().is_some_and(|v| !v.is_empty())
                                || stats.mpls_labels.as_ref().is_some_and(|v| !v.is_empty())
                        }),
                    );
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

                let (last, avg, min, max, stddev, jitter) = if let Some(stats) = hop.primary_stats()
                {
                    if stats.received > 0 {
                        (
                            stats
                                .last_rtt()
                                .map(|d| format!("{:.1}", d.as_secs_f64() * 1000.0))
                                .unwrap_or_else(|| "-".into()),
                            format!("{:.1}", stats.avg_rtt().as_secs_f64() * 1000.0),
                            format!("{:.1}", stats.min_rtt.as_secs_f64() * 1000.0),
                            format!("{:.1}", stats.max_rtt.as_secs_f64() * 1000.0),
                            format!("{:.1}", stats.stddev().as_secs_f64() * 1000.0),
                            format!("{:.1}", stats.jitter().as_secs_f64() * 1000.0),
                        )
                    } else {
                        (
                            "-".into(),
                            "-".into(),
                            "-".into(),
                            "-".into(),
                            "-".into(),
                            "-".into(),
                        )
                    }
                } else {
                    (
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        "-".into(),
                    )
                };

                let (j_avg, j_max) = if is_wide {
                    if let Some(stats) = hop.primary_stats() {
                        if stats.received > 0 {
                            (
                                format!("{:.1}", stats.jitter_avg().as_secs_f64() * 1000.0),
                                format!("{:.1}", stats.jitter_max().as_secs_f64() * 1000.0),
                            )
                        } else {
                            ("-".into(), "-".into())
                        }
                    } else {
                        ("-".into(), "-".into())
                    }
                } else {
                    (String::new(), String::new())
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
                    Cell::from(numeric_cell(hop.sent.to_string())),
                    Cell::from(numeric_cell(last)),
                    Cell::from(numeric_cell(avg)),
                    Cell::from(numeric_cell(min)),
                    Cell::from(numeric_cell(max)),
                    Cell::from(numeric_cell(stddev)),
                    Cell::from(numeric_cell(jitter)),
                ];
                if is_wide {
                    cells.push(Cell::from(numeric_cell(j_avg)));
                    cells.push(Cell::from(numeric_cell(j_max)));
                }

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

                Row::new(
                    layout
                        .indices
                        .iter()
                        .map(|&i| cells[i].clone())
                        .collect::<Vec<_>>(),
                )
                .style(row_style)
            })
            .collect();

        let table = Table::new(rows, layout.widths)
            .header(header)
            .row_highlight_style(Style::default().bg(self.theme.highlight_bg));
        let mut state = TableState::default().with_selected(self.selected);
        StatefulWidget::render(table, inner, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responsive_columns_fit_without_squeezing_numbers() {
        for available in [0, 5, 20, 40, 58, 78, 98, 158, 240] {
            for (wide, multi) in [(false, false), (true, false), (false, true), (true, true)] {
                let layout =
                    table_layout(available, &ColumnWidths { host: 45, asn: 36 }, wide, multi);
                let width: u16 = layout
                    .widths
                    .iter()
                    .map(|c| match c {
                        Constraint::Length(w) => *w,
                        _ => unreachable!(),
                    })
                    .sum();
                assert!(width + layout.widths.len().saturating_sub(1) as u16 <= available);
                assert!(
                    layout
                        .indices
                        .iter()
                        .all(|&i| i < build_header_cells(wide, multi).len())
                );
                if available >= 58 {
                    assert!(layout.indices.contains(&3));
                    assert!(layout.indices.contains(&6));
                }
            }
        }
    }

    #[test]
    fn huge_numbers_remain_complete() {
        assert_eq!(numeric_cell("12345.6".into()), "12345.6");
        for value in [u64::MAX.to_string(), "123456789.1".into()] {
            let compact = numeric_cell(value);
            assert!(compact.len() <= 7);
            assert!(compact.parse::<f64>().is_ok());
        }
    }

    #[test]
    fn test_extension_indicator_in_all_flow_modes() {
        for multi_flow in [false, true] {
            assert_eq!(
                build_hop_indicators(multi_flow, false, false, false, false, true),
                " +"
            );
        }
        assert_eq!(
            build_hop_indicators(false, true, true, true, true, true),
            " E~^+"
        );
    }

    #[test]
    fn test_build_hop_indicators_single_flow_ecmp_suppresses_flap() {
        let indicators = build_hop_indicators(true, true, true, true, true, false);
        assert_eq!(indicators, " ^", "multi-flow hides E/!/~ markers");

        let indicators = build_hop_indicators(false, true, true, true, true, false);
        assert_eq!(indicators, " E~^", "ECMP suppresses route flap marker");
    }
}
