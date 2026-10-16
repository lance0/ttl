use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, StatefulWidget, Table, TableState, Widget};

use crate::prefs::DisplayMode;
use crate::state::{PmtudPhase, Session};
use crate::tui::theme::Theme;
use crate::tui::widgets::loss_history_line;

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

/// Host names below this width stop being recognisable; ASN yields first.
const READABLE_HOST: u16 = 18;
/// Numeric cells: "9999.9" ms or a six-digit probe count.
const NUM: u16 = 6;
/// Loss cell: "100.0%".
const LOSS: u16 = 6;
/// Loss cell plus a separate " RL" rate-limit tag.
const LOSS_RL: u16 = 9;
const HOST_COL: usize = 1;
const ASN_COL: usize = 2;
const LOSS_COL: usize = 3;
const LAST_COL: usize = 5;

/// `omit` lists columns that carry no information in this session (ASN with
/// lookups off; Last and Recent in a static replay).
fn table_layout(
    available: u16,
    preferred: &ColumnWidths,
    wide: bool,
    multi: bool,
    loss: u16,
    omit: &[usize],
) -> TableLayout {
    let mut sizes = vec![3, 8, 12, loss, NUM, NUM, NUM, NUM, NUM, NUM, NUM];
    if wide {
        sizes.extend([NUM, NUM]);
    }
    if multi {
        sizes.extend([3, 5]);
    }
    sizes.push(10);
    let recent = sizes.len() - 1;
    let mut indices: Vec<usize> = (0..sizes.len()).filter(|i| !omit.contains(i)).collect();
    // Drop secondary statistics before identity, loss, counts, and latency.
    let mut remove = Vec::new();
    if wide {
        remove.extend([12, 11]);
    }
    remove.extend([10, 9, 7, 8, ASN_COL, recent]);
    if multi {
        remove.extend([recent - 1, recent - 2]);
    }
    remove.extend([4, LAST_COL, 6, LOSS_COL]);
    // While ASN is shown, Host must keep a readable width, so secondary
    // statistics and then ASN itself go before Host is squeezed.
    let readable_host = READABLE_HOST.min(preferred.host).max(sizes[HOST_COL]);
    let total = |columns: &[usize]| -> u16 {
        let host_floor = if columns.contains(&ASN_COL) {
            readable_host - sizes[HOST_COL]
        } else {
            0
        };
        columns.iter().map(|&i| sizes[i]).sum::<u16>()
            + columns.len().saturating_sub(1) as u16
            + host_floor
    };
    for i in remove {
        if total(&indices) <= available {
            break;
        }
        indices.retain(|&column| column != i);
    }
    // Identity can consume spare space, but never steal numeric column widths.
    // Host takes ~60% and ASN ~40%, each only up to what its content needs.
    let spare = available.saturating_sub(total(&indices));
    if indices.contains(&ASN_COL) {
        sizes[HOST_COL] = readable_host;
        let host_room = preferred.host.saturating_sub(readable_host);
        let mut host = (spare * 3 / 5).min(host_room);
        let asn = (spare - host).min(preferred.asn.saturating_sub(sizes[ASN_COL]));
        host += (spare - host - asn).min(host_room - host);
        sizes[HOST_COL] += host;
        sizes[ASN_COL] += asn;
    } else {
        sizes[HOST_COL] += spare;
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

/// Counts and RTTs (Sent through Jitter, plus the wide jitter columns) are
/// right-aligned under right-aligned headers. Loss is padded instead, so a
/// trailing " RL" tag never shifts its digits.
fn build_header_cells(wide: bool, multi: bool, theme: &Theme) -> Vec<Cell<'static>> {
    let mut names = vec![
        "#", "Host", "ASN", "Loss", "Sent", "Last", "Avg", "Min", "Max", "StDev", "Jitter",
    ];
    if wide {
        names.extend(["JAvg", "JMax"]);
    }
    let numeric = 4..names.len();
    if multi {
        names.extend(["NAT", "Paths"]);
    }
    names.push("Recent");
    let style = Style::default().fg(theme.header).bold();
    names
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            let line = if i == LOSS_COL {
                Line::from(format!("{name:>0$}", usize::from(LOSS)))
            } else if numeric.contains(&i) {
                Line::from(name).right_aligned()
            } else {
                Line::from(name)
            };
            Cell::from(line).style(style)
        })
        .collect()
}

/// Scientific notation keeps unusually large counters/RTTs readable rather
/// than silently clipping digits. RTTs are still expressed in milliseconds.
fn numeric_cell(value: String) -> Line<'static> {
    let value = if value.len() <= usize::from(NUM) {
        value
    } else {
        value
            .parse::<f64>()
            .map(|n| format!("{n:.1e}"))
            .unwrap_or(value)
    };
    Line::from(value).right_aligned()
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
        let visible = || {
            self.session
                .hops
                .iter()
                .filter(move |h| h.sent > 0 && h.ttl <= max_display_ttl)
        };
        let rate_limited =
            |hop: &crate::state::Hop| hop.rate_limit.as_ref().is_some_and(|r| r.suspected);
        let loss_width = if visible().any(rate_limited) {
            LOSS_RL
        } else {
            LOSS
        };
        let mut omit = Vec::new();
        if !self.session.config.asn_enabled {
            omit.push(ASN_COL);
        }
        // A loaded session has no live clock: the last sample and the recent
        // outcome window describe nothing the viewer can watch.
        let static_replay = self.session.started_instant.is_none();
        if static_replay {
            omit.push(LAST_COL);
        }
        let preferred = self.compute_column_widths(max_display_ttl);
        let all_headers = build_header_cells(is_wide, multi_flow, self.theme);
        if static_replay {
            omit.push(all_headers.len() - 1);
        }
        let layout = table_layout(
            inner.width,
            &preferred,
            is_wide,
            multi_flow,
            loss_width,
            &omit,
        );
        let col_widths = ColumnWidths {
            host: layout.host,
            asn: layout.asn,
        };
        let header = Row::new(
            layout
                .indices
                .iter()
                .map(|&i| all_headers[i].clone())
                .collect::<Vec<_>>(),
        );
        let selected_theme = self.theme.for_selection();
        let rows: Vec<Row> = visible()
            .enumerate()
            .map(|(idx, hop)| {
                let is_selected = self.selected == Some(idx);
                let theme = if is_selected {
                    &selected_theme
                } else {
                    self.theme
                };
                let dim = Style::default().fg(theme.text_dim);
                let silent = hop.received == 0;

                let (host, asn_display) = if let Some(stats) = hop.primary_stats() {
                    let display = if let Some(ref hostname) = stats.hostname {
                        hostname.clone()
                    } else {
                        stats.ip.to_string()
                    };
                    let asn = if let Some(ref asn_info) = stats.asn {
                        // Preserve the full ASN; truncate only its optional name.
                        let number = format!("AS{}", asn_info.number);
                        if number.len() + 2 > usize::from(col_widths.asn) {
                            number
                        } else {
                            truncate_with_ellipsis(
                                &format!("{} {}", number, asn_info.name),
                                usize::from(col_widths.asn),
                            )
                        }
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
                    (Cell::from(format!("{}{}", truncated, indicators)), asn)
                } else if silent {
                    (Cell::from("* * *").style(dim), String::new())
                } else {
                    (Cell::from("???").style(dim), String::new())
                };

                let history = loss_history_line(&hop.recent_results, 10, theme, silent);

                // RTT columns in ms with one decimal; "–" until a reply exists.
                let ms = |d: std::time::Duration| format!("{:.1}", d.as_secs_f64() * 1000.0);
                let stats = hop.primary_stats().filter(|s| s.received > 0);
                let rtt = |value: Option<String>| match value {
                    Some(value) => Cell::from(numeric_cell(value)),
                    None => Cell::from(Line::from("–").right_aligned()).style(dim),
                };

                // Loss waits for a completed outcome; a fresh hop has none yet.
                let rate_limited = rate_limited(hop);
                let loss_cell = if hop.received + hop.timeouts == 0 {
                    Cell::from(format!("{:>1$}", "–", usize::from(LOSS))).style(dim)
                } else {
                    let loss = hop.loss_pct();
                    let mut color = theme.loss_color(loss);
                    if silent {
                        // Nothing ever answered (filtered hop, or past the
                        // destination): a quiet row, not a wall of alarms.
                        color = theme.text_dim;
                    } else if rate_limited && color == theme.error {
                        // ICMP rate limiting, not necessarily forwarding loss.
                        color = theme.warning;
                    }
                    let mut spans = vec![Span::styled(
                        format!("{:>1$}", format!("{loss:.1}%"), usize::from(LOSS)),
                        Style::default().fg(color),
                    )];
                    if rate_limited {
                        spans.push(Span::styled(" RL", dim));
                    }
                    Cell::from(Line::from(spans))
                };

                let row_style = if is_selected {
                    Style::default()
                        .fg(theme.text)
                        .bg(theme.highlight_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                };

                let mut cells = vec![
                    Cell::from(hop.ttl.to_string()),
                    host,
                    Cell::from(asn_display).style(dim),
                    loss_cell,
                    Cell::from(numeric_cell(hop.sent.to_string())),
                    rtt(stats.and_then(|s| s.last_rtt()).map(ms)),
                    rtt(stats.map(|s| ms(s.avg_rtt()))),
                    rtt(stats.map(|s| ms(s.min_rtt))),
                    rtt(stats.map(|s| ms(s.max_rtt))),
                    rtt(stats.map(|s| ms(s.stddev()))),
                    rtt(stats.map(|s| ms(s.jitter()))),
                ];
                if is_wide {
                    cells.push(rtt(stats.map(|s| ms(s.jitter_avg()))));
                    cells.push(rtt(stats.map(|s| ms(s.jitter_max()))));
                }

                // Add "NAT" and "Paths" columns if multi-flow mode
                if multi_flow {
                    // NAT indicator
                    let nat_display = if hop.has_nat() { "!" } else { "" };
                    cells.push(Cell::from(nat_display).style(Style::default().fg(theme.warning)));

                    // Paths (ECMP detection), highlighted only when they differ
                    let paths_style = if hop.has_ecmp() {
                        Style::default().fg(theme.warning)
                    } else {
                        Style::default()
                    };
                    cells.push(Cell::from(hop.path_count().to_string()).style(paths_style));
                }

                cells.push(Cell::from(history));

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
                let preferred = ColumnWidths { host: 45, asn: 36 };
                let layout = table_layout(available, &preferred, wide, multi, LOSS_RL, &[]);
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
                    layout.indices.iter().all(|&i| i < build_header_cells(
                        wide,
                        multi,
                        &Theme::default()
                    )
                    .len())
                );
                if available >= 58 {
                    assert!(layout.indices.contains(&3));
                    assert!(layout.indices.contains(&6));
                }
                if layout.indices.contains(&ASN_COL) {
                    assert!(layout.host >= READABLE_HOST, "{available}: host squeezed");
                }
            }
        }
    }

    #[test]
    fn narrow_budget_drops_sent_before_last_and_asn_before_host() {
        let preferred = ColumnWidths { host: 45, asn: 36 };
        // 80x24 terminal: secondary statistics go, Host and ASN stay readable.
        let layout = table_layout(78, &preferred, false, false, LOSS, &[]);
        assert!(layout.indices.contains(&ASN_COL) && !layout.indices.contains(&8));
        assert!(layout.host >= READABLE_HOST);
        // ASN yields rather than squeezing Host below a readable width.
        for available in 30..200 {
            let layout = table_layout(available, &preferred, false, false, LOSS, &[]);
            if layout.indices.contains(&ASN_COL) {
                assert!(layout.host >= READABLE_HOST, "{available}");
            }
        }
        assert!(
            !table_layout(58, &preferred, false, false, LOSS, &[])
                .indices
                .contains(&ASN_COL)
        );
        // Squeeze until one of Sent/Last must go: Sent goes first.
        let layout = table_layout(36, &preferred, false, false, LOSS, &[]);
        assert!(!layout.indices.contains(&4) && layout.indices.contains(&LAST_COL));
        // Wide terminals split spare width ~60/40 between Host and ASN.
        let layout = table_layout(130, &preferred, false, false, LOSS, &[]);
        assert!(
            layout.host > layout.asn && layout.asn > 12,
            "{} {}",
            layout.host,
            layout.asn
        );
        // Omitted columns never appear.
        let layout = table_layout(240, &preferred, false, false, LOSS, &[ASN_COL, LAST_COL]);
        assert!(!layout.indices.contains(&ASN_COL) && !layout.indices.contains(&LAST_COL));
    }

    #[test]
    fn huge_numbers_remain_complete() {
        assert_eq!(numeric_cell("9999.9".into()).to_string(), "9999.9");
        for value in [u64::MAX.to_string(), "123456789.1".into()] {
            let compact = numeric_cell(value).to_string();
            assert!(compact.len() <= usize::from(NUM));
            assert!(compact.parse::<f64>().is_ok());
        }
    }

    /// One buffer row; every cell here is a single char, so char index == x.
    fn row(buf: &Buffer, y: u16) -> Vec<char> {
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
            .collect()
    }

    fn find(row: &[char], pat: &str) -> Option<usize> {
        let pat: Vec<char> = pat.chars().collect();
        row.windows(pat.len()).position(|w| w == pat.as_slice())
    }

    /// The `len` cells ending at `end`.
    fn ending(row: &[char], end: usize, len: usize) -> String {
        row[end - len..end].iter().collect()
    }

    fn sample_session() -> Session {
        use crate::{config::Config, state::Target};
        use std::time::Duration;
        let mut session = Session::new(
            Target::new("example.net".into(), "192.0.2.9".parse().unwrap()),
            Config::default(),
        );
        let replies = [(0, 3, 0), (1, 9, 1), (2, 0, 4)];
        for (i, received, timeouts) in replies {
            let hop = &mut session.hops[i];
            for _ in 0..received + timeouts {
                hop.record_sent();
            }
            let ip = format!("192.0.2.{}", i + 1).parse().unwrap();
            for r in 0..received {
                hop.record_response(ip, Duration::from_micros(1500 + 100_000 * r));
            }
            for _ in 0..timeouts {
                hop.record_timeout();
            }
        }
        session.hops[3].record_sent(); // probe in flight, no outcome yet
        session
    }

    #[test]
    fn numeric_cells_right_align_and_loss_keeps_one_format() {
        let session = sample_session();
        let area = Rect::new(0, 0, 120, 10);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &Theme::default()).render(area, &mut buf);
        let header = row(&buf, 1);
        let text: String = header.iter().collect();
        for name in [
            "Loss", "Sent", "Last", "Avg", "Min", "Max", "StDev", "Jitter",
        ] {
            assert!(text.contains(name), "{name} missing: {text}");
        }
        assert!(!text.contains("ms ") && !text.contains("Loss%"));
        let end = |name: &str| find(&header, name).unwrap() + name.len();
        // Hop 1: 0% loss; hop 2: 10%; hop 3: no reply ever; hop 4: pending.
        let (r1, r2, r3, r4) = (row(&buf, 2), row(&buf, 3), row(&buf, 4), row(&buf, 5));
        assert_eq!(ending(&r1, end("Loss"), 4), "0.0%");
        assert_eq!(ending(&r2, end("Loss"), 5), "10.0%");
        assert_eq!(ending(&r3, end("Loss"), 6), "100.0%");
        assert_eq!(ending(&r4, end("Loss"), 2), " –");
        // Right-aligned digits end where the header ends.
        assert_eq!(ending(&r1, end("Sent"), 2), " 3");
        assert_eq!(ending(&r2, end("Sent"), 2), "10");
        assert_eq!(ending(&r1, end("Min"), 4), " 1.5");
        assert_eq!(ending(&r3, end("Avg"), 2), " –");
        // Recent stays left-aligned with its history.
        assert_eq!(find(&header, "Recent"), find(&r1, "·"));
        assert!(find(&r3, "* * *").is_some());
    }

    #[test]
    fn rate_limit_tag_is_separate_and_quiet() {
        let mut session = sample_session();
        session.hops[1].rate_limit = Some(crate::state::RateLimitInfo {
            suspected: true,
            ..Default::default()
        });
        let theme = Theme::dracula();
        let area = Rect::new(0, 0, 120, 10);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &theme).render(area, &mut buf);
        let r2 = row(&buf, 3);
        let x = find(&r2, "10.0% RL").expect("separate RL tag") as u16;
        assert_eq!(buf[(x + 6, 3)].fg, theme.text_dim);
        // Loss color follows the shared thresholds (10% = warning).
        assert_eq!(buf[(x, 3)].fg, theme.warning);
        // A hop that never answered stays quiet: dim loss and dim crosses.
        let r3 = row(&buf, 4);
        let x = find(&r3, "100.0%").unwrap() as u16;
        assert_eq!(buf[(x, 4)].fg, theme.text_dim);
        let x = find(&r3, "×").unwrap() as u16;
        assert_eq!(buf[(x, 4)].fg, theme.text_dim);
    }

    #[test]
    fn asn_column_is_omitted_when_lookups_are_off() {
        let mut session = sample_session();
        let area = Rect::new(0, 0, 120, 10);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &Theme::default()).render(area, &mut buf);
        assert!(find(&row(&buf, 1), "ASN").is_some());
        session.config.asn_enabled = false;
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &Theme::default()).render(area, &mut buf);
        assert!(find(&row(&buf, 1), "ASN").is_none());
    }

    #[test]
    fn static_replay_hides_last_and_recent() {
        let mut session = sample_session();
        session.started_instant = None; // as loaded from a file
        let area = Rect::new(0, 0, 120, 10);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &Theme::default()).render(area, &mut buf);
        let header = row(&buf, 1);
        assert!(find(&header, "Last").is_none() && find(&header, "Recent").is_none());
        assert!(find(&header, "Avg").is_some());
    }

    #[test]
    fn unselected_rows_keep_terminal_foreground() {
        use crate::{config::Config, state::Target};
        use ratatui::style::Color;
        let mut session = Session::new(
            Target::new("example.net".into(), "192.0.2.1".parse().unwrap()),
            Config::default(),
        );
        session.hops[0].sent = 1;
        session.hops[1].sent = 1;
        let area = Rect::new(0, 0, 80, 10);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, Some(0), false, &Theme::default()).render(area, &mut buf);
        // Row 3 is hop 2: border, header, selected hop 1, then this row. The
        // default ANSI theme must not force White text onto light terminals.
        assert_eq!(buf[(1, 3)].symbol(), "2");
        assert_eq!(buf[(1, 3)].fg, Color::Reset);
        // RGB themes do color rows and headers with their own text colors.
        let theme = Theme::matrix();
        let mut buf = Buffer::empty(area);
        MainView::new(&session, Some(0), false, &theme).render(area, &mut buf);
        assert_eq!(buf[(1, 3)].fg, theme.text);
        assert_eq!(buf[(1, 1)].fg, theme.header);
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
