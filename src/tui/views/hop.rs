use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::state::{EcmpKind, Hop, ResponderStats};
use crate::tui::theme::Theme;
use crate::tui::widgets::{sparkline_range, sparkline_spans};
use std::time::Duration;

/// Expanded hop detail view (modal overlay)
pub struct HopDetailView<'a> {
    hop: &'a Hop,
    theme: &'a Theme,
    scroll: u16,
}

impl<'a> HopDetailView<'a> {
    pub fn new(hop: &'a Hop, theme: &'a Theme) -> Self {
        Self {
            hop,
            theme,
            scroll: 0,
        }
    }

    pub fn with_scroll(mut self, scroll: u16) -> Self {
        self.scroll = scroll;
        self
    }
}

impl HopDetailView<'_> {
    fn popup_width(area: Rect) -> u16 {
        area.width.saturating_sub(10).min(80)
    }

    pub fn max_scroll(&self, area: Rect) -> u16 {
        let width = Self::popup_width(area).saturating_sub(super::POPUP_COLS);
        let height = u16::try_from(self.build_lines(width).len()).unwrap_or(u16::MAX);
        height.saturating_sub(Self::visible_rows(area))
    }

    /// Detail rows visible at once: popup margin (4) and the popup frame.
    pub fn visible_rows(area: Rect) -> u16 {
        area.height.saturating_sub(4 + super::POPUP_ROWS)
    }

    /// Popup title: hop number, hostname (or IP), and the short ASN name.
    fn title(&self) -> String {
        let Some(stats) = self.hop.primary_stats() else {
            return format!("Hop {} · * * *", self.hop.ttl);
        };
        let mut title = format!(
            "Hop {} · {}",
            self.hop.ttl,
            stats
                .hostname
                .clone()
                .unwrap_or_else(|| stats.ip.to_string())
        );
        if let Some(asn) = &stats.asn {
            title.push_str(&format!(" · AS{}", asn.number));
            // "KDDI - KDDI CORPORATION, JP" -> "KDDI"
            if let Some(short) = asn.name.split(" - ").next().filter(|s| !s.is_empty()) {
                title.push_str(&format!(" {short}"));
            }
        }
        title
    }

    /// Build all content lines for the modal
    fn build_lines(&self, inner_width: u16) -> Vec<Line<'static>> {
        let theme = self.theme;
        let dim = Style::default().fg(theme.text_dim);
        let text = Style::default().fg(theme.text);
        let warn = Style::default().fg(theme.warning);
        let mut lines = Vec::new();
        let Some(stats) = self.hop.primary_stats() else {
            lines.push(Line::styled("No responses received at this TTL", dim));
            return wrap_lines(lines, inner_width);
        };

        // Identity
        let mut field = |label: &str, value: String, style: Style| {
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<10}"), dim),
                Span::styled(value, style),
            ]));
        };
        if let Some(hostname) = &stats.hostname {
            field("Host", hostname.clone(), text);
        }
        field("IP", stats.ip.to_string(), text);
        if let Some(asn) = &stats.asn {
            field("ASN", format!("AS{}  {}", asn.number, asn.name), text);
            if let Some(prefix) = &asn.prefix {
                field("Prefix", prefix.clone(), text);
            }
        }
        if let Some(geo) = &stats.geo {
            let location = [
                geo.city.as_deref(),
                geo.region.as_deref(),
                Some(geo.country.as_str()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            field("Location", location, text);
        }
        if let Some(ix) = &stats.ix {
            let location = [ix.city.as_deref(), ix.country.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
            let ix_str = if location.is_empty() {
                ix.name.clone()
            } else {
                format!("{} ({})", ix.name, location)
            };
            field("IX", ix_str, text);
        }

        // Latency: sparkline, then counts and RTTs on the shared grid.
        let heading = |title: &str, style: Style| Line::styled(title.to_owned(), style.bold());
        let section = Style::default().fg(theme.header);
        lines.push(Line::default());
        lines.push(heading("Latency", section));
        let recent: Vec<_> = stats.recent.iter().copied().collect();
        if let Some(line) = sparkline_row(&recent, usize::from(inner_width), theme) {
            lines.push(line);
        }
        // Hop-level sent/loss: probes cannot be attributed to a responder
        // before a reply, so with several responders these are hop totals.
        let hop_loss = self.hop.loss_pct();
        let mut counts = grid(
            &[
                ("Sent", self.hop.sent.to_string(), text),
                ("Recv", self.hop.received.to_string(), text),
                (
                    "Loss",
                    format!("{hop_loss:.1}%"),
                    Style::default().fg(theme.loss_color(hop_loss)),
                ),
            ],
            6,
            dim,
        );
        if self.hop.responders.len() > 1 {
            counts.spans.push(Span::styled("  hop totals", dim));
        }
        lines.push(counts);
        if stats.received > 0 {
            let ms = |d: Duration| format!("{:.1} ms", d.as_secs_f64() * 1000.0);
            lines.push(grid(
                &[
                    ("Min", ms(stats.min_rtt), text),
                    ("Avg", ms(stats.avg_rtt()), text),
                    ("Max", ms(stats.max_rtt), text),
                ],
                6,
                dim,
            ));
            let last = stats.last_rtt().map(ms).unwrap_or_else(|| "–".into());
            lines.push(grid(
                &[("Last", last, text), ("StDev", ms(stats.stddev()), text)],
                6,
                dim,
            ));
            if let (Some(p50), Some(p95), Some(p99)) = (stats.p50(), stats.p95(), stats.p99()) {
                lines.push(grid(
                    &[
                        ("p50", ms(p50), text),
                        ("p95", ms(p95), text),
                        ("p99", ms(p99), text),
                    ],
                    6,
                    dim,
                ));
            }

            // Smoothed = RFC 3550 exponential average; Avg/Max = raw deltas.
            lines.push(Line::default());
            lines.push(heading("Jitter", section));
            lines.push(grid(
                &[
                    ("Smooth", ms(stats.jitter()), text),
                    ("Avg", ms(stats.jitter_avg()), text),
                    ("Max", ms(stats.jitter_max()), text),
                ],
                6,
                dim,
            ));
        }

        append_extensions(&mut lines, stats, theme);

        // NAT detection info (if present)
        if let Some(nat_info) = &self.hop.nat_info {
            if nat_info.has_nat() {
                lines.push(Line::default());
                lines.push(heading("NAT Detected", warn));
                lines.push(grid(
                    &[
                        ("Matched", nat_info.port_matched.to_string(), text),
                        (
                            "Rewritten",
                            format!(
                                "{} ({:.0}%)",
                                nat_info.port_rewritten,
                                nat_info.nat_percentage()
                            ),
                            warn,
                        ),
                    ],
                    10,
                    dim,
                ));
                // Rewrite samples (original -> returned)
                if !nat_info.rewrite_samples.is_empty() {
                    let samples: Vec<String> = nat_info
                        .rewrite_samples
                        .iter()
                        .take(3)
                        .map(|(orig, ret)| format!("{orig} → {ret}"))
                        .collect();
                    lines.push(note("Samples", samples.join(", "), text, dim));
                }
                if self.hop.flow_paths.len() > 1 {
                    lines.push(Line::styled(
                        "  ECMP results may be inaccurate behind NAT",
                        warn,
                    ));
                }
            } else if nat_info.total_checks() > 0 {
                lines.push(Line::default());
                lines.push(heading("NAT", section));
                lines.push(note(
                    "Ports",
                    format!("unchanged in {} checks", nat_info.total_checks()),
                    text,
                    dim,
                ));
            }
        }

        // Rate limit detection info (if present)
        if let Some(rl) = &self.hop.rate_limit
            && rl.suspected
        {
            lines.push(Line::default());
            lines.push(heading("Rate Limiting Suspected", warn));
            if let Some(reason) = &rl.reason {
                lines.push(note("Reason", reason.clone(), text, dim));
            }
            lines.push(note(
                "Confidence",
                format!("{:.0}%", rl.confidence * 100.0),
                text,
                dim,
            ));
            lines.push(note(
                "Tip",
                "try slower probing with -i 1.0 or -i 2.0".into(),
                dim,
                dim,
            ));
        }

        // Route changes (flaps) detected at this hop
        if !self.hop.route_changes.is_empty() {
            lines.push(Line::default());
            lines.push(heading(
                &format!("Route Changes ({})", self.hop.route_changes.len()),
                warn,
            ));
            for change in self.hop.route_changes.iter().rev().take(5) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {}", change.from_ip), text),
                    Span::styled(" → ", dim),
                    Span::styled(change.to_ip.to_string(), text),
                    Span::styled(format!("  after {} responses", change.at_seq), dim),
                ]));
            }
            if self.hop.route_changes.len() > 5 {
                lines.push(Line::styled(
                    format!("  … and {} more", self.hop.route_changes.len() - 5),
                    dim,
                ));
            }
        }

        // Asymmetric routing detection
        if let Some(asym) = &self.hop.asymmetry {
            let total = asym.symmetric_samples + asym.asymmetric_samples;
            if total >= 5 || asym.suspected {
                lines.push(Line::default());
                lines.push(if asym.suspected {
                    heading("Routing Asymmetry Detected", warn)
                } else {
                    heading("Routing Symmetry", section)
                });
                let diff_style = if asym.avg_hop_difference.abs() >= 3.0 {
                    warn
                } else {
                    text
                };
                lines.push(grid(
                    &[
                        ("Forward", self.hop.ttl.to_string(), text),
                        (
                            "Return",
                            asym.last_return_hops
                                .map(|h| h.to_string())
                                .unwrap_or_else(|| "–".into()),
                            text,
                        ),
                        (
                            "Diff",
                            format!("{:.0}", asym.avg_hop_difference),
                            diff_style,
                        ),
                    ],
                    10,
                    dim,
                ));
                lines.push(grid(
                    &[
                        ("Samples", total.to_string(), text),
                        ("Symmetric", asym.symmetric_samples.to_string(), text),
                        (
                            "Asymmetric",
                            asym.asymmetric_samples.to_string(),
                            if asym.asymmetric_samples > 0 {
                                warn
                            } else {
                                text
                            },
                        ),
                    ],
                    10,
                    dim,
                ));
                // High variance indicates return-path ECMP
                if asym.variance > 4.0 {
                    lines.push(note(
                        "Note",
                        "high variance, possible return-path ECMP".into(),
                        text,
                        dim,
                    ));
                }
            }
        }

        // TTL manipulation detection
        if let Some(ttl_info) = &self.hop.ttl_manip {
            let total = ttl_info.normal_samples + ttl_info.anomalous_samples;
            if total >= 5 || ttl_info.suspected {
                lines.push(Line::default());
                lines.push(if ttl_info.suspected {
                    heading("TTL Manipulation Detected", warn)
                } else {
                    heading("TTL Behavior", section)
                });
                if let Some(reason) = &ttl_info.reason {
                    lines.push(note("Reason", reason.clone(), warn, dim));
                }
                lines.push(grid(
                    &[
                        ("Sent TTL", self.hop.ttl.to_string(), text),
                        (
                            "Quoted",
                            ttl_info
                                .last_quoted_ttl
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| "–".into()),
                            text,
                        ),
                    ],
                    10,
                    dim,
                ));
                lines.push(grid(
                    &[
                        ("Samples", total.to_string(), text),
                        ("Normal", ttl_info.normal_samples.to_string(), text),
                        (
                            "Anomalous",
                            ttl_info.anomalous_samples.to_string(),
                            if ttl_info.anomalous_samples > 0 {
                                warn
                            } else {
                                text
                            },
                        ),
                    ],
                    10,
                    dim,
                ));
            }
        }

        // ECMP detail
        match self.hop.ecmp_kind() {
            EcmpKind::PerFlow => {
                lines.push(Line::default());
                lines.push(heading("Per-Flow Paths (ECMP)", warn));
                let ecmp_paths = self.hop.ecmp_paths();
                let num_paths = self.hop.path_count();
                for (flow_id, responder_ip) in &ecmp_paths {
                    let hostname = self
                        .hop
                        .responders
                        .get(responder_ip)
                        .and_then(|s| s.hostname.as_ref())
                        .map(|h| format!(" ({h})"))
                        .unwrap_or_default();
                    // Mark a path only one flow takes
                    let is_unique = ecmp_paths
                        .iter()
                        .filter(|(_, ip)| ip == responder_ip)
                        .count()
                        == 1;
                    let marker = if is_unique && num_paths > 1 {
                        "  alt path"
                    } else {
                        ""
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!("  Flow {flow_id:<4}"), dim),
                        Span::styled(format!("{responder_ip}{hostname}"), text),
                        Span::styled(marker, warn),
                    ]));
                }
            }
            EcmpKind::PerPacket => {
                lines.push(Line::default());
                lines.push(heading("Per-Packet ECMP", warn));
                lines.push(grid(
                    &[
                        ("Responders", self.hop.responders.len().to_string(), text),
                        ("Paths", self.hop.path_count().to_string(), text),
                    ],
                    10,
                    dim,
                ));
            }
            EcmpKind::None => {
                if self.hop.flow_paths.len() > 1 {
                    // Several flows, all on the same path
                    lines.push(Line::default());
                    lines.push(note(
                        "Flows",
                        format!("{} (single path)", self.hop.flow_paths.len()),
                        text,
                        dim,
                    ));
                }
            }
        }

        // Other responders (aggregate view)
        if self.hop.responders.len() > 1 {
            lines.push(Line::default());
            lines.push(heading("Other Responders", section));
            for (ip, other_stats) in &self.hop.responders {
                if *ip != stats.ip {
                    let hostname = other_stats
                        .hostname
                        .as_ref()
                        .map(|h| format!(" ({h})"))
                        .unwrap_or_default();
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {ip}{hostname}"), text),
                        Span::styled(
                            format!(
                                "  {} replies, avg {:.1} ms",
                                other_stats.received,
                                other_stats.avg_rtt().as_secs_f64() * 1000.0
                            ),
                            dim,
                        ),
                    ]));
                    append_extensions(&mut lines, other_stats, theme);
                }
            }
        }

        wrap_lines(lines, inner_width)
    }
}

/// Grid cell width: a fixed-width label plus its right-aligned value. Every
/// section uses the same cell width, so values line up down the popup.
const CELL: usize = 17;

/// One indented grid row: dim labels padded to `label` cells, values
/// right-aligned in the rest of each cell, three spaces between cells.
fn grid(cells: &[(&str, String, Style)], label: usize, dim: Style) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    for (i, (name, value, style)) in cells.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(format!("{name:<label$}"), dim));
        spans.push(Span::styled(format!("{value:>0$}", CELL - label), *style));
    }
    Line::from(spans)
}

/// A free-text row under a section: dim label, then the value.
fn note(label: &str, value: String, style: Style, dim: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label:<12}"), dim),
        Span::styled(value, style),
    ])
}

/// `164 ▁▂▁█ 485 ms`: the sparkline takes exactly the width left after its
/// indent and range labels, so the newest samples are never clipped.
fn sparkline_row(data: &[Option<Duration>], width: usize, theme: &Theme) -> Option<Line<'static>> {
    let (lo, hi) = sparkline_range(data)?;
    let (lo, hi) = (format!("{lo:.0} "), format!(" {hi:.0} ms"));
    let bars = width
        .checked_sub(2 + lo.len() + hi.len())
        .filter(|&w| w > 0)?;
    let dim = Style::default().fg(theme.text_dim);
    let mut spans = vec![Span::raw("  "), Span::styled(lo, dim)];
    spans.extend(sparkline_spans(data, bars, theme));
    spans.push(Span::styled(hi, dim));
    Some(Line::from(spans))
}

/// Wrap before measuring height, retaining span styles. Lines break at the
/// last space that fits and continue under the line's own leading indent
/// (a hanging indent); a word longer than the width breaks between
/// graphemes. Long interface/hostname values must not hide the MTU at the
/// end of a line.
pub(crate) fn wrap_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width);
    if width == 0 {
        return Vec::new();
    }
    let is_space = |span: &Span| span.content == " ";
    let mut wrapped = Vec::new();
    for line in lines {
        let graphemes: Vec<Span<'static>> = line
            .styled_graphemes(Style::default())
            .map(|g| Span::styled(g.symbol.to_owned(), g.style))
            .filter(|span| span.width() <= width)
            .collect();
        let indent = graphemes.iter().take_while(|s| is_space(s)).count();
        // An indent that leaves under half the width is not worth keeping.
        let indent = if indent * 2 < width { indent } else { 0 };
        let mut row: Vec<Span<'static>> = Vec::new();
        let mut used = 0;
        for span in graphemes {
            let cells = span.width();
            if used + cells > width && row.iter().any(|s| !is_space(s)) {
                // Break after the last space past the indent, else hard-break.
                let split = row
                    .iter()
                    .rposition(is_space)
                    .filter(|&i| i >= indent && row[..i].iter().skip(indent).any(|s| !is_space(s)))
                    .unwrap_or(row.len());
                let mut rest = row.split_off(split);
                while row.last().is_some_and(is_space) {
                    row.pop();
                }
                let start = rest.iter().take_while(|s| is_space(s)).count();
                rest.drain(..start);
                wrapped.push(Line::from(std::mem::take(&mut row)));
                row = vec![Span::raw(" "); indent];
                row.extend(rest);
                used = row.iter().map(Span::width).sum();
                if is_space(&span) && row.len() == indent {
                    continue; // the break consumed this space
                }
            }
            used += cells;
            row.push(span);
        }
        wrapped.push(Line::from(row));
    }
    wrapped
}

fn append_extensions(lines: &mut Vec<Line<'static>>, stats: &ResponderStats, theme: &Theme) {
    let heading = Style::default().fg(theme.header).bold();
    let dim = Style::default().fg(theme.text_dim);
    let text = Style::default().fg(theme.text);
    // MPLS labels (if present)
    if let Some(labels) = &stats.mpls_labels {
        lines.push(Line::default());
        lines.push(Line::styled("MPLS", heading));
        let label_str = labels
            .iter()
            .map(|l| format!("{} (TTL {})", l.label, l.ttl))
            .collect::<Vec<_>>()
            .join(" → ");
        lines.push(note("Labels", label_str, text, dim));
    }

    // RFC 5837 Interface Information (if present)
    if let Some(ifaces) = &stats.interface_info {
        lines.push(Line::default());
        lines.push(Line::styled("Interface (RFC 5837)", heading));
        for iface in ifaces {
            let mut parts = Vec::new();
            if let Some(name) = &iface.name {
                parts.push(name.clone());
            }
            if let Some(ip) = iface.ip_addr {
                parts.push(format!("IP {ip}"));
            }
            if let Some(if_index) = iface.if_index {
                parts.push(format!("idx {if_index}"));
            }
            if let Some(mtu) = iface.mtu {
                parts.push(format!("MTU {mtu}"));
            }
            let detail = if parts.is_empty() {
                "(no details)".to_string()
            } else {
                parts.join(", ")
            };
            lines.push(note(iface.role.as_str(), detail, text, dim));
        }
    }
}

impl Widget for HopDetailView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup_width = Self::popup_width(area);
        // Build content first: the sparkline and wrapping need the width,
        // and the popup height follows the content.
        let lines = self.build_lines(popup_width.saturating_sub(super::POPUP_COLS));
        let content_height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
        let popup_height = content_height
            .saturating_add(super::POPUP_ROWS)
            .min(area.height.saturating_sub(4));

        let content = super::popup(
            area,
            buf,
            (popup_width, popup_height),
            &self.title(),
            &[("↑/↓", "hop"), ("PgUp/PgDn", "scroll"), ("Esc", "back")],
            self.theme,
        );
        let max_scroll = content_height.saturating_sub(content.height);
        Paragraph::new(lines)
            .scroll((self.scroll.min(max_scroll), 0))
            .render(content, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{IcmpInterfaceInfo, InterfaceRole, MplsLabel};
    use std::time::Duration;

    fn extension_hop() -> Hop {
        let mut hop = Hop::new(3);
        hop.record_sent();
        hop.record_response_with_extensions(
            "192.0.2.1".parse().unwrap(),
            Duration::from_millis(10),
            None,
            Some(vec![IcmpInterfaceInfo {
                role: InterfaceRole::IncomingIp,
                if_index: Some(1000001),
                ip_addr: Some("2001:db8:1234:5678:abcd:abcd:abcd:abcd".parse().unwrap()),
                name: Some("Ethernet123/456@a-router-with-a-long-hostname.example.net".into()),
                mtu: Some(9000),
            }]),
        );
        hop
    }

    fn buffer_text(buf: &Buffer) -> String {
        buf.content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn long_interface_details_wrap_and_keep_mtu_visible() {
        let hop = extension_hop();
        let theme = Theme::default();
        for width in [60, 100, 200] {
            let area = Rect::new(0, 0, width, 50);
            let mut buf = Buffer::empty(area);
            HopDetailView::new(&hop, &theme).render(area, &mut buf);
            let text = buffer_text(&buf);
            assert!(text.contains("MTU 9000"), "MTU missing at width {width}");
        }
    }

    #[test]
    fn paging_by_visible_rows_reaches_every_line() {
        let hop = extension_hop();
        let theme = Theme::default();
        let area = Rect::new(0, 0, 70, 12);
        let view = HopDetailView::new(&hop, &theme);
        let (page, max) = (HopDetailView::visible_rows(area), view.max_scroll(area));
        assert!(max > page, "content must span several pages");
        let mut seen = Vec::new();
        for scroll in (0..=max).step_by(page.into()).chain([max]) {
            let mut buf = Buffer::empty(area);
            HopDetailView::new(&hop, &theme)
                .with_scroll(scroll)
                .render(area, &mut buf);
            seen.extend(
                buf.content
                    .chunks(70)
                    .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>()),
            );
        }
        for line in view.build_lines(70 - 10 - super::super::POPUP_COLS) {
            let line = line.to_string();
            let line = line.trim();
            assert!(
                line.is_empty() || seen.iter().any(|row| row.contains(line)),
                "{line:?} never shown"
            );
        }
    }

    #[test]
    fn small_terminal_can_scroll_to_end_without_losing_footer() {
        let hop = extension_hop();
        let theme = Theme::default();
        let area = Rect::new(0, 0, 70, 12);
        let view = HopDetailView::new(&hop, &theme);
        assert!(view.max_scroll(area) > 0);
        let mut buf = Buffer::empty(area);
        view.with_scroll(u16::MAX).render(area, &mut buf);
        let text = buffer_text(&buf);
        assert!(text.contains("MTU 9000"));
        assert!(text.contains("PgUp/PgDn"));
    }

    #[test]
    fn secondary_responder_extensions_are_visible() {
        let mut hop = extension_hop();
        let primary = "192.0.2.1".parse().unwrap();
        hop.record_response(primary, Duration::from_millis(10));
        hop.record_response_with_mpls(
            "192.0.2.2".parse().unwrap(),
            Duration::from_millis(20),
            Some(vec![MplsLabel {
                label: 416760,
                exp: 0,
                bottom: true,
                ttl: 1,
            }]),
        );
        let theme = Theme::default();
        let lines = HopDetailView::new(&hop, &theme).build_lines(78);
        let text = lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("192.0.2.2"));
        assert!(text.contains("416760 (TTL 1)"));
    }

    #[test]
    fn wrapping_preserves_unicode_graphemes_and_styles() {
        let style = Style::default().fg(ratatui::style::Color::Yellow);
        let value = "界e\u{301}🙂abcdef";
        let lines = wrap_lines(vec![Line::styled(value, style)], 4);
        assert!(lines.iter().all(|line| line.width() <= 4));
        assert_eq!(
            lines.iter().map(ToString::to_string).collect::<String>(),
            value
        );
        assert!(
            lines
                .iter()
                .flat_map(|line| &line.spans)
                .all(|span| span.style == style)
        );
        assert!(wrap_lines(vec![Line::from(value)], 0).is_empty());
    }

    fn latency_hop(samples: &[u64]) -> Hop {
        let mut hop = Hop::new(10);
        let ip = "203.0.113.5".parse().unwrap();
        for &ms in samples {
            hop.record_sent();
            hop.record_response(ip, Duration::from_millis(ms));
        }
        hop
    }

    #[test]
    fn sparkline_fits_beside_its_labels_and_keeps_the_newest_sample() {
        // A flat route with one final spike: the spike is the newest sample.
        let mut samples = vec![164; 59];
        samples.push(485);
        let hop = latency_hop(&samples);
        let theme = Theme::default();
        for width in [30u16, 46, 56, 76] {
            let lines = HopDetailView::new(&hop, &theme).build_lines(width);
            let row = lines
                .iter()
                .map(ToString::to_string)
                .find(|l| l.ends_with(" ms") && l.contains('▁'))
                .expect("sparkline row");
            assert!(row.chars().count() <= usize::from(width), "{width}: {row}");
            // Newest sample sits right before the range label, never clipped.
            assert!(row.contains("█ "), "{width}: {row}");
            assert!(row.starts_with("  164 ▁"), "{row}");
        }
    }

    #[test]
    fn sparkline_scale_ignores_a_single_outlier() {
        let mut data: Vec<_> = (0..40)
            .map(|i| Some(Duration::from_millis(10 + i % 8)))
            .collect();
        data.push(Some(Duration::from_millis(900)));
        let (lo, hi) = sparkline_range(&data).unwrap();
        assert!(lo >= 10.0 && hi <= 17.0, "{lo} {hi}");
        let bars: String = sparkline_spans(&data, 41, &Theme::default())
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        // Normal variation still spans several block heights.
        let distinct: std::collections::HashSet<char> = bars.chars().collect();
        assert!(distinct.len() >= 5, "{bars}");
        assert!(sparkline_range(&[None, None]).is_none());
    }

    #[test]
    fn detail_values_line_up_in_one_grid() {
        let hop = latency_hop(&[164, 170, 180, 485, 166]);
        let theme = Theme::dracula();
        let lines: Vec<String> = HopDetailView::new(&hop, &theme)
            .build_lines(76)
            .iter()
            .map(ToString::to_string)
            .collect();
        let row = |label: &str| {
            lines
                .iter()
                .find(|l| l.trim_start().starts_with(label))
                .unwrap_or_else(|| panic!("{label} missing: {lines:#?}"))
                .clone()
        };
        let (min, last) = (row("Min"), row("Last"));
        // One decimal, the unit once per value, right edges aligned.
        assert!(
            min.contains("164.0 ms") && min.contains("485.0 ms"),
            "{min}"
        );
        assert_eq!(min.find(" ms").unwrap(), last.find(" ms").unwrap());
        assert_eq!(row("Sent").find('5'), Some(min.find(" ms").unwrap() + 2));
        assert_eq!(
            HopDetailView::new(&hop, &theme).title(),
            "Hop 10 · 203.0.113.5"
        );
        // Section headings stand out; normal counts are not painted green.
        let built = HopDetailView::new(&hop, &theme).build_lines(76);
        let latency = built.iter().find(|l| l.to_string() == "Latency").unwrap();
        assert_eq!(latency.spans[0].style.fg, Some(theme.header));
        assert!(
            built
                .iter()
                .flat_map(|l| &l.spans)
                .all(|s| s.style.fg != Some(theme.success))
        );
    }

    #[test]
    fn wrapping_breaks_at_words_with_a_hanging_indent() {
        let dim = Style::default().fg(ratatui::style::Color::DarkGray);
        let line = Line::from(vec![
            Span::styled("    check ", dim),
            Span::raw("GitHub for new releases at startup"),
        ]);
        let rows: Vec<String> = wrap_lines(vec![line], 24)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            rows,
            ["    check GitHub for", "    new releases at", "    startup"]
        );
        // Styles survive the move to a continuation row.
        let wrapped = wrap_lines(vec![Line::styled("  aaa bbb", dim)], 6);
        assert_eq!(wrapped[1].to_string(), "  bbb");
        assert!(wrapped[1].spans.iter().skip(2).all(|s| s.style == dim));
        // A word longer than the width still breaks, keeping the indent.
        let rows: Vec<String> = wrap_lines(vec![Line::from("  abcdefghij")], 6)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(rows, ["  abcd", "  efgh", "  ij"]);
    }
}
