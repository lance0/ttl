use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

use crate::state::{EcmpKind, Hop, ResponderStats};
use crate::tui::theme::Theme;
use crate::tui::widgets::sparkline_string;

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
    pub fn max_scroll(&self, area: Rect) -> u16 {
        let width = area.width.saturating_sub(10).min(80).saturating_sub(2);
        let height = u16::try_from(self.build_lines(width).len()).unwrap_or(u16::MAX);
        height.saturating_sub(Self::visible_rows(area))
    }

    /// Detail rows visible at once: popup margin (4), borders (2) and footer (1).
    pub fn visible_rows(area: Rect) -> u16 {
        area.height.saturating_sub(7)
    }

    /// Build all content lines for the modal
    fn build_lines(&self, inner_width: u16) -> Vec<Line<'static>> {
        use crate::state::IcmpResponseType;

        let mut lines = Vec::new();
        let stats = self.hop.primary_stats();

        // Put actionable rejections first, including secondary ECMP responders.
        let mut errors: Vec<_> = self
            .hop
            .responders
            .values()
            .filter_map(|stats| stats.last_icmp_error.map(|error| (stats.ip, error)))
            .collect();
        errors.sort_by_key(|(ip, _)| *ip);
        for (ip, error) in errors {
            let Some(reason) = error.processing_error_reason() else {
                continue;
            };
            lines.push(Line::styled(
                format!("  Last rejection from {ip}"),
                Style::default().fg(self.theme.warning),
            ));
            let (kind, pointer) = match error {
                IcmpResponseType::ParameterProblem { code, pointer } => (
                    format!("  ICMPv6 Parameter Problem code {code}"),
                    Some(pointer),
                ),
                IcmpResponseType::HeadersTooLong { pointer } => (
                    "  ICMPv6 Destination Unreachable code 8".to_string(),
                    pointer,
                ),
                _ => continue,
            };
            lines.push(Line::from(kind));
            lines.push(Line::from(format!("  {reason}")));
            if let Some(pointer) = pointer {
                lines.push(Line::from(format!("  Pointer: byte {pointer}")));
            }
            lines.push(Line::from(""));
        }

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

            // IX (if available - PeeringDB)
            if let Some(ref ix) = stats.ix {
                let ix_location = [ix.city.as_deref(), ix.country.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ");

                let ix_str = if ix_location.is_empty() {
                    ix.name.clone()
                } else {
                    format!("{} ({})", ix.name, ix_location)
                };

                lines.push(Line::from(vec![
                    Span::styled("  IX:        ", Style::default().fg(self.theme.text_dim)),
                    Span::styled(ix_str, Style::default().fg(self.theme.shortcut)),
                ]));
            }

            lines.push(Line::from(""));

            // Sparkline visualization
            let recent: Vec<_> = stats.recent.iter().cloned().collect();
            let sparkline = sparkline_string(&recent, inner_width.saturating_sub(4) as usize);
            if !sparkline.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  Latency:   ", Style::default().fg(self.theme.text_dim)),
                    Span::styled(sparkline, Style::default().fg(self.theme.success)),
                ]));
            }

            lines.push(Line::from(""));

            // Stats (use hop-level sent/loss since we can't attribute probes to responders before reply)
            let hop_loss = self.hop.loss_pct();
            // Label as "Hop totals" when multiple responders exist (ECMP) to avoid confusion
            let stats_label = if self.hop.responders.len() > 1 {
                "  Hop totals: "
            } else {
                "  "
            };
            lines.push(Line::from(vec![
                Span::styled(stats_label, Style::default().fg(self.theme.text_dim)),
                Span::styled("Sent: ", Style::default().fg(self.theme.text_dim)),
                Span::raw(format!("{:<6}", self.hop.sent)),
                Span::styled("Recv: ", Style::default().fg(self.theme.text_dim)),
                Span::raw(format!("{:<6}", self.hop.received)),
                Span::styled("Loss: ", Style::default().fg(self.theme.text_dim)),
                Span::styled(
                    format!("{:.1}%", hop_loss),
                    if hop_loss > 10.0 {
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
                    Span::raw(format!(
                        "{:.2}ms    ",
                        stats.avg_rtt().as_secs_f64() * 1000.0
                    )),
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
                    Span::styled(
                        "  Jitter (smoothed): ",
                        Style::default().fg(self.theme.text_dim),
                    ),
                    Span::raw(format!("{:.2}ms  ", stats.jitter().as_secs_f64() * 1000.0)),
                    Span::styled("Avg: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!(
                        "{:.2}ms  ",
                        stats.jitter_avg().as_secs_f64() * 1000.0
                    )),
                    Span::styled("Max: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!(
                        "{:.2}ms",
                        stats.jitter_max().as_secs_f64() * 1000.0
                    )),
                ]));
            }

            append_extensions(&mut lines, stats, self.theme);

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
                            format!(
                                "{} ({:.0}%)",
                                nat_info.port_rewritten,
                                nat_info.nat_percentage()
                            ),
                            Style::default().fg(self.theme.warning),
                        ),
                    ]));

                    // Show rewrite samples (original → returned)
                    if !nat_info.rewrite_samples.is_empty() {
                        let samples: Vec<String> = nat_info
                            .rewrite_samples
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

            // Rate limit detection info (if present)
            if let Some(ref rl) = self.hop.rate_limit
                && rl.suspected
            {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "  Rate Limiting Suspected",
                    Style::default().fg(self.theme.warning),
                )]));
                if let Some(ref reason) = rl.reason {
                    lines.push(Line::from(vec![
                        Span::styled("  Reason: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(reason.clone()),
                    ]));
                }
                lines.push(Line::from(vec![
                    Span::styled("  Confidence: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw(format!("{:.0}%", rl.confidence * 100.0)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  Tip: ", Style::default().fg(self.theme.text_dim)),
                    Span::raw("Try slower probing with -i 1.0 or -i 2.0"),
                ]));
            }

            // Route changes (flaps) detected at this hop
            if !self.hop.route_changes.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    format!("  Route Changes: {} detected", self.hop.route_changes.len()),
                    Style::default().fg(self.theme.warning),
                )]));

                // Show last few route changes
                for change in self.hop.route_changes.iter().rev().take(5) {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::raw(format!("{}", change.from_ip)),
                        Span::styled(" → ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", change.to_ip)),
                        Span::styled(
                            format!(" (after {} responses)", change.at_seq),
                            Style::default().fg(self.theme.text_dim),
                        ),
                    ]));
                }

                if self.hop.route_changes.len() > 5 {
                    lines.push(Line::from(vec![Span::styled(
                        format!("    ... and {} more", self.hop.route_changes.len() - 5),
                        Style::default().fg(self.theme.text_dim),
                    )]));
                }
            }

            // Asymmetric routing detection
            if let Some(ref asym) = self.hop.asymmetry {
                let total = asym.symmetric_samples + asym.asymmetric_samples;
                if total >= 5 || asym.suspected {
                    lines.push(Line::from(""));
                    if asym.suspected {
                        lines.push(Line::from(vec![Span::styled(
                            "  Routing Asymmetry Detected",
                            Style::default().fg(self.theme.warning),
                        )]));
                    } else {
                        lines.push(Line::from(vec![Span::styled(
                            "  Routing Symmetry",
                            Style::default().fg(self.theme.text_dim),
                        )]));
                    }
                    lines.push(Line::from(vec![
                        Span::styled("  Forward hops: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", self.hop.ttl)),
                        Span::styled("  Est. return: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(
                            asym.last_return_hops
                                .map(|h| h.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                        Span::styled("  Diff: ", Style::default().fg(self.theme.text_dim)),
                        if asym.avg_hop_difference.abs() >= 3.0 {
                            Span::styled(
                                format!("{:.1}", asym.avg_hop_difference),
                                Style::default().fg(self.theme.warning),
                            )
                        } else {
                            Span::raw(format!("{:.1}", asym.avg_hop_difference))
                        },
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  Samples: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", total)),
                        Span::styled("  Symmetric: ", Style::default().fg(self.theme.text_dim)),
                        Span::styled(
                            format!("{}", asym.symmetric_samples),
                            Style::default().fg(self.theme.success),
                        ),
                        Span::styled("  Asymmetric: ", Style::default().fg(self.theme.text_dim)),
                        if asym.asymmetric_samples > 0 {
                            Span::styled(
                                format!("{}", asym.asymmetric_samples),
                                Style::default().fg(self.theme.warning),
                            )
                        } else {
                            Span::raw("0".to_string())
                        },
                    ]));
                    // High variance indicates return-path ECMP
                    if asym.variance > 4.0 {
                        lines.push(Line::from(vec![
                            Span::styled("  Note: ", Style::default().fg(self.theme.text_dim)),
                            Span::raw("High variance - possible return-path ECMP"),
                        ]));
                    }
                }
            }

            // TTL manipulation detection
            if let Some(ref ttl_info) = self.hop.ttl_manip {
                let total = ttl_info.normal_samples + ttl_info.anomalous_samples;
                if total >= 5 || ttl_info.suspected {
                    lines.push(Line::from(""));
                    let header_style = if ttl_info.suspected {
                        Style::default().fg(self.theme.warning)
                    } else {
                        Style::default().fg(self.theme.text_dim)
                    };
                    lines.push(Line::from(vec![Span::styled(
                        if ttl_info.suspected {
                            "  TTL Manipulation Detected"
                        } else {
                            "  TTL Behavior"
                        },
                        header_style,
                    )]));

                    if let Some(ref reason) = ttl_info.reason {
                        lines.push(Line::from(vec![
                            Span::styled("  Reason: ", Style::default().fg(self.theme.text_dim)),
                            Span::styled(reason.clone(), Style::default().fg(self.theme.warning)),
                        ]));
                    }

                    lines.push(Line::from(vec![
                        Span::styled("  Sent TTL: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", self.hop.ttl)),
                        Span::styled("  Last Quoted: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(
                            ttl_info
                                .last_quoted_ttl
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                    ]));

                    lines.push(Line::from(vec![
                        Span::styled("  Samples: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", total)),
                        Span::styled("  Normal: ", Style::default().fg(self.theme.text_dim)),
                        Span::styled(
                            format!("{}", ttl_info.normal_samples),
                            Style::default().fg(self.theme.success),
                        ),
                        Span::styled("  Anomalous: ", Style::default().fg(self.theme.text_dim)),
                        if ttl_info.anomalous_samples > 0 {
                            Span::styled(
                                format!("{}", ttl_info.anomalous_samples),
                                Style::default().fg(self.theme.warning),
                            )
                        } else {
                            Span::raw("0".to_string())
                        },
                    ]));
                }
            }

            // ECMP detail
            match self.hop.ecmp_kind() {
                EcmpKind::PerFlow => {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![Span::styled(
                        "  Per-Flow Paths (ECMP detected):",
                        Style::default().fg(self.theme.warning),
                    )]));

                    let ecmp_paths = self.hop.ecmp_paths();
                    let num_paths = self.hop.path_count();
                    for (flow_id, responder_ip) in &ecmp_paths {
                        // Look up hostname from responders map
                        let hostname = self
                            .hop
                            .responders
                            .get(responder_ip)
                            .and_then(|s| s.hostname.as_ref())
                            .map(|h| format!(" ({})", h))
                            .unwrap_or_default();

                        // Mark if this is a unique path
                        let is_unique = ecmp_paths
                            .iter()
                            .filter(|(_, ip)| ip == responder_ip)
                            .count()
                            == 1;
                        let marker = if is_unique && num_paths > 1 {
                            " ← alt path"
                        } else {
                            ""
                        };

                        lines.push(Line::from(vec![
                            Span::raw(format!("    Flow {}: ", flow_id)),
                            Span::raw(format!("{}{}", responder_ip, hostname)),
                            Span::styled(marker, Style::default().fg(self.theme.shortcut)),
                        ]));
                    }
                }
                EcmpKind::PerPacket => {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![Span::styled(
                        "  Per-Packet ECMP detected",
                        Style::default().fg(self.theme.warning),
                    )]));
                    lines.push(Line::from(vec![
                        Span::styled("  Responders: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", self.hop.responders.len())),
                        Span::styled("  Paths shown: ", Style::default().fg(self.theme.text_dim)),
                        Span::raw(format!("{}", self.hop.path_count())),
                    ]));
                }
                EcmpKind::None => {
                    if !self.hop.flow_paths.is_empty() && self.hop.flow_paths.len() > 1 {
                        // Show flows even without ECMP (all same path)
                        lines.push(Line::from(""));
                        lines.push(Line::from(vec![
                            Span::styled("  Flows: ", Style::default().fg(self.theme.text_dim)),
                            Span::raw(format!("{} (single path)", self.hop.flow_paths.len())),
                        ]));
                    }
                }
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
                                format!(
                                    " - {} responses, avg {:.1}ms",
                                    other_stats.received,
                                    other_stats.avg_rtt().as_secs_f64() * 1000.0
                                ),
                                Style::default().fg(self.theme.text_dim),
                            ),
                        ]));
                        append_extensions(&mut lines, other_stats, self.theme);
                    }
                }
            }
        } else {
            lines.push(Line::from("  No responses received at this TTL"));
        }

        wrap_lines(lines, inner_width)
    }
}

/// Wrap on grapheme boundaries before measuring height, retaining span styles.
/// Long interface/hostname values must not hide the MTU at the end of a line.
fn wrap_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let mut wrapped = Vec::new();
    for line in lines {
        let mut spans = Vec::new();
        let mut used = 0;
        for grapheme in line.styled_graphemes(Style::default()) {
            let span = Span::styled(grapheme.symbol.to_owned(), grapheme.style);
            let cells = span.width();
            if used + cells > usize::from(width) && !spans.is_empty() {
                wrapped.push(Line::from(std::mem::take(&mut spans)));
                used = 0;
            }
            if cells <= usize::from(width) {
                used += cells;
                spans.push(span);
            }
        }
        wrapped.push(Line::from(spans));
    }
    wrapped
}

fn append_extensions(lines: &mut Vec<Line<'static>>, stats: &ResponderStats, theme: &Theme) {
    // MPLS labels (if present)
    if let Some(ref labels) = stats.mpls_labels {
        lines.push(Line::from(""));
        let label_str = labels
            .iter()
            .map(|l| format!("{} (TTL {})", l.label, l.ttl))
            .collect::<Vec<_>>()
            .join(" → ");
        lines.push(Line::from(vec![
            Span::styled("  MPLS: ", Style::default().fg(theme.text_dim)),
            Span::styled(label_str, Style::default().fg(theme.shortcut)),
        ]));
    }

    // RFC 5837 Interface Information (if present)
    if let Some(ifaces) = &stats.interface_info {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "  Interface (RFC 5837):",
            Style::default().fg(theme.text_dim),
        )]));
        for iface in ifaces {
            let mut parts = Vec::new();
            if let Some(name) = &iface.name {
                parts.push(format!("\"{}\"", name));
            }
            if let Some(ip) = iface.ip_addr {
                parts.push(format!("IP {}", ip));
            }
            if let Some(if_index) = iface.if_index {
                parts.push(format!("idx {}", if_index));
            }
            if let Some(mtu) = iface.mtu {
                parts.push(format!("MTU {}", mtu));
            }
            let detail_str = if parts.is_empty() {
                "(no details)".to_string()
            } else {
                parts.join(", ")
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {}: ", iface.role.as_str()),
                    Style::default().fg(theme.text_dim),
                ),
                Span::styled(detail_str, Style::default().fg(theme.shortcut)),
            ]));
        }
    }
}

impl Widget for HopDetailView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate popup width first (needed for sparkline sizing)
        let popup_width = area.width.saturating_sub(10).min(80);
        let inner_width = popup_width.saturating_sub(2); // -2 for left/right borders

        // Build content first to calculate required height
        let lines = self.build_lines(inner_width);
        let content_height = u16::try_from(lines.len()).unwrap_or(u16::MAX);

        // Calculate centered popup area with dynamic height
        // Borders plus a fixed navigation footer.
        let needed_height = content_height.saturating_add(3);
        let max_height = area.height.saturating_sub(4);
        let popup_height = needed_height.min(max_height);
        let popup_x = (area.width - popup_width) / 2 + area.x;
        let popup_y = (area.height - popup_height) / 2 + area.y;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear the popup area
        Clear.render(popup_area, buf);

        let stats = self.hop.primary_stats();
        let ip = stats
            .map(|s| s.ip.to_string())
            .unwrap_or_else(|| "* * *".to_string());
        let title = format!(" Hop {}: {} ", self.hop.ttl, ip);

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let content = Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        };
        let max_scroll = content_height.saturating_sub(content.height);
        Paragraph::new(lines)
            .scroll((self.scroll.min(max_scroll), 0))
            .render(content, buf);
        if inner.height > 0 {
            let footer = Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1);
            Paragraph::new(" ↑/↓ hop  PgUp/PgDn scroll  Esc back")
                .style(Style::default().fg(self.theme.text_dim))
                .render(footer, buf);
        }
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
        for line in view.build_lines(58) {
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
}

#[cfg(test)]
mod processing_error_tests {
    use super::*;
    use crate::state::IcmpResponseType;
    use std::time::Duration;

    #[test]
    fn secondary_responder_rejection_and_large_pointer_are_visible() {
        let mut hop = Hop::new(5);
        let primary = "2001:db8::1".parse().unwrap();
        let secondary = "2001:db8::2".parse().unwrap();
        for _ in 0..3 {
            hop.record_sent();
            hop.record_response(primary, Duration::from_millis(1));
        }
        hop.record_sent();
        hop.record_response(secondary, Duration::from_millis(2));
        hop.record_icmp_error(
            secondary,
            IcmpResponseType::ParameterProblem {
                code: 6,
                pointer: u32::MAX,
            },
        );
        assert_eq!(hop.primary, Some(primary));
        let area = Rect::new(0, 0, 80, 35);
        let mut buffer = Buffer::empty(area);
        HopDetailView::new(&hop, &Theme::default()).render(area, &mut buffer);
        let text: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        assert!(text.contains("Last rejection from 2001:db8::2"));
        assert!(text.contains("Extension header too big"));
        assert!(text.contains("byte 4294967295"));
    }
}
