use std::net::IpAddr;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::trace::receiver::SessionMap;
use crate::tui::theme::Theme;

/// Pre-extracted target info to avoid holding locks during render
pub(crate) struct TargetInfo {
    pub ip: IpAddr,
    pub hostname: String,
    pub hops_str: String,
    pub loss_str: String,
    /// Average RTT at the destination
    pub rtt_str: String,
}

/// Extract target info from all sessions, holding locks briefly then releasing.
/// Called before `terminal.draw()` so no locks are held during rendering.
pub(crate) fn extract_target_infos(sessions: &SessionMap, targets: &[IpAddr]) -> Vec<TargetInfo> {
    let sessions_read = sessions.read();
    targets
        .iter()
        .map(|target_ip| {
            let mut info = TargetInfo {
                ip: *target_ip,
                hostname: String::new(),
                hops_str: "–".into(),
                loss_str: "–".into(),
                rtt_str: "–".into(),
            };
            let Some(state) = sessions_read.get(target_ip) else {
                return info;
            };
            let session = state.read();
            let dest = session
                .dest_ttl
                .and_then(|ttl| session.hops.get(usize::from(ttl).checked_sub(1)?));
            let display_name = session.target.display_name();
            info.hostname = if display_name.parse::<IpAddr>().is_ok() {
                // An IP target: reverse DNS, else the destination hop's name
                session
                    .target
                    .hostname
                    .clone()
                    .or_else(|| dest?.primary_stats()?.hostname.clone())
                    .unwrap_or_default()
            } else {
                display_name
            };
            if let (Some(ttl), Some(hop)) = (session.dest_ttl, dest) {
                info.hops_str = format!("{ttl} hops");
                if hop.received + hop.timeouts > 0 {
                    info.loss_str = format!("{:.1}%", hop.loss_pct());
                }
                if let Some(stats) = hop.primary_stats().filter(|s| s.received > 0) {
                    info.rtt_str = format!("{:.0} ms", stats.avg_rtt().as_secs_f64() * 1000.0);
                }
            }
            info
        })
        .collect()
}

/// Target list overlay for multi-target mode
pub struct TargetListView<'a> {
    theme: &'a Theme,
    target_infos: &'a [TargetInfo],
    selected_index: usize,
}

impl<'a> TargetListView<'a> {
    pub fn new(theme: &'a Theme, target_infos: &'a [TargetInfo], selected_index: usize) -> Self {
        Self {
            theme,
            target_infos,
            selected_index,
        }
    }
}

impl Widget for TargetListView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // One aligned row per target: number, address, name, then the
        // destination's hops, loss and RTT right-aligned. The name absorbs
        // any shortage, then disappears; the address is cut last.
        let count = self.target_infos.len().to_string().len();
        let ip_width = self
            .target_infos
            .iter()
            .map(|t| t.ip.to_string().len())
            .max()
            .unwrap_or(0);
        let name_max = self
            .target_infos
            .iter()
            .map(|t| Span::raw(&t.hostname).width())
            .max()
            .unwrap_or(0)
            .min(32);
        let stats_width = 8 + 2 + 6 + 2 + 7;
        let fixed = count + 2 + ip_width + 2 + 2 + stats_width;
        let wanted = (fixed + name_max + usize::from(super::POPUP_COLS)).max(48);
        let width = (wanted as u16).min(area.width.saturating_sub(4));
        let height = (self.target_infos.len() + usize::from(super::POPUP_ROWS))
            .min(usize::from(area.height.saturating_sub(4))) as u16;
        let inner = super::popup(
            area,
            buf,
            (width, height),
            &format!(
                "Targets {}/{}",
                if self.target_infos.is_empty() {
                    0
                } else {
                    self.selected_index + 1
                },
                self.target_infos.len()
            ),
            &[
                ("Esc", "close"),
                ("Enter", "select"),
                ("↑/↓", "move"),
                ("1-9", "jump"),
            ],
            self.theme,
        );
        let visible = usize::from(inner.height);
        let start = self
            .selected_index
            .saturating_add(1)
            .saturating_sub(visible);
        let row_width = usize::from(inner.width);
        let name_width = row_width.saturating_sub(fixed).min(name_max);
        let selected_theme = self.theme.for_selection();
        let lines: Vec<Line> = self
            .target_infos
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, info)| {
                let selected = i == self.selected_index;
                let theme = if selected {
                    &selected_theme
                } else {
                    self.theme
                };
                let dim = Style::default().fg(theme.text_dim);
                let text = Style::default().fg(theme.text);
                let mut spans = vec![
                    Span::styled(format!("{:>count$}  ", i + 1), dim),
                    Span::styled(format!("{:<ip_width$}", info.ip.to_string()), text),
                ];
                if name_width >= 4 {
                    let name = super::fit_text(&info.hostname, name_width as u16);
                    // Pad by terminal cells: `{:<width$}` pads by chars, so a
                    // name with double-width characters would overflow the row
                    // and the stats columns would be cut off.
                    let pad = name_width.saturating_sub(Span::raw(&name).width());
                    spans.push(Span::styled(format!("  {name}{}", " ".repeat(pad)), dim));
                }
                spans.push(Span::styled(
                    format!(
                        "  {:>8}  {:>6}  {:>7}",
                        info.hops_str, info.loss_str, info.rtt_str
                    ),
                    text,
                ));
                let mut line = Line::from(spans);
                if line.width() > row_width {
                    line = Line::styled(super::fit_text(&line.to_string(), inner.width), text);
                }
                // Pad so the selection bar spans the full row.
                let pad = row_width.saturating_sub(line.width());
                line.spans.push(Span::raw(" ".repeat(pad)));
                if selected {
                    line = line.style(
                        Style::default()
                            .bg(self.theme.highlight_bg)
                            .add_modifier(Modifier::BOLD),
                    );
                }
                line
            })
            .collect();
        Paragraph::new(lines).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Buffer, layout::Rect};

    fn info(hostname: &str) -> TargetInfo {
        TargetInfo {
            ip: "192.0.2.1".parse().unwrap(),
            hostname: hostname.to_string(),
            hops_str: "12 hops".to_string(),
            loss_str: "0.0%".to_string(),
            rtt_str: "18 ms".to_string(),
        }
    }

    fn render(infos: &[TargetInfo], width: u16) -> String {
        let theme = Theme::default();
        let area = Rect::new(0, 0, width, 12);
        let mut buf = Buffer::empty(area);
        TargetListView::new(&theme, infos, 0).render(area, &mut buf);
        (0..12)
            .map(|y| (0..width).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn wide_hostnames_keep_the_statistics_columns() {
        // 10 double-width characters are 20 cells but only 10 chars: padding by
        // chars overflowed the row, and the whole line was truncated, losing
        // loss and RTT.
        let wide = "ネットワークテスト.example";
        let ascii = "a".repeat(20);
        let wide_infos = [info(wide)];
        let ascii_infos = [info(&ascii)];
        let wide_row = render(&wide_infos, 100);
        let ascii_row = render(&ascii_infos, 100);
        for expected in ["12 hops", "0.0%", "18 ms"] {
            assert!(
                wide_row.contains(expected),
                "wide name lost {expected}:\n{wide_row}"
            );
            assert!(
                ascii_row.contains(expected),
                "ascii name lost {expected}:\n{ascii_row}"
            );
        }
    }
}
