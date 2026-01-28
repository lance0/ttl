use std::net::IpAddr;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

use crate::trace::receiver::SessionMap;
use crate::tui::theme::Theme;

/// Pre-extracted target info to avoid holding locks during render
pub(crate) struct TargetInfo {
    pub ip: IpAddr,
    pub hostname: String,
    pub hops_str: String,
    pub loss_str: String,
}

/// Extract target info from all sessions, holding locks briefly then releasing.
/// Called before `terminal.draw()` so no locks are held during rendering.
pub(crate) fn extract_target_infos(sessions: &SessionMap, targets: &[IpAddr]) -> Vec<TargetInfo> {
    let sessions_read = sessions.read();
    targets
        .iter()
        .map(|target_ip| {
            let (hostname, hops_str, loss_str) = if let Some(state) = sessions_read.get(target_ip) {
                let session = state.read();

                // Get display name (hostname or original input)
                let display_name = session.target.display_name();
                let hostname = if display_name.parse::<IpAddr>().is_ok() {
                    // Original was an IP, use reverse DNS hostname if available
                    session.target.hostname.clone().unwrap_or_default()
                } else {
                    display_name
                };

                // Get hop count (dest_ttl if known)
                let hops = if let Some(dest_ttl) = session.dest_ttl {
                    format!("{} hops", dest_ttl)
                } else {
                    "--".to_string()
                };

                // Get loss % at destination
                let loss = if let Some(dest_ttl) = session.dest_ttl {
                    if let Some(hop) = session.hops.get(dest_ttl as usize - 1) {
                        format!("{:.1}%", hop.loss_pct())
                    } else {
                        "--".to_string()
                    }
                } else {
                    "--".to_string()
                };

                (hostname, hops, loss)
            } else {
                (String::new(), "--".to_string(), "--".to_string())
            };

            TargetInfo {
                ip: *target_ip,
                hostname,
                hops_str,
                loss_str,
            }
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
        // Calculate centered popup area
        let popup_width = 65.min(area.width.saturating_sub(4));
        let popup_height =
            (self.target_infos.len() + 8).min(area.height.saturating_sub(4) as usize) as u16;
        let popup_x = (area.width - popup_width) / 2 + area.x;
        let popup_y = (area.height - popup_height) / 2 + area.y;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear the popup area
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(" Targets ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let mut lines = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("  Resolved {} addresses:", self.target_infos.len()),
            Style::default().fg(self.theme.header),
        )]));
        lines.push(Line::from(""));

        for (i, info) in self.target_infos.iter().enumerate() {
            let is_selected = i == self.selected_index;
            let marker = if is_selected { ">" } else { " " };

            let style = if is_selected {
                Style::default()
                    .fg(self.theme.shortcut)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.text)
            };

            // Truncate hostname to fit
            let hostname_display = if info.hostname.len() > 18 {
                format!("{}...", &info.hostname[..15])
            } else {
                info.hostname.clone()
            };

            lines.push(Line::from(vec![Span::styled(
                format!(
                    "  {} {:2}. {:17} {:18} {:8} {:>5}",
                    marker,
                    i + 1,
                    info.ip,
                    hostname_display,
                    info.hops_str,
                    info.loss_str
                ),
                style,
            )]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "  Up/Down navigate   Enter select   1-9 jump",
            Style::default().fg(self.theme.text_dim),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "  Esc close",
            Style::default().fg(self.theme.text_dim),
        )]));

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}
