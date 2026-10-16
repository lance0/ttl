use std::net::IpAddr;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Widget};

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
                    usize::from(dest_ttl)
                        .checked_sub(1)
                        .and_then(|idx| session.hops.get(idx))
                        .map(|hop| format!("{:.1}%", hop.loss_pct()))
                        .unwrap_or_else(|| "--".to_string())
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
        let width = 76.min(area.width.saturating_sub(4));
        let height = (self.target_infos.len().saturating_mul(2) + usize::from(super::POPUP_ROWS))
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
        let body_height = inner.height;
        let visible = usize::from(body_height / 2);
        let start = self
            .selected_index
            .saturating_add(1)
            .saturating_sub(visible);
        let mut lines = Vec::new();
        let selected_theme = self.theme.for_selection();
        for (i, info) in self
            .target_infos
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
        {
            let selected = i == self.selected_index;
            let style = if selected {
                Style::default()
                    .fg(selected_theme.text)
                    .bg(self.theme.highlight_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.text)
            };
            lines.push(Line::styled(
                super::fit_text(
                    &format!(
                        "{} {}. {}",
                        if selected { ">" } else { " " },
                        i + 1,
                        info.ip
                    ),
                    inner.width,
                ),
                style,
            ));
            lines.push(Line::styled(
                super::fit_text(
                    &format!("   {}  {}  {}", info.hops_str, info.loss_str, info.hostname),
                    inner.width,
                ),
                style,
            ));
        }
        Paragraph::new(lines).render(
            Rect {
                height: body_height,
                ..inner
            },
            buf,
        );
    }
}
