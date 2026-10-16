use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

use crate::tui::theme::Theme;
use crate::update::InstallMethod;

/// Help overlay
pub struct HelpView<'a> {
    theme: &'a Theme,
    is_replay: bool,
    scroll: u16,
}

impl<'a> HelpView<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self {
            theme,
            is_replay: false,
            scroll: 0,
        }
    }

    pub fn with_replay(mut self, is_replay: bool) -> Self {
        self.is_replay = is_replay;
        self
    }
    pub fn with_scroll(mut self, scroll: u16) -> Self {
        self.scroll = scroll;
        self
    }

    fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  q       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Quit"),
            ]),
            Line::from(vec![
                Span::styled("  p/Space ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Pause/Resume"),
            ]),
            Line::from(vec![
                Span::styled("  r       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Reset statistics"),
            ]),
            Line::from(vec![
                Span::styled("  t       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Cycle theme"),
            ]),
            Line::from(vec![
                Span::styled("  w       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Cycle display mode"),
            ]),
            Line::from(vec![
                Span::styled("  s       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Settings"),
            ]),
            Line::from(vec![
                Span::styled("  e       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Export to JSON"),
            ]),
            Line::from(vec![
                Span::styled("  ?/h     ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Show this help"),
            ]),
            Line::from(vec![
                Span::styled("  u       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Dismiss update banner"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  o       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Add target"),
            ]),
            Line::from(vec![
                Span::styled("  Tab/n   ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Next target (multi-target)"),
            ]),
            Line::from(vec![
                Span::styled("  S-Tab/N ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Previous target"),
            ]),
            Line::from(vec![
                Span::styled("  l       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Target list"),
            ]),
            Line::from(vec![
                Span::styled("  Up/k    ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Move selection up"),
            ]),
            Line::from(vec![
                Span::styled("  Down/j  ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Move selection down"),
            ]),
            Line::from(vec![
                Span::styled("  Enter   ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Expand selected hop"),
            ]),
            Line::from(vec![
                Span::styled("  Esc     ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Close popup / Deselect"),
            ]),
            Line::from(vec![
                Span::styled("  PgUp/Dn ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Scroll hop details"),
            ]),
            Line::from(vec![
                Span::styled("  +       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Hop has interface/MPLS details"),
            ]),
            Line::from(""),
        ];

        if self.is_replay {
            lines.push(Line::from(vec![Span::styled(
                "  Replay Controls:",
                Style::default().fg(self.theme.header),
            )]));
            lines.push(Line::from(vec![
                Span::styled("  Left/Right ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Seek 0.5s"),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  [ / ]      ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Seek 5s"),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  + / -      ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Speed up / slow down"),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Home / End ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Seek to start / end"),
            ]));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(vec![Span::styled(
            format!("  Update: {}", InstallMethod::cached().update_command()),
            Style::default().fg(self.theme.text_dim),
        )]));
        lines
    }

    pub fn max_scroll(&self, area: Rect) -> u16 {
        let width = 50.min(area.width.saturating_sub(4)).saturating_sub(2);
        let height = area.height.saturating_sub(7);
        super::hop::wrap_lines(self.lines(), width)
            .len()
            .saturating_sub(usize::from(height))
            .min(usize::from(u16::MAX)) as u16
    }
}

impl Widget for HelpView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate centered popup area
        let popup_width = 50.min(area.width.saturating_sub(4));
        let lines = super::hop::wrap_lines(self.lines(), popup_width.saturating_sub(2));
        let popup_height = (lines.len() + 3).min(usize::from(area.height.saturating_sub(4))) as u16;
        let popup_x = (area.width - popup_width) / 2 + area.x;
        let popup_y = (area.height - popup_height) / 2 + area.y;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear the popup area
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(format!(" Help — ttl {} ", env!("CARGO_PKG_VERSION")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let body = Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        };
        let max_scroll = lines
            .len()
            .saturating_sub(usize::from(body.height))
            .min(usize::from(u16::MAX)) as u16;
        Paragraph::new(lines)
            .scroll((self.scroll.min(max_scroll), 0))
            .render(body, buf);
        if inner.height > 0 {
            let footer = super::fit_text("PgUp/PgDn scroll · Esc/other key close", inner.width);
            Paragraph::new(footer)
                .style(Style::default().fg(self.theme.text_dim))
                .render(Rect::new(inner.x, inner.bottom() - 1, inner.width, 1), buf);
        }
    }
}
