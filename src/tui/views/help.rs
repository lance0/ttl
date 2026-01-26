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
}

impl<'a> HelpView<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self { theme }
    }
}

impl Widget for HelpView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate centered popup area
        let popup_width = 50.min(area.width.saturating_sub(4));
        let popup_height = 24.min(area.height.saturating_sub(4));
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

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  q       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Quit"),
            ]),
            Line::from(vec![
                Span::styled("  p       ", Style::default().fg(self.theme.shortcut)),
                Span::raw("Pause/Resume probing"),
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
            Line::from(""),
            Line::from(vec![Span::styled(
                format!("  Update: {}", InstallMethod::cached().update_command()),
                Style::default().fg(self.theme.text_dim),
            )]),
            Line::from(vec![Span::styled(
                "  Press any key to close",
                Style::default().fg(self.theme.text_dim),
            )]),
        ];

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}
