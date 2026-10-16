//! Target input modal: add a target mid-session (or from the empty state).
//!
//! The TUI sends an [`AddTargetRequest`] to the target-manager task in main,
//! which resolves the hostname, creates the session, and spawns the probe
//! engine (and a receiver if the IP family is new). The result comes back on
//! a oneshot channel polled each tick.

use std::net::IpAddr;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::tui::theme::Theme;

/// A successfully added (or already-tracked) target
#[derive(Debug, Clone)]
pub struct AddedTarget {
    pub ip: IpAddr,
    pub name: String,
    /// True if the target was already being traced
    pub existed: bool,
}

/// Request from the TUI to the target-manager task
pub struct AddTargetRequest {
    /// Hostname or IP as typed by the user
    pub host: String,
    /// Reply channel: Ok on success, Err with a user-facing message
    pub reply: tokio::sync::oneshot::Sender<Result<AddedTarget, String>>,
}

/// State for the target input modal
#[derive(Default)]
pub struct TargetInputState {
    /// Current input text (ASCII only; cursor is a byte offset)
    pub input: String,
    /// Cursor position within input
    pub cursor: usize,
    /// Error message from the last failed attempt
    pub error: Option<String>,
    /// Whether a resolution is in flight
    pub resolving: bool,
    /// Pending reply from the target manager
    pub pending: Option<tokio::sync::oneshot::Receiver<Result<AddedTarget, String>>>,
}

impl TargetInputState {
    /// Insert a character at the cursor (ASCII only, keeps cursor math valid)
    pub fn handle_char(&mut self, c: char) {
        if c.is_ascii() && !c.is_ascii_control() {
            self.input.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    /// Delete the character before the cursor
    pub fn handle_backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.input.remove(self.cursor);
        }
    }

    /// Delete the character at the cursor
    pub fn handle_delete(&mut self) {
        if self.cursor < self.input.len() {
            self.input.remove(self.cursor);
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor < self.input.len() {
            self.cursor += 1;
        }
    }
}

/// Centered modal for entering a new target
pub struct TargetInputView<'a> {
    theme: &'a Theme,
    state: &'a TargetInputState,
}

impl<'a> TargetInputView<'a> {
    pub fn new(theme: &'a Theme, state: &'a TargetInputState) -> Self {
        Self { theme, state }
    }
}

impl Widget for TargetInputView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let width = 50.min(area.width.saturating_sub(4));
        let height = 5;
        if width < 20 || area.height < height {
            return;
        }
        let inner = super::popup(
            area,
            buf,
            (width, height),
            "Add Target",
            &[("Enter", "add"), ("Esc", "cancel")],
            self.theme,
        );

        // Keep the cursor in view for long FQDNs and addresses. Input is
        // ASCII, so byte offsets also count terminal cells. Reserve two cells
        // for the prompt and one for the cursor, then center the editing point
        // where possible without hiding the end of a short input.
        let available = usize::from(inner.width.saturating_sub(3));
        let start = self
            .state
            .cursor
            .saturating_sub(available / 2)
            .min(self.state.input.len().saturating_sub(available));
        let end = (start + available).min(self.state.input.len());
        let before = &self.state.input[start..self.state.cursor];
        let after = &self.state.input[self.state.cursor..end];
        let input_line = Line::from(vec![
            Span::styled("> ", Style::default().fg(self.theme.text_dim)),
            Span::styled(before, Style::default().fg(self.theme.text)),
            Span::styled(
                "\u{2502}",
                Style::default()
                    .fg(self.theme.shortcut)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::styled(after, Style::default().fg(self.theme.text)),
        ]);

        // Status line: error > resolving > hint
        let status_line = if let Some(ref err) = self.state.error {
            Line::from(Span::styled(
                err.as_str(),
                Style::default().fg(self.theme.error),
            ))
        } else if self.state.resolving {
            Line::from(Span::styled(
                "Resolving...",
                Style::default().fg(self.theme.warning),
            ))
        } else {
            Line::from(Span::styled(
                "Hostname or IP address",
                Style::default().fg(self.theme.text_dim),
            ))
        };

        let text = vec![Line::default(), input_line, status_line];
        Paragraph::new(text).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_editing() {
        let mut s = TargetInputState::default();
        for c in "8.8.8.8".chars() {
            s.handle_char(c);
        }
        assert_eq!(s.input, "8.8.8.8");
        assert_eq!(s.cursor, 7);

        s.handle_backspace();
        assert_eq!(s.input, "8.8.8.");
        s.move_cursor_left();
        s.move_cursor_left();
        s.handle_delete(); // removes the '8' under the cursor at index 4
        assert_eq!(s.input, "8.8..");
        assert_eq!(s.cursor, 4);

        // Cursor stays in bounds
        for _ in 0..20 {
            s.move_cursor_right();
        }
        assert_eq!(s.cursor, s.input.len());
    }

    fn input_row(state: &TargetInputState, width: u16) -> Vec<String> {
        let area = Rect::new(0, 0, width, 10);
        let mut buffer = Buffer::empty(area);
        TargetInputView::new(&Theme::default(), state).render(area, &mut buffer);
        let y = buffer
            .content
            .iter()
            .position(|cell| cell.symbol() == ">")
            .expect("input prompt");
        let start = (y / usize::from(width)) * usize::from(width);
        let prompt = y % usize::from(width);
        let inner_width = usize::from(50.min(width.saturating_sub(4)).saturating_sub(4));
        buffer.content[start + prompt..start + prompt + inner_width]
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect()
    }

    #[test]
    fn test_long_target_keeps_cursor_and_edited_tail_visible() {
        let name = "a-very-long-router-name.branch-office.example.internal";
        let mut state = TargetInputState::default();
        for c in name.chars() {
            state.handle_char(c);
        }
        for width in [32, 54, 100] {
            let row = input_row(&state, width);
            assert!(
                row.iter().any(|cell| cell == "│"),
                "cursor missing at width {width}"
            );
            assert!(
                row.concat().contains("example.internal"),
                "tail hidden at width {width}"
            );
        }
        state.handle_backspace();
        state.handle_char('x');
        assert!(input_row(&state, 54).concat().contains("example.internax"));
    }

    #[test]
    fn test_long_target_cursor_can_visit_start_middle_and_end() {
        let mut state = TargetInputState::default();
        for c in "a-router-with-a-long-name.at-an-office.example.internal".chars() {
            state.handle_char(c);
        }
        for position in [0, 5, 25, state.input.len()] {
            state.cursor = position;
            let row = input_row(&state, 36);
            assert!(row.iter().any(|cell| cell == "│"));
            if position < state.input.len() {
                let cursor = row.iter().position(|cell| cell == "│").unwrap();
                assert_eq!(row[cursor + 1], state.input[position..position + 1]);
            }
        }
    }

    #[test]
    fn test_non_ascii_ignored() {
        let mut s = TargetInputState::default();
        s.handle_char('h');
        s.handle_char('\u{00e9}'); // é: ignored, keeps byte-cursor math valid
        s.handle_char('\t');
        s.handle_char('x');
        assert_eq!(s.input, "hx");
        assert_eq!(s.cursor, 2);
    }
}
