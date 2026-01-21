use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget};

use crate::lookup::ix::CacheStatus;
use crate::tui::theme::Theme;

/// Settings state for the modal
#[derive(Default, Clone)]
pub struct SettingsState {
    /// 0 = theme section, 1 = wide mode section, 2 = PeeringDB section
    pub selected_section: usize,
    /// Scroll offset for theme list
    pub theme_scroll: usize,
    /// Selected theme index
    pub theme_index: usize,
    /// Wide mode toggle value
    pub wide_mode: bool,
    /// PeeringDB API key input value
    pub api_key: String,
    /// Cursor position in API key input
    pub api_key_cursor: usize,
}

impl SettingsState {
    pub fn new(theme_index: usize, wide_mode: bool, api_key: Option<String>) -> Self {
        let api_key = api_key.unwrap_or_default();
        let cursor = api_key.len();
        Self {
            selected_section: 0,
            theme_scroll: 0,
            theme_index,
            wide_mode,
            api_key,
            api_key_cursor: cursor,
        }
    }

    /// Insert a character at the cursor position
    pub fn handle_char(&mut self, c: char) {
        self.api_key.insert(self.api_key_cursor, c);
        self.api_key_cursor += 1;
    }

    /// Delete the character before the cursor (backspace)
    pub fn handle_backspace(&mut self) {
        if self.api_key_cursor > 0 {
            self.api_key_cursor -= 1;
            self.api_key.remove(self.api_key_cursor);
        }
    }

    /// Delete the character at the cursor position (delete key)
    pub fn handle_delete(&mut self) {
        if self.api_key_cursor < self.api_key.len() {
            self.api_key.remove(self.api_key_cursor);
        }
    }

    /// Move cursor left
    pub fn move_cursor_left(&mut self) {
        if self.api_key_cursor > 0 {
            self.api_key_cursor -= 1;
        }
    }

    /// Move cursor right
    pub fn move_cursor_right(&mut self) {
        if self.api_key_cursor < self.api_key.len() {
            self.api_key_cursor += 1;
        }
    }

    /// Move selection up within current section
    pub fn move_up(&mut self, _theme_count: usize) {
        if self.selected_section == 0 {
            // Theme section
            if self.theme_index > 0 {
                self.theme_index -= 1;
                // Adjust scroll if needed
                if self.theme_index < self.theme_scroll {
                    self.theme_scroll = self.theme_index;
                }
            }
        }
        // Wide mode section has no up/down navigation
    }

    /// Move selection down within current section
    pub fn move_down(&mut self, theme_count: usize) {
        if self.selected_section == 0 {
            // Theme section
            if self.theme_index < theme_count - 1 {
                self.theme_index += 1;
                // Adjust scroll if needed (show 5 themes at once)
                let visible_themes = 5;
                if self.theme_index >= self.theme_scroll + visible_themes {
                    self.theme_scroll = self.theme_index - visible_themes + 1;
                }
            }
        }
        // Wide mode section has no up/down navigation
    }

    /// Switch between sections (0=Theme, 1=Wide Mode, 2=PeeringDB)
    pub fn next_section(&mut self, ix_enabled: bool) {
        let num_sections = if ix_enabled { 3 } else { 2 };
        self.selected_section = (self.selected_section + 1) % num_sections;
    }

    /// Select current theme (when in theme section) or toggle wide mode
    pub fn select(&mut self) {
        if self.selected_section == 1 {
            self.wide_mode = !self.wide_mode;
        }
        // Theme is already selected by navigation
    }
}

/// Settings modal view
pub struct SettingsView<'a> {
    theme: &'a Theme,
    state: &'a SettingsState,
    theme_names: &'a [&'static str],
    cache_status: Option<CacheStatus>,
    ix_enabled: bool,
}

impl<'a> SettingsView<'a> {
    pub fn new(
        theme: &'a Theme,
        state: &'a SettingsState,
        theme_names: &'a [&'static str],
        cache_status: Option<CacheStatus>,
        ix_enabled: bool,
    ) -> Self {
        Self {
            theme,
            state,
            theme_names,
            cache_status,
            ix_enabled,
        }
    }

    /// Format the cache age as a human-readable string
    fn format_cache_age(fetched_at: u64) -> String {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now.saturating_sub(fetched_at);

        if age_secs < 60 {
            "just now".to_string()
        } else if age_secs < 3600 {
            format!("{}m ago", age_secs / 60)
        } else if age_secs < 86400 {
            format!("{}h ago", age_secs / 3600)
        } else {
            format!("{}d ago", age_secs / 86400)
        }
    }
}

impl Widget for SettingsView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate centered popup area (taller if IX is enabled)
        let popup_width = 44.min(area.width.saturating_sub(4));
        let base_height = if self.ix_enabled { 22 } else { 16 };
        let popup_height = base_height.min(area.height.saturating_sub(4));
        let popup_x = (area.width - popup_width) / 2 + area.x;
        let popup_y = (area.height - popup_height) / 2 + area.y;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear the popup area
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let mut lines = Vec::new();

        // Theme section header
        let theme_header_style = if self.state.selected_section == 0 {
            Style::default()
                .fg(self.theme.header)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.text_dim)
        };
        lines.push(Line::from(vec![Span::styled(
            "  Theme",
            theme_header_style,
        )]));

        // Show visible themes (5 at a time)
        let visible_themes = 5.min(self.theme_names.len());
        let start = self.state.theme_scroll;
        let end = (start + visible_themes).min(self.theme_names.len());

        // Scroll indicator (up)
        if start > 0 {
            lines.push(Line::from(vec![Span::styled(
                "    \u{25b2} more",
                Style::default().fg(self.theme.text_dim),
            )]));
        } else {
            lines.push(Line::from(""));
        }

        // Theme list
        for (i, name) in self.theme_names[start..end].iter().enumerate() {
            let idx = start + i;
            let is_selected = idx == self.state.theme_index;
            let bullet = if is_selected { "\u{25cf}" } else { "\u{25cb}" };
            let style = if is_selected && self.state.selected_section == 0 {
                Style::default()
                    .fg(self.theme.shortcut)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default().fg(self.theme.text)
            } else {
                Style::default().fg(self.theme.text_dim)
            };
            lines.push(Line::from(vec![Span::styled(
                format!("    {} {}", bullet, name),
                style,
            )]));
        }

        // Scroll indicator (down)
        if end < self.theme_names.len() {
            lines.push(Line::from(vec![Span::styled(
                "    \u{25bc} more",
                Style::default().fg(self.theme.text_dim),
            )]));
        } else {
            lines.push(Line::from(""));
        }

        lines.push(Line::from(""));

        // Wide mode section header
        let wide_header_style = if self.state.selected_section == 1 {
            Style::default()
                .fg(self.theme.header)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.text_dim)
        };
        lines.push(Line::from(vec![Span::styled(
            "  Wide Mode",
            wide_header_style,
        )]));

        // Wide mode toggle
        let checkbox = if self.state.wide_mode { "[x]" } else { "[ ]" };
        let toggle_style = if self.state.selected_section == 1 {
            Style::default()
                .fg(self.theme.shortcut)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.text_dim)
        };
        lines.push(Line::from(vec![Span::styled(
            format!("    {} Expand columns", checkbox),
            toggle_style,
        )]));

        // PeeringDB section (only if IX detection is enabled)
        if self.ix_enabled {
            lines.push(Line::from(""));

            // PeeringDB section header
            let pdb_header_style = if self.state.selected_section == 2 {
                Style::default()
                    .fg(self.theme.header)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.text_dim)
            };
            lines.push(Line::from(vec![Span::styled(
                "  PeeringDB (IX Detection)",
                pdb_header_style,
            )]));

            // API key input
            let api_key_style = if self.state.selected_section == 2 {
                Style::default().fg(self.theme.text)
            } else {
                Style::default().fg(self.theme.text_dim)
            };

            // Build the API key display with cursor
            let label = "    API Key: ";
            let display_key = if self.state.api_key.is_empty() {
                "(not set)".to_string()
            } else {
                // Show the key with cursor indicator when section is selected
                if self.state.selected_section == 2 {
                    let (before, after) = self.state.api_key.split_at(self.state.api_key_cursor);
                    format!("{}\u{2502}{}", before, after)
                } else {
                    self.state.api_key.clone()
                }
            };
            lines.push(Line::from(vec![
                Span::styled(label, api_key_style),
                Span::styled(
                    display_key,
                    if self.state.selected_section == 2 {
                        Style::default()
                            .fg(self.theme.shortcut)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        api_key_style
                    },
                ),
            ]));

            // Cache status
            if let Some(ref status) = self.cache_status {
                let status_text = if status.refreshing {
                    "    Cache: Refreshing...".to_string()
                } else if !status.loaded && status.prefix_count == 0 {
                    "    Cache: Not loaded".to_string()
                } else {
                    let age_str = status
                        .fetched_at
                        .map(Self::format_cache_age)
                        .unwrap_or_else(|| "unknown".to_string());
                    let status_indicator = if status.expired { " (expired)" } else { "" };
                    format!(
                        "    Cache: {} prefixes, {}{}",
                        status.prefix_count, age_str, status_indicator
                    )
                };
                lines.push(Line::from(vec![Span::styled(
                    status_text,
                    Style::default().fg(self.theme.text_dim),
                )]));

                // Refresh hint when in PeeringDB section
                if self.state.selected_section == 2 && !status.refreshing {
                    lines.push(Line::from(vec![Span::styled(
                        "    Press Ctrl+R to refresh cache",
                        Style::default().fg(self.theme.text_dim),
                    )]));
                } else {
                    lines.push(Line::from(""));
                }
            }
        }

        lines.push(Line::from(""));

        // Footer with keybindings
        lines.push(Line::from(vec![Span::styled(
            "  \u{2191}\u{2193} navigate  Tab section  Enter select",
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
