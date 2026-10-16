use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::tui::theme::Theme;
use crate::update::InstallMethod;

/// Help overlay
pub struct HelpView<'a> {
    theme: &'a Theme,
    is_replay: bool,
    has_update: bool,
    scroll: u16,
}

impl<'a> HelpView<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self {
            theme,
            is_replay: false,
            has_update: false,
            scroll: 0,
        }
    }

    pub fn with_replay(mut self, is_replay: bool) -> Self {
        self.is_replay = is_replay;
        self
    }
    /// List the dismiss key only while an update banner is showing.
    pub fn with_update(mut self, has_update: bool) -> Self {
        self.has_update = has_update;
        self
    }

    pub fn with_scroll(mut self, scroll: u16) -> Self {
        self.scroll = scroll;
        self
    }

    fn lines(&self) -> Vec<Line<'static>> {
        let theme = self.theme;
        let key = Style::default().fg(theme.shortcut).bold();
        let text = Style::default().fg(theme.text);
        let dim = Style::default().fg(theme.text_dim);
        let heading =
            |title: &str| Line::styled(title.to_owned(), Style::default().fg(theme.header).bold());
        // A 10-cell key column keeps every description in one column.
        let row = |keys: &str, style: Style, desc: &str| {
            Line::from(vec![
                Span::styled(format!("  {keys:<10}"), style),
                Span::styled(desc.to_owned(), text),
            ])
        };
        let bind = |keys: &str, desc: &str| row(keys, key, desc);

        let mut lines = vec![
            heading("General"),
            bind("q", "Quit"),
            bind("p Space", "Pause / resume"),
            bind("r", "Reset statistics"),
            bind("e", "Export to JSON"),
            bind("? h", "Show this help"),
        ];
        if self.has_update {
            lines.push(bind("u", "Dismiss update banner"));
        }
        lines.extend([
            Line::default(),
            heading("Targets"),
            bind("o", "Add target"),
            bind("Tab n", "Next target"),
            bind("S-Tab N", "Previous target"),
            bind("l", "Target list"),
            Line::default(),
            heading("Navigation"),
            bind("↑ k  ↓ j", "Move selection"),
            bind("Enter", "Hop details"),
            bind("Esc", "Close popup / deselect"),
            bind("PgUp PgDn", "Scroll hop details and help"),
            Line::default(),
            heading("Display"),
            bind("t", "Cycle theme"),
            bind("w", "Column widths: auto, compact, wide"),
            bind("s", "Settings"),
        ]);
        if self.is_replay {
            lines.extend([
                Line::default(),
                heading("Replay"),
                bind("← →", "Seek 0.5 s"),
                bind("[ ]", "Seek 5 s"),
                bind("+ -", "Speed up / slow down"),
                bind("Home End", "Jump to start / end"),
            ]);
        }
        let marker = Style::default().fg(theme.text).bold();
        let flag = Style::default().fg(theme.warning).bold();
        lines.extend([
            Line::default(),
            heading("Legend"),
            Line::styled("  Host markers", dim),
            row("E", marker, "ECMP: several paths at this hop"),
            row("!", marker, "Route flap: the responder changed"),
            row("~", marker, "Asymmetric return path"),
            row("^", marker, "TTL manipulation"),
            row("+", marker, "Interface/MPLS details (Enter)"),
            Line::styled("  Columns", dim),
            row("RL", marker, "Loss likely ICMP rate limiting"),
            row("· ×", marker, "Recent: reply, timeout (old → new)"),
            Line::styled("  Title flags", dim),
            row("RL?", flag, "Rate limiting suspected on the path"),
            row("ASYM", flag, "Asymmetric routing"),
            row("NAT", flag, "NAT rewriting probe ports"),
            row("TTL!", flag, "TTL manipulation on the path"),
            row("MTU", flag, "Path MTU, or unconfirmed"),
            row("max_ttl", flag, "Destination not reached yet"),
            Line::default(),
            Line::styled(
                "Narrow windows omit secondary columns; Enter shows every hop statistic.",
                dim,
            ),
            Line::styled(
                format!("Update: {}", InstallMethod::cached().update_command()),
                dim,
            ),
        ]);
        lines
    }

    fn popup_width(area: Rect) -> u16 {
        58.min(area.width.saturating_sub(4))
    }

    /// Content lines wrapped to the popup width for `area`.
    pub fn wrapped_lines(&self, area: Rect) -> Vec<Line<'static>> {
        let width = Self::popup_width(area).saturating_sub(super::POPUP_COLS);
        super::hop::wrap_lines(self.lines(), width)
    }

    pub fn max_scroll(&self, area: Rect) -> u16 {
        self.wrapped_lines(area)
            .len()
            .saturating_sub(usize::from(Self::visible_rows(area)))
            .min(usize::from(u16::MAX)) as u16
    }

    /// Help rows visible at once: popup margin (4) and the popup frame.
    pub fn visible_rows(area: Rect) -> u16 {
        area.height.saturating_sub(4 + super::POPUP_ROWS)
    }
}

impl Widget for HelpView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let lines = self.wrapped_lines(area);
        let height = u16::try_from(lines.len())
            .unwrap_or(u16::MAX)
            .saturating_add(super::POPUP_ROWS)
            .min(area.height.saturating_sub(4));
        let body = super::popup(
            area,
            buf,
            (Self::popup_width(area), height),
            &format!("Help · ttl {}", env!("CARGO_PKG_VERSION")),
            &[("PgUp/PgDn", "scroll"), ("Esc", "close")],
            self.theme,
        );
        let max_scroll = lines
            .len()
            .saturating_sub(usize::from(body.height))
            .min(usize::from(u16::MAX)) as u16;
        Paragraph::new(lines)
            .scroll((self.scroll.min(max_scroll), 0))
            .render(body, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(view: &HelpView) -> Vec<String> {
        view.lines().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn keys_sit_in_one_column_with_groups_and_a_legend() {
        let theme = Theme::default();
        let lines = text(&HelpView::new(&theme));
        for heading in ["General", "Targets", "Navigation", "Display", "Legend"] {
            assert!(lines.iter().any(|l| l == heading), "{heading} missing");
        }
        for desc in [
            "Pause / resume",
            "Previous target",
            "Scroll hop details and help",
        ] {
            let line = lines.iter().find(|l| l.ends_with(desc)).unwrap();
            assert_eq!(line.find(desc), Some(12), "{line:?}");
        }
        for marker in [
            "E", "!", "~", "^", "+", "RL?", "ASYM", "NAT", "TTL!", "MTU", "max_ttl",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|l| l.starts_with(&format!("  {marker:<10}"))),
                "{marker} not explained"
            );
        }
        assert!(!lines.iter().any(|l| l.contains("Dismiss update banner")));
        let with_update = text(&HelpView::new(&theme).with_update(true));
        assert!(
            with_update
                .iter()
                .any(|l| l.contains("Dismiss update banner"))
        );
    }
}
