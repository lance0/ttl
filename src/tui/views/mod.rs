pub mod help;
pub mod hop;
pub mod main;
pub mod settings;
pub mod target_input;
pub mod targets;

pub use help::*;
pub use hop::*;
pub use main::*;
pub use settings::*;
pub use target_input::*;
pub use targets::*;

/// Fit terminal cells, preserving wide characters and combining sequences.
pub(crate) fn fit_text(text: &str, width: u16) -> String {
    use ratatui::{style::Style, text::Span};
    if Span::raw(text).width() <= usize::from(width) {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut result = String::new();
    let mut used = 0;
    for grapheme in Span::raw(text).styled_graphemes(Style::default()) {
        let cells = Span::raw(grapheme.symbol).width();
        if used + cells >= usize::from(width) {
            break;
        }
        result.push_str(grapheme.symbol);
        used += cells;
    }
    result.push('…');
    result
}

/// Rows and columns a popup's frame takes from its size: rounded borders,
/// plus one column of padding on each side.
pub(crate) const POPUP_ROWS: u16 = 2;
pub(crate) const POPUP_COLS: u16 = 4;

/// The one popup frame: centered in `area`, cleared, rounded border in the
/// theme's border color, ` Title ` bold in the header color, and key hints
/// on the bottom border. Returns the padded content area.
pub(crate) fn popup(
    area: ratatui::layout::Rect,
    buf: &mut ratatui::buffer::Buffer,
    (width, height): (u16, u16),
    title: &str,
    hints: &[(&str, &str)],
    theme: &crate::tui::theme::Theme,
) -> ratatui::layout::Rect {
    use ratatui::{
        layout::Rect,
        style::Style,
        text::{Line, Span},
        widgets::{Block, BorderType, Clear, Padding, Widget},
    };
    let (width, height) = (width.min(area.width), height.min(area.height));
    let rect = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    Clear.render(rect, buf);
    let mut footer = hint_line(hints, width.saturating_sub(6), theme);
    if !footer.spans.is_empty() {
        footer.spans.insert(0, Span::raw(" "));
        footer.spans.push(Span::raw(" "));
    }
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .title(Line::styled(
            format!(" {} ", fit_text(title, width.saturating_sub(4))),
            Style::default().fg(theme.header).bold(),
        ))
        .title_bottom(footer.right_aligned())
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    block.render(rect, buf);
    inner
}

/// Key hints in one style everywhere: key in the shortcut color and bold,
/// label dim, two spaces between pairs. `pairs` are in priority order and
/// drop from the end until the rest fits `width`; no pair is ever cut.
pub(crate) fn hint_line(
    pairs: &[(&str, &str)],
    width: u16,
    theme: &crate::tui::theme::Theme,
) -> ratatui::text::Line<'static> {
    use ratatui::{style::Style, text::Span};
    let cells =
        |(key, label): &(&str, &str)| Span::raw(*key).width() + 1 + Span::raw(*label).width();
    let mut used = 0;
    let mut spans = Vec::new();
    for pair in pairs {
        let gap = if spans.is_empty() { 0 } else { 2 };
        if used + gap + cells(pair) > usize::from(width) {
            break;
        }
        used += gap + cells(pair);
        if gap > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            pair.0.to_owned(),
            Style::default().fg(theme.shortcut).bold(),
        ));
        spans.push(Span::styled(
            format!(" {}", pair.1),
            Style::default().fg(theme.text_dim),
        ));
    }
    spans.into()
}

#[cfg(test)]
mod responsive_tests {
    use super::*;
    use crate::{
        config::Config,
        prefs::DisplayMode,
        state::{Session, Target},
        tui::theme::Theme,
    };
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    fn text(buf: &Buffer) -> String {
        buf.content.iter().map(|cell| cell.symbol()).collect()
    }

    #[test]
    fn last_hop_stays_visible_at_small_sizes_in_every_mode() {
        let mut session = Session::new(
            Target::new("example.net".into(), "192.0.2.1".parse().unwrap()),
            Config {
                max_ttl: 64,
                ..Config::default()
            },
        );
        for hop in &mut session.hops {
            hop.sent = 11;
            hop.received = 10;
            hop.timeouts = 1;
        }
        let theme = Theme::default();
        for (w, h) in [(60, 20), (80, 24), (160, 40)] {
            for mode in [DisplayMode::Auto, DisplayMode::Compact, DisplayMode::Wide] {
                let area = Rect::new(0, 0, w, h);
                let mut buf = Buffer::empty(area);
                MainView::new(&session, Some(63), true, &theme)
                    .with_display_mode(mode)
                    .render(area, &mut buf);
                let rendered = text(&buf);
                assert!(rendered.contains("64"));
                assert!(
                    rendered.contains("9.1%"),
                    "loss must retain all digits: {w} {mode:?}"
                );
                assert!(rendered.contains(" PAUSED "));
                assert!(
                    buf.content
                        .iter()
                        .any(|cell| cell.symbol() == "6" && cell.bg == theme.highlight_bg)
                );
            }
        }
    }

    #[test]
    fn narrow_columns_preserve_full_asn_identifiers() {
        use crate::state::{AsnInfo, ResponderStats};
        let ip = "192.0.2.1".parse().unwrap();
        let mut session = Session::new(Target::new("example.net".into(), ip), Config::default());
        let hop = &mut session.hops[0];
        hop.sent = 1;
        hop.primary = Some(ip);
        let mut stats = ResponderStats::new(ip);
        stats.asn = Some(AsnInfo {
            number: u32::MAX,
            name: "Long provider name".into(),
            prefix: None,
        });
        hop.responders.insert(ip, stats);
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        MainView::new(&session, None, false, &Theme::default()).render(area, &mut buf);
        assert!(text(&buf).contains("AS4294967295"));
    }

    #[test]
    fn target_view_scrolls_to_last_ipv6_target_with_statistics_and_controls() {
        let infos: Vec<_> = (1..=20)
            .map(|i| targets::TargetInfo {
                ip: format!("2001:db8:1234:5678:abcd:abcd:abcd:{i}")
                    .parse()
                    .unwrap(),
                hostname: format!("router-{i}.example.net"),
                hops_str: "12 hops".into(),
                loss_str: "15.0%".into(),
            })
            .collect();
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        TargetListView::new(&Theme::default(), &infos, 19).render(area, &mut buf);
        let rendered = text(&buf);
        for expected in [
            "> 20.",
            "2001:db8:1234:5678:abcd:abcd:abcd:20",
            "router-20.example.net",
            "12 hops",
            "15.0%",
            "Esc close",
            "Enter select",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn help_scroll_reaches_the_end_and_keeps_close_hint() {
        let area = Rect::new(0, 0, 60, 20);
        let theme = Theme::default();
        let view = HelpView::new(&theme).with_replay(true);
        assert!(view.max_scroll(area) > 0);
        let mut buf = Buffer::empty(area);
        view.with_scroll(u16::MAX).render(area, &mut buf);
        let rendered = text(&buf);
        assert!(rendered.contains("Update:"));
        assert!(rendered.contains("close"));
    }

    #[test]
    fn settings_scrolls_selected_section_and_key_cursor_into_view() {
        let area = Rect::new(0, 0, 60, 20);
        let theme = Theme::default();
        let mut state = SettingsState::new(
            0,
            DisplayMode::Auto,
            Some(format!("{}END", "a".repeat(100))),
        );
        for section in 0..=3 {
            state.selected_section = section;
            let mut buf = Buffer::empty(area);
            SettingsView::new(&theme, &state, Theme::list(), None, true).render(area, &mut buf);
            let rendered = text(&buf);
            assert!(rendered.contains("Esc close"));
            assert!(
                rendered.contains(["Theme", "Display Mode", "API Key:", "Update Check"][section])
            );
            if section == 2 {
                assert!(rendered.contains("END│"));
            }
            if section == 2 {
                state.api_key_cursor = 50;
                let mut middle = Buffer::empty(area);
                SettingsView::new(&theme, &state, Theme::list(), None, true)
                    .render(area, &mut middle);
                assert!(text(&middle).contains('│'));
                // Check the actual cursor line, rather than a popup border.
                assert!(text(&middle).contains("aaaa│"));
            }
        }
    }

    #[test]
    fn hint_line_drops_whole_pairs_from_the_end() {
        let theme = Theme::dracula();
        let pairs = [("?", "help"), ("q", "quit"), ("Enter", "details")];
        assert_eq!(
            hint_line(&pairs, 80, &theme).to_string(),
            "? help  q quit  Enter details"
        );
        // One cell short of the full line: the lowest-priority pair goes.
        assert_eq!(hint_line(&pairs, 28, &theme).to_string(), "? help  q quit");
        assert_eq!(hint_line(&pairs, 6, &theme).to_string(), "? help");
        assert_eq!(hint_line(&pairs, 5, &theme).to_string(), "");
        let line = hint_line(&pairs, 80, &theme);
        assert_eq!(line.spans[0].style.fg, Some(theme.shortcut));
        assert!(
            line.spans[0]
                .style
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
        assert_eq!(line.spans[1].style.fg, Some(theme.text_dim));
    }

    #[test]
    fn cell_truncation_respects_wide_and_combining_text() {
        use ratatui::text::Span;
        for width in 0..10 {
            let fitted = fit_text("日本語e\u{301}example", width);
            assert!(Span::raw(fitted).width() <= usize::from(width));
        }
    }
}
