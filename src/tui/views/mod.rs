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
                assert!(rendered.contains("[PAUSED]"));
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
    fn cell_truncation_respects_wide_and_combining_text() {
        use ratatui::text::Span;
        for width in 0..10 {
            let fitted = fit_text("日本語e\u{301}example", width);
            assert!(Span::raw(fitted).width() <= usize::from(width));
        }
    }
}
