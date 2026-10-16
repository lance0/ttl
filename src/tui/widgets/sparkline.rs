use crate::tui::theme::Theme;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;
use std::collections::VecDeque;
use std::time::Duration;

/// Unicode block characters for sparkline
const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// A sparkline widget for displaying RTT history
#[allow(dead_code)]
pub struct RttSparkline<'a> {
    data: &'a [Option<Duration>],
    style: Style,
    timeout_style: Style,
}

#[allow(dead_code)]
impl<'a> RttSparkline<'a> {
    pub fn new(data: &'a [Option<Duration>]) -> Self {
        Self {
            data,
            style: Style::default().fg(Color::Green),
            timeout_style: Style::default().fg(Color::Red),
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    pub fn timeout_style(mut self, style: Style) -> Self {
        self.timeout_style = style;
        self
    }
}

impl Widget for RttSparkline<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 || self.data.is_empty() {
            return;
        }

        // Find min/max for scaling
        let rtts: Vec<f64> = self
            .data
            .iter()
            .filter_map(|d| d.as_ref())
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();

        if rtts.is_empty() {
            return;
        }

        let min_rtt = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_rtt = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = if (max_rtt - min_rtt).abs() < 0.001 {
            1.0
        } else {
            max_rtt - min_rtt
        };

        // Take last N samples that fit in the width
        let width = area.width as usize;
        let samples: Vec<_> = self.data.iter().rev().take(width).rev().collect();

        for (i, sample) in samples.iter().enumerate() {
            let x = area.x + i as u16;
            if x >= area.x + area.width {
                break;
            }

            let (ch, style) = match sample {
                Some(d) => {
                    let ms = d.as_secs_f64() * 1000.0;
                    let normalized = (ms - min_rtt) / range;
                    let idx = (normalized * 7.0).round() as usize;
                    let idx = idx.min(7);
                    (BLOCKS[idx], self.style)
                }
                None => ('×', self.timeout_style),
            };

            buf[(x, area.y)].set_char(ch).set_style(style);
        }
    }
}

/// Recent probe outcomes, oldest to newest. Quiet dots distinguish replies
/// from loss crosses without making a healthy route a wall of bright blocks.
/// `silent` hops (never replied) draw their crosses dim too, so a dead tail
/// past the destination or a filtered hop is not a wall of red.
pub fn loss_history_line(
    data: &VecDeque<bool>,
    width: usize,
    theme: &Theme,
    silent: bool,
) -> Line<'static> {
    let start = data.len().saturating_sub(width);
    let loss = if silent { theme.text_dim } else { theme.error };
    Line::from(
        data.iter()
            .skip(start)
            .map(|&success| {
                Span::styled(
                    if success { "·" } else { "×" },
                    Style::default().fg(if success { theme.text_dim } else { loss }),
                )
            })
            .collect::<Vec<_>>(),
    )
}

/// Generate sparkline string from RTT data
pub fn sparkline_string(data: &[Option<Duration>], width: usize) -> String {
    if data.is_empty() {
        return String::new();
    }

    let rtts: Vec<f64> = data
        .iter()
        .filter_map(|d| d.as_ref())
        .map(|d| d.as_secs_f64() * 1000.0)
        .collect();

    if rtts.is_empty() {
        return "×".repeat(data.len().min(width));
    }

    let min_rtt = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_rtt = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = if (max_rtt - min_rtt).abs() < 0.001 {
        1.0
    } else {
        max_rtt - min_rtt
    };

    let samples: Vec<_> = data.iter().rev().take(width).rev().collect();

    samples
        .iter()
        .map(|sample| match sample {
            Some(d) => {
                let ms = d.as_secs_f64() * 1000.0;
                let normalized = (ms - min_rtt) / range;
                let idx = (normalized * 7.0).round() as usize;
                BLOCKS[idx.min(7)]
            }
            None => '×',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_preserves_order_and_marks_each_loss_independently() {
        let data = VecDeque::from([false, true, false, true, true, false]);
        let theme = Theme::dracula();
        let line = loss_history_line(&data, 4, &theme, false);
        assert_eq!(line.to_string(), "×··×");
        assert_eq!(line.spans[0].style.fg, Some(theme.error));
        assert_eq!(line.spans[1].style.fg, Some(theme.text_dim));
        assert!(loss_history_line(&data, 0, &theme, false).spans.is_empty());
        assert!(
            loss_history_line(&VecDeque::new(), 10, &theme, false)
                .spans
                .is_empty()
        );
        let silent = loss_history_line(&VecDeque::from([false, false]), 4, &theme, true);
        assert!(
            silent
                .spans
                .iter()
                .all(|s| s.style.fg == Some(theme.text_dim))
        );
    }
}
