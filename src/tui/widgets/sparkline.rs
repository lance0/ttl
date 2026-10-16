use crate::tui::theme::Theme;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use std::collections::VecDeque;
use std::time::Duration;

/// Unicode block characters for sparkline
const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

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

/// Scale range of an RTT sparkline in ms: the 5th..95th percentile of the
/// replies, so one spike cannot flatten everything else (outliers clamp to
/// the end blocks). `None` when nothing replied.
pub fn sparkline_range(data: &[Option<Duration>]) -> Option<(f64, f64)> {
    let mut rtts: Vec<f64> = data
        .iter()
        .flatten()
        .map(|d| d.as_secs_f64() * 1000.0)
        .collect();
    rtts.sort_by(f64::total_cmp);
    let at = |p: f64| rtts[((rtts.len() - 1) as f64 * p).round() as usize];
    (!rtts.is_empty()).then(|| (at(0.05), at(0.95)))
}

/// The newest `width` samples as bars on the [`sparkline_range`] scale, in
/// the header color; timeouts are crosses in the error color.
pub fn sparkline_spans(
    data: &[Option<Duration>],
    width: usize,
    theme: &Theme,
) -> Vec<Span<'static>> {
    let Some((lo, hi)) = sparkline_range(data) else {
        return Vec::new();
    };
    let range = (hi - lo).max(f64::EPSILON);
    let bar = Style::default().fg(theme.header);
    let timeout = Style::default().fg(theme.error);
    data.iter()
        .skip(data.len().saturating_sub(width))
        .map(|sample| match sample {
            Some(d) => {
                let level = ((d.as_secs_f64() * 1000.0 - lo) / range).clamp(0.0, 1.0);
                Span::styled(BLOCKS[(level * 7.0).round() as usize].to_string(), bar)
            }
            None => Span::styled("×", timeout),
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
