use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use scopeguard::defer;
use std::io::stdout;
use std::net::IpAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::export::export_json_file;
use crate::state::Session;
use crate::trace::receiver::SessionMap;
use crate::tui::theme::Theme;
use crate::tui::views::{HelpView, HopDetailView, MainView};

/// UI state
#[derive(Default)]
pub struct UiState {
    /// Currently selected hop index (0-indexed into displayed hops)
    pub selected: Option<usize>,
    /// Whether probing is paused
    pub paused: bool,
    /// Show help overlay
    pub show_help: bool,
    /// Show expanded hop view
    pub show_hop_detail: bool,
    /// Status message to display
    pub status_message: Option<(String, std::time::Instant)>,
    /// Current theme index
    pub theme_index: usize,
    /// Currently selected target index (for multi-target mode)
    pub selected_target: usize,
}

impl UiState {
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), std::time::Instant::now()));
    }

    pub fn clear_old_status(&mut self) {
        if let Some((_, time)) = &self.status_message
            && time.elapsed() > Duration::from_secs(3)
        {
            self.status_message = None;
        }
    }
}

/// Run the TUI application. Returns the final theme name for persistence.
pub async fn run_tui(
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    cancel: CancellationToken,
    initial_theme: Theme,
) -> Result<String> {
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    // Ensure terminal is restored on any exit (success, error, or panic)
    defer! {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    // Find initial theme index
    let theme_names = Theme::list();
    let initial_index = theme_names
        .iter()
        .position(|&name| Theme::by_name(name).name() == initial_theme.name())
        .unwrap_or(0);

    let mut ui_state = UiState {
        theme_index: initial_index,
        ..Default::default()
    };
    let tick_rate = Duration::from_millis(100);

    run_app(
        &mut terminal,
        sessions,
        targets,
        &mut ui_state,
        cancel.clone(),
        tick_rate,
    )
    .await?;

    // Return final theme name for persistence
    Ok(theme_names[ui_state.theme_index].to_string())
}

async fn run_app<B>(
    terminal: &mut Terminal<B>,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    ui_state: &mut UiState,
    cancel: CancellationToken,
    tick_rate: Duration,
) -> Result<()>
where
    B: ratatui::backend::Backend,
    B::Error: Send + Sync + 'static,
{
    let theme_names = Theme::list();
    let num_targets = targets.len();

    loop {
        // Check cancellation
        if cancel.is_cancelled() {
            break;
        }

        // Clear old status messages
        ui_state.clear_old_status();

        // Get current theme
        let theme = Theme::by_name(theme_names[ui_state.theme_index]);

        // Get current target's session
        let current_target = targets[ui_state.selected_target];

        // Draw
        terminal.draw(|f| {
            let sessions_read = sessions.read();
            if let Some(state) = sessions_read.get(&current_target) {
                let session = state.read();
                draw_ui(f, &session, ui_state, &theme, num_targets);
            }
        })?;

        // Handle input with timeout
        if event::poll(tick_rate)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // Handle overlays first
            if ui_state.show_help {
                ui_state.show_help = false;
                continue;
            }

            if ui_state.show_hop_detail {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        ui_state.show_hop_detail = false;
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') => {
                    cancel.cancel();
                    break;
                }
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    ui_state.show_help = true;
                }
                // Target switching
                KeyCode::Tab | KeyCode::Char('n') => {
                    if num_targets > 1 {
                        ui_state.selected_target = (ui_state.selected_target + 1) % num_targets;
                        ui_state.selected = None; // Reset hop selection when switching targets
                        let target = targets[ui_state.selected_target];
                        ui_state.set_status(format!(
                            "Target {}/{}: {}",
                            ui_state.selected_target + 1,
                            num_targets,
                            target
                        ));
                        // Sync pause state with new target's session
                        let sessions_read = sessions.read();
                        if let Some(state) = sessions_read.get(&target) {
                            ui_state.paused = state.read().paused;
                        }
                    }
                }
                KeyCode::BackTab | KeyCode::Char('N') => {
                    if num_targets > 1 {
                        ui_state.selected_target = if ui_state.selected_target == 0 {
                            num_targets - 1
                        } else {
                            ui_state.selected_target - 1
                        };
                        ui_state.selected = None; // Reset hop selection when switching targets
                        let target = targets[ui_state.selected_target];
                        ui_state.set_status(format!(
                            "Target {}/{}: {}",
                            ui_state.selected_target + 1,
                            num_targets,
                            target
                        ));
                        // Sync pause state with new target's session
                        let sessions_read = sessions.read();
                        if let Some(state) = sessions_read.get(&target) {
                            ui_state.paused = state.read().paused;
                        }
                    }
                }
                KeyCode::Char('p') => {
                    ui_state.paused = !ui_state.paused;
                    // Pause/resume current target's probe engine
                    let sessions_read = sessions.read();
                    if let Some(state) = sessions_read.get(&current_target) {
                        let mut session = state.write();
                        session.paused = ui_state.paused;
                    }
                    ui_state.set_status(if ui_state.paused { "Paused" } else { "Resumed" });
                }
                KeyCode::Char('r') => {
                    // Reset current target's statistics
                    let sessions_read = sessions.read();
                    if let Some(state) = sessions_read.get(&current_target) {
                        let mut session = state.write();
                        session.reset_stats();
                    }
                    ui_state.set_status("Stats reset");
                }
                KeyCode::Char('t') => {
                    // Cycle through themes
                    ui_state.theme_index = (ui_state.theme_index + 1) % theme_names.len();
                    let new_theme = theme_names[ui_state.theme_index];
                    ui_state.set_status(format!("Theme: {}", new_theme));
                }
                KeyCode::Char('e') => {
                    let sessions_read = sessions.read();
                    if let Some(state) = sessions_read.get(&current_target) {
                        let session = state.read();
                        match export_json_file(&session) {
                            Ok(filename) => {
                                ui_state.set_status(format!("Exported to {}", filename));
                            }
                            Err(e) => {
                                ui_state.set_status(format!("Export failed: {}", e));
                            }
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let sessions_read = sessions.read();
                    if let Some(state) = sessions_read.get(&current_target) {
                        let session = state.read();
                        let hop_count = session.hops.iter().filter(|h| h.sent > 0).count();
                        if hop_count > 0 {
                            ui_state.selected = Some(match ui_state.selected {
                                Some(i) if i > 0 => i - 1,
                                Some(_) => hop_count - 1,
                                None => hop_count - 1,
                            });
                        }
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let sessions_read = sessions.read();
                    if let Some(state) = sessions_read.get(&current_target) {
                        let session = state.read();
                        let hop_count = session.hops.iter().filter(|h| h.sent > 0).count();
                        if hop_count > 0 {
                            ui_state.selected = Some(match ui_state.selected {
                                Some(i) if i < hop_count - 1 => i + 1,
                                Some(_) => 0,
                                None => 0,
                            });
                        }
                    }
                }
                KeyCode::Enter => {
                    if ui_state.selected.is_some() {
                        ui_state.show_hop_detail = true;
                    }
                }
                KeyCode::Esc => {
                    ui_state.selected = None;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn draw_ui(
    f: &mut ratatui::Frame,
    session: &Session,
    ui_state: &UiState,
    theme: &Theme,
    num_targets: usize,
) {
    let area = f.area();

    // Layout: main view + status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    // Main view (with target indicator)
    let main_view = MainView::new(session, ui_state.selected, ui_state.paused, theme)
        .with_target_info(ui_state.selected_target + 1, num_targets);
    f.render_widget(main_view, chunks[0]);

    // Status bar
    let status_text = if let Some((ref msg, _)) = ui_state.status_message {
        msg.clone()
    } else if num_targets > 1 {
        "q quit | Tab next target | p pause | r reset | t theme | e export | ? help".to_string()
    } else {
        "q quit | p pause | r reset | t theme | e export | ? help | \u{2191}\u{2193} select"
            .to_string()
    };

    let status_bar = Paragraph::new(status_text).style(Style::default().fg(theme.text_dim));
    f.render_widget(status_bar, chunks[1]);

    // Overlays
    if ui_state.show_help {
        f.render_widget(HelpView::new(theme), area);
    }

    if ui_state.show_hop_detail
        && let Some(selected) = ui_state.selected
    {
        let hops: Vec<_> = session.hops.iter().filter(|h| h.sent > 0).collect();
        if let Some(hop) = hops.get(selected) {
            f.render_widget(HopDetailView::new(hop, theme), area);
        }
    }
}
