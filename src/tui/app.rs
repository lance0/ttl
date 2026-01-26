use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use scopeguard::defer;
use std::borrow::Cow;
use std::io::stdout;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::export::export_json_file;
use crate::lookup::ix::IxLookup;
use crate::prefs::{DisplayMode, Prefs};
use crate::state::Session;
use crate::trace::receiver::SessionMap;
use crate::tui::theme::Theme;
use crate::tui::views::{
    HelpView, HopDetailView, MainView, SettingsState, SettingsView, TargetListView,
};

/// Information about skipped IPs during resolution
#[derive(Clone, Default)]
pub struct ResolveInfo {
    pub skipped_ipv4: usize,
    pub skipped_ipv6: usize,
}

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
    /// Show settings modal
    pub show_settings: bool,
    /// Settings modal state
    pub settings: SettingsState,
    /// Status message to display
    pub status_message: Option<(String, std::time::Instant)>,
    /// Current theme index
    pub theme_index: usize,
    /// Display mode for column widths (auto/compact/wide)
    pub display_mode: DisplayMode,
    /// Currently selected target index (for multi-target mode)
    pub selected_target: usize,
    /// Show target list overlay
    pub show_target_list: bool,
    /// Selected index in target list overlay
    pub target_list_index: usize,
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

/// Run the TUI application. Returns the final preferences for persistence.
pub async fn run_tui(
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    cancel: CancellationToken,
    initial_prefs: Prefs,
    resolve_info: Option<ResolveInfo>,
    ix_lookup: Option<Arc<IxLookup>>,
) -> Result<Prefs> {
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
    let initial_theme = Theme::by_name(initial_prefs.theme.as_deref().unwrap_or("default"));
    let initial_index = theme_names
        .iter()
        .position(|&name| Theme::by_name(name).name() == initial_theme.name())
        .unwrap_or(0);

    let display_mode = initial_prefs.display_mode.unwrap_or_default();
    let api_key = initial_prefs.peeringdb_api_key.clone();

    let mut ui_state = UiState {
        theme_index: initial_index,
        display_mode,
        settings: SettingsState::new(initial_index, display_mode, api_key),
        ..Default::default()
    };
    let tick_rate = Duration::from_millis(100);

    // Show initial status if resolve_info is present and multiple targets
    if let Some(info) = resolve_info {
        let skip_msg = if info.skipped_ipv6 > 0 {
            format!(" ({} IPv6 skipped)", info.skipped_ipv6)
        } else if info.skipped_ipv4 > 0 {
            format!(" ({} IPv4 skipped)", info.skipped_ipv4)
        } else {
            String::new()
        };
        if targets.len() > 1 {
            ui_state.set_status(format!(
                "Resolved {} targets{}; press l to list",
                targets.len(),
                skip_msg
            ));
        }
    }

    run_app(
        &mut terminal,
        sessions,
        targets,
        &mut ui_state,
        cancel.clone(),
        tick_rate,
        ix_lookup.clone(),
    )
    .await?;

    // Return final preferences for persistence
    let final_api_key = if ui_state.settings.api_key.is_empty() {
        None
    } else {
        Some(ui_state.settings.api_key.clone())
    };

    Ok(Prefs {
        theme: Some(theme_names[ui_state.theme_index].to_string()),
        display_mode: Some(ui_state.display_mode),
        peeringdb_api_key: final_api_key,
    })
}

async fn run_app<B>(
    terminal: &mut Terminal<B>,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    ui_state: &mut UiState,
    cancel: CancellationToken,
    tick_rate: Duration,
    ix_lookup: Option<Arc<IxLookup>>,
) -> Result<()>
where
    B: ratatui::backend::Backend,
    B::Error: Send + Sync + 'static,
{
    let theme_names = Theme::list();
    let num_targets = targets.len();
    let ix_enabled = ix_lookup.is_some();

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

        // Get cache status for settings modal
        let cache_status = ix_lookup.as_ref().map(|ix| ix.get_cache_status());

        // Draw
        terminal.draw(|f| {
            let sessions_read = sessions.read();
            if let Some(state) = sessions_read.get(&current_target) {
                let session = state.read();
                draw_ui(
                    f,
                    &session,
                    ui_state,
                    &theme,
                    num_targets,
                    &sessions,
                    &targets,
                    cache_status.clone(),
                    ix_enabled,
                );
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

            if ui_state.show_settings {
                // PeeringDB section (section 2) - handle text input
                if ui_state.settings.selected_section == 2 && ix_enabled {
                    match key.code {
                        KeyCode::Esc => {
                            // Close settings and apply changes
                            ui_state.theme_index = ui_state.settings.theme_index;
                            ui_state.display_mode = ui_state.settings.display_mode;
                            // Update IxLookup with new API key if provided
                            if let Some(ref ix) = ix_lookup {
                                let key = if ui_state.settings.api_key.is_empty() {
                                    None
                                } else {
                                    Some(ui_state.settings.api_key.clone())
                                };
                                ix.set_api_key(key);
                            }
                            ui_state.show_settings = false;
                        }
                        KeyCode::Tab => {
                            ui_state.settings.next_section(ix_enabled);
                        }
                        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+R: Refresh PeeringDB cache
                            if let Some(ref ix) = ix_lookup {
                                ix.refresh_cache();
                                ui_state.set_status("Refreshing PeeringDB cache...");
                            }
                        }
                        KeyCode::Backspace => {
                            ui_state.settings.handle_backspace();
                        }
                        KeyCode::Delete => {
                            ui_state.settings.handle_delete();
                        }
                        KeyCode::Left => {
                            ui_state.settings.move_cursor_left();
                        }
                        KeyCode::Right => {
                            ui_state.settings.move_cursor_right();
                        }
                        KeyCode::Char(c) => {
                            // Insert character (except 'r' which is handled above)
                            ui_state.settings.handle_char(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Theme/Display Mode sections - normal navigation
                match key.code {
                    KeyCode::Esc => {
                        // Close settings and apply changes
                        ui_state.theme_index = ui_state.settings.theme_index;
                        ui_state.display_mode = ui_state.settings.display_mode;
                        // Update IxLookup with new API key if provided
                        if let Some(ref ix) = ix_lookup {
                            let key = if ui_state.settings.api_key.is_empty() {
                                None
                            } else {
                                Some(ui_state.settings.api_key.clone())
                            };
                            ix.set_api_key(key);
                        }
                        ui_state.show_settings = false;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        ui_state.settings.move_up(theme_names.len());
                        // Live preview theme changes
                        ui_state.theme_index = ui_state.settings.theme_index;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        ui_state.settings.move_down(theme_names.len());
                        // Live preview theme changes
                        ui_state.theme_index = ui_state.settings.theme_index;
                    }
                    KeyCode::Tab => {
                        ui_state.settings.next_section(ix_enabled);
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        ui_state.settings.select();
                        // Live preview display mode changes
                        ui_state.display_mode = ui_state.settings.display_mode;
                    }
                    _ => {}
                }
                continue;
            }

            if ui_state.show_hop_detail {
                // Get hop count for bounds checking
                let hop_count = {
                    let sessions_read = sessions.read();
                    let current_target = targets[ui_state.selected_target];
                    sessions_read
                        .get(&current_target)
                        .map(|state| {
                            let session = state.read();
                            session.hops.iter().filter(|h| h.sent > 0).count()
                        })
                        .unwrap_or(0)
                };

                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(sel) = ui_state.selected {
                            ui_state.selected = Some(sel.saturating_sub(1));
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(sel) = ui_state.selected {
                            ui_state.selected = Some((sel + 1).min(hop_count.saturating_sub(1)));
                        }
                    }
                    KeyCode::Char(c @ '1'..='9') => {
                        let idx = (c as usize - '1' as usize).min(hop_count.saturating_sub(1));
                        ui_state.selected = Some(idx);
                    }
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        ui_state.show_hop_detail = false;
                    }
                    _ => {}
                }
                continue;
            }

            if ui_state.show_target_list {
                match key.code {
                    KeyCode::Esc => {
                        ui_state.show_target_list = false;
                    }
                    KeyCode::Enter => {
                        // Extract pause state BEFORE closing dialog to avoid lock contention
                        let new_target_idx = ui_state.target_list_index;
                        let target = targets[new_target_idx];
                        let paused = {
                            let sessions_read = sessions.read();
                            sessions_read
                                .get(&target)
                                .map(|state| state.read().paused)
                                .unwrap_or(false)
                        };
                        // Now update UI state (no locks held)
                        ui_state.selected_target = new_target_idx;
                        ui_state.selected = None;
                        ui_state.show_target_list = false;
                        ui_state.paused = paused;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if ui_state.target_list_index > 0 {
                            ui_state.target_list_index -= 1;
                        } else {
                            ui_state.target_list_index = num_targets - 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        ui_state.target_list_index = (ui_state.target_list_index + 1) % num_targets;
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        // Jump to target by number (1-9) and select
                        let num = c.to_digit(10).unwrap() as usize;
                        if num >= 1 && num <= num_targets {
                            let new_target_idx = num - 1;
                            let target = targets[new_target_idx];
                            let paused = {
                                let sessions_read = sessions.read();
                                sessions_read
                                    .get(&target)
                                    .map(|state| state.read().paused)
                                    .unwrap_or(false)
                            };
                            ui_state.selected_target = new_target_idx;
                            ui_state.target_list_index = new_target_idx;
                            ui_state.selected = None;
                            ui_state.show_target_list = false;
                            ui_state.paused = paused;
                        }
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
                // Ctrl+C also quits (some terminals send ETX '\x03' instead of Ctrl+C)
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    cancel.cancel();
                    break;
                }
                KeyCode::Char('\x03') => {
                    cancel.cancel();
                    break;
                }
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    ui_state.show_help = true;
                }
                // Target switching
                KeyCode::Tab | KeyCode::Char('n') => {
                    if num_targets > 1 {
                        let new_idx = (ui_state.selected_target + 1) % num_targets;
                        let target = targets[new_idx];
                        // Extract pause state before updating UI to avoid lock contention
                        let paused = {
                            let sessions_read = sessions.read();
                            sessions_read
                                .get(&target)
                                .map(|state| state.read().paused)
                                .unwrap_or(false)
                        };
                        ui_state.selected_target = new_idx;
                        ui_state.selected = None;
                        ui_state.paused = paused;
                        ui_state.set_status(format!(
                            "Target {}/{}: {}",
                            new_idx + 1,
                            num_targets,
                            target
                        ));
                    }
                }
                KeyCode::BackTab | KeyCode::Char('N') => {
                    if num_targets > 1 {
                        let new_idx = if ui_state.selected_target == 0 {
                            num_targets - 1
                        } else {
                            ui_state.selected_target - 1
                        };
                        let target = targets[new_idx];
                        // Extract pause state before updating UI to avoid lock contention
                        let paused = {
                            let sessions_read = sessions.read();
                            sessions_read
                                .get(&target)
                                .map(|state| state.read().paused)
                                .unwrap_or(false)
                        };
                        ui_state.selected_target = new_idx;
                        ui_state.selected = None;
                        ui_state.paused = paused;
                        ui_state.set_status(format!(
                            "Target {}/{}: {}",
                            new_idx + 1,
                            num_targets,
                            target
                        ));
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
                    ui_state.settings.theme_index = ui_state.theme_index;
                    let new_theme = theme_names[ui_state.theme_index];
                    ui_state.set_status(format!("Theme: {}", new_theme));
                }
                KeyCode::Char('w') => {
                    // Cycle through display modes (auto -> compact -> wide -> auto)
                    ui_state.display_mode = ui_state.display_mode.next();
                    ui_state.settings.display_mode = ui_state.display_mode;
                    ui_state.set_status(format!("Display: {}", ui_state.display_mode.label()));
                }
                KeyCode::Char('s') => {
                    // Open settings modal - preserve existing API key
                    let current_api_key = if ui_state.settings.api_key.is_empty() {
                        None
                    } else {
                        Some(ui_state.settings.api_key.clone())
                    };
                    ui_state.settings = SettingsState::new(
                        ui_state.theme_index,
                        ui_state.display_mode,
                        current_api_key,
                    );
                    ui_state.show_settings = true;
                }
                KeyCode::Char('l') => {
                    // Open target list overlay (only in multi-target mode)
                    if num_targets > 1 {
                        ui_state.target_list_index = ui_state.selected_target;
                        ui_state.show_target_list = true;
                    }
                }
                KeyCode::Char('e') => {
                    // Clone session data before releasing lock to avoid holding lock during I/O
                    let session_clone = {
                        let sessions_read = sessions.read();
                        sessions_read
                            .get(&current_target)
                            .map(|state| state.read().clone())
                    };
                    if let Some(session) = session_clone {
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
                    // Extract hop_count quickly, then release lock before updating UI
                    let hop_count = {
                        let sessions_read = sessions.read();
                        sessions_read
                            .get(&current_target)
                            .map(|state| state.read().hops.iter().filter(|h| h.sent > 0).count())
                            .unwrap_or(0)
                    };
                    if hop_count > 0 {
                        ui_state.selected = Some(match ui_state.selected {
                            Some(i) if i > 0 => i - 1,
                            Some(_) => hop_count - 1,
                            None => hop_count - 1,
                        });
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let hop_count = {
                        let sessions_read = sessions.read();
                        sessions_read
                            .get(&current_target)
                            .map(|state| state.read().hops.iter().filter(|h| h.sent > 0).count())
                            .unwrap_or(0)
                    };
                    if hop_count > 0 {
                        ui_state.selected = Some(match ui_state.selected {
                            Some(i) if i < hop_count - 1 => i + 1,
                            Some(_) => 0,
                            None => 0,
                        });
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

#[allow(clippy::too_many_arguments)]
fn draw_ui(
    f: &mut ratatui::Frame,
    session: &Session,
    ui_state: &UiState,
    theme: &Theme,
    num_targets: usize,
    sessions: &SessionMap,
    targets: &[IpAddr],
    cache_status: Option<crate::lookup::ix::CacheStatus>,
    ix_enabled: bool,
) {
    let area = f.area();

    // Layout: main view + status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    // Main view (with target indicator and display mode)
    let main_view = MainView::new(session, ui_state.selected, ui_state.paused, theme)
        .with_target_info(ui_state.selected_target + 1, num_targets)
        .with_display_mode(ui_state.display_mode);
    f.render_widget(main_view, chunks[0]);

    // Status bar (use Cow to avoid allocation for static strings)
    let status_text: Cow<'_, str> = if let Some((ref msg, _)) = ui_state.status_message {
        Cow::Borrowed(msg.as_str())
    } else if num_targets > 1 {
        Cow::Borrowed(
            "q quit | Tab next | l list | p pause | r reset | t theme | w display | s settings | e export | ? help",
        )
    } else {
        Cow::Borrowed(
            "q quit | p pause | r reset | t theme | w display | s settings | e export | ? help",
        )
    };

    let status_bar =
        Paragraph::new(status_text.as_ref()).style(Style::default().fg(theme.text_dim));
    f.render_widget(status_bar, chunks[1]);

    // Overlays
    if ui_state.show_help {
        f.render_widget(HelpView::new(theme), area);
    }

    if ui_state.show_settings {
        let theme_names = Theme::list();
        f.render_widget(
            SettingsView::new(
                theme,
                &ui_state.settings,
                theme_names,
                cache_status,
                ix_enabled,
            ),
            area,
        );
    }

    if ui_state.show_hop_detail
        && let Some(selected) = ui_state.selected
    {
        let hops: Vec<_> = session.hops.iter().filter(|h| h.sent > 0).collect();
        if let Some(hop) = hops.get(selected) {
            f.render_widget(HopDetailView::new(hop, theme), area);
        }
    }

    if ui_state.show_target_list {
        f.render_widget(
            TargetListView::new(theme, sessions, targets, ui_state.target_list_index),
            area,
        );
    }
}
