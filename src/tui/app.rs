use anyhow::Result;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{LineGauge, Paragraph};
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
#[cfg(test)]
use crate::state::ProbeOutcome;
use crate::state::{ProbeEvent, Session};
use crate::trace::receiver::SessionMap;
use crate::tui::theme::Theme;
use crate::tui::views::{
    HelpView, HopDetailView, MainView, SettingsState, SettingsView, TargetInfo, TargetListView,
    extract_target_infos,
};

/// State for animated replay playback
pub struct ReplayState {
    /// All events to replay
    pub events: Vec<ProbeEvent>,
    /// Current event index
    pub current_index: usize,
    /// When the replay started (monotonic clock)
    pub replay_started_at: std::time::Instant,
    /// Speed multiplier (1.0 = realtime, 10.0 = 10x speed)
    pub speed_multiplier: f32,
    /// Whether replay is paused
    pub paused: bool,
    /// Whether replay is complete
    pub finished: bool,
    /// Adjusted elapsed ms at time of pause (for accurate resume)
    pub paused_at_elapsed_ms: u64,
}

impl ReplayState {
    pub fn new(mut events: Vec<ProbeEvent>, speed: f32) -> Self {
        // Sort events by offset to prevent stalled replay from out-of-order events
        events.sort_by_key(|e| e.offset_ms);
        Self {
            events,
            current_index: 0,
            replay_started_at: std::time::Instant::now(),
            speed_multiplier: speed.max(0.1), // Prevent zero/negative speed
            paused: false,
            finished: false,
            paused_at_elapsed_ms: 0,
        }
    }
}

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
    /// Update available notification (version string)
    pub update_available: Option<String>,
    /// Receiver for background update check result
    pub update_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
    /// Replay animation state (None = live mode or static replay)
    pub replay_state: Option<ReplayState>,
    /// Cached target list info (populated when overlay is open, refreshed every 30 ticks)
    pub target_list_cache: Option<Vec<TargetInfo>>,
    /// Tick counter for target list cache refresh
    pub target_list_tick: u32,
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
#[allow(clippy::too_many_arguments)]
pub async fn run_tui(
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    cancel: CancellationToken,
    initial_prefs: Prefs,
    resolve_info: Option<ResolveInfo>,
    ix_lookup: Option<Arc<IxLookup>>,
    update_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
    replay_state: Option<ReplayState>,
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
        update_rx,
        replay_state,
        ..Default::default()
    };
    let tick_rate = Duration::from_millis(16); // ~60fps for responsive per-probe updates

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

/// Toggle pause/resume for replay animation
fn toggle_replay_pause(ui_state: &mut UiState) {
    if let Some(ref mut replay) = ui_state.replay_state {
        if replay.paused {
            // RESUMING: Restore start time from the elapsed time we recorded at pause
            rebase_replay_start(replay, replay.paused_at_elapsed_ms);
            replay.paused = false;
            ui_state.set_status("Replay resumed");
        } else {
            // PAUSING: Record exactly how far into the replay we are (in adjusted ms)
            replay.paused_at_elapsed_ms = replay_current_ms(replay);
            replay.paused = true;
            ui_state.set_status("Replay paused. Press p or Space to resume.");
        }
    }
}

/// Format milliseconds as human-readable time (e.g., "1:23.4" or "5.2s")
fn format_replay_time(ms: u64) -> String {
    let secs = ms / 1000;
    let frac = (ms % 1000) / 100;
    let mins = secs / 60;
    let secs_rem = secs % 60;
    if mins > 0 {
        format!("{}:{:02}.{}", mins, secs_rem, frac)
    } else {
        format!("{}.{}s", secs_rem, frac)
    }
}

/// Get the current adjusted elapsed time in replay milliseconds
fn replay_current_ms(replay: &ReplayState) -> u64 {
    if replay.paused {
        replay.paused_at_elapsed_ms
    } else if replay.finished {
        replay.events.last().map_or(0, |e| e.offset_ms)
    } else {
        let elapsed_ms = replay.replay_started_at.elapsed().as_secs_f64() * 1000.0;
        let adjusted = elapsed_ms * replay.speed_multiplier as f64;
        adjusted.clamp(0.0, u64::MAX as f64) as u64
    }
}

/// Convert replay timeline ms into wall-clock duration at the current speed.
fn replay_wall_offset(replay_ms: u64, speed_multiplier: f32) -> Duration {
    let speed = speed_multiplier.max(0.1) as f64;
    let wall_ms = (replay_ms as f64 / speed).clamp(0.0, u64::MAX as f64);
    Duration::from_millis(wall_ms as u64)
}

/// Rebase replay start instant so replay_current_ms() resolves to target replay ms.
fn rebase_replay_start(replay: &mut ReplayState, replay_ms: u64) {
    let now = std::time::Instant::now();
    let offset = replay_wall_offset(replay_ms, replay.speed_multiplier);
    // Guard against malformed/very-large replay timestamps.
    replay.replay_started_at = now.checked_sub(offset).unwrap_or(now);
}

/// Compute replay event index for a requested timeline position.
/// target_ms=0 maps to index 0 (pre-first-event) for Home key semantics.
fn replay_event_index_for_time(events: &[ProbeEvent], target_ms: u64) -> usize {
    if target_ms == 0 {
        0
    } else {
        events.partition_point(|e| e.offset_ms <= target_ms)
    }
}

/// Human-friendly replay position label for status messages.
fn format_replay_position(
    target_ms: u64,
    total_duration: u64,
    target_index: usize,
    total_events: usize,
) -> String {
    if total_events == 0 {
        "empty replay (0/0 events)".to_string()
    } else if target_index == 0 {
        format!("start (event 0/{})", total_events)
    } else if target_index >= total_events {
        if total_duration == 0 {
            format!(
                "end (event {}/{}, instant timeline)",
                target_index, total_events
            )
        } else {
            format!(
                "end {} (event {}/{})",
                format_replay_time(total_duration),
                target_index,
                total_events
            )
        }
    } else {
        format!(
            "{} (event {}/{})",
            format_replay_time(target_ms),
            target_index,
            total_events
        )
    }
}

/// Seek replay to an absolute time position (in replay milliseconds).
/// Rebuilds session state from scratch for backward seeks.
fn seek_replay_to(
    ui_state: &mut UiState,
    sessions: &SessionMap,
    target_ip: IpAddr,
    target_ms: u64,
) {
    // Extract what we need from replay_state, then release the borrow
    let (total_duration, target_index, current_index, total_events) = {
        let replay = match ui_state.replay_state.as_ref() {
            Some(r) => r,
            None => return,
        };
        let total_duration = replay.events.last().map_or(0, |e| e.offset_ms);
        let target_ms = target_ms.min(total_duration);
        let target_index = replay_event_index_for_time(&replay.events, target_ms);
        (
            total_duration,
            target_index,
            replay.current_index,
            replay.events.len(),
        )
    };

    let target_ms = target_ms.min(total_duration);

    if target_index == current_index {
        let replay = ui_state.replay_state.as_mut().unwrap();
        replay.paused = true;
        replay.paused_at_elapsed_ms = target_ms;
        replay.finished = target_index >= total_events;
        ui_state.set_status(format!(
            "Already at {}",
            format_replay_position(target_ms, total_duration, target_index, total_events)
        ));
        return;
    }

    if target_index <= current_index {
        // Backward seek: rebuild session from scratch
        let replay = ui_state.replay_state.as_ref().unwrap();
        let sessions_read = sessions.read();
        if let Some(session_lock) = sessions_read.get(&target_ip) {
            let mut session = session_lock.write();
            let target = session.target.clone();
            let config = session.config.clone();
            *session = Session::new(target, config);
            for event in &replay.events[..target_index] {
                session.apply_replay_event(event);
            }
        }
    } else {
        // Forward seek: apply events incrementally
        let replay = ui_state.replay_state.as_ref().unwrap();
        let sessions_read = sessions.read();
        if let Some(session_lock) = sessions_read.get(&target_ip) {
            let mut session = session_lock.write();
            for event in &replay.events[current_index..target_index] {
                session.apply_replay_event(event);
            }
        }
    }

    // Now mutate replay state
    let replay = ui_state.replay_state.as_mut().unwrap();
    replay.paused = true;
    replay.paused_at_elapsed_ms = target_ms;
    replay.finished = target_index >= total_events;
    replay.current_index = target_index;

    ui_state.set_status(format!(
        "Moved to {}",
        format_replay_position(target_ms, total_duration, target_index, total_events)
    ));
}

/// Seek replay to the final event position (all events applied).
fn seek_replay_to_end(ui_state: &mut UiState, sessions: &SessionMap, target_ip: IpAddr) {
    let (total_duration, target_index, current_index) = {
        let replay = match ui_state.replay_state.as_ref() {
            Some(r) => r,
            None => return,
        };
        (
            replay.events.last().map_or(0, |e| e.offset_ms),
            replay.events.len(),
            replay.current_index,
        )
    };

    if target_index > current_index {
        let replay = ui_state.replay_state.as_ref().unwrap();
        let sessions_read = sessions.read();
        if let Some(session_lock) = sessions_read.get(&target_ip) {
            let mut session = session_lock.write();
            for event in &replay.events[current_index..target_index] {
                session.apply_replay_event(event);
            }
        }
    }

    let replay = ui_state.replay_state.as_mut().unwrap();
    replay.paused = true;
    replay.paused_at_elapsed_ms = total_duration;
    replay.finished = true;
    replay.current_index = target_index;

    ui_state.set_status(format!(
        "Moved to {}",
        format_replay_position(total_duration, total_duration, target_index, target_index)
    ));
}

/// Compute a replay target time from current position + signed delta using saturation.
fn replay_target_ms_from_delta(current_ms: u64, delta_ms: i64) -> u64 {
    if delta_ms >= 0 {
        current_ms.saturating_add(delta_ms as u64)
    } else {
        current_ms.saturating_sub(delta_ms.unsigned_abs())
    }
}

/// Seek replay by a relative delta (in replay milliseconds). Negative values seek backward.
fn seek_replay(ui_state: &mut UiState, sessions: &SessionMap, target_ip: IpAddr, delta_ms: i64) {
    let current_ms = match ui_state.replay_state.as_ref() {
        Some(r) => replay_current_ms(r),
        None => return,
    };
    let target_ms = replay_target_ms_from_delta(current_ms, delta_ms);
    seek_replay_to(ui_state, sessions, target_ip, target_ms);
}

/// Adjust replay speed by delta, preserving current position
fn adjust_replay_speed(ui_state: &mut UiState, delta: f32) {
    let new_speed = {
        let replay = match ui_state.replay_state.as_mut() {
            Some(r) => r,
            None => return,
        };
        let current_ms = replay_current_ms(replay);
        replay.speed_multiplier = (replay.speed_multiplier + delta).clamp(0.1, 1000.0);

        if !replay.paused {
            rebase_replay_start(replay, current_ms);
        }

        replay.speed_multiplier
    };

    ui_state.set_status(format!("Speed: {:.1}x", new_speed));
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

        // Poll for update check result (non-blocking)
        // Drop receiver once we get any result (Some or None) or sender disconnects
        if let (None, Some(rx)) = (&ui_state.update_available, &ui_state.update_rx) {
            match rx.try_recv() {
                Ok(result) => {
                    ui_state.update_available = result;
                    ui_state.update_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    ui_state.update_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }

        // Process replay animation tick
        if let Some(ref mut replay) = ui_state.replay_state
            && !replay.paused
            && !replay.finished
        {
            // Calculate elapsed replay time (adjusted for speed)
            let adjusted_elapsed = replay_current_ms(replay);

            // Capture target before acquiring locks to prevent race condition
            let target_ip = targets[ui_state.selected_target];

            // Find all events up to current adjusted time
            let start = replay.current_index;
            let mut end = start;
            while end < replay.events.len() && replay.events[end].offset_ms <= adjusted_elapsed {
                end += 1;
            }

            // Apply all events in a single lock acquisition (no per-event lock churn)
            if end > start {
                let sessions_read = sessions.read();
                if let Some(session_lock) = sessions_read.get(&target_ip) {
                    let mut session = session_lock.write();
                    for event in &replay.events[start..end] {
                        session.apply_replay_event(event);
                    }
                }
                replay.current_index = end;
            }

            // Check if replay is complete
            if replay.current_index >= replay.events.len() {
                replay.finished = true;
                ui_state.set_status("Replay complete");
            }
        }

        // Get current theme
        let theme = Theme::by_name(theme_names[ui_state.theme_index]);

        // Get current target's session
        let current_target = targets[ui_state.selected_target];

        // Get cache status for settings modal
        let cache_status = ix_lookup.as_ref().map(|ix| ix.get_cache_status());

        // Snapshot session data BEFORE draw so no locks are held during rendering.
        // Uses snapshot_for_render() to skip cloning the events vec (unbounded, not used in render).
        let session_snapshot = {
            let sessions_read = sessions.read();
            sessions_read
                .get(&current_target)
                .map(|state| state.read().snapshot_for_render())
        };

        // Refresh target list cache (~every 500ms while overlay is open)
        if ui_state.show_target_list {
            ui_state.target_list_tick += 1;
            if ui_state.target_list_cache.is_none() || ui_state.target_list_tick.is_multiple_of(30)
            {
                ui_state.target_list_cache = Some(extract_target_infos(&sessions, &targets));
            }
        } else {
            ui_state.target_list_cache = None;
            ui_state.target_list_tick = 0;
        }

        // Draw (no locks held — all data is pre-extracted snapshots)
        if let Some(ref session) = session_snapshot {
            terminal.draw(|f| {
                draw_ui(
                    f,
                    session,
                    ui_state,
                    &theme,
                    num_targets,
                    cache_status.clone(),
                    ix_enabled,
                );
            })?;
        }

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
                    if ui_state.replay_state.is_some() {
                        // In replay mode, 'p' toggles replay pause (same as Space)
                        toggle_replay_pause(ui_state);
                    } else {
                        // In live mode, 'p' toggles probe engine pause
                        ui_state.paused = !ui_state.paused;
                        let sessions_read = sessions.read();
                        if let Some(state) = sessions_read.get(&current_target) {
                            let mut session = state.write();
                            session.paused = ui_state.paused;
                        }
                        ui_state.set_status(if ui_state.paused { "Paused" } else { "Resumed" });
                    }
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
                        ui_state.target_list_cache =
                            Some(extract_target_infos(&sessions, &targets));
                        ui_state.target_list_tick = 0;
                    }
                }
                KeyCode::Char('u') => {
                    // Dismiss update notification
                    if ui_state.update_available.is_some() {
                        ui_state.update_available = None;
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
                KeyCode::Char(' ') => {
                    // Space works the same as 'p': replay pause or live pause
                    if ui_state.replay_state.is_some() {
                        toggle_replay_pause(ui_state);
                    } else {
                        ui_state.paused = !ui_state.paused;
                        let sessions_read = sessions.read();
                        if let Some(state) = sessions_read.get(&current_target) {
                            let mut session = state.write();
                            session.paused = ui_state.paused;
                        }
                        ui_state.set_status(if ui_state.paused { "Paused" } else { "Resumed" });
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
                // Replay controls
                KeyCode::Left if ui_state.replay_state.is_some() => {
                    seek_replay(ui_state, &sessions, current_target, -500);
                }
                KeyCode::Right if ui_state.replay_state.is_some() => {
                    seek_replay(ui_state, &sessions, current_target, 500);
                }
                KeyCode::Char('[') if ui_state.replay_state.is_some() => {
                    seek_replay(ui_state, &sessions, current_target, -5000);
                }
                KeyCode::Char(']') if ui_state.replay_state.is_some() => {
                    seek_replay(ui_state, &sessions, current_target, 5000);
                }
                KeyCode::Char('+') | KeyCode::Char('>') if ui_state.replay_state.is_some() => {
                    adjust_replay_speed(ui_state, 0.5);
                }
                KeyCode::Char('-') | KeyCode::Char('<') if ui_state.replay_state.is_some() => {
                    adjust_replay_speed(ui_state, -0.5);
                }
                KeyCode::Home if ui_state.replay_state.is_some() => {
                    seek_replay_to(ui_state, &sessions, current_target, 0);
                }
                KeyCode::End if ui_state.replay_state.is_some() => {
                    seek_replay_to_end(ui_state, &sessions, current_target);
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
    cache_status: Option<crate::lookup::ix::CacheStatus>,
    ix_enabled: bool,
) {
    let area = f.area();

    // Layout: optional update banner + main view + optional replay progress + status bar
    let has_update = ui_state.update_available.is_some();
    let has_replay = ui_state.replay_state.is_some();
    let mut constraints = Vec::new();
    if has_update {
        constraints.push(Constraint::Length(1)); // Update banner
    }
    constraints.push(Constraint::Min(0)); // Main view
    if has_replay {
        constraints.push(Constraint::Length(1)); // Replay progress bar
    }
    constraints.push(Constraint::Length(1)); // Status bar

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // Assign chunk indices based on which optional rows are present
    let mut idx = 0;

    // Update notification banner (if available)
    if has_update {
        if let Some(ref version) = ui_state.update_available {
            let update_text = format!(
                " Update available: v{} -> {} | Press 'u' to dismiss ",
                env!("CARGO_PKG_VERSION"),
                version
            );
            let update_bar = Paragraph::new(update_text)
                .style(Style::default().fg(Color::Black).bg(Color::Yellow));
            f.render_widget(update_bar, chunks[idx]);
        }
        idx += 1;
    }

    let main_chunk = chunks[idx];
    idx += 1;

    let progress_chunk = if has_replay {
        let chunk = chunks[idx];
        idx += 1;
        Some(chunk)
    } else {
        None
    };

    let status_chunk = chunks[idx];

    // Main view (with target indicator and display mode)
    let main_view = MainView::new(session, ui_state.selected, ui_state.paused, theme)
        .with_target_info(ui_state.selected_target + 1, num_targets)
        .with_display_mode(ui_state.display_mode);
    f.render_widget(main_view, main_chunk);

    // Replay progress bar
    if let (Some(chunk), Some(replay)) = (progress_chunk, &ui_state.replay_state) {
        let current_ms = replay_current_ms(replay);
        let total_ms = replay.events.last().map_or(0, |e| e.offset_ms);
        let icon = if replay.finished {
            "--"
        } else if replay.paused {
            "||"
        } else {
            ">>"
        };
        let instant_suffix = if total_ms == 0 && !replay.events.is_empty() {
            " instant"
        } else {
            ""
        };
        let label = format!(
            " {} {}/{} {} / {} {:.1}x{} ",
            icon,
            replay.current_index,
            replay.events.len(),
            format_replay_time(current_ms),
            format_replay_time(total_ms),
            replay.speed_multiplier,
            instant_suffix,
        );
        let ratio = if total_ms > 0 {
            (current_ms as f64 / total_ms as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let gauge = LineGauge::default()
            .filled_style(Style::default().fg(theme.success).bg(theme.highlight_bg))
            .label(label)
            .ratio(ratio);
        f.render_widget(gauge, chunk);
    }

    // Status bar (use Cow to avoid allocation for static strings)
    // Update notification takes priority over normal status
    let (status_text, status_style): (Cow<'_, str>, Style) = if let Some(ref version) =
        ui_state.update_available
    {
        (
            Cow::Owned(format!(
                "UPDATE: v{} -> {} available | Press 'u' to dismiss | ? for update command",
                env!("CARGO_PKG_VERSION"),
                version
            )),
            Style::default().fg(Color::Yellow),
        )
    } else if let Some((ref msg, _)) = ui_state.status_message {
        (
            Cow::Borrowed(msg.as_str()),
            Style::default().fg(theme.text_dim),
        )
    } else if ui_state.replay_state.is_some() {
        (
            Cow::Borrowed(
                "q quit | p pause | Left/Right seek | [/] seek 5s | +/- speed | Home/End | ? help",
            ),
            Style::default().fg(theme.text_dim),
        )
    } else if num_targets > 1 {
        (
            Cow::Borrowed(
                "q quit | Tab next | l list | p pause | r reset | t theme | w display | s settings | e export | ? help",
            ),
            Style::default().fg(theme.text_dim),
        )
    } else {
        (
            Cow::Borrowed(
                "q quit | p pause | r reset | t theme | w display | s settings | e export | ? help",
            ),
            Style::default().fg(theme.text_dim),
        )
    };

    let status_bar = Paragraph::new(status_text.as_ref()).style(status_style);
    f.render_widget(status_bar, status_chunk);

    // Overlays
    if ui_state.show_help {
        f.render_widget(
            HelpView::new(theme).with_replay(ui_state.replay_state.is_some()),
            area,
        );
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

    if ui_state.show_target_list
        && let Some(ref infos) = ui_state.target_list_cache
    {
        f.render_widget(
            TargetListView::new(theme, infos, ui_state.target_list_index),
            area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::Target;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn make_single_session_map(target: IpAddr, session: Session) -> SessionMap {
        let mut map = HashMap::new();
        map.insert(target, Arc::new(parking_lot::RwLock::new(session)));
        Arc::new(parking_lot::RwLock::new(map))
    }

    fn make_timeout_event(offset_ms: u64, ttl: u8, seq: u8) -> ProbeEvent {
        ProbeEvent {
            offset_ms,
            ttl,
            seq,
            flow_id: 0,
            outcome: ProbeOutcome::Timeout,
        }
    }

    #[test]
    fn test_replay_event_index_for_time_home_is_empty() {
        let events = vec![make_timeout_event(0, 1, 0), make_timeout_event(100, 1, 1)];
        assert_eq!(replay_event_index_for_time(&events, 0), 0);
    }

    #[test]
    fn test_replay_event_index_for_time_end_includes_all() {
        let events = vec![make_timeout_event(0, 1, 0), make_timeout_event(100, 1, 1)];
        assert_eq!(replay_event_index_for_time(&events, 100), 2);
    }

    #[test]
    fn test_adjust_replay_speed_clamps() {
        let mut ui_state = UiState {
            replay_state: Some(ReplayState::new(Vec::new(), 0.1)),
            ..UiState::default()
        };
        adjust_replay_speed(&mut ui_state, -0.5);
        assert_eq!(
            ui_state.replay_state.as_ref().unwrap().speed_multiplier,
            0.1
        );

        ui_state.replay_state.as_mut().unwrap().speed_multiplier = 1000.0;
        adjust_replay_speed(&mut ui_state, 0.5);
        assert_eq!(
            ui_state.replay_state.as_ref().unwrap().speed_multiplier,
            1000.0
        );
    }

    #[test]
    fn test_rebase_replay_start_handles_large_timestamps() {
        let mut replay = ReplayState::new(Vec::new(), 1.0);
        rebase_replay_start(&mut replay, u64::MAX);
    }

    #[test]
    fn test_replay_target_ms_from_delta_saturates() {
        assert_eq!(replay_target_ms_from_delta(1000, -500), 500);
        assert_eq!(replay_target_ms_from_delta(1000, -5000), 0);
        assert_eq!(replay_target_ms_from_delta(u64::MAX - 10, 100), u64::MAX);
        assert_eq!(replay_target_ms_from_delta(u64::MAX, i64::MAX), u64::MAX);
    }

    #[test]
    fn test_seek_replay_to_end_applies_all_zero_offset_events() {
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let session = Session::new(Target::new("t".to_string(), target), Config::default());
        let sessions = make_single_session_map(target, session);
        let events = vec![make_timeout_event(0, 1, 0), make_timeout_event(0, 2, 1)];

        let mut ui_state = UiState {
            replay_state: Some(ReplayState {
                events,
                current_index: 0,
                replay_started_at: std::time::Instant::now(),
                speed_multiplier: 1.0,
                paused: false,
                finished: false,
                paused_at_elapsed_ms: 0,
            }),
            ..UiState::default()
        };

        seek_replay_to_end(&mut ui_state, &sessions, target);

        let session_lock = sessions.read().get(&target).cloned().unwrap();
        let session = session_lock.read();
        assert_eq!(session.total_sent, 2);
        assert_eq!(session.hop(1).unwrap().timeouts, 1);
        assert_eq!(session.hop(2).unwrap().timeouts, 1);

        let replay = ui_state.replay_state.as_ref().unwrap();
        assert!(replay.finished);
        assert_eq!(replay.current_index, 2);
    }

    #[test]
    fn test_seek_replay_to_same_position_is_noop_for_session_state() {
        let target = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let session = Session::new(Target::new("t".to_string(), target), Config::default());
        let sessions = make_single_session_map(target, session);
        let events = vec![make_timeout_event(100, 1, 0)];

        let mut ui_state = UiState {
            replay_state: Some(ReplayState {
                events,
                current_index: 0,
                replay_started_at: std::time::Instant::now(),
                speed_multiplier: 1.0,
                paused: false,
                finished: false,
                paused_at_elapsed_ms: 0,
            }),
            ..UiState::default()
        };

        seek_replay_to(&mut ui_state, &sessions, target, 0);

        let session_lock = sessions.read().get(&target).cloned().unwrap();
        let session = session_lock.read();
        assert_eq!(session.total_sent, 0);
        assert_eq!(session.hop(1).unwrap().sent, 0);

        let replay = ui_state.replay_state.as_ref().unwrap();
        assert_eq!(replay.current_index, 0);
        assert!(replay.paused);
    }
}
